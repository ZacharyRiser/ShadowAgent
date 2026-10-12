// 组织（orgs）域：列表/成员/SSO 配置/切换组织归仓（阶段 2）。
// orgContext 是会话级状态（侧栏、鉴权共用），仍归 page；switchActiveOrg 通过参数读写它。
// setAuthSession / setUser 同理注入 —— 本 hook 不拥有会话。

import { useCallback, useEffect, useState } from "react";
import type { AppSettings, AuthSession, OrgInfo, OrgListItem, OrgMemberItem, SessionUser, SsoConfigItem, Toast, ViewKey } from "../types";
import { apiGet, buildHeaders, detailText } from "../api-client";
import { asNumber } from "../components/ui-kit";

export function useOrgs({
  apiBaseUrl,
  settings,
  authSession,
  setAuthSession,
  setUser,
  orgContext,
  setOrgContext,
  hasAdminAccess,
  addToast,
  mounted,
  user,
  effectiveView,
}: {
  apiBaseUrl: string;
  settings: AppSettings;
  authSession: AuthSession | null;
  setAuthSession: (session: AuthSession | null) => void;
  setUser: (user: SessionUser | null) => void;
  orgContext: { orgs: OrgInfo[]; activeOrgId: number | null; activeOrgRole: string | null };
  setOrgContext: (updater: (current: { orgs: OrgInfo[]; activeOrgId: number | null; activeOrgRole: string | null }) => { orgs: OrgInfo[]; activeOrgId: number | null; activeOrgRole: string | null }) => void;
  hasAdminAccess: boolean;
  addToast: (message: string, type?: Toast["type"]) => void;
  mounted: boolean;
  user: SessionUser | null;
  effectiveView: ViewKey;
}) {
  const [orgList, setOrgList] = useState<OrgListItem[]>([]);
  const [orgListLoading, setOrgListLoading] = useState(false);
  const [orgListError, setOrgListError] = useState("");
  const [orgCreateOpen, setOrgCreateOpen] = useState(false);
  const [orgCreateBusy, setOrgCreateBusy] = useState(false);
  const [orgCreateForm, setOrgCreateForm] = useState({ slug: "", name: "" });
  const [orgSelectedId, setOrgSelectedId] = useState<number | null>(null);
  const [orgMembers, setOrgMembers] = useState<OrgMemberItem[]>([]);
  const [orgMembersLoading, setOrgMembersLoading] = useState(false);
  const [memberAddForm, setMemberAddForm] = useState({ email: "", role: "member" });
  const [memberAddBusy, setMemberAddBusy] = useState(false);
  const [memberBusyId, setMemberBusyId] = useState<number | null>(null);
  const [orgSsoConfig, setOrgSsoConfig] = useState<SsoConfigItem | null>(null);
  const [orgSsoForm, setOrgSsoForm] = useState({
    provider_name: "",
    client_id: "",
    client_secret: "",
    issuer_url: "",
    scopes: "openid email profile",
    default_role: "client",
    jit_enabled: true,
    enabled: true,
  });
  const [orgSsoLoading, setOrgSsoLoading] = useState(false);
  const [orgSsoBusy, setOrgSsoBusy] = useState(false);
  const [orgSwitchBusy, setOrgSwitchBusy] = useState(false);

  const switchActiveOrg = async (orgId: number) => {
    if (!authSession || orgId === orgContext.activeOrgId || orgSwitchBusy) return;
    setOrgSwitchBusy(true);
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/auth/switch-org`, {
        method: "POST",
        headers: {
          ...(buildHeaders(settings, "client", true, authSession)),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ org_id: orgId }),
      });
      const data = (await response.json().catch(() => ({}))) as {
        access_token?: string;
        token_type?: string;
        expires_at?: number;
        user?: { id: string; name: string; email: string; role: string; created_at: string };
        org?: { id: number; slug: string; name: string; is_default: boolean; role: string } | null;
        detail?: unknown;
      };
      if (!response.ok || !data.access_token || !data.user) {
        throw new Error(detailText(data.detail) || `HTTP ${response.status}`);
      }
      const sessionUser: SessionUser = {
        id: data.user.id,
        name: data.user.name,
        email: data.user.email,
        role: data.user.role,
        createdAt: data.user.created_at,
      };
      setAuthSession({
        accessToken: data.access_token,
        tokenType: "bearer",
        expiresAt: asNumber(data.expires_at),
        user: sessionUser,
      });
      setUser(sessionUser);
      const nextOrg = data.org ?? null;
      if (nextOrg) {
        setOrgContext((current) => ({
          orgs: current.orgs.some((org) => org.id === nextOrg.id)
            ? current.orgs.map((org) => (org.id === nextOrg.id ? { ...org, role: nextOrg.role } : org))
            : [...current.orgs, { ...nextOrg, role: nextOrg.role }],
          activeOrgId: nextOrg.id,
          activeOrgRole: nextOrg.role,
        }));
      }
      addToast(`已切换到组织「${nextOrg?.name ?? orgId}」`, "success");
    } catch (error) {
      addToast(error instanceof Error ? error.message : "组织切换失败", "error");
    } finally {
      setOrgSwitchBusy(false);
    }
  };

  const loadOrgList = useCallback(async () => {
    if (!hasAdminAccess) return;
    setOrgListLoading(true);
    setOrgListError("");
    try {
      const data = await apiGet<{ items?: Array<OrgListItem>; detail?: unknown }>(`${apiBaseUrl}/api/v1/orgs`, {
        headers: buildHeaders(settings, "admin", false, authSession),
      });
      if (!Array.isArray(data.items)) {
        throw new Error(detailText(data.detail) || "HTTP 200（响应缺少 items）");
      }
      setOrgList(data.items);
    } catch (error) {
      setOrgListError(error instanceof Error ? error.message : "组织列表加载失败");
    } finally {
      setOrgListLoading(false);
    }
  }, [apiBaseUrl, authSession, hasAdminAccess, settings]);

  const selectOrg = useCallback(
    (orgId: number | null) => {
      setOrgSelectedId(orgId);
      setOrgMembers([]);
      setOrgSsoConfig(null);
      if (orgId === null) return;
      const load = async () => {
        setOrgMembersLoading(true);
        setOrgSsoLoading(true);
        const headers = buildHeaders(settings, "admin", false, authSession);
        try {
          const membersResponse = await fetch(`${apiBaseUrl}/api/v1/orgs/${orgId}/members`, {
            headers,
            cache: "no-store",
          });
          const membersData = (await membersResponse.json().catch(() => ({}))) as {
            items?: Array<OrgMemberItem>;
            detail?: unknown;
          };
          if (!membersResponse.ok || !Array.isArray(membersData.items)) {
            throw new Error(detailText(membersData.detail) || `HTTP ${membersResponse.status}`);
          }
          setOrgMembers(membersData.items);
        } catch (error) {
          addToast(error instanceof Error ? error.message : "成员列表加载失败", "error");
        } finally {
          setOrgMembersLoading(false);
        }
        try {
          const ssoData = await apiGet<{
            item?: SsoConfigItem | null;
            detail?: unknown;
          }>(`${apiBaseUrl}/api/v1/orgs/${orgId}/sso`, { headers });
          setOrgSsoConfig(ssoData.item ?? null);
          if (ssoData.item) {
            setOrgSsoForm({
              provider_name: ssoData.item.provider_name,
              client_id: ssoData.item.client_id,
              client_secret: "",
              issuer_url: ssoData.item.issuer_url,
              scopes: ssoData.item.scopes,
              default_role: ssoData.item.default_role,
              jit_enabled: ssoData.item.jit_enabled,
              enabled: ssoData.item.enabled,
            });
          } else {
            setOrgSsoForm({
              provider_name: "",
              client_id: "",
              client_secret: "",
              issuer_url: "",
              scopes: "openid email profile",
              default_role: "client",
              jit_enabled: true,
              enabled: true,
            });
          }
        } catch (error) {
          addToast(error instanceof Error ? error.message : "SSO 配置加载失败", "error");
        } finally {
          setOrgSsoLoading(false);
        }
      };
      void load();
    },
    [addToast, apiBaseUrl, authSession, settings]
  );

  const createOrg = async () => {
    const slug = orgCreateForm.slug.trim().toLowerCase();
    const name = orgCreateForm.name.trim();
    if (!slug || !name) {
      addToast("请填写组织标识与名称", "error");
      return;
    }
    setOrgCreateBusy(true);
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/orgs`, {
        method: "POST",
        headers: {
          ...buildHeaders(settings, "admin", true, authSession),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ slug, name }),
      });
      const data = (await response.json().catch(() => ({}))) as { item?: OrgListItem; detail?: unknown };
      if (!response.ok || !data.item) {
        throw new Error(detailText(data.detail) || `HTTP ${response.status}`);
      }
      addToast(`组织「${data.item.name}」已创建`, "success");
      setOrgCreateForm({ slug: "", name: "" });
      setOrgCreateOpen(false);
      await loadOrgList();
      await selectOrg(data.item.id);
    } catch (error) {
      addToast(error instanceof Error ? error.message : "组织创建失败", "error");
    } finally {
      setOrgCreateBusy(false);
    }
  };

  const addOrgMember = async () => {
    if (orgSelectedId === null) return;
    const email = memberAddForm.email.trim().toLowerCase();
    if (!email) {
      addToast("请输入成员邮箱", "error");
      return;
    }
    setMemberAddBusy(true);
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/orgs/${orgSelectedId}/members`, {
        method: "POST",
        headers: {
          ...buildHeaders(settings, "admin", true, authSession),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email, role: memberAddForm.role }),
      });
      const data = (await response.json().catch(() => ({}))) as { item?: OrgMemberItem; detail?: unknown };
      if (!response.ok || !data.item) {
        throw new Error(detailText(data.detail) || `HTTP ${response.status}`);
      }
      setOrgMembers((current) => [...current, data.item!]);
      setMemberAddForm({ email: "", role: "member" });
      addToast(`已添加成员 ${data.item.email}`, "success");
    } catch (error) {
      addToast(error instanceof Error ? error.message : "成员添加失败", "error");
    } finally {
      setMemberAddBusy(false);
    }
  };

  const updateOrgMemberRole = async (userId: number, role: string) => {
    if (orgSelectedId === null) return;
    setMemberBusyId(userId);
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/orgs/${orgSelectedId}/members/${userId}`, {
        method: "PATCH",
        headers: {
          ...buildHeaders(settings, "admin", true, authSession),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ role }),
      });
      const data = (await response.json().catch(() => ({}))) as { item?: OrgMemberItem; detail?: unknown };
      if (!response.ok || !data.item) {
        throw new Error(detailText(data.detail) || `HTTP ${response.status}`);
      }
      setOrgMembers((current) => current.map((item) => (item.user_id === userId ? data.item! : item)));
      addToast(`已更新 ${data.item.email} 的组织角色`, "success");
    } catch (error) {
      addToast(error instanceof Error ? error.message : "角色更新失败", "error");
    } finally {
      setMemberBusyId(null);
    }
  };

  const removeOrgMember = async (userId: number, email: string) => {
    if (orgSelectedId === null) return;
    setMemberBusyId(userId);
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/orgs/${orgSelectedId}/members/${userId}`, {
        method: "DELETE",
        headers: buildHeaders(settings, "admin", false, authSession),
      });
      const data = (await response.json().catch(() => ({}))) as { deleted?: boolean; detail?: unknown };
      if (!response.ok || !data.deleted) {
        throw new Error(detailText(data.detail) || `HTTP ${response.status}`);
      }
      setOrgMembers((current) => current.filter((item) => item.user_id !== userId));
      addToast(`已移除成员 ${email}`, "success");
    } catch (error) {
      addToast(error instanceof Error ? error.message : "成员移除失败", "error");
    } finally {
      setMemberBusyId(null);
    }
  };

  const saveOrgSso = async () => {
    if (orgSelectedId === null) return;
    const providerName = orgSsoForm.provider_name.trim();
    const clientId = orgSsoForm.client_id.trim();
    const issuerUrl = orgSsoForm.issuer_url.trim().replace(/\/$/, "");
    // A secret is only required when the connection does not exist yet.
    const hasExistingSecret = Boolean(orgSsoConfig?.client_secret_masked);
    const clientSecret = orgSsoForm.client_secret.trim();
    if (!providerName || !clientId || !issuerUrl || (!clientSecret && !hasExistingSecret)) {
      addToast("请填写 provider 名称、client_id、issuer 与 client_secret", "error");
      return;
    }
    setOrgSsoBusy(true);
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/orgs/${orgSelectedId}/sso`, {
        method: "PUT",
        headers: {
          ...buildHeaders(settings, "admin", true, authSession),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          provider_name: providerName,
          client_id: clientId,
          // Empty secret keeps the stored one (backend treats "" as no-rotation).
          client_secret: clientSecret,
          issuer_url: issuerUrl,
          scopes: orgSsoForm.scopes.trim() || "openid email profile",
          default_role: orgSsoForm.default_role,
          jit_enabled: orgSsoForm.jit_enabled,
          enabled: orgSsoForm.enabled,
        }),
      });
      const data = (await response.json().catch(() => ({}))) as { item?: SsoConfigItem; detail?: unknown };
      if (!response.ok || !data.item) {
        throw new Error(detailText(data.detail) || `HTTP ${response.status}`);
      }
      setOrgSsoConfig(data.item);
      setOrgSsoForm((current) => ({ ...current, client_secret: "" }));
      addToast("SSO 配置已保存", "success");
    } catch (error) {
      addToast(error instanceof Error ? error.message : "SSO 配置保存失败", "error");
    } finally {
      setOrgSsoBusy(false);
    }
  };

  const deleteOrgSso = async () => {
    if (orgSelectedId === null || !orgSsoConfig) return;
    setOrgSsoBusy(true);
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/orgs/${orgSelectedId}/sso`, {
        method: "DELETE",
        headers: buildHeaders(settings, "admin", false, authSession),
      });
      const data = (await response.json().catch(() => ({}))) as { deleted?: boolean; detail?: unknown };
      if (!response.ok || !data.deleted) {
        throw new Error(detailText(data.detail) || `HTTP ${response.status}`);
      }
      setOrgSsoConfig(null);
      setOrgSsoForm({
        provider_name: "",
        client_id: "",
        client_secret: "",
        issuer_url: "",
        scopes: "openid email profile",
        default_role: "client",
        jit_enabled: true,
        enabled: true,
      });
      addToast("SSO 连接已删除", "success");
    } catch (error) {
      addToast(error instanceof Error ? error.message : "SSO 配置删除失败", "error");
    } finally {
      setOrgSsoBusy(false);
    }
  };

  // Load the org list whenever the organizations view becomes active.
  useEffect(() => {
    if (!mounted || !user || effectiveView !== "orgs" || !hasAdminAccess) return;
    const timer = window.setTimeout(() => {
      void loadOrgList();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [effectiveView, hasAdminAccess, loadOrgList, mounted, user]);

  return {
    orgList,
    orgListLoading,
    orgListError,
    orgCreateOpen,
    setOrgCreateOpen,
    orgCreateBusy,
    orgCreateForm,
    setOrgCreateForm,
    orgSelectedId,
    setOrgSelectedId,
    orgMembers,
    orgMembersLoading,
    memberAddForm,
    setMemberAddForm,
    memberAddBusy,
    memberBusyId,
    orgSsoConfig,
    orgSsoForm,
    setOrgSsoForm,
    orgSsoLoading,
    orgSsoBusy,
    orgSwitchBusy,
    switchActiveOrg,
    loadOrgList,
    selectOrg,
    createOrg,
    addOrgMember,
    updateOrgMemberRole,
    removeOrgMember,
    saveOrgSso,
    deleteOrgSso,
  };
}
