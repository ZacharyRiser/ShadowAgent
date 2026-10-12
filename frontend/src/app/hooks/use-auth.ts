// 认证（auth）域：登录/注册表单、bootstrap 状态、SSO 发起、演示身份、登出归仓（阶段 2）。
// user / authSession / settings 是跨域会话根，仍由 page 持有并通过参数注入；
// enterDemo / logout 需要重置的跨域状态（日志、托管密钥、网关结果、组织上下文）
// 同样以 setter 参数注入 —— 与 useGateway 接收 localInspect 的既有模式一致。
// handleAuth 的「网络层失败 → 后端不可达横幅」翻译保留在本 hook（它同时是 UI 语义）。

import { useCallback, useState } from "react";
import type { AuthSession, InterceptLog, ManagedApiKeyIssueState, ManagedApiKeyItem, OrgInfo, SessionUser, Toast } from "../types";
import type { GatewayResult } from "../gateway-types";
import { apiGet, detailText } from "../api-client";
import { isValidEmailInput, type BootstrapStatus } from "../auth-logic";
import { removeStorage, STORAGE_KEYS, writeStorage } from "../app-meta";
import { asNumber } from "../components/ui-kit";

export type AuthForm = {
  name: string;
  email: string;
  password: string;
  confirmPassword: string;
  bootstrapToken: string;
  inviteToken: string;
};

export function useAuth({
  apiBaseUrl,
  addToast,
  setAuthSession,
  setUser,
  setLogs,
  setManagedKeys,
  setManagedKeyIssueState,
  setGatewayResult,
  setOrgContext,
  stampSampleLogs,
}: {
  apiBaseUrl: string;
  addToast: (message: string, type?: Toast["type"]) => void;
  setAuthSession: (next: AuthSession | null) => void;
  setUser: (next: SessionUser | null) => void;
  setLogs: (next: InterceptLog[]) => void;
  setManagedKeys: (next: ManagedApiKeyItem[]) => void;
  setManagedKeyIssueState: (next: ManagedApiKeyIssueState | null) => void;
  setGatewayResult: (next: GatewayResult | null) => void;
  setOrgContext: (next: { orgs: OrgInfo[]; activeOrgId: number | null; activeOrgRole: string | null }) => void;
  stampSampleLogs: () => InterceptLog[];
}) {
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [authForm, setAuthForm] = useState<AuthForm>({ name: "", email: "", password: "", confirmPassword: "", bootstrapToken: "", inviteToken: "" });
  const [bootstrapStatus, setBootstrapStatus] = useState<BootstrapStatus | null>(null);
  // null 的 bootstrapStatus 有歧义：既可能是「还没加载完」，也可能是「后端连不上」。
  // 这两者必须分开——否则连不上后端时，横幅会谎报成「注册已关闭」这类确定性策略结论。
  const [bootstrapUnreachable, setBootstrapUnreachable] = useState(false);
  const [authBusy, setAuthBusy] = useState(false);
  const [authError, setAuthError] = useState("");
  const [ssoSlug, setSsoSlug] = useState("");
  const [ssoBusy, setSsoBusy] = useState(false);
  const [ssoHint, setSsoHint] = useState("");

  const loadBootstrapStatus = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const response = await fetch(`${apiBaseUrl}/api/v1/auth/bootstrap-status`, {
          signal,
          cache: "no-store",
        });
        const data = (await response.json().catch(() => null)) as BootstrapStatus | null;
        if (!response.ok || !data) {
          setBootstrapStatus(null);
          setBootstrapUnreachable(false);
          return;
        }
        setBootstrapStatus(data);
        setBootstrapUnreachable(false);
      } catch {
        // AbortError = 组件卸载 / 依赖变更导致的正常中止，不是「连不上后端」，别误报。
        if (signal?.aborted) return;
        setBootstrapStatus(null);
        setBootstrapUnreachable(true);
      }
    },
    [apiBaseUrl]
  );

  const handleAuth = async (event: { preventDefault(): void }) => {
    event.preventDefault();
    const email = authForm.email.trim().toLowerCase();
    const password = authForm.password;

    // 校验失败必须**同时**给内联错误与 toast：只弹 toast 时用户很容易认为
    // 「点了没反应」——toast 会自动消失，且可能落在可视区之外。
    const fail = (message: string) => {
      setAuthError(message);
      addToast(message, "error");
    };

    setAuthError("");

    if (!email || !password) {
      fail("请输入邮箱和密码");
      return;
    }

    if (authMode === "register") {
      if (!authForm.name.trim()) {
        fail("请输入姓名");
        return;
      }
      // 注册即建立身份，格式必须在发请求前拦住（后端同样会校验）。
      // 登录不做形状拦截：历史上已存在的非标准账号不能被锁在门外。
      if (!isValidEmailInput(email)) {
        fail("邮箱格式不正确，请填写形如 name@example.com 的地址");
        return;
      }
      if (password.length < 6) {
        fail("密码至少需要 6 位");
        return;
      }
      if (password !== authForm.confirmPassword) {
        fail("两次输入的密码不一致");
        return;
      }
    }

    setAuthBusy(true);
    try {
      const endpoint =
        authMode === "login"
          ? `${apiBaseUrl}/api/v1/auth/login`
          : `${apiBaseUrl}/api/v1/auth/register`;
      const bootstrapToken = authForm.bootstrapToken.trim();
      const inviteToken = authForm.inviteToken.trim();
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(authMode === "register" && bootstrapToken ? { "X-Shadow-Agent-Bootstrap-Token": bootstrapToken } : {}),
          ...(authMode === "register" && inviteToken ? { "X-Shadow-Agent-Invite-Token": inviteToken } : {}),
        },
        body: JSON.stringify(
          authMode === "login"
            ? { email, password }
            : { name: authForm.name.trim(), email, password }
        ),
      });
      const data = (await response.json().catch(() => ({}))) as {
        access_token?: string;
        token_type?: string;
        expires_at?: number;
        user?: { id: string; name: string; email: string; role: string; created_at: string };
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
      const nextAuthSession: AuthSession = {
        accessToken: data.access_token,
        tokenType: "bearer",
        expiresAt: asNumber(data.expires_at),
        user: sessionUser,
      };
      setAuthSession(nextAuthSession);
      setUser(sessionUser);
      removeStorage(STORAGE_KEYS.authSession);
      removeStorage(STORAGE_KEYS.session);
      setAuthForm({ name: "", email: "", password: "", confirmPassword: "", bootstrapToken: "", inviteToken: "" });
      void loadBootstrapStatus();
      setAuthError("");
      addToast(
        authMode === "login"
          ? "登录成功"
          : data.user.role === "admin" || data.user.role === "security_admin"
            ? "注册成功，已进入管理员控制台"
            : "注册成功，当前为普通网关账号",
        "success"
      );
    } catch (error) {
      // 网络层失败（后端没起 / 端口不通）时浏览器只给一句 "Failed to fetch"，
      // 对用户毫无指向性 → 翻译成可执行的排查提示，并顺手点亮横幅的「后端不可达」状态。
      const isNetworkFailure =
        error instanceof TypeError ||
        (error instanceof Error && /failed to fetch|network ?error|load failed/i.test(error.message));
      if (isNetworkFailure) {
        setBootstrapUnreachable(true);
      }
      const message = isNetworkFailure
        ? `无法连接后端服务（${apiBaseUrl}），请确认后端已启动后重试`
        : error instanceof Error
          ? error.message
          : authMode === "login"
            ? "登录失败"
            : "注册失败";
      setAuthError(message);
      addToast(message, "error");
    } finally {
      setAuthBusy(false);
    }
  };

  const enterDemo = () => {
    const demoUser: SessionUser = {
      id: "demo-admin",
      name: "安全管理员（演示）",
      email: "demo@shadow.local",
      role: "admin",
      createdAt: new Date().toISOString(),
    };
    const stamped = stampSampleLogs();
    writeStorage(STORAGE_KEYS.session, demoUser);
    writeStorage(STORAGE_KEYS.localLogs, stamped);
    removeStorage(STORAGE_KEYS.authSession);
    setAuthSession(null);
    setUser(demoUser);
    setLogs(stamped);
    setManagedKeys([]);
    setManagedKeyIssueState(null);
    addToast("已使用本地验证身份进入", "success");
  };

  const logout = () => {
    removeStorage(STORAGE_KEYS.authSession);
    removeStorage(STORAGE_KEYS.session);
    setAuthSession(null);
    setUser(null);
    setGatewayResult(null);
    setManagedKeys([]);
    setManagedKeyIssueState(null);
    setOrgContext({ orgs: [], activeOrgId: null, activeOrgRole: null });
    addToast("已退出登录", "info");
  };

  const startSsoLogin = async () => {
    const slug = ssoSlug.trim().toLowerCase();
    if (!slug) {
      addToast("请输入组织标识（slug）", "error");
      return;
    }
    setSsoBusy(true);
    setSsoHint("");
    try {
      const data = await apiGet<{
        enabled?: boolean;
        provider_name?: string;
        login_url?: string;
        detail?: unknown;
      }>(`${apiBaseUrl}/api/v1/auth/sso/providers/${encodeURIComponent(slug)}`);
      if (!data.enabled || !data.login_url) {
        throw new Error("该组织未启用 SSO 登录，请使用邮箱密码登录或联系组织管理员。");
      }
      // login_url is a backend-relative path; the gateway owns discovery/PKCE.
      window.location.href = `${apiBaseUrl}${data.login_url}`;
    } catch (error) {
      setSsoHint(error instanceof Error ? error.message : "SSO 登录发起失败");
      addToast(error instanceof Error ? error.message : "SSO 登录发起失败", "error");
    } finally {
      setSsoBusy(false);
    }
  };

  return {
    authMode,
    setAuthMode,
    authForm,
    setAuthForm,
    bootstrapStatus,
    setBootstrapStatus,
    bootstrapUnreachable,
    authBusy,
    authError,
    setAuthError,
    ssoSlug,
    setSsoSlug,
    ssoBusy,
    ssoHint,
    loadBootstrapStatus,
    handleAuth,
    enterDemo,
    logout,
    startSsoLogin,
  };
}
