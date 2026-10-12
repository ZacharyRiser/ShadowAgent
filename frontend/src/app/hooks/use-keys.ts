// 托管密钥（keys）域：状态 + CRUD/轮换/生命周期归仓（阶段 2）。
// applyIssuedKeyToSettings / removeDeletedKeyFromSession 需要写 settings，
// 通过 setSettings 参数注入 —— 本 hook 不拥有 settings（全局配置仍归 page）。

import { useCallback, useState } from "react";
import type { AppSettings, AuthSession, ManagedApiKeyIssueState, ManagedApiKeyItem, ManagedApiKeyRole, Toast } from "../types";
import { apiGet, apiSend, buildHeaders, detailText } from "../api-client";
import { isAdminRole } from "../app-meta";

export function useKeys({
  apiBaseUrl,
  settings,
  setSettings,
  authSession,
  hasAdminAccess,
  addToast,
}: {
  apiBaseUrl: string;
  settings: AppSettings;
  setSettings: (updater: (current: AppSettings) => AppSettings) => void;
  authSession: AuthSession | null;
  hasAdminAccess: boolean;
  addToast: (message: string, type?: Toast["type"]) => void;
}) {
  const [managedKeys, setManagedKeys] = useState<ManagedApiKeyItem[]>([]);
  const [managedKeysLoading, setManagedKeysLoading] = useState(false);
  const [managedKeysError, setManagedKeysError] = useState("");
  const [managedKeyDraftOpen, setManagedKeyDraftOpen] = useState(false);
  const [managedKeyDraft, setManagedKeyDraft] = useState({
    name: "",
    role: "client" as ManagedApiKeyRole,
    description: "",
    expiresInDays: "30",
  });
  const [managedKeyIssueState, setManagedKeyIssueState] = useState<ManagedApiKeyIssueState | null>(null);
  const [managedKeyBusyId, setManagedKeyBusyId] = useState<number | null>(null);
  const [includeInactiveKeys, setIncludeInactiveKeys] = useState(true);

  const loadManagedApiKeys = useCallback(
    async (showFeedback = false) => {
      if (!hasAdminAccess) {
        setManagedKeys([]);
        setManagedKeysError("");
        return;
      }

      setManagedKeysLoading(true);
      setManagedKeysError("");
      const controller = new AbortController();
      const timer = window.setTimeout(() => controller.abort(), 7000);

      try {
        const data = await apiGet<{ items?: ManagedApiKeyItem[] }>(
          `${apiBaseUrl}/api/v1/api-keys?include_inactive=${includeInactiveKeys ? "true" : "false"}`,
          {
            headers: buildHeaders(settings, "admin", false, authSession),
            signal: controller.signal,
          }
        );
        setManagedKeys(data.items ?? []);
        if (showFeedback) addToast("托管密钥列表已刷新", "success");
      } catch (error) {
        const message =
          error instanceof Error && error.name === "AbortError"
            ? "请求超时"
            : error instanceof Error
              ? error.message
              : "无法获取托管密钥列表";
        setManagedKeysError(message);
        if (showFeedback) addToast(`密钥列表刷新失败：${message}`, "error");
      } finally {
        window.clearTimeout(timer);
        setManagedKeysLoading(false);
      }
    },
    [addToast, apiBaseUrl, authSession, hasAdminAccess, includeInactiveKeys, settings]
  );

  const applyIssuedKeyToSettings = (item: ManagedApiKeyItem, apiKey: string) => {
    const nextSettings: AppSettings = isAdminRole(item.role)
      ? { ...settings, adminApiKey: apiKey }
      : { ...settings, clientApiKey: apiKey };
    setSettings(() => nextSettings);
    addToast(
      isAdminRole(item.role)
        ? "已写入当前会话的 Admin API Key，不会持久化到本地存储"
        : "已写入当前会话的 Client API Key，不会持久化到本地存储",
      "success"
    );
  };

  const createManagedKey = async (event: { preventDefault(): void }) => {
    event.preventDefault();
    if (!hasAdminAccess) {
      addToast("请先登录管理员账号或配置 Admin API Key", "error");
      return;
    }
    if (!managedKeyDraft.name.trim()) {
      addToast("请填写密钥名称", "error");
      return;
    }

    const expiresValue = managedKeyDraft.expiresInDays.trim();
    const expiresInDays = expiresValue ? Number(expiresValue) : undefined;
    if (expiresValue && (expiresInDays === undefined || !Number.isFinite(expiresInDays) || expiresInDays < 1)) {
      addToast("过期天数必须是大于 0 的数字", "error");
      return;
    }

    setManagedKeyBusyId(0);
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/api-keys`, {
        method: "POST",
        headers: buildHeaders(settings, "admin", true, authSession),
        body: JSON.stringify({
          name: managedKeyDraft.name.trim(),
          role: managedKeyDraft.role,
          description: managedKeyDraft.description.trim(),
          expires_in_days: expiresInDays ? Math.round(expiresInDays) : undefined,
        }),
      });
      const data = (await response.json().catch(() => ({}))) as {
        item?: ManagedApiKeyItem;
        api_key?: string;
        detail?: unknown;
      };
      if (!response.ok || !data.item || !data.api_key) {
        throw new Error(detailText(data.detail) || `HTTP ${response.status}`);
      }

      setManagedKeyIssueState({
        action: "created",
        apiKey: data.api_key,
        item: data.item,
      });
      setManagedKeyDraft({
        name: "",
        role: "client",
        description: "",
        expiresInDays: managedKeyDraft.expiresInDays || "30",
      });
      setManagedKeyDraftOpen(false);
      await loadManagedApiKeys();
      addToast("托管密钥已创建", "success");
    } catch (error) {
      addToast(error instanceof Error ? error.message : "创建托管密钥失败", "error");
    } finally {
      setManagedKeyBusyId(null);
    }
  };

  const rotateManagedKey = async (item: ManagedApiKeyItem) => {
    if (!hasAdminAccess) {
      addToast("请先登录管理员账号或配置 Admin API Key", "error");
      return;
    }

    setManagedKeyBusyId(item.id);
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/api-keys/${item.id}/rotate`, {
        method: "POST",
        headers: buildHeaders(settings, "admin", true, authSession),
        body: JSON.stringify({}),
      });
      const data = (await response.json().catch(() => ({}))) as {
        item?: ManagedApiKeyItem;
        api_key?: string;
        detail?: unknown;
      };
      if (!response.ok || !data.item || !data.api_key) {
        throw new Error(detailText(data.detail) || `HTTP ${response.status}`);
      }

      setManagedKeyIssueState({
        action: "rotated",
        apiKey: data.api_key,
        item: data.item,
      });
      await loadManagedApiKeys();
      addToast("托管密钥已轮换，旧密钥立即失效", "success");
    } catch (error) {
      addToast(error instanceof Error ? error.message : "轮换托管密钥失败", "error");
    } finally {
      setManagedKeyBusyId(null);
    }
  };

  const removeDeletedKeyFromSession = useCallback(
    (item: ManagedApiKeyItem) => {
      const keyPrefixWithSeparator = `${item.key_prefix}.`;
      setSettings((current) => ({
        ...current,
        adminApiKey:
          isAdminRole(item.role) && current.adminApiKey.startsWith(keyPrefixWithSeparator)
            ? ""
            : current.adminApiKey,
        clientApiKey:
          !isAdminRole(item.role) && current.clientApiKey.startsWith(keyPrefixWithSeparator)
            ? ""
            : current.clientApiKey,
      }));
      if (managedKeyIssueState?.item.id === item.id) {
        setManagedKeyIssueState(null);
      }
    },
    [managedKeyIssueState, setSettings]
  );

  const updateManagedKeyLifecycle = useCallback(
    async (item: ManagedApiKeyItem, action: "revoke" | "activate" | "delete") => {
      if (!hasAdminAccess) {
        addToast("请先登录管理员账号或配置 Admin API Key", "error");
        return;
      }

      if (action === "delete") {
        const confirmed = window.confirm(`确定删除密钥“${item.name}”吗？删除后该密钥会立即失效，且不会再出现在列表中。`);
        if (!confirmed) {
          return;
        }
      }

      setManagedKeyBusyId(item.id);
      try {
        const endpoint =
          action === "delete"
            ? `${apiBaseUrl}/api/v1/api-keys/${item.id}`
            : `${apiBaseUrl}/api/v1/api-keys/${item.id}/${action}`;
        await apiSend(endpoint, action === "delete" ? "DELETE" : "POST", undefined, {
          headers: buildHeaders(settings, "admin", false, authSession),
        });

        if (action === "delete") {
          removeDeletedKeyFromSession(item);
        }
        await loadManagedApiKeys();
        addToast(
          action === "revoke"
            ? "托管密钥已停用"
            : action === "activate"
              ? "托管密钥已恢复"
              : "托管密钥已删除并立即失效",
          "success"
        );
      } catch (error) {
        addToast(
          error instanceof Error
            ? error.message
            : action === "revoke"
              ? "停用密钥失败"
              : action === "activate"
                ? "恢复密钥失败"
                : "删除密钥失败",
          "error"
        );
      } finally {
        setManagedKeyBusyId(null);
      }
    },
    [addToast, apiBaseUrl, authSession, hasAdminAccess, loadManagedApiKeys, removeDeletedKeyFromSession, settings]
  );

  return {
    managedKeys,
    setManagedKeys,
    managedKeysLoading,
    managedKeysError,
    managedKeyDraftOpen,
    setManagedKeyDraftOpen,
    managedKeyDraft,
    setManagedKeyDraft,
    managedKeyIssueState,
    setManagedKeyIssueState,
    managedKeyBusyId,
    includeInactiveKeys,
    setIncludeInactiveKeys,
    loadManagedApiKeys,
    applyIssuedKeyToSettings,
    createManagedKey,
    rotateManagedKey,
    removeDeletedKeyFromSession,
    updateManagedKeyLifecycle,
  };
}
