// 策略（policies）域：安全策略 + 工具权限 + 草稿面板 + 后端持久化/加载归仓（阶段 2）。
// persistPoliciesToBackend / persistToolsToBackend 保留逐项收集错误的原始语义
// （单项失败不中断其余项的同步，最后汇总第一条错误抛出 + 回滚本地快照），因此保留手工 fetch。
// loadSecurityConfiguration / resetPolicies / removePolicy 是「非 ok 即抛」的单响应
// 模式，与 apiGet/apiSend + ApiError 逐字等价，已切换到数据层。
// resetPolicies / addPolicy / removePolicy 也归仓在本 hook（读写同一份 policies/tools 状态）。

import { useCallback, useState } from "react";
import type { AppSettings, AuthSession, BackendPolicy, BackendToolPolicy, PolicyRule, Toast, ToolPermission } from "../types";
import { apiGet, apiSend, buildHeaders, detailText } from "../api-client";
import { DEFAULT_POLICIES, DEFAULT_TOOLS, makeId, readStorage, STORAGE_KEYS, writeStorage } from "../app-meta";

function normalizeSeverity(value: unknown): PolicyRule["severity"] {
  const text = typeof value === "string" ? value.toLowerCase() : "";
  if (text === "high" || text === "medium" || text === "low") return text;
  return "medium";
}

function mapBackendPolicy(policy: BackendPolicy): PolicyRule {
  return {
    id: String(policy.id),
    name: policy.name,
    description: policy.description,
    enabled: policy.enabled,
    severity: normalizeSeverity(policy.severity),
    scope: policy.scope || "Prompt",
    pattern: policy.blacklist_keyword,
    systemManaged: policy.system_managed,
    custom: !policy.system_managed,
  };
}

function mapBackendToolPolicy(policy: BackendToolPolicy): ToolPermission {
  return {
    id: String(policy.id),
    name: policy.tool_name,
    description: policy.description,
    allowed: policy.allowed,
    requiresAdminApproval: policy.requires_admin_approval,
    systemManaged: policy.system_managed,
  };
}

export function usePolicies({
  apiBaseUrl,
  settings,
  authSession,
  hasAdminAccess,
  addToast,
}: {
  apiBaseUrl: string;
  settings: AppSettings;
  authSession: AuthSession | null;
  hasAdminAccess: boolean;
  addToast: (message: string, type?: Toast["type"]) => void;
}) {
  const [policies, setPolicies] = useState<PolicyRule[]>(DEFAULT_POLICIES);
  const [tools, setTools] = useState<ToolPermission[]>(DEFAULT_TOOLS);
  const [policyDraftOpen, setPolicyDraftOpen] = useState(false);
  const [policyDraft, setPolicyDraft] = useState({
    name: "",
    pattern: "",
    description: "",
    severity: "medium" as PolicyRule["severity"],
    scope: "Prompt",
  });

  const syncLocalSecurityConfig = useCallback((nextPolicies: PolicyRule[], nextTools: ToolPermission[]) => {
    writeStorage(STORAGE_KEYS.policies, nextPolicies);
    writeStorage(STORAGE_KEYS.tools, nextTools);
  }, []);

  const persistPoliciesToBackend = useCallback(
    async (nextPolicies: PolicyRule[]) => {
      const currentById = new Map(policies.map((policy) => [policy.id, policy] as const));
      const nextById = new Map(nextPolicies.map((policy) => [policy.id, policy] as const));
      const responseErrors: string[] = [];

      for (const policy of nextPolicies) {
        const payload = {
          name: policy.name.trim(),
          blacklist_keyword: (policy.pattern || policy.name).trim(),
          description: policy.description.trim(),
          severity: policy.severity,
          scope: policy.scope.trim() || "Prompt",
          enabled: policy.enabled,
        };

        const isPersisted = /^\d+$/.test(policy.id);
        const endpoint = isPersisted
          ? `${apiBaseUrl}/api/v1/policies/${policy.id}`
          : `${apiBaseUrl}/api/v1/policies`;
        const method = isPersisted ? "PUT" : "POST";
        const response = await fetch(endpoint, {
          method,
          headers: buildHeaders(settings, "admin", true, authSession),
          body: JSON.stringify(payload),
        });
        const data = (await response.json().catch(() => ({}))) as { detail?: unknown };
        if (!response.ok) {
          responseErrors.push(detailText(data.detail) || `HTTP ${response.status}`);
        }
      }

      for (const policy of policies) {
        const wasPersisted = /^\d+$/.test(policy.id);
        if (!wasPersisted || nextById.has(policy.id)) continue;
        const response = await fetch(`${apiBaseUrl}/api/v1/policies/${policy.id}`, {
          method: "DELETE",
          headers: buildHeaders(settings, "admin", false, authSession),
        });
        const data = (await response.json().catch(() => ({}))) as { detail?: unknown };
        if (!response.ok) {
          responseErrors.push(detailText(data.detail) || `HTTP ${response.status}`);
        }
      }

      if (responseErrors.length > 0) {
        const currentSnapshot = Array.from(currentById.values());
        syncLocalSecurityConfig(currentSnapshot, tools);
        throw new Error(responseErrors[0]);
      }
    },
    // 原实现 deps 不含 apiBaseUrl（存量告警），行为不变地原样保留。
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [authSession, policies, settings, syncLocalSecurityConfig, tools]
  );

  const persistToolsToBackend = useCallback(
    async (nextTools: ToolPermission[]) => {
      const responseErrors: string[] = [];

      for (const tool of nextTools) {
        if (!/^\d+$/.test(tool.id)) continue;
        const response = await fetch(`${apiBaseUrl}/api/v1/tool-policies/${tool.id}`, {
          method: "PUT",
          headers: buildHeaders(settings, "admin", true, authSession),
          body: JSON.stringify({
            tool_name: tool.name,
            description: tool.description,
            allowed: tool.allowed,
            requires_admin_approval: Boolean(tool.requiresAdminApproval),
          }),
        });
        const data = (await response.json().catch(() => ({}))) as { detail?: unknown };
        if (!response.ok) {
          responseErrors.push(detailText(data.detail) || `HTTP ${response.status}`);
        }
      }

      if (responseErrors.length > 0) {
        throw new Error(responseErrors[0]);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [authSession, settings]
  );

  const loadSecurityConfiguration = useCallback(async () => {
    const localPolicies = readStorage<PolicyRule[]>(STORAGE_KEYS.policies, DEFAULT_POLICIES);
    const localTools = readStorage<ToolPermission[]>(STORAGE_KEYS.tools, DEFAULT_TOOLS);

    if (!hasAdminAccess) {
      setPolicies(localPolicies);
      setTools(localTools);
      return;
    }

    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 7000);

    try {
      const [policyData, toolData] = await Promise.all([
        apiGet<{ items?: BackendPolicy[]; detail?: unknown }>(`${apiBaseUrl}/api/v1/policies`, {
          headers: buildHeaders(settings, "admin", false, authSession),
          signal: controller.signal,
        }),
        apiGet<{ items?: BackendToolPolicy[]; detail?: unknown }>(`${apiBaseUrl}/api/v1/tool-policies`, {
          headers: buildHeaders(settings, "admin", false, authSession),
          signal: controller.signal,
        }),
      ]);

      const nextPolicies = (policyData.items ?? []).map(mapBackendPolicy);
      const nextTools = (toolData.items ?? []).map(mapBackendToolPolicy);
      setPolicies(nextPolicies.length > 0 ? nextPolicies : localPolicies);
      setTools(nextTools.length > 0 ? nextTools : localTools);
      writeStorage(STORAGE_KEYS.policies, nextPolicies.length > 0 ? nextPolicies : localPolicies);
      writeStorage(STORAGE_KEYS.tools, nextTools.length > 0 ? nextTools : localTools);
    } catch {
      setPolicies(localPolicies);
      setTools(localTools);
    } finally {
      window.clearTimeout(timer);
    }
    // 原实现 deps 不含 apiBaseUrl（存量告警），行为不变地原样保留。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authSession, hasAdminAccess, settings]);

  const savePolicies = () => {
    writeStorage(STORAGE_KEYS.policies, policies);
    writeStorage(STORAGE_KEYS.tools, tools);
    if (hasAdminAccess) {
      void (async () => {
        try {
          await persistPoliciesToBackend(policies);
          await persistToolsToBackend(tools);
          await loadSecurityConfiguration();
          addToast("策略已同步到后端", "success");
        } catch (error) {
          addToast(error instanceof Error ? error.message : "策略同步失败", "error");
        }
      })();
      return;
    }
    addToast("策略配置已保存", "success");
  };

  const resetPolicies = () => {
    if (hasAdminAccess) {
      void (async () => {
        try {
          await Promise.all([
            apiSend(`${apiBaseUrl}/api/v1/policies/reset`, "POST", undefined, {
              headers: buildHeaders(settings, "admin", false, authSession),
            }),
            apiSend(`${apiBaseUrl}/api/v1/tool-policies/reset`, "POST", undefined, {
              headers: buildHeaders(settings, "admin", false, authSession),
            }),
          ]);
          await loadSecurityConfiguration();
          addToast("策略已恢复为后端默认配置", "success");
        } catch (error) {
          addToast(error instanceof Error ? error.message : "策略重置失败", "error");
        }
      })();
      return;
    }
    setPolicies(DEFAULT_POLICIES);
    setTools(DEFAULT_TOOLS);
    writeStorage(STORAGE_KEYS.policies, DEFAULT_POLICIES);
    writeStorage(STORAGE_KEYS.tools, DEFAULT_TOOLS);
    addToast("策略已恢复默认", "info");
  };

  const addPolicy = (event: { preventDefault(): void }) => {
    event.preventDefault();
    if (!policyDraft.name.trim() || !policyDraft.description.trim()) {
      addToast("请填写策略名称和描述", "error");
      return;
    }

    const nextPolicy: PolicyRule = {
      id: makeId("policy"),
      name: policyDraft.name.trim(),
      description: policyDraft.description.trim(),
      enabled: true,
      severity: policyDraft.severity,
      scope: policyDraft.scope.trim() || "Prompt",
      pattern: policyDraft.pattern.trim() || policyDraft.name.trim(),
      custom: true,
    };
    const nextPolicies = [nextPolicy, ...policies];
    setPolicies(nextPolicies);
    writeStorage(STORAGE_KEYS.policies, nextPolicies);
    if (hasAdminAccess) {
      void (async () => {
        try {
          await persistPoliciesToBackend(nextPolicies);
          await loadSecurityConfiguration();
          addToast("策略已添加并写入后端", "success");
        } catch (error) {
          addToast(error instanceof Error ? error.message : "新增策略失败", "error");
        }
      })();
    }
    setPolicyDraft({ name: "", pattern: "", description: "", severity: "medium", scope: "Prompt" });
    setPolicyDraftOpen(false);
    addToast("策略已添加，记得保存", "success");
  };

  const removePolicy = (policyId: string) => {
    const next = policies.filter((policy) => policy.id !== policyId);
    setPolicies(next);
    writeStorage(STORAGE_KEYS.policies, next);
    if (hasAdminAccess && /^\d+$/.test(policyId)) {
      void (async () => {
        try {
          await apiSend(`${apiBaseUrl}/api/v1/policies/${policyId}`, "DELETE", undefined, {
            headers: buildHeaders(settings, "admin", false, authSession),
          });
          await loadSecurityConfiguration();
          addToast("策略已从后端删除", "success");
        } catch (error) {
          addToast(error instanceof Error ? error.message : "删除策略失败", "error");
        }
      })();
      return;
    }
    addToast("策略已删除", "info");
  };

  return {
    policies,
    setPolicies,
    tools,
    setTools,
    policyDraftOpen,
    setPolicyDraftOpen,
    policyDraft,
    setPolicyDraft,
    syncLocalSecurityConfig,
    persistPoliciesToBackend,
    persistToolsToBackend,
    loadSecurityConfiguration,
    savePolicies,
    resetPolicies,
    addPolicy,
    removePolicy,
  };
}
