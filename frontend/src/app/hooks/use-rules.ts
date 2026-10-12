// 自定义规则（rules）域：状态 + CRUD + 测试/导入/导出 + DLP 状态归仓（阶段 2）。
// dlpStatus 只由本域的 loadCustomRules 顺带刷新，随域迁移。

import { useCallback, useState } from "react";
import type { AppSettings, AuthSession, CustomRuleDraft, CustomRuleItem, DlpStatusInfo, RuleTestResult, Toast } from "../types";
import { apiGet, apiSend, buildHeaders, detailText } from "../api-client";

export function useRules({
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
  const [customRules, setCustomRules] = useState<CustomRuleItem[]>([]);
  const [customRulesLoading, setCustomRulesLoading] = useState(false);
  const [customRulesError, setCustomRulesError] = useState("");
  const [ruleDraftOpen, setRuleDraftOpen] = useState(false);
  const [ruleEditingId, setRuleEditingId] = useState<number | null>(null);
  const [ruleDraft, setRuleDraft] = useState<CustomRuleDraft>({
    name: "",
    description: "",
    rule_type: "regex",
    pattern: "",
    target: "prompt",
    action: "block",
    risk_score: 0.8,
    enabled: true,
  });
  const [ruleTestText, setRuleTestText] = useState("");
  const [ruleTestResult, setRuleTestResult] = useState<RuleTestResult | null>(null);
  const [ruleTestBusy, setRuleTestBusy] = useState(false);
  const [ruleBusyId, setRuleBusyId] = useState<number | null>(null);
  const [dlpStatus, setDlpStatus] = useState<DlpStatusInfo | null>(null);

  const loadCustomRules = useCallback(
    async (showFeedback = false) => {
      if (!hasAdminAccess) {
        setCustomRules([]);
        setCustomRulesError("");
        return;
      }

      setCustomRulesLoading(true);
      setCustomRulesError("");
      const controller = new AbortController();
      const timer = window.setTimeout(() => controller.abort(), 7000);

      try {
        const [rulesData, dlpResponse] = await Promise.all([
          apiGet<{ items?: CustomRuleItem[]; detail?: unknown }>(`${apiBaseUrl}/api/v1/rules`, {
            headers: buildHeaders(settings, "admin", false, authSession),
            signal: controller.signal,
          }),
          fetch(`${apiBaseUrl}/api/v1/rules/dlp-status`, {
            headers: buildHeaders(settings, "admin", false, authSession),
            signal: controller.signal,
            cache: "no-store",
          }),
        ]);
        setCustomRules(rulesData.items ?? []);
        if (dlpResponse.ok) {
          const dlpData = (await dlpResponse.json().catch(() => ({}))) as DlpStatusInfo;
          setDlpStatus(dlpData);
        }
        if (showFeedback) addToast("自定义规则已刷新", "success");
      } catch (error) {
        const message =
          error instanceof Error && error.name === "AbortError"
            ? "请求超时"
            : error instanceof Error
              ? error.message
              : "无法获取自定义规则";
        setCustomRulesError(message);
        if (showFeedback) addToast(`规则列表刷新失败：${message}`, "error");
      } finally {
        window.clearTimeout(timer);
        setCustomRulesLoading(false);
      }
    },
    [addToast, apiBaseUrl, authSession, hasAdminAccess, settings]
  );

  const submitCustomRule = async () => {
    if (!hasAdminAccess) {
      addToast("请先登录管理员账号或配置 Admin API Key", "error");
      return;
    }
    const name = ruleDraft.name.trim();
    const pattern = ruleDraft.pattern.trim();
    if (!name || !pattern) {
      addToast("规则名称与匹配模式不能为空", "error");
      return;
    }

    setRuleTestBusy(true);
    try {
      const editing = ruleEditingId !== null;
      await apiSend(
        editing ? `${apiBaseUrl}/api/v1/rules/${ruleEditingId}` : `${apiBaseUrl}/api/v1/rules`,
        editing ? "PUT" : "POST",
        {
          name,
          description: ruleDraft.description.trim(),
          rule_type: ruleDraft.rule_type,
          pattern,
          target: ruleDraft.target,
          action: ruleDraft.action,
          risk_score: ruleDraft.risk_score,
          enabled: ruleDraft.enabled,
        },
        { headers: buildHeaders(settings, "admin", true, authSession) }
      );
      addToast(editing ? "规则已更新" : "规则已创建", "success");
      setRuleDraftOpen(false);
      setRuleEditingId(null);
      setRuleDraft({
        name: "",
        description: "",
        rule_type: "regex",
        pattern: "",
        target: "prompt",
        action: "block",
        risk_score: 0.8,
        enabled: true,
      });
      await loadCustomRules();
    } catch (error) {
      addToast(error instanceof Error ? error.message : "保存规则失败", "error");
    } finally {
      setRuleTestBusy(false);
    }
  };

  const deleteCustomRule = async (item: CustomRuleItem) => {
    setRuleBusyId(item.id);
    try {
      await apiSend(`${apiBaseUrl}/api/v1/rules/${item.id}`, "DELETE", undefined, {
        headers: buildHeaders(settings, "admin", true, authSession),
      });
      addToast(`规则 ${item.name} 已删除`, "success");
      await loadCustomRules();
    } catch (error) {
      addToast(error instanceof Error ? error.message : "删除规则失败", "error");
    } finally {
      setRuleBusyId(null);
    }
  };

  const toggleCustomRule = async (item: CustomRuleItem, enabled: boolean) => {
    setRuleBusyId(item.id);
    setCustomRules((current) => current.map((rule) => (rule.id === item.id ? { ...rule, enabled } : rule)));
    try {
      await apiSend(`${apiBaseUrl}/api/v1/rules/${item.id}`, "PUT", {
        name: item.name,
        description: item.description,
        rule_type: item.rule_type,
        pattern: item.pattern,
        target: item.target,
        action: item.action,
        risk_score: item.risk_score,
        enabled,
      }, { headers: buildHeaders(settings, "admin", true, authSession) });
    } catch (error) {
      setCustomRules((current) => current.map((rule) => (rule.id === item.id ? { ...rule, enabled: !enabled } : rule)));
      addToast(error instanceof Error ? error.message : "切换规则失败", "error");
    } finally {
      setRuleBusyId(null);
    }
  };

  const testCustomRule = async () => {
    if (!ruleDraft.pattern.trim()) {
      addToast("请先填写匹配模式", "error");
      return;
    }
    setRuleTestBusy(true);
    setRuleTestResult(null);
    try {
      const data = await apiSend<RuleTestResult & { detail?: unknown }>(
        `${apiBaseUrl}/api/v1/rules/test`,
        "POST",
        {
          sample_text: ruleTestText,
          rule_id: null,
          draft: {
            name: ruleDraft.name.trim() || "draft",
            description: ruleDraft.description.trim(),
            rule_type: ruleDraft.rule_type,
            pattern: ruleDraft.pattern.trim(),
            target: ruleDraft.target,
            action: ruleDraft.action,
            risk_score: ruleDraft.risk_score,
            enabled: ruleDraft.enabled,
          },
        },
        { headers: buildHeaders(settings, "admin", true, authSession) }
      );
      setRuleTestResult(data);
    } catch (error) {
      addToast(error instanceof Error ? error.message : "测试规则失败", "error");
    } finally {
      setRuleTestBusy(false);
    }
  };

  const exportCustomRules = async () => {
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/rules/export`, {
        headers: buildHeaders(settings, "admin", false, authSession),
        cache: "no-store",
      });
      const data = await response.json();
      if (!response.ok) throw new Error(detailText(data.detail) || `HTTP ${response.status}`);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = window.document.createElement("a");
      anchor.href = url;
      anchor.download = "shadow-agent-rules.json";
      anchor.click();
      URL.revokeObjectURL(url);
      addToast("规则已导出", "success");
    } catch (error) {
      addToast(error instanceof Error ? error.message : "导出失败", "error");
    }
  };

  const importCustomRules = async (file: File) => {
    setRuleTestBusy(true);
    try {
      const text = await file.text();
      const parsed = JSON.parse(text) as { exported_rules?: unknown };
      const rules = Array.isArray(parsed.exported_rules) ? parsed.exported_rules : null;
      if (!rules) throw new Error("文件格式不正确：缺少 exported_rules 数组");
      const data = await apiSend<{
        created?: number;
        updated?: number;
        skipped?: string[];
        detail?: unknown;
      }>(
        `${apiBaseUrl}/api/v1/rules/import`,
        "POST",
        { mode: "merge", rules },
        { headers: buildHeaders(settings, "admin", true, authSession) }
      );
      const skippedCount = data.skipped?.length ?? 0;
      addToast(`导入完成：新增 ${data.created ?? 0}，更新 ${data.updated ?? 0}${skippedCount ? `，跳过 ${skippedCount}` : ""}`, "success");
      await loadCustomRules();
    } catch (error) {
      addToast(error instanceof Error ? error.message : "导入失败", "error");
    } finally {
      setRuleTestBusy(false);
    }
  };
  return {
    customRules,
    setCustomRules,
    customRulesLoading,
    customRulesError,
    ruleDraftOpen,
    setRuleDraftOpen,
    ruleEditingId,
    setRuleEditingId,
    ruleDraft,
    setRuleDraft,
    ruleTestText,
    setRuleTestText,
    ruleTestResult,
    setRuleTestResult,
    ruleTestBusy,
    ruleBusyId,
    dlpStatus,
    loadCustomRules,
    submitCustomRule,
    deleteCustomRule,
    toggleCustomRule,
    testCustomRule,
    exportCustomRules,
    importCustomRules,
  };
}
