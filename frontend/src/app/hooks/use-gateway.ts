// 网关测试（gateway）域：表单状态 + 检测提交归仓（阶段 2）。
// localInspect（前端预检）与 appendLocalDecisionLog（本地日志落账）仍属 page 的演示骨架，
// 以回调注入；friendlyDecisionReason 已上移 app-meta 供 page/Hook 共用。

import { useState, type FormEvent } from "react";
import type { AnalyzeResponse, AppSettings, AuthSession, InterceptLog, LocalDecision, Toast } from "../types";
import type { GatewayFormState, GatewayResult } from "../gateway-types";
import { apiSend, buildHeaders, detailText } from "../api-client";
import { asNumber, friendlyDecisionReason } from "../components/ui-kit";
import { DEFAULT_GATEWAY_FORM } from "../gateway-types";

export function useGateway({
  apiBaseUrl,
  settings,
  authSession,
  hasGatewayAccess,
  addToast,
  localInspect,
  appendLocalDecisionLog,
}: {
  apiBaseUrl: string;
  settings: AppSettings;
  authSession: AuthSession | null;
  hasGatewayAccess: boolean;
  addToast: (message: string, type?: Toast["type"]) => void;
  localInspect: (prompt: string, externalContext: string, toolName: string, parameters: string) => LocalDecision;
  appendLocalDecisionLog: (decision: LocalDecision, prompt: string, extra?: Record<string, unknown>) => InterceptLog;
}) {
  const [gatewayLoading, setGatewayLoading] = useState(false);
  const [gatewayResult, setGatewayResult] = useState<GatewayResult | null>(null);
  const [gatewayForm, setGatewayForm] = useState<GatewayFormState>(DEFAULT_GATEWAY_FORM);

  const submitGatewayTest = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!gatewayForm.prompt.trim() && !gatewayForm.externalContext.trim()) {
      addToast("请输入 Prompt 或外部上下文", "error");
      return;
    }

    let parameters: Record<string, unknown> | null = null;
    try {
      parameters = gatewayForm.parameters.trim() ? (JSON.parse(gatewayForm.parameters) as Record<string, unknown>) : null;
    } catch {
      addToast("工具参数不是有效 JSON", "error");
      return;
    }

    const decision = localInspect(gatewayForm.prompt, gatewayForm.externalContext, gatewayForm.toolName, gatewayForm.parameters);

    if (!hasGatewayAccess) {
      const log = appendLocalDecisionLog(decision, gatewayForm.prompt || gatewayForm.externalContext || "Local preflight", {
        local_preflight: true,
        external_context: gatewayForm.externalContext,
        tool_name: gatewayForm.toolName || undefined,
      });
      setGatewayResult({
        ok: decision.allowed,
        title: decision.allowed ? "本地预检通过" : "本地预检已拦截",
        message: decision.allowed
          ? "当前未登录且未配置 API Key，因此仅执行本地风险预检；登录后可请求后端网关。"
          : "当前未登录且未配置 API Key，已使用前端预检模拟 Shadow Agent 的间接提示词注入拦截。",
        detail: log.details,
      });
      addToast(decision.allowed ? "本地预检通过" : "本地预检已拦截", decision.allowed ? "success" : "error");
      return;
    }

    setGatewayLoading(true);
    setGatewayResult(null);
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 10000);

    try {
      const analyzeData = await apiSend<AnalyzeResponse & { detail?: unknown }>(
        `${apiBaseUrl}/api/v1/analyze`,
        "POST",
        {
          prompt: gatewayForm.prompt || "请处理外部上下文",
          external_context: gatewayForm.externalContext || null,
          tool_name: gatewayForm.toolName || null,
          parameters,
        },
        { headers: buildHeaders(settings, "client", true, authSession), signal: controller.signal }
      );
      if (analyzeData.decision === "blocked") {
        const firstBlocked = analyzeData.blocked_checks?.[0] ?? {};
        const blockedDecision: LocalDecision = {
          allowed: false,
          riskScore: asNumber(analyzeData.risk_score, decision.riskScore),
          reason: friendlyDecisionReason(detailText(firstBlocked.reason), detailText(firstBlocked.category) || analyzeData.category),
          matchedRules: Array.isArray(firstBlocked.matched_rules) ? firstBlocked.matched_rules.map(detailText) : decision.matchedRules,
          layer: detailText(firstBlocked.name) || decision.layer,
          category: detailText(firstBlocked.category) || analyzeData.category,
          recommendedAction: analyzeData.recommended_action,
        };
        appendLocalDecisionLog(blockedDecision, gatewayForm.prompt || gatewayForm.externalContext || "Local preflight", {
          analyze_detail: analyzeData,
          external_context: gatewayForm.externalContext,
          tool_name: gatewayForm.toolName || undefined,
        });
        setGatewayResult({
          ok: false,
          title: "后端预检已拦截",
          message: blockedDecision.reason,
          detail: analyzeData,
        });
        addToast("后端预检已拦截", "error");
        return;
      }

      const response = await fetch(`${apiBaseUrl}/api/v1/chat/completions`, {
        method: "POST",
        headers: buildHeaders(settings, "client", true, authSession),
        signal: controller.signal,
        body: JSON.stringify({
          model: gatewayForm.model,
          messages: [{ role: "user", content: gatewayForm.prompt || "请处理外部上下文" }],
          external_context: gatewayForm.externalContext || null,
          tool_name: gatewayForm.toolName || null,
          parameters,
          stream: gatewayForm.stream,
        }),
      });
      const data = (await response.json().catch(() => ({}))) as Record<string, unknown>;
      if (!response.ok) {
        const detail = data.detail && typeof data.detail === "object" ? (data.detail as Record<string, unknown>) : data;
        const blockedDecision: LocalDecision = {
          allowed: false,
          riskScore: asNumber(detail.risk_score, decision.riskScore),
          reason: friendlyDecisionReason(detailText(detail.reason), detailText(detail.category)),
          matchedRules: Array.isArray(detail.matched_rules) ? detail.matched_rules.map(detailText) : decision.matchedRules,
          layer: detailText(detail.layer) || decision.layer,
        };
        appendLocalDecisionLog(blockedDecision, gatewayForm.prompt || gatewayForm.externalContext || "Local preflight", { backend_detail: detail });
        setGatewayResult({ ok: false, title: "后端网关已拦截", message: blockedDecision.reason, detail });
        addToast("后端网关已拦截", "error");
        return;
      }

      setGatewayResult({ ok: true, title: "后端网关通过", message: "请求已通过 Shadow Agent 审计并返回响应。", detail: data });
      addToast("网关测试通过", "success");
    } catch (error) {
      const message =
        error instanceof Error && error.name === "AbortError"
          ? "请求超时"
          : error instanceof Error
            ? error.message
            : "请求失败";
      setGatewayResult({ ok: false, title: "请求失败", message, detail: { local_preflight: decision } });
      addToast(`网关测试失败：${message}`, "error");
    } finally {
      window.clearTimeout(timer);
      setGatewayLoading(false);
    }
  };


  return {
    gatewayLoading,
    gatewayResult,
    gatewayForm,
    setGatewayForm,
    setGatewayResult,
    submitGatewayTest,
  };
}
