// 验证套件（validation）域：演示场景执行 + 结果/历史归仓（阶段 2）。
// selectedScenario 备忘录一并归仓（runValidationSuite 依赖其 label，且 page 的
// 证据包/导出也读同一份）。纯助手（createInitialValidationResults 等）在 demo-scenarios。
// loadScenarioIntoGateway / loadGatewaySample / resetGatewayForm / launchValidationPreset
// 与网关表单强耦合，仍留在 page，通过本 hook 的 setSelectedScenarioId 复用状态。

import { useCallback, useMemo, useState } from "react";
import type { AnalyzeResponse, AppSettings, AuthSession, LocalDecision, Toast } from "../types";
import type { GatewayResult } from "../gateway-types";
import {
  DEMO_SCENARIOS,
  DEFAULT_VALIDATION_SCENARIO_ID,
  createInitialValidationResults,
  summarizeValidationResults,
  MAX_VALIDATION_RUNS,
  type DemoScenario,
  type DemoScenarioId,
  type ValidationRunRecord,
  type ValidationSuiteItem,
} from "../demo-scenarios";
import { apiSend, buildHeaders } from "../api-client";
import { makeId, STORAGE_KEYS, writeStorage } from "../app-meta";
import { asNumber, categoryLabel, formatTime } from "../components/ui-kit";

export function useValidation({
  apiBaseUrl,
  settings,
  authSession,
  hasGatewayAccess,
  addToast,
  localInspect,
  setGatewayResult,
}: {
  apiBaseUrl: string;
  settings: AppSettings;
  authSession: AuthSession | null;
  hasGatewayAccess: boolean;
  addToast: (message: string, type?: Toast["type"]) => void;
  localInspect: (prompt: string, externalContext: string, toolName: string, parameters: string) => LocalDecision;
  setGatewayResult: (next: GatewayResult | null) => void;
}) {
  const [selectedScenarioId, setSelectedScenarioId] = useState<DemoScenarioId>(DEFAULT_VALIDATION_SCENARIO_ID);
  const [validationRunning, setValidationRunning] = useState(false);
  const [validationResults, setValidationResults] = useState<ValidationSuiteItem[]>(createInitialValidationResults);
  const [validationHistory, setValidationHistory] = useState<ValidationRunRecord[]>([]);

  const selectedScenario = useMemo(
    () => DEMO_SCENARIOS.find((scenario) => scenario.id === selectedScenarioId) ?? DEMO_SCENARIOS[0],
    [selectedScenarioId]
  );

  const evaluateScenario = useCallback(
    async (scenario: DemoScenario): Promise<ValidationSuiteItem> => {
      let parameters: Record<string, unknown> | null = null;
      try {
        parameters = scenario.parameters.trim() ? (JSON.parse(scenario.parameters) as Record<string, unknown>) : null;
      } catch {
        return {
          id: scenario.id,
          label: scenario.label,
          expectedOutcome: scenario.expectedOutcome,
          actualOutcome: "error",
          category: scenario.expectedCategory ?? "invalid_parameters",
          riskScore: null,
          status: "failed",
          note: "场景参数 JSON 无法解析",
        };
      }

      const localDecision = localInspect(scenario.prompt, scenario.externalContext, scenario.toolName, scenario.parameters);

      if (!hasGatewayAccess) {
        const actualOutcome = localDecision.allowed ? "allowed" : "blocked";
        return {
          id: scenario.id,
          label: scenario.label,
          expectedOutcome: scenario.expectedOutcome,
          actualOutcome,
          category: localDecision.category ?? "none",
          riskScore: localDecision.riskScore,
          status: actualOutcome === scenario.expectedOutcome ? "passed" : "failed",
          note: "使用前端本地预检完成验证",
        };
      }

      try {
        const analyzeData = await apiSend<AnalyzeResponse & { detail?: unknown }>(
          `${apiBaseUrl}/api/v1/analyze`,
          "POST",
          {
            prompt: scenario.prompt,
            external_context: scenario.externalContext || null,
            tool_name: scenario.toolName || null,
            parameters,
          },
          { headers: buildHeaders(settings, "client", true, authSession) }
        );

        const actualOutcome = analyzeData.decision === "blocked" ? "blocked" : "allowed";
        return {
          id: scenario.id,
          label: scenario.label,
          expectedOutcome: scenario.expectedOutcome,
          actualOutcome,
          category: analyzeData.category || "none",
          riskScore: asNumber(analyzeData.risk_score, 0),
          status: actualOutcome === scenario.expectedOutcome ? "passed" : "failed",
          note:
            actualOutcome === "blocked"
              ? `命中 ${categoryLabel(analyzeData.category) || analyzeData.category || "阻断规则"}`
              : "后端预检允许该请求进入网关",
        };
      } catch (error) {
        return {
          id: scenario.id,
          label: scenario.label,
          expectedOutcome: scenario.expectedOutcome,
          actualOutcome: "error",
          category: "request_error",
          riskScore: null,
          status: "failed",
          note: error instanceof Error ? error.message : "验证请求失败",
        };
      }
    },
    // 原实现 deps 不含 apiBaseUrl 与 localInspect（存量告警），行为不变地原样保留。
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [authSession, hasGatewayAccess, settings]
  );

  const runValidationSuite = useCallback(async () => {
    setValidationRunning(true);
    setValidationResults(
      createInitialValidationResults().map((item) => ({
        ...item,
        status: "running",
        note: "执行中",
      }))
    );

    const results: ValidationSuiteItem[] = [];
    for (const scenario of DEMO_SCENARIOS) {
      const result = await evaluateScenario(scenario);
      results.push(result);
      setValidationResults((current) =>
        current.map((item) => (item.id === result.id ? result : item))
      );
    }

    setValidationResults(results);
    setValidationRunning(false);
    const summary = summarizeValidationResults(results);
    const runRecord: ValidationRunRecord = {
      id: makeId("validation-run"),
      createdAt: new Date().toISOString(),
      mode: hasGatewayAccess ? "backend" : "local",
      scenarioId: selectedScenarioId,
      scenarioLabel: selectedScenario.label,
      summary,
      items: results,
    };
    setValidationHistory((current) => {
      const next = [runRecord, ...current].slice(0, MAX_VALIDATION_RUNS);
      writeStorage(STORAGE_KEYS.validationRuns, next);
      return next;
    });
    addToast(
      summary.failed === 0 ? "验证套件执行完成，所有场景符合预期" : `验证套件执行完成，${summary.failed} 个场景与预期不一致`,
      summary.failed === 0 ? "success" : "error"
    );
  }, [addToast, evaluateScenario, hasGatewayAccess, selectedScenario.label, selectedScenarioId]);

  const restoreValidationRun = useCallback(
    (run: ValidationRunRecord) => {
      setValidationResults(run.items);
      setSelectedScenarioId(run.scenarioId);
      setGatewayResult(null);
      addToast(`已恢复 ${formatTime(run.createdAt)} 的验证结果`, "info");
    },
    [addToast, setGatewayResult]
  );

  return {
    selectedScenarioId,
    setSelectedScenarioId,
    selectedScenario,
    validationRunning,
    setValidationRunning,
    validationResults,
    setValidationResults,
    validationHistory,
    setValidationHistory,
    evaluateScenario,
    runValidationSuite,
    restoreValidationRun,
  };
}
