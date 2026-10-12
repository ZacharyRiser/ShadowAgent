"use client";

// 网关测试视图（#gateway）：场景化安全验证 + 批量验证套件。
// 前端单体拆解阶段 1：JSX 自 page.tsx renderGateway 原样搬出，逐字未改
// （仅删除一段 `{false ? ...}` 死代码，其引用的 tools 列表早已被 toolOptions 取代）。
// 状态与副作用仍归 page.tsx 所有（阶段 2 再归仓）；本组件是纯展示 + 回调上抛。

import type { Dispatch, FormEvent, SetStateAction } from "react";
import { AlertTriangle, CheckCircle2, Clipboard, KeyRound, Network, Play, Save, Sparkles } from "lucide-react";
import { GlassSelect, type GlassSelectOption } from "../components/glass-select";
import {
  EmptyState,
  asNumber,
  buttonClass,
  categoryLabel,
  formatTime,
  glassPanelClass,
  glassPanelMotionClass,
  glassPanelSoftClass,
  inputBase,
  riskLabel,
  riskTone,
  severityClass,
} from "../components/ui-kit";
import {
  DEMO_SCENARIOS,
  type DemoScenario,
  type DemoScenarioId,
  type ValidationRunRecord,
  type ValidationSuiteItem,
} from "../demo-scenarios";
import type { GatewayFormState, GatewayResult } from "../gateway-types";
import { buildTimeTooltip, formatRelativeTime } from "../time-utils";

type GatewayViewProps = {
  selectedScenario: DemoScenario;
  selectedScenarioId: DemoScenarioId;
  gatewayForm: GatewayFormState;
  onFormChange: Dispatch<SetStateAction<GatewayFormState>>;
  gatewayLoading: boolean;
  gatewayResult: GatewayResult | null;
  toolOptions: GlassSelectOption[];
  validationRunning: boolean;
  validationResults: ValidationSuiteItem[];
  validationHistory: ValidationRunRecord[];
  validationSummary: ValidationRunRecord["summary"];
  // 证据包当前只消费最近证据链的展示字段；结构化最小类型，富对象可直接赋值。
  evidenceBundle: {
    latestEvidenceChain: {
      requestId: string;
      approval: unknown;
      alerts: unknown[];
      replay: unknown;
    } | null;
  };
  roleShowcase: { label: string; judgeFocus: string };
  onSubmitTest: (event: FormEvent<HTMLFormElement>) => void;
  onLoadScenario: (scenarioId: DemoScenarioId) => void;
  onLoadSample: (kind: "safe" | "risky") => void;
  onLaunchValidationPreset: () => void;
  onRunValidationSuite: () => Promise<void>;
  onResetGatewayForm: () => void;
  navigateTo: (view: "settings") => void;
  onDownloadEvidenceBundle: () => void;
  onCheckHealth: () => Promise<unknown>;
  onDownloadValidationResults: () => void;
  onRestoreValidationRun: (run: ValidationRunRecord) => void;
};

export function GatewayView({
  selectedScenario,
  selectedScenarioId,
  gatewayForm,
  onFormChange,
  gatewayLoading,
  gatewayResult,
  toolOptions,
  validationRunning,
  validationResults,
  validationHistory,
  validationSummary,
  evidenceBundle,
  roleShowcase,
  onSubmitTest,
  onLoadScenario,
  onLoadSample,
  onLaunchValidationPreset,
  onRunValidationSuite,
  onResetGatewayForm,
  navigateTo,
  onDownloadEvidenceBundle,
  onCheckHealth,
  onDownloadValidationResults,
  onRestoreValidationRun,
}: GatewayViewProps) {
  return (
    <div className="grid gap-5 2xl:grid-cols-[minmax(0,1fr)_minmax(320px,420px)]">
      <form onSubmit={onSubmitTest} className={`${glassPanelClass} relative space-y-4 p-5`}>
        <div className={`${glassPanelSoftClass} relative space-y-4 p-4`}>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <div className="inline-flex max-w-full self-start whitespace-nowrap items-center gap-2 rounded-full border border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--tone-accent-surface)] px-3 py-1 text-[length:var(--text-micro)] font-medium text-[var(--tone-accent-text)]">
                <Sparkles className="h-3.5 w-3.5" aria-hidden />
                场景化安全验证
              </div>
              <h2 className="mt-3 text-[length:var(--text-title)] font-semibold text-[var(--text-primary)]">{selectedScenario.label}</h2>
              <p className="mt-2 text-[length:var(--text-body)] leading-6 text-[var(--text-secondary)]">{selectedScenario.summary}</p>
            </div>
            <span className={`self-start shrink-0 whitespace-nowrap rounded-full border px-3 py-1 text-[length:var(--text-micro)] sm:self-auto ${severityClass(selectedScenario.severity)}`}>
              {selectedScenario.expectedOutcome === "blocked" ? "预期拦截" : "预期放行"}
            </span>
          </div>

          {/* 攻击面 / 操作提示：原先是两张并列小卡。两个键值对不值得各占一个盒子，
              改成一条定义列表 —— spatial-design：Cards Are Not Required。 */}
          <dl className="grid gap-x-6 gap-y-2 border-y border-[var(--divider)] py-3 sm:grid-cols-2">
            <div className="flex min-w-0 flex-col gap-1">
              <dt className="text-[length:var(--text-micro)] uppercase tracking-[0.08em] text-[var(--text-muted)]">攻击面</dt>
              <dd className="break-words text-[length:var(--text-body)] leading-6 text-[var(--text-primary)]">{selectedScenario.attackSurface}</dd>
            </div>
            <div className="flex min-w-0 flex-col gap-1">
              <dt className="text-[length:var(--text-micro)] uppercase tracking-[0.08em] text-[var(--text-muted)]">操作提示</dt>
              <dd className="break-words text-[length:var(--text-body)] leading-6 text-[var(--text-primary)]">{selectedScenario.operatorHint}</dd>
            </div>
          </dl>

          <div className="grid gap-2 md:grid-cols-2 2xl:grid-cols-1">
            {DEMO_SCENARIOS.map((scenario) => {
              const active = selectedScenarioId === scenario.id;
              return (
                <button
                  key={scenario.id}
                  type="button"
                  onClick={() => onLoadScenario(scenario.id)}
                  className={`flex flex-col gap-2 rounded-[var(--radius-md)] border px-3.5 py-2.5 text-left text-[length:var(--text-body)] transition-[color,background-color,border-color,box-shadow,transform,opacity] duration-[var(--dur-fast)] active:scale-[0.98] sm:flex-row sm:items-center sm:justify-between ${
                    active
                      ? "border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[color-mix(in_oklab,var(--tone-accent)_8%,transparent)] text-[var(--text-primary)]"
                      : "border-[var(--panel-border)] bg-[var(--surface-raised)] text-[var(--text-secondary)] hover:border-[var(--panel-border)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  <span className="min-w-0 break-words">{scenario.label}</span>
                  <span className="shrink-0 whitespace-nowrap text-[length:var(--text-micro)] opacity-75">{scenario.expectedOutcome === "blocked" ? "Block" : "Allow"}</span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="relative grid gap-4 md:grid-cols-2">
          <label>
            <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">模型</span>
            <input value={gatewayForm.model} onChange={(event) => onFormChange((current) => ({ ...current, model: event.target.value }))} className={inputBase} />
          </label>
          <label>
            <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">工具名</span>
            <GlassSelect
              value={gatewayForm.toolName}
              onChange={(next) => onFormChange((current) => ({ ...current, toolName: next }))}
              options={toolOptions}
              ariaLabel="工具名称"
            />
          </label>
        </div>

        <label className="relative block">
          <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">用户 Prompt</span>
          <textarea value={gatewayForm.prompt} onChange={(event) => onFormChange((current) => ({ ...current, prompt: event.target.value }))} className={`${inputBase} min-h-32 resize-y py-3 leading-6`} placeholder="输入用户请求" />
        </label>

        <label className="relative block">
          <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">外部上下文</span>
          <textarea
            value={gatewayForm.externalContext}
            onChange={(event) => onFormChange((current) => ({ ...current, externalContext: event.target.value }))}
            className={`${inputBase} min-h-28 resize-y py-3 leading-6`}
            placeholder="检索结果、插件返回值或工具结果；这里会按不可信数据处理"
          />
        </label>

        <label className="relative block">
          <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">工具参数 JSON</span>
          <textarea value={gatewayForm.parameters} onChange={(event) => onFormChange((current) => ({ ...current, parameters: event.target.value }))} className={`${inputBase} min-h-28 resize-y py-3 font-mono leading-6`} spellCheck={false} />
        </label>

          <div className="relative flex flex-col gap-3 border-t border-[var(--divider)] pt-4 xl:flex-row xl:items-center xl:justify-between">
            <label className="flex items-center gap-3 text-[length:var(--text-body)] text-[var(--text-secondary)]">
              <input type="checkbox" checked={gatewayForm.stream} onChange={(event) => onFormChange((current) => ({ ...current, stream: event.target.checked }))} className="h-4 w-4 accent-[var(--tone-accent)]" />
              Stream
            </label>
          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
            <button type="button" onClick={() => onLoadSample("safe")} className={`${buttonClass("secondary")} w-full`}>
              安全样例
            </button>
            <button type="button" onClick={() => onLoadSample("risky")} className={`${buttonClass("secondary")} w-full`}>
              默认高风险场景
            </button>
            <button type="button" onClick={onLaunchValidationPreset} className={`${buttonClass("secondary")} w-full`}>
              载入默认验证
            </button>
            <button type="button" onClick={() => void onRunValidationSuite()} disabled={validationRunning} className={`${buttonClass("secondary")} w-full`}>
              {validationRunning ? "批量验证中" : "运行批量验证"}
            </button>
            <button type="button" onClick={onResetGatewayForm} className={`${buttonClass("secondary")} w-full`}>
              清空
            </button>
            <button type="submit" disabled={gatewayLoading} className={`${buttonClass("primary")} w-full`}>
              <Play className="h-4 w-4" aria-hidden />
              {gatewayLoading ? "发送中" : "发送检测"}
            </button>
          </div>
        </div>
      </form>

      <aside className="space-y-4">
        <section className={`${glassPanelClass} ${glassPanelMotionClass} p-5`}>
          <div className="relative flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <h2 className="text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">测试结果</h2>
            <button type="button" onClick={() => navigateTo("settings")} className={`${buttonClass("ghost")} w-full sm:w-auto`}>
              <KeyRound className="h-4 w-4" aria-hidden />
              API Key
            </button>
          </div>
          {gatewayResult ? (
            <div className="relative mt-4">
              <div className={`rounded-[var(--radius-lg)] border p-4.5 ${gatewayResult.ok ? "border-[color-mix(in_oklab,var(--tone-success)_28%,transparent)] bg-[var(--tone-success-surface)] text-[var(--tone-success-text)]" : "border-[color-mix(in_oklab,var(--tone-danger)_28%,transparent)] bg-[var(--tone-danger-surface)] text-[var(--tone-danger-text)]"}`}>
                <div className="flex items-center gap-2 font-semibold">
                  {gatewayResult.ok ? <CheckCircle2 className="h-4 w-4" aria-hidden /> : <AlertTriangle className="h-4 w-4" aria-hidden />}
                  {gatewayResult.title}
                </div>
                <p className="mt-2 text-[length:var(--text-body)] leading-6 opacity-90">{gatewayResult.message}</p>
                <div className="mt-3 rounded-[var(--radius-md)] border border-[var(--panel-border)] bg-[var(--surface-raised)] px-3.5 py-2.5 text-[length:var(--text-micro)] leading-5 text-[var(--text-secondary)]">
                  预期结果：{selectedScenario.expectedOutcome === "blocked" ? "阻断" : "放行"}。
                  {selectedScenario.expectedCategory ? ` 重点关注分类 ${categoryLabel(selectedScenario.expectedCategory)}。` : " 该场景用于验证正常流量不会被误拦。"}
                </div>
                {gatewayResult.detail && typeof gatewayResult.detail === "object" && "risk_score" in gatewayResult.detail ? (
                  <div
                    className={`mt-3 inline-flex items-center rounded-full border px-3 py-1 text-[length:var(--text-micro)] font-medium ${riskTone(
                      asNumber((gatewayResult.detail as Record<string, unknown>).risk_score)
                    )}`}
                  >
                    {riskLabel(asNumber((gatewayResult.detail as Record<string, unknown>).risk_score))} /{" "}
                    {Math.round(asNumber((gatewayResult.detail as Record<string, unknown>).risk_score) * 100)}
                  </div>
                ) : null}
              </div>
              {gatewayResult.detail ? <pre className={`${glassPanelSoftClass} mt-4 max-h-[360px] overflow-auto p-4 text-[length:var(--text-micro)] leading-5 text-[var(--text-secondary)]`}>{JSON.stringify(gatewayResult.detail, null, 2)}</pre> : null}
              <div className="mt-4 grid gap-3">
                <div className={`${glassPanelSoftClass} p-4`}>
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <h3 className="text-[length:var(--text-body)] font-semibold text-[var(--text-primary)]">证据包摘要</h3>
                    <button type="button" onClick={onDownloadEvidenceBundle} className={`${buttonClass("secondary")} w-full sm:w-auto`}>
                      <Save className="h-4 w-4" aria-hidden />
                      一键导出
                    </button>
                  </div>
                  <div className="mt-3 grid gap-3 sm:grid-cols-2">
                    <div className="rounded-[var(--radius-md)] border border-[var(--panel-border)] bg-[var(--surface-raised)] p-3.5 text-[length:var(--text-body)]">
                      <div className="text-[length:var(--text-micro)] text-[var(--text-muted)]">当前角色视角</div>
                      <div className="mt-2 text-[var(--text-primary)]">{roleShowcase.label}</div>
                      <div className="mt-1 text-[length:var(--text-micro)] leading-5 text-[var(--text-secondary)]">{roleShowcase.judgeFocus}</div>
                    </div>
                    <div className="rounded-[var(--radius-md)] border border-[var(--panel-border)] bg-[var(--surface-raised)] p-3.5 text-[length:var(--text-body)]">
                      <div className="text-[length:var(--text-micro)] text-[var(--text-muted)]">最近证据链</div>
                      <div className="mt-2 text-[var(--text-primary)]">{evidenceBundle.latestEvidenceChain?.requestId || "本次尚未形成阻断 request id"}</div>
                      <div className="mt-1 text-[length:var(--text-micro)] leading-5 text-[var(--text-secondary)]">
                        {evidenceBundle.latestEvidenceChain
                          ? `审批 ${evidenceBundle.latestEvidenceChain.approval ? "已关联" : "未关联"} · 告警 ${evidenceBundle.latestEvidenceChain.alerts.length} 条 · 回放 ${evidenceBundle.latestEvidenceChain.replay ? "已关联" : "未关联"}`
                          : "导出后会附带当前场景输入、验证结果、最近日志、审批、告警与回放快照。"}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="relative mt-4">
              <EmptyState icon={Play} title="尚未发送测试">
                <div className="flex flex-wrap justify-center gap-2">
                  <button type="button" onClick={() => onLoadSample("safe")} className={buttonClass("secondary")}>
                    安全样例
                  </button>
                  <button type="button" onClick={() => onLoadSample("risky")} className={buttonClass("primary")}>
                    默认高风险场景
                  </button>
                </div>
              </EmptyState>
            </div>
          )}
        </section>

        <section className={`${glassPanelClass} ${glassPanelMotionClass} p-5`}>
          <h2 className="relative text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">验证套件</h2>
          <div className="relative mt-4 space-y-3 text-[length:var(--text-body)]">
            <div className="flex justify-between gap-3 border-b border-[var(--divider)] pb-3">
              <span className="text-[var(--text-secondary)]">已执行</span>
              <span className="font-medium text-[var(--text-primary)]">
                {validationSummary.executed}/{validationSummary.total}
              </span>
            </div>
            <div className="flex justify-between border-b border-[var(--divider)] pb-3">
              <span className="text-[var(--text-secondary)]">符合预期</span>
              <span className="font-medium text-[var(--tone-success-text)]">{validationSummary.passed}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[var(--text-secondary)]">偏差场景</span>
              <span className={validationSummary.failed > 0 ? "text-[var(--tone-danger-text)]" : "text-[var(--text-primary)]"}>{validationSummary.failed}</span>
            </div>
          </div>
          <div className="relative mt-5 divide-y divide-[var(--divider)] border-y border-[var(--divider)]">
            {validationResults.map((item) => (
              <div key={item.id} className="flex items-start justify-between gap-3 py-2.5">
                <div className="min-w-0">
                  <div className="text-[length:var(--text-body)] text-[var(--text-primary)]">{item.label}</div>
                  <div className="mt-0.5 text-[length:var(--text-micro)] text-[var(--text-muted)]">{item.note}</div>
                </div>
                <span
                  className={`chip shrink-0 ${
                    item.status === "passed"
                      ? "chip-success"
                      : item.status === "failed"
                        ? "chip-danger"
                        : item.status === "running"
                          ? "chip-warning"
                          : "chip-neutral"
                  }`}
                >
                  {item.status === "passed" ? "通过" : item.status === "failed" ? "偏差" : item.status === "running" ? "运行中" : "待执行"}
                </span>
              </div>
            ))}
          </div>
          <div className="relative mt-5 grid gap-2 sm:grid-cols-2">
            <button type="button" onClick={() => void onCheckHealth()} className={`${buttonClass("secondary")} w-full`}>
              <Network className="h-4 w-4" aria-hidden />
              检测网关
            </button>
            <button
              type="button"
              onClick={() => void onDownloadValidationResults()}
              disabled={validationRunning || (validationSummary.executed === 0 && validationHistory.length === 0)}
              className={`${buttonClass("secondary")} w-full`}
            >
              <Save className="h-4 w-4" aria-hidden />
              导出结果
            </button>
            <button type="button" onClick={() => void onRunValidationSuite()} disabled={validationRunning} className={`${buttonClass("primary")} w-full`}>
              <Play className="h-4 w-4" aria-hidden />
              {validationRunning ? "运行中" : "批量验证"}
            </button>
            <button type="button" onClick={onDownloadEvidenceBundle} className={`${buttonClass("secondary")} w-full`}>
              <Clipboard className="h-4 w-4" aria-hidden />
              证据包导出
            </button>
          </div>
          <div className="relative mt-5">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <h3 className="text-[length:var(--text-body)] font-semibold text-[var(--text-primary)]">最近运行</h3>
              <span className="text-[length:var(--text-micro)] text-[var(--text-secondary)]">自动保存在当前浏览器</span>
            </div>
            {validationHistory.length > 0 ? (
              <div className="mt-3 divide-y divide-[var(--divider)] border-y border-[var(--divider)]">
                {validationHistory.map((run) => (
                  <button
                    key={run.id}
                    type="button"
                    onClick={() => onRestoreValidationRun(run)}
                    className="flex w-full flex-col gap-1 px-1 py-2.5 text-left transition-colors duration-[var(--dur-fast)] hover:bg-[var(--surface-sunken)] focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--tone-accent)]"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="text-[length:var(--text-body)] font-medium text-[var(--text-primary)]">{formatRelativeTime(run.createdAt)}</div>
                        <div className="mt-0.5 text-[length:var(--text-micro)] text-[var(--text-secondary)]" title={buildTimeTooltip(run.createdAt)}>
                          {formatTime(run.createdAt)} CST · {run.mode === "backend" ? "后端预检" : "本地预检"}
                        </div>
                      </div>
                      <span className={`chip shrink-0 ${run.summary.failed === 0 ? "chip-success" : "chip-warning"}`}>
                        {run.summary.passed}/{run.summary.total}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-3 text-[length:var(--text-micro)] text-[var(--text-secondary)]">
                      <span className="truncate">{run.scenarioLabel}</span>
                      <span className="shrink-0">{run.summary.failed === 0 ? "全部符合预期" : `${run.summary.failed} 个偏差`}</span>
                    </div>
                  </button>
                ))}
              </div>
            ) : (
              <p className="mt-3 border-y border-[var(--divider)] py-4 text-[length:var(--text-micro)] leading-6 text-[var(--text-muted)]">
                暂无历史验证结果。执行一次批量验证后，这里会保留最近运行记录，方便回归对比与导出留档。
              </p>
            )}
          </div>
        </section>
      </aside>
    </div>
  );
}
