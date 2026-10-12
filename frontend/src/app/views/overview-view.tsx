"use client";

// 总览视图：前端单体拆解阶段 1，JSX 自 page.tsx renderOverview 逐字搬出（AST 定位，零手抄）。
// 状态与副作用仍归 page.tsx 所有（阶段 2 再归仓）；本组件纯展示 + 回调上抛。

import type { Dispatch, SetStateAction } from "react";
import { Bell, ChevronRight, Copy, Database, FileText, KeyRound, Network, Play, Plus, RefreshCcw, Save, SlidersHorizontal, Sparkles } from "lucide-react";
import { AnimatedInterceptLogList, LogListSkeleton } from "../components/intercept-log-card";
import { AnimatedNumber } from "../components/animated-number";
import { EmptyState, buttonClass, glassPanelClass, glassPanelMotionClass, glassPanelSoftClass, type IconComponent } from "../components/ui-kit";
import { PanelGlow, Switch, ledgerRowClass } from "../components/page-widgets";
import { ROLE_PERMISSION_MATRIX, ROLE_SHOWCASE_DEFINITIONS, STORAGE_KEYS, sanitizeSettingsForStorage, severityChipClass, writeStorage } from "../app-meta";
import { DEMO_SCENARIOS, type DemoScenario, type DemoScenarioId } from "../demo-scenarios";
import type { AlertItem, ApprovalItem, AppSettings, HealthState, InterceptLog, PolicyRule, ReplayItem, RoleShowcaseDefinition, RoleShowcaseId, ToolPermission, ViewKey } from "../types";

export function OverviewView({
  alerts,
  approvals,
  attackCoverage,
  checkHealth,
  copyText,
  detectionLayerStats,
  downloadEvidenceBundle,
  hasAdminAccess,
  health,
  launchValidationPreset,
  loadLogs,
  loadScenarioIntoGateway,
  logsLoading,
  managedKeyStats,
  metrics,
  navigateTo,
  policies,
  recentLogs,
  replays,
  roleShowcase,
  roleShowcaseDefinition,
  roleShowcaseStatus,
  seedLogs,
  selectedScenario,
  selectedScenarioId,
  setRoleShowcase,
  setSelectedLog,
  setSettings,
  settings,
  tools,
  validationReadiness,
}: {
  alerts: AlertItem[];
  approvals: ApprovalItem[];
  attackCoverage: { label: string; count: number; tone: string }[];
  checkHealth: () => Promise<unknown>;
  copyText: (value: string, successMessage: string) => Promise<void>;
  detectionLayerStats: { signature: number; semantic: number; dlp: number; tool: number };
  downloadEvidenceBundle: () => void;
  hasAdminAccess: boolean;
  health: HealthState;
  launchValidationPreset: () => void;
  loadLogs: () => Promise<void>;
  loadScenarioIntoGateway: (scenarioId: DemoScenarioId) => void;
  logsLoading: boolean;
  managedKeyStats: { total: number; active: number; paused: number; expired: number };
  metrics: { label: string; value: number | string; icon: IconComponent; tone: string }[];
  navigateTo: (target: ViewKey) => void;
  policies: PolicyRule[];
  recentLogs: InterceptLog[];
  replays: ReplayItem[];
  roleShowcase: RoleShowcaseId;
  roleShowcaseDefinition: RoleShowcaseDefinition;
  roleShowcaseStatus: Record<"admin" | "client" | "gateway", { enabled: boolean; source: string }>;
  seedLogs: () => void;
  selectedScenario: DemoScenario;
  selectedScenarioId: DemoScenarioId;
  setRoleShowcase: Dispatch<SetStateAction<RoleShowcaseId>>;
  setSelectedLog: Dispatch<SetStateAction<InterceptLog | null>>;
  setSettings: Dispatch<SetStateAction<AppSettings>>;
  settings: AppSettings;
  tools: ToolPermission[];
  validationReadiness: { score: number; label: string };
}) {
{
    const enabledPolicies = policies.filter((policy) => policy.enabled).length;
    const allowedTools = tools.filter((tool) => tool.allowed).length;
    const RoleShowcaseIcon = roleShowcaseDefinition.icon;

    return (
      <div className="space-y-5">
        <section className={`${glassPanelClass} relative overflow-hidden p-6`}>
          <PanelGlow />
          <div className="relative grid gap-6 2xl:grid-cols-[minmax(0,1.35fr)_minmax(300px,360px)]">
            <div className="space-y-5">
              <div className="inline-flex items-center gap-2 rounded-full border border-[color-mix(in_oklab,var(--tone-accent)_26%,transparent)] bg-[var(--tone-accent-surface)] px-3 py-1 text-[length:var(--text-micro)] font-semibold uppercase tracking-[0.12em] text-[var(--tone-accent-text)]">
                <Sparkles className="h-3.5 w-3.5" aria-hidden />
                安全验证总览
              </div>
              <div className="space-y-3">
                <h2 className="max-w-4xl text-[length:var(--text-title)] font-bold leading-[1.15] tracking-[-0.025em] text-[var(--text-primary)] sm:text-[length:var(--text-title)]">
                  不是简单拦 Prompt，而是在 Agent 运行时切断
                  <span className="text-[var(--tone-accent-text)]"> 不可信上下文到危险执行 </span>
                  的整条链路
                </h2>
                <p className="max-w-3xl text-[length:var(--text-body)] leading-7 text-[var(--text-secondary)] sm:text-[length:var(--text-heading)]">
                  Shadow Agent 把检索结果、插件输出、工具返回值视为不可信数据，并在真正调用大模型或工具前完成分层审计、权限校验、危险行为识别与证据留痕。
                </p>
              </div>

              {/* 不用「三特性卡」——那是反 AI 味检查表 #3 的逐字命中。
                 换成产品特有的东西：真实的检测层清单 + 各自当前命中数。
                 这是"只有 ShadowAgent 才有的一块"，换 Logo 不会变成别家。 */}
              <dl className="grid gap-x-6 gap-y-0 border-y border-[var(--divider)] sm:grid-cols-2">
                {[
                  { layer: "层一 · 确定性签名", detail: "强档独立阻断；弱档需指令动词佐证", count: detectionLayerStats.signature },
                  { layer: "层二 · 语义检测", detail: "词袋模型 + 探针标定阈值，灰带留痕", count: detectionLayerStats.semantic },
                  { layer: "响应侧 · DLP", detail: "出站内容脱敏，密钥与凭据模式识别", count: detectionLayerStats.dlp },
                  { layer: "工具权限 · 策略", detail: "未授权工具调用与提权动作拦截", count: detectionLayerStats.tool },
                ].map((item) => (
                  <div
                    key={item.layer}
                    className="flex items-baseline justify-between gap-3 border-b border-[var(--divider)] py-2.5 last:border-b-0 sm:[&:nth-last-child(-n+2)]:border-b-0"
                  >
                    <dt className="min-w-0">
                      <span className="block text-[length:var(--text-caption)] font-medium text-[var(--text-primary)]">{item.layer}</span>
                      <span className="mt-0.5 block text-[length:var(--text-micro)] text-[var(--text-muted)]">{item.detail}</span>
                    </dt>
                    <dd className="tnum shrink-0 font-mono text-[length:var(--text-caption)] font-semibold text-[var(--text-secondary)]">
                      <AnimatedNumber value={item.count} />
                    </dd>
                  </div>
                ))}
              </dl>

              <div className="flex flex-wrap gap-3">
                <button type="button" onClick={launchValidationPreset} className={buttonClass("primary")}>
                  <Play className="h-4 w-4" aria-hidden />
                  打开默认验证场景
                </button>
                <button type="button" onClick={() => navigateTo("gateway")} className={buttonClass("secondary")}>
                  <ChevronRight className="h-4 w-4" aria-hidden />
                  打开验证控制台
                </button>
                <button type="button" onClick={() => navigateTo("logs")} className={buttonClass("ghost")}>
                  <FileText className="h-4 w-4" aria-hidden />
                  查看证据日志
                </button>
              </div>
            </div>

            <aside className="space-y-4">
              <section className={`${glassPanelSoftClass} p-5`}>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="text-[length:var(--text-micro)] font-semibold uppercase tracking-[0.12em] text-[var(--text-muted)]">验证准备度</div>
                    <div className="tnum mt-2 text-[length:var(--text-display)] font-bold leading-none tracking-[-0.03em] text-[var(--text-primary)]">
                      <AnimatedNumber value={validationReadiness.score} />%
                    </div>
                  </div>
                  <span className="chip chip-accent">
                    {validationReadiness.label}
                  </span>
                </div>
                <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-[var(--surface-sunken)]">
                  <div className="h-full rounded-full bg-[var(--accent-solid)]" style={{ width: `${validationReadiness.score}%` }} />
                </div>
                <div className="mt-4 grid gap-2.5">
                  {attackCoverage.map((item) => (
                    <div key={item.label} className="flex items-center justify-between rounded-[var(--radius-sm)] border border-[var(--panel-border-soft)] bg-[var(--surface-sunken)] px-3.5 py-2">
                      <span className="text-[length:var(--text-body)] text-[var(--text-secondary)]">{item.label}</span>
                      <span className={`tnum text-[length:var(--text-body)] font-semibold ${item.tone}`}>
                        <AnimatedNumber value={item.count} />
                      </span>
                    </div>
                  ))}
                </div>
              </section>

              <section className={`${glassPanelSoftClass} p-5`}>
                <div className="flex items-center gap-2 text-[length:var(--text-micro)] font-semibold uppercase tracking-[0.12em] text-[var(--text-muted)]">
                  <Bell className="h-3.5 w-3.5 text-[var(--tone-warning-text)]" aria-hidden />
                  当前验证焦点
                </div>
                <h3 className="mt-3 text-[length:var(--text-title)] font-semibold tracking-[-0.012em] text-[var(--text-primary)]">{selectedScenario.label}</h3>
                <p className="mt-2 text-[length:var(--text-body)] leading-6 text-[var(--text-secondary)]">{selectedScenario.summary}</p>
                <div className="mt-4 space-y-2 text-[length:var(--text-micro)] text-[var(--text-secondary)]">
                  <div className="rounded-[var(--radius-sm)] border border-[var(--panel-border-soft)] bg-[var(--surface-sunken)] px-3.5 py-2">
                    攻击面：{selectedScenario.attackSurface}
                  </div>
                  <div className="rounded-[var(--radius-sm)] border border-[var(--panel-border-soft)] bg-[var(--surface-sunken)] px-3.5 py-2">
                    操作提示：{selectedScenario.operatorHint}
                  </div>
                </div>
              </section>
            </aside>
          </div>
        </section>

        {/* 四个指标：不用四张独立卡片（那是「一模一样圆角卡片」模板），
            改成一条被竖线切开的指标带 —— 同一屏宽下更紧凑，且没有 hover 位移的廉价感。
            motion-design：不要 bounce/spring；指标不是可点元素，就不该有位移反馈。 */}
        <section className="grid gap-px overflow-hidden rounded-[var(--radius-lg)] border border-[var(--panel-border)] bg-[var(--divider)] sm:grid-cols-2 xl:grid-cols-4">
          {metrics.map((metric) => (
            <div key={metric.label} className="relative bg-[var(--panel-bg)] p-5">
              <div className="flex items-center justify-between">
                <span className="text-[length:var(--text-micro)] font-medium uppercase tracking-[0.1em] text-[var(--text-muted)]">{metric.label}</span>
                <metric.icon className={`h-4 w-4 ${metric.tone}`} aria-hidden />
              </div>
              <div className="tnum mt-3 font-mono text-[length:var(--text-title)] font-semibold leading-none tracking-[-0.03em] text-[var(--text-primary)]">
                {typeof metric.value === "number" ? <AnimatedNumber value={metric.value} /> : metric.value}
              </div>
            </div>
          ))}
        </section>

        <section className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(320px,360px)]">
          <section className={`${glassPanelClass} relative overflow-hidden p-5`}>
            <div className="relative flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0">
                <h2 className="text-[length:var(--text-title)] font-semibold tracking-[-0.012em] text-[var(--text-primary)]">验证链路</h2>
                <p className="mt-1 text-[length:var(--text-body)] text-[var(--text-secondary)]">用一个高风险样例检查攻击输入、风险识别、处置动作和证据链是否完整闭环。</p>
              </div>
              <button
                type="button"
                onClick={() => loadScenarioIntoGateway(selectedScenario.id)}
                className={buttonClass("secondary")}
              >
                <Copy className="h-4 w-4" aria-hidden />
                载入场景
              </button>
            </div>

            {/* 链路四步是流程说明，不是状态 —— 不用语义状态色上粉彩底（那是「彩卡模板」味），
                改成中性面板 + accent 步骤徽章，编号用数据序号而非标题里的手写数字。 */}
            <div className="relative mt-5 grid gap-3 md:grid-cols-2 2xl:grid-cols-4">
              {[
                { title: "注入载荷", body: "攻击指令混入检索结果、插件输出或工具返回值。" },
                { title: "分层审计", body: "Shadow Agent 将可信用户意图与不可信上下文拆分处理。" },
                { title: "风险阻断", body: "策略、权限与危险行为检查在真正调用模型前完成拦截。" },
                { title: "证据留痕", body: "日志、告警、审批、回放把每次拦截都变成可复盘的证据链。" },
              ].map((item, index) => (
                <div
                  key={item.title}
                  className="rounded-[var(--radius-md)] border border-[var(--panel-border)] bg-[var(--surface-raised)] p-4 transition-colors duration-[var(--dur-fast)]"
                >
                  <div className="flex items-center gap-2">
                    <span
                      aria-hidden
                      className="tnum inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-[var(--accent-solid)] text-[length:var(--text-micro)] font-semibold text-[var(--accent-on-solid)]"
                    >
                      {index + 1}
                    </span>
                    <div className="text-[length:var(--text-caption)] font-semibold text-[var(--text-primary)]">{item.title}</div>
                  </div>
                  <p className="mt-2 text-[length:var(--text-micro)] leading-6 text-[var(--text-secondary)]">{item.body}</p>
                </div>
              ))}
            </div>
          </section>

          <section className={`${glassPanelClass} relative overflow-hidden p-5`}>
            <div className="relative flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0">
                <h2 className="text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">验证场景库</h2>
                <p className="mt-1 text-[length:var(--text-body)] text-[var(--text-secondary)]">覆盖正常流量、检索投毒、工具越权、插件外传与内网探测。</p>
              </div>
              <span className="self-start whitespace-nowrap rounded-full border border-[var(--panel-border)] bg-[var(--surface-raised)] px-3 py-1 text-[length:var(--text-micro)] text-[var(--text-secondary)] sm:self-auto">
                {DEMO_SCENARIOS.length} 个场景
              </span>
            </div>

            {/* 场景库 → 台账：原来是 5 张同构卡片，每张都有圆角+描边+双层 padding。
                现在一条表头 + 5 行，行高从 ~92px 压到 ~56px，一屏能看全整个场景库。 */}
            <div className="relative mt-4 overflow-hidden rounded-[var(--radius-lg)] border border-[var(--panel-border)]">
              <div className="grid grid-cols-[1.75rem_minmax(0,1fr)_auto] items-center gap-x-3 border-b border-[var(--panel-border)] bg-[var(--surface-sunken)] px-4 py-2 text-[length:var(--text-micro)] font-medium uppercase tracking-[0.08em] text-[var(--text-muted)]">
                <span aria-hidden />
                <span>场景</span>
                <span className="text-right">预期</span>
              </div>
              {DEMO_SCENARIOS.map((scenario, index) => {
                const selected = selectedScenarioId === scenario.id;
                return (
                  <button
                    key={scenario.id}
                    type="button"
                    onClick={() => loadScenarioIntoGateway(scenario.id)}
                    aria-pressed={selected}
                    className={`relative grid w-full grid-cols-[1.75rem_minmax(0,1fr)_auto] items-start gap-x-3 gap-y-1.5 px-4 py-3 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--tone-accent)] ${ledgerRowClass} ${
                      selected ? "bg-[var(--tone-accent-surface)]" : ""
                    }`}
                  >
                    {/* 选中态用行首竖条 + 序号变色，不再整行换边框+阴影 */}
                    <span
                      aria-hidden
                      className={`absolute inset-y-2 left-0 w-[3px] rounded-r-full transition-colors duration-[var(--dur-fast)] ${
                        selected ? "bg-[var(--accent-solid)]" : "bg-transparent"
                      }`}
                    />
                    <span
                      className={`tnum mt-0.5 text-center font-mono text-[length:var(--text-micro)] transition-colors duration-[var(--dur-fast)] ${
                        selected ? "text-[var(--tone-accent-text)]" : "text-[var(--text-muted)]"
                      }`}
                    >
                      {String(index + 1).padStart(2, "0")}
                    </span>
                    <span className="col-start-2 min-w-0">
                      <span
                        className={`block text-[length:var(--text-body)] font-medium transition-colors duration-[var(--dur-fast)] ${
                          selected ? "text-[var(--tone-accent-text)]" : "text-[var(--text-primary)]"
                        }`}
                      >
                        {scenario.label}
                      </span>
                      {/* 摘要只在选中时展开 —— 未选中时是单行截断，进一步压低行高 */}
                      <span
                        className={`mt-1 block text-[length:var(--text-micro)] leading-5 text-[var(--text-secondary)] ${
                          selected ? "" : "line-clamp-1"
                        }`}
                      >
                        {scenario.summary}
                      </span>
                    </span>
                    <span className={`chip shrink-0 justify-self-end ${severityChipClass(scenario.severity)}`}>
                      {scenario.expectedOutcome === "blocked" ? "应拦截" : "应放行"}
                    </span>
                  </button>
                );
              })}
            </div>
          </section>
        </section>

        <section className={`${glassPanelClass} relative p-5`}>
          <div className="relative flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
            <div className="min-w-0">
              <h2 className="text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">角色切换演示台</h2>
              <p className="mt-1 text-[length:var(--text-body)] text-[var(--text-secondary)]">把 Admin、Client、Gateway 放到同一块面板里，评委一眼就能看出权限边界。</p>
            </div>
            <button type="button" onClick={() => navigateTo("keys")} className={`${buttonClass("secondary")} w-full sm:w-auto xl:shrink-0`}>
              <KeyRound className="h-4 w-4" aria-hidden />
              去签发密钥
            </button>
          </div>

            <div className="relative mt-4 grid gap-2.5 sm:grid-cols-2 xl:grid-cols-3">
              {ROLE_SHOWCASE_DEFINITIONS.map((item) => {
                const Icon = item.icon;
              const selected = roleShowcase === item.id;
              const status = roleShowcaseStatus[item.id];
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setRoleShowcase(item.id)}
                  className={`min-w-0 rounded-[var(--radius-lg)] border p-4 text-left transition-[color,background-color,border-color,box-shadow,transform,opacity] duration-[var(--dur-fast)] ease-[var(--ease-out-quart)] active:scale-[0.98] ${
                    selected
                      ? "border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[color-mix(in_oklab,var(--tone-accent)_9%,transparent)] shadow-[var(--panel-shadow-soft)]"
                      : "border-[var(--panel-border)] bg-[var(--surface-raised)] hover:border-[var(--panel-border)] hover:bg-[var(--surface-raised)]"
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <span className="inline-flex min-w-0 items-center gap-2 text-[length:var(--text-body)] font-semibold text-[var(--text-primary)]">
                      <Icon className="h-4 w-4 text-[var(--tone-accent-text)]" aria-hidden />
                      {item.label}
                    </span>
                      <span className={`shrink-0 whitespace-nowrap rounded-full border px-2.5 py-1 text-[length:var(--text-micro)] ${status.enabled ? "border-[color-mix(in_oklab,var(--tone-success)_28%,transparent)] bg-[var(--tone-success-surface)] text-[var(--tone-success-text)]" : "border-[var(--panel-border)] bg-[var(--surface-raised)] text-[var(--text-secondary)]"}`}>
                        {status.enabled ? "已接入" : "未接入"}
                      </span>
                    </div>
                    <div className="mt-2 break-words text-[length:var(--text-micro)] leading-6 text-[var(--text-secondary)]">{item.badge} · {status.source}</div>
                  </button>
                );
              })}
          </div>

            <div className="relative mt-4 grid gap-4">
              <div className={`${glassPanelSoftClass} min-w-0 p-4`}>
                <div className="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
                  <div className="min-w-0">
                    <div className={`inline-flex max-w-full self-start whitespace-nowrap rounded-full border px-3 py-1 text-[length:var(--text-micro)] ${roleShowcaseDefinition.tone}`}>
                      <RoleShowcaseIcon className="h-3.5 w-3.5" aria-hidden />
                      {roleShowcaseDefinition.badge}
                    </div>
                  <h3 className="mt-3 text-[length:var(--text-title)] font-semibold text-[var(--text-primary)]">{roleShowcaseDefinition.label}</h3>
                  <p className="mt-2 text-[length:var(--text-body)] leading-6 text-[var(--text-secondary)]">{roleShowcaseDefinition.description}</p>
                </div>
                <span className={`shrink-0 self-start whitespace-nowrap rounded-full border px-3 py-1 text-[length:var(--text-micro)] ${roleShowcaseStatus[roleShowcase].enabled ? "border-[color-mix(in_oklab,var(--tone-success)_28%,transparent)] bg-[var(--tone-success-surface)] text-[var(--tone-success-text)]" : "border-[color-mix(in_oklab,var(--tone-warning)_28%,transparent)] bg-[var(--tone-warning-surface)] text-[var(--tone-warning-text)]"}`}>
                  {roleShowcaseStatus[roleShowcase].enabled ? "可直接演示" : "建议先接入"}
                </span>
              </div>

                <div className="mt-4 grid gap-3 lg:grid-cols-2">
                  <div className="rounded-[var(--radius-md)] border border-[var(--panel-border)] bg-[var(--surface-raised)] p-3.5 text-[length:var(--text-body)]">
                    <div className="text-[length:var(--text-micro)] text-[var(--text-muted)]">接入方式</div>
                    <div className="mt-2 break-words text-[var(--text-primary)]">{roleShowcaseDefinition.authHint}</div>
                  </div>
                  <div className="rounded-[var(--radius-md)] border border-[var(--panel-border)] bg-[var(--surface-raised)] p-3.5 text-[length:var(--text-body)]">
                    <div className="text-[length:var(--text-micro)] text-[var(--text-muted)]">评委关注点</div>
                    <div className="mt-2 break-words text-[var(--text-primary)]">{roleShowcaseDefinition.judgeFocus}</div>
                  </div>
                </div>

              <div className="mt-4 grid gap-3 lg:grid-cols-2">
                <div className="rounded-[var(--radius-md)] border border-[color-mix(in_oklab,var(--tone-success)_28%,transparent)] bg-[var(--tone-success-surface)] p-3.5">
                  <div className="text-[length:var(--text-body)] font-medium text-[var(--tone-success-text)]">能做什么</div>
                  <div className="mt-2 space-y-2 text-[length:var(--text-micro)] leading-6 text-[var(--tone-success-text)]/90">
                    {roleShowcaseDefinition.allowed.map((line) => (
                      <div key={line}>• {line}</div>
                    ))}
                  </div>
                </div>
                <div className="rounded-[var(--radius-md)] border border-[color-mix(in_oklab,var(--tone-danger)_28%,transparent)] bg-[var(--tone-danger-surface)] p-3.5">
                  <div className="text-[length:var(--text-body)] font-medium text-[var(--tone-danger-text)]">被限制什么</div>
                  <div className="mt-2 space-y-2 text-[length:var(--text-micro)] leading-6 text-[var(--tone-danger-text)]/90">
                    {roleShowcaseDefinition.restricted.map((line) => (
                      <div key={line}>• {line}</div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

              <div className={`${glassPanelSoftClass} min-w-0 p-4`}>
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <h3 className="text-[length:var(--text-body)] font-semibold text-[var(--text-primary)]">权限矩阵</h3>
                  <button type="button" onClick={downloadEvidenceBundle} className={`${buttonClass("secondary")} w-full sm:w-auto`}>
                    <Save className="h-4 w-4" aria-hidden />
                  导出演示证据包
                </button>
              </div>
                <div className="mt-4 grid gap-3 lg:grid-cols-2">
                  {ROLE_PERMISSION_MATRIX.map((row) => (
                    <div key={row.capability} className="rounded-[var(--radius-md)] border border-[var(--panel-border)] bg-[var(--surface-raised)] px-3.5 py-3 text-[length:var(--text-micro)]">
                      <div className="break-words leading-6 text-[var(--text-secondary)]">{row.capability}</div>
                      <div className="mt-3 grid gap-2 sm:grid-cols-3">
                        {[
                          { label: "Admin", enabled: row.admin },
                        { label: "Client", enabled: row.client },
                        { label: "Gateway", enabled: row.gateway },
                      ].map((cell) => (
                        <div key={cell.label} className={`rounded-[var(--radius-sm)] px-2 py-2 text-center whitespace-nowrap ${cell.enabled ? "bg-[var(--tone-success-surface)] text-[var(--tone-success-text)]" : "bg-[var(--surface-raised)] text-[var(--text-muted)]"}`}>
                          {cell.label}
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
              <div className="mt-4 rounded-[var(--radius-md)] border border-[var(--panel-border)] bg-[var(--surface-raised)] px-3.5 py-3 text-[length:var(--text-micro)] leading-6 text-[var(--text-secondary)]">
                推荐话术：先用 `client/gateway` 跑正常和高风险场景，证明“业务可用但权限克制”；再切到 `admin`，展示日志、审批、回放与证据包导出闭环。
              </div>
            </div>
          </div>
        </section>

        <section className="grid gap-4 2xl:grid-cols-[minmax(0,1fr)_minmax(300px,360px)]">
          <div className={`${glassPanelClass} relative overflow-visible`}>
            <div className="relative flex flex-col gap-3 border-b border-[var(--divider)] px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">最新拦截事件</h2>
                <p className="mt-1 text-[length:var(--text-body)] text-[var(--text-secondary)]">来自后端审计接口和本地预检结果。</p>
              </div>
              <div className="flex flex-wrap gap-2">
                <button type="button" onClick={() => navigateTo("logs")} className={buttonClass("secondary")}>
                  <FileText className="h-4 w-4" aria-hidden />
                  查看日志
                </button>
                <button type="button" onClick={() => void loadLogs()} className={buttonClass("secondary")}>
                  <RefreshCcw className={`h-4 w-4 ${logsLoading ? "animate-spin" : ""}`} aria-hidden />
                  刷新
                </button>
              </div>
            </div>
            {logsLoading && recentLogs.length === 0 ? (
              <LogListSkeleton rows={4} />
            ) : recentLogs.length === 0 ? (
              <div className="relative p-5">
                <EmptyState icon={Database} title="暂无日志">
                  <button type="button" onClick={seedLogs} className={`${buttonClass("primary")} mt-3`}>
                    <Plus className="h-4 w-4" aria-hidden />
                    生成验证样例
                  </button>
                </EmptyState>
              </div>
            ) : (
              <AnimatedInterceptLogList
                logs={recentLogs}
                compact
                onSelect={(log) => setSelectedLog(log)}
                onCopyRequestId={(requestId) => void copyText(requestId, "请求 ID 已复制")}
              />
            )}
          </div>

          <div className="space-y-4">
            <section className={`${glassPanelSoftClass} ${glassPanelMotionClass} p-5`}>
              <h2 className="relative text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">审计运营</h2>
              <dl className="relative mt-3 divide-y divide-[var(--divider)] text-[length:var(--text-body)]">
                <div className="flex items-baseline justify-between gap-3 py-2.5">
                  <dt className="text-[var(--text-secondary)]">待审批</dt>
                  <dd className="tnum font-medium text-[var(--text-primary)]">{approvals.length}</dd>
                </div>
                <div className="flex items-baseline justify-between gap-3 py-2.5">
                  <dt className="text-[var(--text-secondary)]">告警事件</dt>
                  <dd className="tnum font-medium text-[var(--text-primary)]">{alerts.length}</dd>
                </div>
                <div className="flex items-baseline justify-between gap-3 py-2.5">
                  <dt className="text-[var(--text-secondary)]">回放记录</dt>
                  <dd className="tnum font-medium text-[var(--text-primary)]">{replays.length}</dd>
                </div>
              </dl>
            </section>

            <section className={`${glassPanelSoftClass} ${glassPanelMotionClass} p-5`}>
              <div className="relative flex items-center justify-between gap-3">
                <h2 className="text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">鉴权资产</h2>
                <span className={`chip ${hasAdminAccess ? "chip-success" : "chip-neutral"}`}>
                  {hasAdminAccess ? "后台已连接" : "待接入"}
                </span>
              </div>
              <dl className="relative mt-3 divide-y divide-[var(--divider)] text-[length:var(--text-body)]">
                <div className="flex items-baseline justify-between gap-3 py-2.5">
                  <dt className="text-[var(--text-secondary)]">托管密钥总数</dt>
                  <dd className="tnum font-medium text-[var(--text-primary)]">{managedKeyStats.total}</dd>
                </div>
                <div className="flex items-baseline justify-between gap-3 py-2.5">
                  <dt className="text-[var(--text-secondary)]">生效中</dt>
                  <dd className="tnum font-medium text-[var(--tone-success-text)]">{managedKeyStats.active}</dd>
                </div>
                <div className="flex items-baseline justify-between gap-3 py-2.5">
                  <dt className="text-[var(--text-secondary)]">已停用</dt>
                  <dd className="tnum font-medium text-[var(--tone-danger-text)]">{managedKeyStats.paused}</dd>
                </div>
                <div className="flex items-baseline justify-between gap-3 py-2.5">
                  <dt className="text-[var(--text-secondary)]">已过期</dt>
                  <dd className="tnum font-medium text-[var(--tone-warning-text)]">{managedKeyStats.expired}</dd>
                </div>
              </dl>
              <button type="button" onClick={() => navigateTo("keys")} className={`${buttonClass("secondary")} relative mt-5 w-full`}>
                <KeyRound className="h-4 w-4" aria-hidden />
                打开密钥中心
              </button>
            </section>

            <section className={`${glassPanelSoftClass} ${glassPanelMotionClass} p-5`}>
              <div className="relative flex items-center justify-between">
                <h2 className="text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">运行状态</h2>
                <span
                  className={`chip ${
                    health.status === "online"
                      ? "chip-success"
                      : health.status === "offline"
                        ? "chip-danger"
                        : "chip-neutral"
                  }`}
                >
                  {health.status === "online" ? "Online" : health.status === "offline" ? "Offline" : health.status === "checking" ? "Checking" : "Unknown"}
                </span>
              </div>
              <dl className="relative mt-3 divide-y divide-[var(--divider)] text-[length:var(--text-body)]">
                <div className="flex items-baseline justify-between gap-3 py-2.5">
                  <dt className="text-[var(--text-secondary)]">启用策略</dt>
                  <dd className="tnum font-medium text-[var(--text-primary)]">
                    {enabledPolicies}/{policies.length}
                  </dd>
                </div>
                <div className="flex items-baseline justify-between gap-3 py-2.5">
                  <dt className="text-[var(--text-secondary)]">允许工具</dt>
                  <dd className="tnum font-medium text-[var(--text-primary)]">
                    {allowedTools}/{tools.length}
                  </dd>
                </div>
                <div className="flex items-center justify-between gap-3 py-2.5">
                  <dt className="text-[var(--text-secondary)]">自动刷新</dt>
                  <dd>
                    <Switch
                      label="切换自动刷新"
                      checked={settings.autoRefresh}
                      onChange={(value) => {
                        const next = { ...settings, autoRefresh: value };
                        setSettings(next);
                        writeStorage(STORAGE_KEYS.settings, sanitizeSettingsForStorage(next));
                      }}
                    />
                  </dd>
                </div>
              </dl>
              <button type="button" onClick={() => void checkHealth()} className={`${buttonClass("secondary")} relative mt-5 w-full`}>
                <Network className="h-4 w-4" aria-hidden />
                检测网关
              </button>
            </section>

            <section className={`${glassPanelSoftClass} ${glassPanelMotionClass} p-5`}>
              <h2 className="relative text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">快捷操作</h2>
              <div className="relative mt-4 grid gap-2">
                {[
                  { label: "运行网关测试", icon: Play, onClick: () => navigateTo("gateway"), variant: "primary" as const },
                  { label: "调整策略", icon: SlidersHorizontal, onClick: () => navigateTo("policies"), variant: "secondary" as const },
                  { label: "管理托管密钥", icon: KeyRound, onClick: () => navigateTo("keys"), variant: "secondary" as const },
                  { label: "生成验证样例", icon: Plus, onClick: seedLogs, variant: "secondary" as const },
                ].map((item) => (
                  <button key={item.label} type="button" onClick={item.onClick} className={`${buttonClass(item.variant)} justify-between`}>
                    <span className="inline-flex items-center gap-2">
                      <item.icon className="h-4 w-4" aria-hidden />
                      {item.label}
                    </span>
                    <ChevronRight className="h-4 w-4" aria-hidden />
                  </button>
                ))}
              </div>
            </section>
          </div>
        </section>
      </div>
    );
  }
}
