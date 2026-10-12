"use client";

// 指标视图：前端单体拆解阶段 1，JSX 自 page.tsx renderMetrics 逐字搬出（AST 定位，零手抄）。
// 状态与副作用仍归 page.tsx 所有（阶段 2 再归仓）；本组件纯展示 + 回调上抛。

import type { Dispatch, SetStateAction } from "react";
import { Activity, AlertTriangle, Database, Gauge, Network, RefreshCcw, Shield, ShieldCheck, Sparkles } from "lucide-react";
import { PanelGlow, Sparkline, ledgerRowClass } from "../components/page-widgets";
import { buttonClass, glassPanelClass, glassPanelSoftClass } from "../components/ui-kit";
import { formatMetricsCount, formatMetricsLatency } from "../app-meta";
import type { HealthState, MetricsHistoryPoint, ParsedMetrics } from "../types";

export function MetricsView({
  hasAdminAccess,
  health,
  loadMetrics,
  metricsAutoRefresh,
  metricsError,
  metricsHistory,
  metricsLoading,
  metricsSnapshot,
  setMetricsAutoRefresh,
}: {
  hasAdminAccess: boolean;
  health: HealthState;
  loadMetrics: (options?: { silent?: boolean }) => Promise<void>;
  metricsAutoRefresh: boolean;
  metricsError: string;
  metricsHistory: MetricsHistoryPoint[];
  metricsLoading: boolean;
  metricsSnapshot: ParsedMetrics | null;
  setMetricsAutoRefresh: Dispatch<SetStateAction<boolean>>;
}) {
{
    if (!hasAdminAccess) {
      return (
        <section className={`${glassPanelClass} relative overflow-hidden p-6`}>
          <PanelGlow />
          <div className="relative flex items-start gap-3 text-[length:var(--text-body)] leading-6 text-[var(--text-secondary)]">
            <Shield className="mt-0.5 h-5 w-5 shrink-0 text-[var(--tone-warning-text)]" aria-hidden />
            <span>
              运行状态页需要管理员权限。请使用管理员账号登录，或在「设置」中配置 Admin API Key 后重试。
            </span>
          </div>
        </section>
      );
    }

    const qpsSeries: number[] = [];
    const latencySeries: number[] = [];
    for (let index = 1; index < metricsHistory.length; index += 1) {
      const previous = metricsHistory[index - 1];
      const current = metricsHistory[index];
      const deltaSeconds = (current.ts - previous.ts) / 1000;
      if (deltaSeconds <= 0) continue;
      qpsSeries.push(Math.max(0, (current.totalRequests - previous.totalRequests) / deltaSeconds));
      const previousAvg = previous.latencyCount > 0 ? previous.latencySum / previous.latencyCount : 0;
      const currentAvg = current.latencyCount > 0 ? current.latencySum / current.latencyCount : 0;
      latencySeries.push(((previousAvg + currentAvg) / 2) * 1000);
    }

    const currentQps = qpsSeries.length > 0 ? qpsSeries[qpsSeries.length - 1] : 0;
    const avgLatency =
      metricsSnapshot && metricsSnapshot.latencyCount > 0
        ? (metricsSnapshot.latencySum / metricsSnapshot.latencyCount) * 1000
        : null;

    const statusGroups = new Map<string, number>();
    if (metricsSnapshot) {
      for (const route of metricsSnapshot.routes) {
        for (const [status, count] of Object.entries(route.statusCodes)) {
          statusGroups.set(status, (statusGroups.get(status) ?? 0) + count);
        }
      }
    }
    const statusItems = Array.from(statusGroups.entries()).sort((a, b) => a[0].localeCompare(b[0]));
    const statusTotal = statusItems.reduce((sum, [, count]) => sum + count, 0);

    /* 状态码 → 语义 chip。原先手写 emerald/rose/amber/red 调色板在浅色主题下
       部分组合对比度不达标；语义 token 两主题都安全（见 globals.css 的 chip-*）。 */
    const statusChipClass = (status: string) => {
      if (status.startsWith("2")) return "chip-success";
      if (status === "403") return "chip-danger";
      if (status.startsWith("4")) return "chip-warning";
      if (status.startsWith("5")) return "chip-danger";
      return "chip-neutral";
    };
    /* 分布条填充色：需要实心而非 chip 的浅底，用 --tone-* 实心色。 */
    const statusBarClass = (status: string) => {
      if (status.startsWith("2")) return "bg-[var(--tone-success)]";
      if (status === "403" || status.startsWith("5")) return "bg-[var(--tone-danger)]";
      if (status.startsWith("4")) return "bg-[var(--tone-warning)]";
      return "bg-[var(--divider-strong)]";
    };

    const retentionEntries = metricsSnapshot
      ? Object.entries(metricsSnapshot.retentionPurged).filter(([, count]) => count > 0)
      : [];

    const statCards = [
      {
        label: "累计请求",
        value: metricsSnapshot ? formatMetricsCount(metricsSnapshot.totalRequests) : "—",
        icon: Activity,
        tone: "text-[var(--tone-accent-text)]",
        hint: metricsSnapshot ? `${metricsSnapshot.routes.length} 个路由` : "尚未采集",
      },
      {
        label: "安全阻断 (403)",
        value: metricsSnapshot ? formatMetricsCount(metricsSnapshot.blockedRequests) : "—",
        icon: ShieldCheck,
        tone: metricsSnapshot && metricsSnapshot.blockedRequests > 0 ? "text-[var(--tone-danger-text)]" : "text-[var(--tone-success-text)]",
        hint: "被策略引擎拦截的请求",
      },
      {
        label: "服务端错误 (5xx)",
        value: metricsSnapshot ? formatMetricsCount(metricsSnapshot.serverErrors) : "—",
        icon: AlertTriangle,
        tone: metricsSnapshot && metricsSnapshot.serverErrors > 0 ? "text-[var(--tone-danger-text)]" : "text-[var(--text-primary)]",
        hint: metricsSnapshot && metricsSnapshot.serverErrors > 0 ? "需要立即关注" : "运行正常",
      },
      {
        label: "平均响应延迟",
        value: avgLatency !== null ? formatMetricsLatency(avgLatency / 1000) : "—",
        icon: Gauge,
        tone: "text-[var(--tone-info-text)]",
        hint: metricsSnapshot ? `${formatMetricsCount(metricsSnapshot.latencyCount)} 次采样` : "尚未采集",
      },
    ];

    return (
      <div className="space-y-5">
        <section className={`${glassPanelClass} relative overflow-hidden p-6`}>
          <PanelGlow />
          <div className="relative flex flex-wrap items-start justify-between gap-4">
            <div className="space-y-3">
              <div className="inline-flex items-center gap-2 rounded-full border border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--tone-accent-surface)] px-3 py-1 text-[length:var(--text-micro)] font-medium text-[var(--tone-accent-text)]">
                <Sparkles className="h-3.5 w-3.5" aria-hidden />
                实时遥测 · 每 5 秒自动采集
              </div>
              <h2 className="text-[length:var(--text-title)] font-semibold leading-tight text-[var(--text-primary)] sm:text-[length:var(--text-title)]">网关运行状态</h2>
              <p className="max-w-2xl text-[length:var(--text-body)] leading-7 text-[var(--text-secondary)]">
                数据来自后端 <span className="font-mono text-[var(--tone-accent-text)]">/metrics</span>（Prometheus 格式）：请求计数、延迟直方图与保留清理计数。切换到其他页面时自动停止采集。
              </p>
              <div className="flex flex-wrap items-center gap-2 text-[length:var(--text-micro)]">
                <span
                  className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 ${
                    health.status === "online"
                      ? "border-[color-mix(in_oklab,var(--tone-success)_28%,transparent)] bg-[var(--tone-success-surface)] text-[var(--tone-success-text)]"
                      : "border-[color-mix(in_oklab,var(--tone-warning)_28%,transparent)] bg-[var(--tone-warning-surface)] text-[var(--tone-warning-text)]"
                  }`}
                >
                  <Network className="h-3 w-3" aria-hidden />
                  {health.status === "online" ? `网关在线${health.message ? ` · ${health.message}` : ""}` : "网关未检测"}
                </span>
                {metricsSnapshot && (
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--panel-border)] bg-[var(--surface-raised)] px-2.5 py-1 text-[var(--text-secondary)]">
                    <Database className="h-3 w-3" aria-hidden />
                    数据库保留清理已移除 {formatMetricsCount(Object.values(metricsSnapshot.retentionPurged).reduce((sum, count) => sum + count, 0))} 行
                  </span>
                )}
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => setMetricsAutoRefresh((current) => !current)}
                className={`${buttonClass(metricsAutoRefresh ? "primary" : "secondary")} relative`}
              >
                <Activity className="h-4 w-4" aria-hidden />
                {metricsAutoRefresh ? "自动采集中" : "自动刷新已暂停"}
              </button>
              <button
                type="button"
                onClick={() => void loadMetrics({ silent: false })}
                disabled={metricsLoading}
                className={`${buttonClass("secondary")} relative`}
              >
                <RefreshCcw className={`h-4 w-4 ${metricsLoading ? "animate-spin" : ""}`} aria-hidden />
                {metricsLoading ? "采集中…" : "立即刷新"}
              </button>
            </div>
          </div>
        </section>

        {metricsError && !metricsSnapshot && (
          <section className={`${glassPanelClass} relative overflow-hidden p-5`}>
            <div className="relative flex items-start gap-3 text-[length:var(--text-body)] leading-6 text-[var(--tone-danger-text)]">
              <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" aria-hidden />
              <span>指标拉取失败：{metricsError}。请确认后端已启动、管理员凭证有效，然后点击「立即刷新」。</span>
            </div>
          </section>
        )}

        {/* 四张同构指标卡 → 一条被分隔线切开的指标带。
            原先每张都带 PanelGlow 光斑 + hover 上浮，四个光斑同屏是纯噪声。 */}
        <div className="grid gap-px overflow-hidden rounded-[var(--radius-lg)] border border-[var(--panel-border)] bg-[var(--divider)] sm:grid-cols-2 xl:grid-cols-4">
          {statCards.map((card) => (
            <div key={card.label} className="bg-[var(--panel-bg)] p-5">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-[length:var(--text-micro)] font-medium uppercase tracking-[0.08em] text-[var(--text-muted)]">{card.label}</div>
                  <div className={`tnum mt-2 font-mono text-[length:var(--text-title)] font-semibold ${card.tone}`}>{card.value}</div>
                  <div className="mt-1.5 text-[length:var(--text-micro)] text-[var(--text-muted)]">{card.hint}</div>
                </div>
                <card.icon className={`h-4 w-4 shrink-0 ${card.tone}`} aria-hidden />
              </div>
            </div>
          ))}
        </div>

        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.6fr)_minmax(300px,1fr)]">
          <section className={`${glassPanelClass} relative overflow-hidden p-5`}>
            <div className="relative flex items-start justify-between gap-3">
              <div>
                <h3 className="text-[length:var(--text-body)] font-semibold text-[var(--text-primary)]">请求吞吐趋势</h3>
                <p className="mt-1 text-[length:var(--text-micro)] text-[var(--text-muted)]">
                  相邻两次采集的计数差分，窗口约 {metricsHistory.length * 5}s
                  {metricsHistory.length > 0 &&
                    ` · 始于 ${new Date(metricsHistory[0].ts).toLocaleTimeString("zh-CN", { hour12: false })}`}
                </p>
              </div>
              <div className="text-right">
                <div className="font-mono text-[length:var(--text-title)] font-semibold text-[var(--tone-accent-text)]">{currentQps.toFixed(1)}</div>
                <div className="text-[length:var(--text-micro)] text-[var(--text-muted)]">req/s</div>
              </div>
            </div>
            <div className="relative mt-4 h-36 rounded-[var(--radius-md)] border border-[var(--panel-border)] bg-[var(--surface-sunken)] p-2.5">
              <Sparkline points={qpsSeries} strokeWidth={2} />
            </div>
            <div className="relative mt-4 grid grid-cols-2 gap-3 text-[length:var(--text-micro)] text-[var(--text-muted)] sm:grid-cols-4">
              <div>
                <div className="text-[var(--text-secondary)]">窗口峰值</div>
                <div className="mt-1 font-mono text-[length:var(--text-body)] text-[var(--text-primary)]">
                  {qpsSeries.length > 0 ? `${Math.max(...qpsSeries).toFixed(1)} req/s` : "—"}
                </div>
              </div>
              <div>
                <div className="text-[var(--text-secondary)]">窗口均值</div>
                <div className="mt-1 font-mono text-[length:var(--text-body)] text-[var(--text-primary)]">
                  {qpsSeries.length > 0 ? `${(qpsSeries.reduce((sum, value) => sum + value, 0) / qpsSeries.length).toFixed(1)} req/s` : "—"}
                </div>
              </div>
              <div>
                <div className="text-[var(--text-secondary)]">延迟趋势</div>
                <div className="mt-1 font-mono text-[length:var(--text-body)] text-[var(--text-primary)]">
                  {latencySeries.length > 0 ? formatMetricsLatency(latencySeries[latencySeries.length - 1] / 1000) : "—"}
                </div>
              </div>
              <div>
                <div className="text-[var(--text-secondary)]">采集点数</div>
                <div className="mt-1 font-mono text-[length:var(--text-body)] text-[var(--text-primary)]">{metricsHistory.length}</div>
              </div>
            </div>
          </section>

          <section className={`${glassPanelClass} relative overflow-hidden p-5`}>
            <h3 className="relative text-[length:var(--text-body)] font-semibold text-[var(--text-primary)]">状态码分布</h3>
            <p className="relative mt-1 text-[length:var(--text-micro)] text-[var(--text-muted)]">自后端启动以来的全部请求</p>
            <div className="relative mt-4 space-y-2.5">
              {statusItems.length === 0 && (
                <div className="rounded-[var(--radius-md)] border border-[var(--panel-border)] bg-[var(--surface-sunken)] px-3 py-6 text-center text-[length:var(--text-body)] text-[var(--text-muted)]">
                  暂无请求数据，等待下一次采集
                </div>
              )}
              {statusItems.map(([status, count]) => (
                <div key={status} className="space-y-1">
                  <div className="flex items-center justify-between text-[length:var(--text-micro)]">
                    <span className={`chip font-mono ${statusChipClass(status)}`}>{status}</span>
                    <span className="font-mono text-[var(--text-secondary)]">
                      {formatMetricsCount(count)}
                      {statusTotal > 0 && <span className="ml-1.5 text-[var(--text-muted)]">{((count / statusTotal) * 100).toFixed(1)}%</span>}
                    </span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-[var(--surface-sunken)]">
                    <div
                      className={`h-full rounded-full ${statusBarClass(status)}`}
                      style={{ width: `${statusTotal > 0 ? Math.max(2, (count / statusTotal) * 100) : 0}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </section>
        </div>

        <section className={`${glassPanelClass} relative overflow-hidden p-5`}>
          <div className="relative flex items-start justify-between gap-3">
            <div>
              <h3 className="text-[length:var(--text-body)] font-semibold text-[var(--text-primary)]">路由明细</h3>
              <p className="mt-1 text-[length:var(--text-micro)] text-[var(--text-muted)]">按请求量排序 · 平均延迟来自延迟直方图 sum/count</p>
            </div>
          </div>
          <div className="relative mt-4 overflow-x-auto">
            <div className="min-w-[640px]">
              <div className="grid grid-cols-[minmax(0,1.5fr)_90px_110px_minmax(120px,1fr)] gap-3 border-b border-[var(--panel-border)] px-3 py-2 text-[length:var(--text-micro)] font-medium uppercase tracking-[0.08em] text-[var(--text-muted)]">
                <span>路由</span>
                <span className="text-right">请求数</span>
                <span className="text-right">平均延迟</span>
                <span>状态码</span>
              </div>
              {metricsSnapshot && metricsSnapshot.routes.length > 0 ? (
                metricsSnapshot.routes.map((route) => {
                  const routeAvg = route.latencyCount > 0 ? route.latencySum / route.latencyCount : null;
                  const maxRequests = metricsSnapshot.routes[0]?.requests ?? 1;
                  return (
                    <div
                      key={route.route}
                      className={`grid grid-cols-[minmax(0,1.5fr)_90px_110px_minmax(120px,1fr)] items-center gap-3 px-3 py-2.5 ${ledgerRowClass}`}
                    >
                      <div className="min-w-0">
                        <div className="truncate font-mono text-[length:var(--text-body)] text-[var(--text-primary)]">{route.route}</div>
                        {/* 请求量条：h-1 的细线即可，不必包一层容器盒 */}
                        <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-[var(--surface-sunken)]">
                          <div className="h-full rounded-full bg-[var(--accent-solid)]" style={{ width: `${Math.max(2, (route.requests / Math.max(1, maxRequests)) * 100)}%` }} />
                        </div>
                      </div>
                      <span className="tnum text-right font-mono text-[length:var(--text-body)] text-[var(--text-primary)]">{formatMetricsCount(route.requests)}</span>
                      <span className="tnum text-right font-mono text-[length:var(--text-body)] text-[var(--text-primary)]">
                        {routeAvg !== null ? formatMetricsLatency(routeAvg) : "—"}
                      </span>
                      <div className="flex flex-wrap justify-end gap-1.5">
                        {Object.entries(route.statusCodes)
                          .sort((a, b) => a[0].localeCompare(b[0]))
                          .map(([status, count]) => (
                            <span key={status} className={`chip font-mono ${statusChipClass(status)}`}>
                              {status}
                              <span className="opacity-75">{formatMetricsCount(count)}</span>
                            </span>
                          ))}
                      </div>
                    </div>
                  );
                })
              ) : (
                <p className="border-b border-[var(--divider)] px-3 py-8 text-center text-[length:var(--text-body)] text-[var(--text-muted)]">
                  暂无路由数据。切换到「网关测试」发送几次请求，或等待自动采集。
                </p>
              )}
            </div>
          </div>
        </section>

        {retentionEntries.length > 0 && (
          <section className={`${glassPanelClass} relative overflow-hidden p-5`}>
            <div className="relative flex items-center gap-2 text-[length:var(--text-body)] font-semibold text-[var(--text-primary)]">
              <Database className="h-4 w-4 text-[var(--tone-accent-text)]" aria-hidden />
              日志保留清理记录
            </div>
            <p className="relative mt-1 text-[length:var(--text-micro)] text-[var(--text-muted)]">
              满足 GDPR 数据最小化：过期的拦截/审计/告警/重放日志会被周期性删除。
            </p>
            <div className="relative mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              {retentionEntries.map(([table, count]) => (
                <div key={table} className={`${glassPanelSoftClass} flex items-center justify-between px-3 py-2.5`}>
                  <span className="font-mono text-[length:var(--text-body)] text-[var(--text-secondary)]">{table}</span>
                  <span className="font-mono text-[length:var(--text-body)] font-semibold text-[var(--tone-accent-text)]">-{formatMetricsCount(count)} 行</span>
                </div>
              ))}
            </div>
          </section>
        )}
      </div>
    );
  }
}
