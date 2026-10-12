"use client";

/**
 * Security Dashboard (SOC mode) — full-screen real-time operations view.
 *
 * Data sources:
 * - Live intercepts over SSE (`GET /api/v1/events/stream`, fetch-based so
 *   Authorization headers work; automatic reconnection with backoff).
 * - Recent history on mount (`GET /api/v1/logs?limit=12`).
 * - Aggregate traffic counters (`GET /metrics`, 10s polling).
 *
 * The overlay is keyboard accessible: ESC exits. Exiting aborts the stream.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { AnimatedNumber } from "./animated-number";
import {
  Activity,
  AlertTriangle,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Timer,
  X,
  Zap,
} from "lucide-react";

type LiveEvent = {
  key: string;
  requestId: string;
  threatType: string;
  category: string;
  riskScore: number;
  layer: string;
  reason: string;
  ts: number;
};

type MetricsSummary = {
  totalRequests: number;
  blocked: number;
  latencySum: number;
  latencyCount: number;
};

type SecurityDashboardProps = {
  apiBase: string;
  buildAuthHeaders: () => Record<string, string>;
  onExit: () => void;
};

const MAX_EVENTS = 24;
const METRICS_POLL_MS = 10_000;

function riskLevel(score: number): "high" | "medium" | "low" {
  if (score >= 0.9) return "high";
  if (score >= 0.75) return "medium";
  return "low";
}

function formatClock(date: Date): string {
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function parseMetricsSummary(body: string): MetricsSummary {
  let totalRequests = 0;
  let blocked = 0;
  let latencySum = 0;
  let latencyCount = 0;

  for (const rawLine of body.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const spaceIndex = line.lastIndexOf(" ");
    if (spaceIndex === -1) continue;
    const value = Number.parseFloat(line.slice(spaceIndex + 1));
    if (!Number.isFinite(value)) continue;

    const series = line.slice(0, spaceIndex);
    const name = series.split("{")[0];
    if (name === "shadow_agent_http_requests_total") {
      totalRequests += value;
      if (series.includes('status="403"')) blocked += value;
    } else if (name === "shadow_agent_http_request_duration_seconds_sum") {
      latencySum += value;
    } else if (name === "shadow_agent_http_request_duration_seconds_count") {
      latencyCount += value;
    }
  }
  return { totalRequests, blocked, latencySum, latencyCount };
}

export default function SecurityDashboard({ apiBase, buildAuthHeaders, onExit }: SecurityDashboardProps) {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [connection, setConnection] = useState<"connecting" | "live" | "reconnecting">("connecting");
  const [clock, setClock] = useState(() => formatClock(new Date()));
  const [metrics, setMetrics] = useState<MetricsSummary | null>(null);
  const eventsRef = useRef<LiveEvent[]>([]);

  const pushEvent = useCallback((event: LiveEvent) => {
    // The same intercept arrives via /logs seeding AND SSE history replay;
    // deduplicate on requestId+threatType, keeping the newest copy.
    const dedupeKey = `${event.requestId}:${event.threatType}`;
    const withoutDuplicate = eventsRef.current.filter(
      (existing) => `${existing.requestId}:${existing.threatType}` !== dedupeKey
    );
    const next = [event, ...withoutDuplicate].slice(0, MAX_EVENTS);
    eventsRef.current = next;
    setEvents(next);
  }, []);

  // Seed with recent history so the wall is never empty on mount.
  useEffect(() => {
    let disposed = false;
    const timer = window.setTimeout(() => {
      void (async () => {
        try {
          const response = await fetch(`${apiBase.replace(/\/$/, "")}/api/v1/logs?limit=12`, {
            headers: buildAuthHeaders(),
            cache: "no-store",
          });
          if (!response.ok) return;
          const data = (await response.json().catch(() => ({}))) as {
            items?: Array<{
              request_id?: string;
              threat_type?: string;
              timestamp?: string;
              details?: Record<string, unknown>;
            }>;
          };
          if (disposed) return;
          const seeded: LiveEvent[] = (data.items ?? []).map((item, index) => ({
            key: `seed-${item.request_id ?? index}-${index}`,
            requestId: item.request_id ?? "unknown",
            threatType: item.threat_type ?? "Unknown",
            category: typeof item.details?.category === "string" ? item.details.category : "",
            riskScore: typeof item.details?.risk_score === "number" ? item.details.risk_score : 0,
            layer: typeof item.details?.layer === "string" ? item.details.layer : "",
            reason: typeof item.details?.reason === "string" ? item.details.reason : "",
            ts: item.timestamp ? new Date(item.timestamp).getTime() : Date.now(),
          }));
          if (seeded.length > 0) {
            const merged = [...seeded, ...eventsRef.current].slice(0, MAX_EVENTS);
            eventsRef.current = merged;
            setEvents(merged);
          }
        } catch {
          // History is best-effort; the live stream is the primary source.
        }
      })();
    }, 0);
    return () => {
      disposed = true;
      window.clearTimeout(timer);
    };
  }, [apiBase, buildAuthHeaders]);

  // Live SSE stream with reconnect + backoff.
  useEffect(() => {
    let disposed = false;
    let retryDelay = 2000;
    const controller = new AbortController();

    const handleFrame = (frame: string) => {
      const dataLine = frame
        .split("\n")
        .find((line) => line.startsWith("data:"));
      if (!dataLine) return;
      try {
        const payload = JSON.parse(dataLine.slice(5).trim()) as {
          type?: string;
          request_id?: string;
          threat_type?: string;
          category?: string;
          risk_score?: number;
          layer?: string;
          reason?: string;
          ts?: number;
        };
        if (payload.type !== "intercept") return;
        pushEvent({
          key: `${payload.request_id ?? "evt"}-${payload.ts ?? Date.now()}`,
          requestId: payload.request_id ?? "unknown",
          threatType: payload.threat_type ?? "Unknown",
          category: payload.category ?? "",
          riskScore: typeof payload.risk_score === "number" ? payload.risk_score : 0,
          layer: payload.layer ?? "",
          reason: payload.reason ?? "",
          ts: (payload.ts ?? Date.now()) * 1000,
        });
      } catch {
        // Malformed frame: skip.
      }
    };

    const connect = async () => {
      while (!disposed) {
        try {
          setConnection("connecting");
          const response = await fetch(`${apiBase.replace(/\/$/, "")}/api/v1/events/stream`, {
            headers: buildAuthHeaders(),
            signal: controller.signal,
            cache: "no-store",
          });
          if (!response.ok || !response.body) throw new Error(`HTTP ${response.status}`);

          setConnection("live");
          retryDelay = 2000;
          const reader = response.body.getReader();
          const decoder = new TextDecoder();
          let buffer = "";
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const frames = buffer.split("\n\n");
            buffer = frames.pop() ?? "";
            for (const frame of frames) handleFrame(frame);
          }
        } catch {
          // Fall through to retry below.
        }
        if (disposed || controller.signal.aborted) return;
        setConnection("reconnecting");
        await new Promise<void>((resolve) => {
          window.setTimeout(resolve, retryDelay);
        });
        retryDelay = Math.min(retryDelay * 2, 30_000);
      }
    };

    void connect();
    return () => {
      disposed = true;
      controller.abort();
    };
  }, [apiBase, buildAuthHeaders, pushEvent]);

  // Aggregate traffic counters.
  useEffect(() => {
    let disposed = false;
    const load = async () => {
      try {
        const response = await fetch(`${apiBase.replace(/\/$/, "")}/metrics`, {
          headers: buildAuthHeaders(),
          cache: "no-store",
        });
        if (!response.ok) return;
        if (disposed) return;
        setMetrics(parseMetricsSummary(await response.text()));
      } catch {
        // Metrics are supplemental.
      }
    };
    const timer = window.setTimeout(() => void load(), 0);
    const interval = window.setInterval(() => void load(), METRICS_POLL_MS);
    return () => {
      disposed = true;
      window.clearTimeout(timer);
      window.clearInterval(interval);
    };
  }, [apiBase, buildAuthHeaders]);

  // Wall clock.
  useEffect(() => {
    const interval = window.setInterval(() => {
      setClock(formatClock(new Date()));
    }, 1000);
    return () => window.clearInterval(interval);
  }, []);

  // ESC exits the dashboard.
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onExit();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onExit]);

  const threatDistribution = useMemo(() => {
    const counts = new Map<string, number>();
    for (const event of events) {
      counts.set(event.threatType, (counts.get(event.threatType) ?? 0) + 1);
    }
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [events]);

  const riskDistribution = useMemo(() => {
    let high = 0;
    let medium = 0;
    let low = 0;
    for (const event of events) {
      const level = riskLevel(event.riskScore);
      if (level === "high") high += 1;
      else if (level === "medium") medium += 1;
      else low += 1;
    }
    return { high, medium, low };
  }, [events]);

  const maxThreatCount = threatDistribution.length > 0 ? threatDistribution[0][1] : 1;
  const avgLatencyMs =
    metrics && metrics.latencyCount > 0 ? (metrics.latencySum / metrics.latencyCount) * 1000 : null;

  const connectionBadge =
    connection === "live"
      ? { label: "实时连接", dotClass: "bg-[var(--tone-success)]", textClass: "text-[var(--tone-success-text)]", borderClass: "border-[color-mix(in_oklab,var(--tone-success)_28%,transparent)] bg-[var(--tone-success-surface)]" }
      : connection === "reconnecting"
        ? { label: "重连中", dotClass: "bg-[var(--tone-warning)] animate-pulse", textClass: "text-[var(--tone-warning-text)]", borderClass: "border-[color-mix(in_oklab,var(--tone-warning)_28%,transparent)] bg-[var(--tone-warning-surface)]" }
        : { label: "连接中", dotClass: "bg-[var(--tone-info)] animate-pulse", textClass: "text-[var(--tone-info-text)]", borderClass: "border-[color-mix(in_oklab,var(--tone-info)_28%,transparent)] bg-[var(--tone-info-surface)]" };

  return (
    <div
      className="soc-shell fixed inset-0 z-[var(--z-modal)] overflow-hidden bg-[var(--background)] text-[var(--text-primary)]"
      role="dialog"
      aria-modal="true"
      aria-label="安全大屏"
    >
      {/* Grid backdrop —— 底纹色走 token（原先硬编码 rgba(45,212,191,.05)，
          浅色主题下会与纸白底撞成脏绿）。 */}
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.35]"
        style={{
          backgroundImage:
            "linear-gradient(color-mix(in oklab, var(--tone-accent) 6%, transparent) 1px, transparent 1px)," +
            " linear-gradient(90deg, color-mix(in oklab, var(--tone-accent) 6%, transparent) 1px, transparent 1px)",
          backgroundSize: "44px 44px",
        }}
        aria-hidden
      />
      {/* 环境光斑已移除：spatial-design —— 阴影/发光若明显可见就太强。
          原先两团 480px 的 blur-3xl 光斑是纯粹的 AI 味装饰。 */}
      {/* Scan line */}
      <motion.div
        className="pointer-events-none absolute inset-x-0 h-px bg-gradient-to-r from-transparent via-[color-mix(in_oklab,var(--tone-accent)_32%,transparent)] to-transparent"
        animate={{ top: ["0%", "100%", "0%"] }}
        transition={{ duration: 18, repeat: Infinity, ease: "linear" }}
        aria-hidden
      />

      <div className="relative flex h-full flex-col">
        {/* Header */}
        <header className="flex items-center justify-between gap-4 border-b border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] px-6 py-4">
          <div className="flex items-center gap-3">
            <span className="flex h-11 w-11 items-center justify-center rounded-[var(--radius-md)] border border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--tone-accent-surface)]">
              <ShieldCheck className="h-6 w-6 text-[var(--tone-accent-text)]" aria-hidden />
            </span>
            <div>
              <h1 className="text-[length:var(--text-subhead)] font-semibold tracking-wide text-[var(--text-primary)] sm:text-[length:var(--text-heading)]">
                SHADOW AGENT <span className="text-[var(--tone-accent-text)]">安全作战大屏</span>
              </h1>
              <p className="text-[length:var(--text-micro)] text-[var(--text-muted)]">Runtime Security Operations Center</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-[length:var(--text-micro)] font-medium ${connectionBadge.borderClass} ${connectionBadge.textClass}`}>
              <span className={`h-2 w-2 rounded-full ${connectionBadge.dotClass}`} aria-hidden />
              <Radio className="h-3.5 w-3.5" aria-hidden />
              {connectionBadge.label}
            </span>
            <span className="hidden font-mono text-2xl font-semibold tabular-nums text-[var(--tone-accent-text)] sm:block">{clock}</span>
            <button
              type="button"
              onClick={onExit}
              className="flex h-9 items-center gap-2 rounded-[var(--radius-md)] border border-[var(--panel-border)] bg-[var(--surface-raised)] px-3.5 text-[length:var(--text-body)] text-[var(--text-secondary)] transition-[color,background-color,border-color,box-shadow,transform,opacity] duration-[var(--dur-fast)] ease-[var(--ease-out-quart)] hover:border-[color-mix(in_oklab,var(--tone-danger)_28%,transparent)] hover:bg-[var(--tone-danger-surface)] hover:text-[var(--tone-danger-text)] focus:outline-none focus:ring-2 focus:ring-[var(--tone-accent)] active:scale-[0.98]"
            >
              <X className="h-4 w-4" aria-hidden />
              退出大屏 <kbd className="hidden rounded-lg bg-[var(--surface-raised)] px-1.5 py-0.5 text-[10px] text-[var(--text-secondary)] sm:inline">ESC</kbd>
            </button>
          </div>
        </header>

        {/* Body */}
        <div className="grid min-h-0 flex-1 gap-4 p-4 xl:grid-cols-[minmax(280px,1fr)_minmax(0,1.9fr)_minmax(280px,1fr)] xl:p-6">
          {/* Left column: KPIs + threat distribution */}
          <div className="flex min-h-0 flex-col gap-4 overflow-y-auto">
            <section className="grid grid-cols-2 gap-3">
              <div className="soc-card relative overflow-hidden rounded-[var(--radius-lg)] border border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--surface-raised)] p-4.5 backdrop-blur-md">
                <div className="text-[length:var(--text-micro)] text-[var(--text-muted)]">实时拦截</div>
                <motion.div key={`events-${events.length}`} initial={{ opacity: 0.4, y: 5 }} animate={{ opacity: 1, y: 0 }} className="mt-1 font-mono text-3xl font-bold tabular-nums text-[var(--tone-danger-text)]">
                  <AnimatedNumber value={events.length} durationMs={600} />
                </motion.div>
                <ShieldAlert className={`absolute right-3.5 top-3.5 h-4 w-4 text-[var(--tone-danger-text)]/60 ${events.length > 0 ? "pulse-alert" : ""}`} aria-hidden />
              </div>
              <div className="soc-card relative overflow-hidden rounded-[var(--radius-lg)] border border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--surface-raised)] p-4.5 backdrop-blur-md">
                <div className="text-[length:var(--text-micro)] text-[var(--text-muted)]">网关请求</div>
                <div className="mt-1 font-mono text-3xl font-bold tabular-nums text-[var(--tone-accent-text)]">
                  {metrics ? <AnimatedNumber value={metrics.totalRequests} format={(n) => n.toLocaleString("zh-CN")} /> : "—"}
                </div>
                <Activity className="absolute right-3.5 top-3.5 h-4 w-4 text-[var(--tone-accent-text)]/60" aria-hidden />
              </div>
              <div className="soc-card relative overflow-hidden rounded-[var(--radius-lg)] border border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--surface-raised)] p-4.5 backdrop-blur-md">
                <div className="text-[length:var(--text-micro)] text-[var(--text-muted)]">累计阻断 403</div>
                <div className="mt-1 font-mono text-3xl font-bold tabular-nums text-[var(--tone-warning-text)]">
                  {metrics ? <AnimatedNumber value={metrics.blocked} format={(n) => n.toLocaleString("zh-CN")} /> : "—"}
                </div>
                <Zap className="absolute right-3.5 top-3.5 h-4 w-4 text-[var(--tone-warning-text)]/60" aria-hidden />
              </div>
              <div className="soc-card relative overflow-hidden rounded-[var(--radius-lg)] border border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--surface-raised)] p-4.5 backdrop-blur-md">
                <div className="text-[length:var(--text-micro)] text-[var(--text-muted)]">平均延迟</div>
                <div className="mt-1 font-mono text-3xl font-bold tabular-nums text-[var(--tone-info-text)]">
                  {avgLatencyMs !== null ? <AnimatedNumber value={avgLatencyMs} format={(n) => `${Math.round(n)}ms`} /> : "—"}
                </div>
                <Timer className="absolute right-3.5 top-3.5 h-4 w-4 text-[var(--tone-info-text)]/60" aria-hidden />
              </div>
            </section>

            <section className="soc-card rounded-[var(--radius-lg)] border border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--surface-sunken)] p-4.5 backdrop-blur-md">
              <h2 className="text-[length:var(--text-body)] font-semibold text-[var(--text-primary)]">威胁类型分布</h2>
              <div className="mt-4 space-y-3">
                {threatDistribution.length === 0 && (
                  <p className="py-6 text-center text-[length:var(--text-micro)] text-[var(--text-muted)]">暂无拦截记录</p>
                )}
                {threatDistribution.map(([threat, count]) => (
                  <div key={threat} className="space-y-1.5">
                    <div className="flex items-center justify-between text-[length:var(--text-micro)]">
                      <span className="truncate text-[var(--text-secondary)]">{threat}</span>
                      <span className="ml-2 font-mono tabular-nums text-[var(--text-secondary)]">{count}</span>
                    </div>
                    <div className="h-1.5 overflow-hidden rounded-full bg-[var(--surface-raised)]">
                      <motion.div
                        className="h-full rounded-full bg-gradient-to-r from-[var(--tone-accent-surface)] to-[var(--tone-danger)]"
                        initial={{ width: 0 }}
                        animate={{ width: `${Math.max(4, (count / maxThreatCount) * 100)}%` }}
                        transition={{ duration: 0.5 }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </section>

            <section className="soc-card rounded-[var(--radius-lg)] border border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--surface-sunken)] p-4.5 backdrop-blur-md">
              <h2 className="text-[length:var(--text-body)] font-semibold text-[var(--text-primary)]">风险等级</h2>
              <div className="mt-4 grid grid-cols-3 gap-2.5 text-center">
                {[
                  { label: "高危", value: riskDistribution.high, className: "border-[color-mix(in_oklab,var(--tone-danger)_28%,transparent)] bg-[var(--tone-danger-surface)] text-[var(--tone-danger-text)]" },
                  { label: "中危", value: riskDistribution.medium, className: "border-[color-mix(in_oklab,var(--tone-warning)_28%,transparent)] bg-[var(--tone-warning-surface)] text-[var(--tone-warning-text)]" },
                  { label: "低危", value: riskDistribution.low, className: "border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--tone-accent-surface)] text-[var(--tone-accent-text)]" },
                ].map((item) => (
                  <div key={item.label} className={`rounded-[var(--radius-md)] border px-2 py-3 ${item.className}`}>
                    <div className="font-mono text-2xl font-bold tabular-nums">{item.value}</div>
                    <div className="mt-1 text-[length:var(--text-micro)] opacity-80">{item.label}</div>
                  </div>
                ))}
              </div>
            </section>
          </div>

          {/* Center column: live event stream */}
          <section className="soc-card flex min-h-0 flex-col rounded-[var(--radius-lg)] border border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--surface-sunken)] backdrop-blur-md">
            <div className="flex items-center justify-between border-b border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] px-4 py-3">
              <h2 className="text-[length:var(--text-body)] font-semibold text-[var(--text-primary)]">实时拦截事件流</h2>
              <span className="inline-flex items-center gap-1.5 text-[length:var(--text-micro)] text-[var(--text-muted)]">
                <span className={`h-1.5 w-1.5 rounded-full ${connection === "live" ? "bg-[var(--tone-success)]" : "bg-[var(--divider-strong)]"}`} aria-hidden />
                {connection === "live" ? "SSE 推送中" : "等待推送"}
              </span>
            </div>
            <div className="min-h-0 flex-1 space-y-2 overflow-y-auto p-3">
              <AnimatePresence initial={false}>
                {events.length === 0 && (
                  <div className="flex h-full items-center justify-center px-6 text-center">
                    <div>
                      <ShieldCheck className="mx-auto h-10 w-10 text-[var(--tone-accent-text)]/30" aria-hidden />
                      <p className="mt-3 text-[length:var(--text-body)] text-[var(--text-muted)]">暂无拦截事件</p>
                      <p className="mt-1 text-[length:var(--text-micro)] text-[var(--text-muted)]">
                        在「网关测试」发送恶意请求，或等待上游触发策略，事件将实时推送到此处
                      </p>
                    </div>
                  </div>
                )}
                {events.map((event) => {
                  const level = riskLevel(event.riskScore);
                  const levelStyle =
                    level === "high"
                      ? "border-[color-mix(in_oklab,var(--tone-danger)_28%,transparent)] bg-[color-mix(in_oklab,var(--tone-danger)_8%,transparent)]"
                      : level === "medium"
                        ? "border-[color-mix(in_oklab,var(--tone-warning)_28%,transparent)] bg-[color-mix(in_oklab,var(--tone-warning)_6%,transparent)]"
                        : "border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[color-mix(in_oklab,var(--tone-accent)_5%,transparent)]";
                  return (
                    <motion.article
                      key={event.key}
                      layout
                      initial={{ opacity: 0, x: -18, scale: 0.98 }}
                      animate={{ opacity: 1, x: 0, scale: 1 }}
                      exit={{ opacity: 0, x: 18 }}
                      transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
                      className={`rounded-[var(--radius-lg)] border px-3.5 py-3 transition-[color,background-color,border-color,box-shadow,transform,opacity] duration-[var(--dur-fast)] ${levelStyle}`}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div className="flex min-w-0 items-center gap-2">
                          <AlertTriangle
                            className={`h-4 w-4 shrink-0 ${level === "high" ? "text-[var(--tone-danger-text)]" : level === "medium" ? "text-[var(--tone-warning-text)]" : "text-[var(--tone-accent-text)]"}`}
                            aria-hidden
                          />
                          <span className="truncate text-[length:var(--text-body)] font-semibold text-[var(--text-primary)]">{event.threatType}</span>
                          <span className="shrink-0 rounded-full border border-[var(--panel-border)] px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide text-[var(--text-secondary)]">
                            {level}
                          </span>
                        </div>
                        <span className="shrink-0 font-mono text-[length:var(--text-micro)] tabular-nums text-[var(--text-muted)]">
                          {new Date(event.ts).toLocaleTimeString("zh-CN", { hour12: false })}
                        </span>
                      </div>
                      <div className="mt-1.5 flex items-center gap-2 text-[11px] text-[var(--text-muted)]">
                        <span className="truncate font-mono">req {event.requestId}</span>
                        <span className="shrink-0 rounded-full bg-[var(--surface-raised)] px-2 py-0.5 font-mono">{(event.riskScore * 100).toFixed(0)}%</span>
                        {event.layer && <span className="shrink-0 truncate">{event.layer}</span>}
                      </div>
                      {event.reason && (
                        <p className="mt-1.5 line-clamp-2 text-[length:var(--text-micro)] leading-5 text-[var(--text-secondary)]">{event.reason}</p>
                      )}
                    </motion.article>
                  );
                })}
              </AnimatePresence>
            </div>
          </section>

          {/* Right column: recent request ids + stream info */}
          <div className="flex min-h-0 flex-col gap-4 overflow-y-auto">
            <section className="soc-card rounded-[var(--radius-lg)] border border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--surface-sunken)] p-4.5 backdrop-blur-md">
              <h2 className="text-[length:var(--text-body)] font-semibold text-[var(--text-primary)]">最近拦截对象</h2>
              <div className="mt-3 space-y-1.5">
                {events.slice(0, 10).map((event) => (
                  <div key={`rid-${event.key}`} className="flex items-center justify-between gap-2 rounded-[var(--radius-md)] border border-[var(--panel-border)] bg-[var(--surface-sunken)] px-3 py-2 font-mono text-[11px] transition-colors hover:bg-[var(--surface-raised)]">
                    <span className="truncate text-[var(--text-secondary)]">{event.requestId}</span>
                    <span
                      className={`shrink-0 ${(riskLevel(event.riskScore)) === "high" ? "text-[var(--tone-danger-text)]" : "text-[var(--text-muted)]"}`}
                    >
                      {(event.riskScore * 100).toFixed(0)}
                    </span>
                  </div>
                ))}
                {events.length === 0 && <p className="py-4 text-center text-[length:var(--text-micro)] text-[var(--text-muted)]">暂无数据</p>}
              </div>
            </section>

            <section className="soc-card rounded-[var(--radius-lg)] border border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--surface-sunken)] p-4.5 text-[length:var(--text-micro)] leading-6 text-[var(--text-secondary)] backdrop-blur-md">
              <h2 className="text-[length:var(--text-body)] font-semibold text-[var(--text-primary)]">数据通道</h2>
              <dl className="mt-3 space-y-2.5">
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-[var(--text-muted)]">实时事件</dt>
                  <dd className="truncate font-mono text-[11px] text-[var(--tone-accent-text)]">GET /api/v1/events/stream</dd>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-[var(--text-muted)]">历史日志</dt>
                  <dd className="truncate font-mono text-[11px] text-[var(--tone-accent-text)]">GET /api/v1/logs</dd>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-[var(--text-muted)]">聚合指标</dt>
                  <dd className="truncate font-mono text-[11px] text-[var(--tone-accent-text)]">GET /metrics · 10s</dd>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-[var(--text-muted)]">网关地址</dt>
                  <dd className="ml-2 truncate font-mono text-[11px] text-[var(--text-secondary)]">{apiBase}</dd>
                </div>
              </dl>
              <p className="mt-4 border-t border-[var(--panel-border)] pt-3 text-[11px] leading-5 text-[var(--text-muted)]">
                事件来自策略引擎的实时判定，断线自动重连（最长 30s 退避）；持久记录以数据库审计日志为准。
              </p>
            </section>
          </div>
        </div>

        {/* Footer ticker */}
        <footer className="overflow-hidden border-t border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--surface-sunken)] py-2">
          <div className="flex whitespace-nowrap">
            <motion.div
              className="flex shrink-0 items-center gap-10 pr-10 font-mono text-[length:var(--text-micro)] text-[var(--text-muted)]"
              animate={{ x: ["0%", "-100%"] }}
              transition={{ duration: 40, repeat: Infinity, ease: "linear" }}
            >
              {(events.length > 0
                ? events.slice(0, 8).map((event) => `[${new Date(event.ts).toLocaleTimeString("zh-CN", { hour12: false })}] ${event.threatType} · risk ${(event.riskScore * 100).toFixed(0)}% · ${event.requestId}`)
                : ["Shadow Agent 安全运行中 · 实时监控所有经过网关的 LLM 请求", "等待策略引擎事件推送…"]
              ).map((text, index) => (
                <span key={index} className="flex items-center gap-2">
                  <span className="h-1 w-1 rounded-full bg-[var(--tone-accent-surface)]" aria-hidden />
                  {text}
                </span>
              ))}
            </motion.div>
            <motion.div
              className="flex shrink-0 items-center gap-10 pr-10 font-mono text-[length:var(--text-micro)] text-[var(--text-muted)]"
              animate={{ x: ["0%", "-100%"] }}
              transition={{ duration: 40, repeat: Infinity, ease: "linear" }}
              aria-hidden
            >
              {(events.length > 0
                ? events.slice(0, 8).map((event) => `[${new Date(event.ts).toLocaleTimeString("zh-CN", { hour12: false })}] ${event.threatType} · risk ${(event.riskScore * 100).toFixed(0)}% · ${event.requestId}`)
                : ["Shadow Agent 安全运行中 · 实时监控所有经过网关的 LLM 请求", "等待策略引擎事件推送…"]
              ).map((text, index) => (
                <span key={`dup-${index}`} className="flex items-center gap-2">
                  <span className="h-1 w-1 rounded-full bg-[var(--tone-accent-surface)]" />
                  {text}
                </span>
              ))}
            </motion.div>
          </div>
        </footer>
      </div>
    </div>
  );
}
