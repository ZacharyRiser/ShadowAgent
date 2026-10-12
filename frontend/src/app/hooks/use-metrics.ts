// 运行状态（metrics）域：状态 + 采集循环 + Prometheus 解析全部归仓（阶段 2）。
// 纯解析函数（parseMetricLabels / parsePrometheusText）无副作用，可直接被单测覆盖。

import { useCallback, useEffect, useState } from "react";
import type { AppSettings, AuthSession, MetricsHistoryPoint, MetricsRouteRow, ParsedMetrics, Toast, ViewKey } from "../types";
import { buildHeaders } from "../api-client";

const METRICS_HISTORY_LIMIT = 60;

function parseMetricLabels(raw: string): Record<string, string> {
  const labels: Record<string, string> = {};
  const labelPattern = /(\w+)="((?:[^"\\]|\\.)*)"/g;
  let match = labelPattern.exec(raw);
  while (match !== null) {
    labels[match[1]] = match[2].replace(/\\(.)/g, "$1");
    match = labelPattern.exec(raw);
  }
  return labels;
}

function parsePrometheusText(body: string): ParsedMetrics {
  const routes = new Map<string, MetricsRouteRow>();
  const retentionPurged: Record<string, number> = {};
  let totalRequests = 0;
  let blockedRequests = 0;
  let serverErrors = 0;
  let clientErrors = 0;
  let latencySum = 0;
  let latencyCount = 0;

  for (const rawLine of body.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const spaceIndex = line.lastIndexOf(" ");
    if (spaceIndex === -1) continue;

    const series = line.slice(0, spaceIndex);
    const value = Number.parseFloat(line.slice(spaceIndex + 1));
    if (!Number.isFinite(value)) continue;

    const braceIndex = series.indexOf("{");
    const metricName = braceIndex === -1 ? series : series.slice(0, braceIndex);
    const labels = braceIndex === -1 ? {} : parseMetricLabels(series.slice(braceIndex));

    if (metricName === "shadow_agent_http_requests_total") {
      const route = labels.route ?? "unknown";
      const status = labels.status ?? "";
      const row = routes.get(route) ?? { route, requests: 0, statusCodes: {}, latencySum: 0, latencyCount: 0 };
      row.requests += value;
      row.statusCodes[status] = (row.statusCodes[status] ?? 0) + value;
      routes.set(route, row);

      totalRequests += value;
      if (status === "403") blockedRequests += value;
      if (status.startsWith("5")) serverErrors += value;
      if (status.startsWith("4")) clientErrors += value;
    } else if (metricName === "shadow_agent_http_request_duration_seconds_sum") {
      const route = labels.route ?? "unknown";
      const row = routes.get(route) ?? { route, requests: 0, statusCodes: {}, latencySum: 0, latencyCount: 0 };
      row.latencySum += value;
      routes.set(route, row);
      latencySum += value;
    } else if (metricName === "shadow_agent_http_request_duration_seconds_count") {
      const route = labels.route ?? "unknown";
      const row = routes.get(route) ?? { route, requests: 0, statusCodes: {}, latencySum: 0, latencyCount: 0 };
      row.latencyCount += value;
      routes.set(route, row);
      latencyCount += value;
    } else if (metricName === "shadow_agent_retention_purged_rows_total") {
      retentionPurged[labels.table ?? "unknown"] = value;
    }
  }

  return {
    totalRequests,
    blockedRequests,
    serverErrors,
    clientErrors,
    latencySum,
    latencyCount,
    routes: Array.from(routes.values()).sort((a, b) => b.requests - a.requests),
    retentionPurged,
  };
}

export function useMetrics({
  apiBaseUrl,
  settings,
  authSession,
  addToast,
  effectiveView,
  hasAdminAccess,
}: {
  apiBaseUrl: string;
  settings: AppSettings;
  authSession: AuthSession | null;
  addToast: (message: string, type?: Toast["type"]) => void;
  effectiveView: ViewKey;
  hasAdminAccess: boolean;
}) {
  const [metricsSnapshot, setMetricsSnapshot] = useState<ParsedMetrics | null>(null);
  const [metricsHistory, setMetricsHistory] = useState<MetricsHistoryPoint[]>([]);
  const [metricsError, setMetricsError] = useState("");
  const [metricsLoading, setMetricsLoading] = useState(false);
  const [metricsAutoRefresh, setMetricsAutoRefresh] = useState(true);

  const loadMetrics = useCallback(
    async (options?: { silent?: boolean }) => {
      const silent = options?.silent ?? true;
      if (!silent) setMetricsLoading(true);

      const controller = new AbortController();
      const timer = window.setTimeout(() => controller.abort(), 7000);

      try {
        const response = await fetch(`${apiBaseUrl}/metrics`, {
          headers: buildHeaders(settings, "admin", false, authSession),
          signal: controller.signal,
          cache: "no-store",
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const parsed = parsePrometheusText(await response.text());
        setMetricsSnapshot(parsed);
        setMetricsError("");
        setMetricsHistory((prev) => [
          ...prev.slice(-(METRICS_HISTORY_LIMIT - 1)),
          {
            ts: Date.now(),
            totalRequests: parsed.totalRequests,
            blockedRequests: parsed.blockedRequests,
            serverErrors: parsed.serverErrors,
            latencySum: parsed.latencySum,
            latencyCount: parsed.latencyCount,
          },
        ]);
        if (!silent) addToast("运行状态已刷新", "success");
      } catch (error) {
        const message =
          error instanceof Error && error.name === "AbortError"
            ? "请求超时"
            : error instanceof Error
              ? error.message
              : "无法连接指标接口";
        setMetricsError(message);
        if (!silent) addToast(`运行状态刷新失败：${message}`, "error");
      } finally {
        window.clearTimeout(timer);
        if (!silent) setMetricsLoading(false);
      }
    },
    [addToast, apiBaseUrl, authSession, settings]
  );

  useEffect(() => {
    if (effectiveView !== "metrics" || !hasAdminAccess || !metricsAutoRefresh) return;

    const tick = () => {
      void loadMetrics({ silent: true });
    };
    // Defer the first sample out of the effect body to avoid cascading renders.
    const initialTimer = window.setTimeout(tick, 0);
    const timer = window.setInterval(tick, 5000);
    return () => {
      window.clearTimeout(initialTimer);
      window.clearInterval(timer);
    };
  }, [effectiveView, hasAdminAccess, loadMetrics, metricsAutoRefresh]);

  return {
    metricsSnapshot,
    metricsHistory,
    metricsError,
    metricsLoading,
    metricsAutoRefresh,
    setMetricsAutoRefresh,
    loadMetrics,
  };
}
