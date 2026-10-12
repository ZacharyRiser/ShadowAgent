// 拦截日志（logs）域：数据状态 + 后端加载 + 本地持久化/合并归仓（阶段 2）。
// seedLogs / appendLocalDecisionLog / 筛选器仍留在 page（与演示流程、视图筛选强耦合），
// 通过本 hook 返回的 setLogs / mergeLogs / persistLocalLogs 复用同一份数据面。

import { useCallback, useState } from "react";
import type { AppSettings, AuthSession, InterceptLog, Toast } from "../types";
import { apiGet, buildHeaders, detailText } from "../api-client";
import { readStorage, STORAGE_KEYS, writeStorage } from "../app-meta";

export function useLogs({
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
  const [logs, setLogs] = useState<InterceptLog[]>([]);
  const [logsLoading, setLogsLoading] = useState(false);
  const [logsError, setLogsError] = useState("");

  const persistLocalLogs = useCallback((next: InterceptLog[]) => {
    const localOnly = next.filter((log) => log.id < 0).slice(0, 80);
    writeStorage(STORAGE_KEYS.localLogs, localOnly);
  }, []);

  const mergeLogs = useCallback((remote: InterceptLog[], local: InterceptLog[]) => {
    const seen = new Set<string>();
    return [...local, ...remote]
      .filter((log) => {
        const key = detailText(log.details.request_id) || `${log.id}-${log.timestamp}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      })
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, []);

  const loadLogs = useCallback(async () => {
    const localLogs = readStorage<InterceptLog[]>(STORAGE_KEYS.localLogs, []);

    if (!hasAdminAccess) {
      setLogs(localLogs);
      setLogsError("未登录管理员账号且未配置 Admin API Key，当前仅显示本地验证日志。");
      addToast("当前显示本地日志，未请求后端", "info");
      return;
    }

    setLogsLoading(true);
    setLogsError("");
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 7000);

    try {
      const data = await apiGet<{ items?: InterceptLog[] }>(`${apiBaseUrl}/api/v1/logs?limit=80`, {
        headers: buildHeaders(settings, "admin", false, authSession),
        signal: controller.signal,
      });
      setLogs(mergeLogs(data.items ?? [], localLogs));
      addToast("日志已刷新", "success");
    } catch (error) {
      const message =
        error instanceof Error && error.name === "AbortError"
          ? "请求超时"
          : error instanceof Error
            ? error.message
            : "无法连接日志接口";
      setLogsError(message);
      setLogs(localLogs);
      addToast(`日志刷新失败：${message}`, "error");
    } finally {
      window.clearTimeout(timer);
      setLogsLoading(false);
    }
  }, [addToast, apiBaseUrl, authSession, hasAdminAccess, mergeLogs, settings]);

  return {
    logs,
    setLogs,
    logsLoading,
    logsError,
    loadLogs,
    mergeLogs,
    persistLocalLogs,
  };
}
