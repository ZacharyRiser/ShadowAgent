// 健康探测（health）域：健康状态 + checkHealth 归仓（阶段 2 收尾档）。
// checkHealth 的 5s 超时中止与 AbortError 文案分支逐字保留；
// deps 由原 [addToast, settings.apiBase] 收敛为 [addToast, apiBaseUrl] ——
// apiBaseUrl 即 (settings.apiBase || DEFAULT_API_BASE) 的派生值，二者同步变化，行为等价。

import { useCallback, useState } from "react";
import type { HealthState, Toast } from "../types";
import { detailText } from "../api-client";

export function useHealth({
  apiBaseUrl,
  addToast,
}: {
  apiBaseUrl: string;
  addToast: (message: string, type?: Toast["type"]) => void;
}) {
  const [health, setHealth] = useState<HealthState>({ status: "unknown", message: "尚未检测" });

  const checkHealth = useCallback(async (options?: { silent?: boolean }) => {
    const silent = options?.silent === true;
    setHealth({ status: "checking", message: "检测中" });
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 5000);

    try {
      const response = await fetch(`${apiBaseUrl}/health`, {
        signal: controller.signal,
        cache: "no-store",
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = (await response.json()) as Record<string, unknown>;
      const serviceLabel = detailText(data.service) || "online";
      const proxyMode = typeof data.proxy_mode === "string" ? data.proxy_mode : "";
      setHealth({
        status: "online",
        message: proxyMode ? `${serviceLabel} / ${proxyMode}` : serviceLabel,
      });
      if (!silent) addToast("网关连接正常", "success");
    } catch (error) {
      const message =
        error instanceof Error && error.name === "AbortError"
          ? "连接超时"
          : error instanceof Error
            ? error.message
            : "连接失败";
      setHealth({ status: "offline", message });
      // silent（挂载自动探测）只更新侧栏状态点，不弹 toast —— 状态卡本身已用红点表达离线，
      // 自动探测再弹「连接失败」就是把被动感知变成打扰。
      if (!silent) addToast(`网关连接失败：${message}`, "error");
    } finally {
      window.clearTimeout(timer);
    }
  }, [addToast, apiBaseUrl]);

  return { health, checkHealth };
}
