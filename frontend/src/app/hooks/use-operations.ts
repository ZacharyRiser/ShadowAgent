// 运营数据（operations）域：待审批 / 告警 / 回放 归仓（阶段 2）。
// 加载与审批/回放操作统一走本 hook；loadOperations 保留「部分失败不清空其他两项」
// 的原始容错语义（三个独立 fetch，仅 ok 的项写入 state），因此不走 apiGet。

import { useCallback, useState } from "react";
import type { AlertItem, ApprovalItem, AppSettings, AuthSession, ReplayItem, Toast } from "../types";
import type { GatewayResult } from "../gateway-types";
import { apiSend, buildHeaders } from "../api-client";

export function useOperations({
  apiBaseUrl,
  settings,
  authSession,
  hasAdminAccess,
  addToast,
  setGatewayResult,
}: {
  apiBaseUrl: string;
  settings: AppSettings;
  authSession: AuthSession | null;
  hasAdminAccess: boolean;
  addToast: (message: string, type?: Toast["type"]) => void;
  setGatewayResult: (next: GatewayResult | null) => void;
}) {
  const [approvals, setApprovals] = useState<ApprovalItem[]>([]);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [replays, setReplays] = useState<ReplayItem[]>([]);

  // 三个独立请求、各自容错：任何一项失败只影响自己，不拖垮另外两项。
  const loadOperations = useCallback(async () => {
    if (!hasAdminAccess) {
      setApprovals([]);
      setAlerts([]);
      setReplays([]);
      return;
    }

    try {
      const [approvalResponse, alertResponse, replayResponse] = await Promise.all([
        fetch(`${apiBaseUrl}/api/v1/approvals?status=pending`, {
          headers: buildHeaders(settings, "admin", false, authSession),
          cache: "no-store",
        }),
        fetch(`${apiBaseUrl}/api/v1/alerts`, {
          headers: buildHeaders(settings, "admin", false, authSession),
          cache: "no-store",
        }),
        fetch(`${apiBaseUrl}/api/v1/replays`, {
          headers: buildHeaders(settings, "admin", false, authSession),
          cache: "no-store",
        }),
      ]);

      const approvalData = (await approvalResponse.json().catch(() => ({}))) as { items?: ApprovalItem[] };
      const alertData = (await alertResponse.json().catch(() => ({}))) as { items?: AlertItem[] };
      const replayData = (await replayResponse.json().catch(() => ({}))) as { items?: ReplayItem[] };

      if (approvalResponse.ok) setApprovals(approvalData.items ?? []);
      if (alertResponse.ok) setAlerts(alertData.items ?? []);
      if (replayResponse.ok) setReplays(replayData.items ?? []);
    } catch {
      setApprovals([]);
      setAlerts([]);
      setReplays([]);
    }
    // 原实现 deps 不含 apiBaseUrl（存量告警），行为不变地原样保留。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authSession, hasAdminAccess, settings]);

  const reviewApproval = async (approvalId: number, status: "approved" | "rejected") => {
    if (!hasAdminAccess) {
      addToast("请先登录管理员账号或配置 Admin API Key", "error");
      return;
    }

    try {
      await apiSend(`${apiBaseUrl}/api/v1/approvals/${approvalId}/review`, "POST", {
        status,
        review_comment: status === "approved" ? "Approved from console" : "Rejected from console",
      }, {
        headers: buildHeaders(settings, "admin", true, authSession),
      });
      await loadOperations();
      addToast(status === "approved" ? "审批已通过" : "审批已拒绝", "success");
    } catch (error) {
      addToast(error instanceof Error ? error.message : "审批操作失败", "error");
    }
  };

  const replaySelectedRequest = async (requestId: string) => {
    if (!hasAdminAccess) {
      addToast("请先登录管理员账号或配置 Admin API Key", "error");
      return;
    }

    try {
      const data = await apiSend<{ item?: ReplayItem; detail?: unknown }>(
        `${apiBaseUrl}/api/v1/replays`,
        "POST",
        { request_id: requestId },
        { headers: buildHeaders(settings, "admin", true, authSession) }
      );
      await loadOperations();
      setGatewayResult({
        ok: data.item?.verdict === "allowed",
        title: "请求回放已完成",
        message: `回放结果：${data.item?.verdict === "allowed" ? "通过" : data.item?.verdict === "blocked" ? "拦截" : data.item?.verdict ?? "unknown"}`,
        detail: data.item,
      });
      addToast("请求回放已完成", "success");
    } catch (error) {
      addToast(error instanceof Error ? error.message : "请求回放失败", "error");
    }
  };

  return {
    approvals,
    alerts,
    replays,
    loadOperations,
    reviewApproval,
    replaySelectedRequest,
  };
}
