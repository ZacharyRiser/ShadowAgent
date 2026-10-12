"use client";

// 拦截日志视图：前端单体拆解阶段 1，JSX 自 page.tsx renderLogs 逐字搬出（AST 定位，零手抄）。
// 状态与副作用仍归 page.tsx 所有（阶段 2 再归仓）；本组件纯展示 + 回调上抛。

import type { Dispatch, SetStateAction } from "react";
import { Clipboard, Database, Filter, Plus, RefreshCcw, Search, Trash2 } from "lucide-react";
import { AnimatedInterceptLogList, LogListSkeleton } from "../components/intercept-log-card";
import { AnimatedNumber } from "../components/animated-number";
import { GlassSelect, type GlassSelectOption } from "../components/glass-select";
import { EmptyState, buttonClass, glassPanelClass, inputBase } from "../components/ui-kit";
import type { InterceptLog } from "../types";

export function LogsView({
  clearLocalLogs,
  copyText,
  downloadLogs,
  filteredLogs,
  loadLogs,
  logs,
  logsError,
  logsLoading,
  riskFilter,
  riskFilterOptions,
  search,
  seedLogs,
  setRiskFilter,
  setSearch,
  setSelectedLog,
  setThreatFilter,
  threatFilter,
  threatFilterOptions,
}: {
  clearLocalLogs: () => void;
  copyText: (value: string, successMessage: string) => Promise<void>;
  downloadLogs: () => void;
  filteredLogs: InterceptLog[];
  loadLogs: () => Promise<void>;
  logs: InterceptLog[];
  logsError: string;
  logsLoading: boolean;
  riskFilter: "all" | "high" | "medium" | "low";
  riskFilterOptions: GlassSelectOption[];
  search: string;
  seedLogs: () => void;
  setRiskFilter: Dispatch<SetStateAction<"all" | "high" | "medium" | "low">>;
  setSearch: Dispatch<SetStateAction<string>>;
  setSelectedLog: Dispatch<SetStateAction<InterceptLog | null>>;
  setThreatFilter: Dispatch<SetStateAction<string>>;
  threatFilter: string;
  threatFilterOptions: GlassSelectOption[];
}) {
  return (
    <div className="space-y-5">
      <section className={`${glassPanelClass} relative p-4`}>
        <div className="relative grid gap-3 xl:grid-cols-[minmax(220px,1fr)_minmax(150px,180px)_minmax(150px,180px)_auto]">
          <label className="relative block">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-muted)]" aria-hidden />
            <input value={search} onChange={(event) => setSearch(event.target.value)} className={`${inputBase} pl-10`} placeholder="搜索请求 ID、风险类型、原始输入" />
          </label>
          <GlassSelect value={riskFilter} onChange={(next) => setRiskFilter(next as typeof riskFilter)} options={riskFilterOptions} ariaLabel="风险等级筛选" />
          <GlassSelect value={threatFilter} onChange={setThreatFilter} options={threatFilterOptions} ariaLabel="威胁类型筛选" />
          <div className="flex flex-wrap gap-2">
            <button type="button" onClick={() => void loadLogs()} className={buttonClass("secondary")}>
              <RefreshCcw className={`h-4 w-4 ${logsLoading ? "animate-spin" : ""}`} aria-hidden />
              刷新
            </button>
            <button type="button" onClick={downloadLogs} className={buttonClass("secondary")} disabled={filteredLogs.length === 0}>
              <Clipboard className="h-4 w-4" aria-hidden />
              导出
            </button>
          </div>
        </div>
        <div className="relative mt-3 flex flex-wrap items-center justify-between gap-2 text-[length:var(--text-body)]">
          <div className="flex items-center gap-2 text-[var(--text-secondary)]">
            <Filter className="h-4 w-4" aria-hidden />
            当前显示 <AnimatedNumber value={filteredLogs.length} /> / <AnimatedNumber value={logs.length} /> 条
          </div>
          <div className="flex flex-wrap gap-2">
            <button type="button" onClick={seedLogs} className={buttonClass("secondary")}>
              <Plus className="h-4 w-4" aria-hidden />
              验证样例
            </button>
            <button type="button" onClick={clearLocalLogs} className={buttonClass("danger")} disabled={!logs.some((log) => log.id < 0)}>
              <Trash2 className="h-4 w-4" aria-hidden />
              清空本地日志
            </button>
          </div>
        </div>
        {logsError ? <div className="relative mt-4 rounded-[var(--radius-lg)] border border-[color-mix(in_oklab,var(--tone-warning)_28%,transparent)] bg-[var(--tone-warning-surface)] px-4.5 py-3.5 text-[length:var(--text-body)] text-[var(--tone-warning-text)]">{logsError}</div> : null}
      </section>

      <section className={`${glassPanelClass} relative overflow-visible`}>
        {logsLoading && logs.length === 0 ? (
          <div className="relative">
            <LogListSkeleton rows={8} />
          </div>
        ) : filteredLogs.length === 0 ? (
          <div className="relative p-5">
            <EmptyState icon={Database} title="没有匹配的日志">
              <div className="flex flex-wrap justify-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setSearch("");
                    setRiskFilter("all");
                    setThreatFilter("all");
                  }}
                  className={buttonClass("secondary")}
                >
                  清除筛选
                </button>
                <button type="button" onClick={seedLogs} className={buttonClass("primary")}>
                  <Plus className="h-4 w-4" aria-hidden />
                  生成验证样例
                </button>
              </div>
            </EmptyState>
          </div>
        ) : (
          <AnimatedInterceptLogList logs={filteredLogs} onSelect={(log) => setSelectedLog(log)} onCopyRequestId={(requestId) => void copyText(requestId, "请求 ID 已复制")} />
        )}
      </section>
    </div>
  );
}
