"use client";

// 帮助视图：前端单体拆解阶段 1，JSX 自 page.tsx renderHelp 逐字搬出（AST 定位，零手抄）。
// 状态与副作用仍归 page.tsx 所有（阶段 2 再归仓）；本组件纯展示 + 回调上抛。

import { ArrowRight, Bell, KeyRound, Network } from "lucide-react";
import { Ledger, ledgerRowClass } from "../components/page-widgets";
import { buttonClass, glassPanelClass } from "../components/ui-kit";
import type { ViewKey } from "../types";

export function HelpView({
  checkHealth,
  navigateTo,
}: {
  checkHealth: () => Promise<unknown>;
  navigateTo: (target: ViewKey) => void;
}) {
  return (
    <div className="grid gap-5 2xl:grid-cols-[minmax(0,1fr)_minmax(320px,380px)]">
      {/* 三张同构卡片（每张：图标+眉标+标题+描述+端点列表+满宽按钮）→ 一张说明台账。
         反 AI 味检查表 #3「三特性卡」+#4「一模一样圆角卡片」的逐字命中，已消除。
         每行一个主题，操作降级为行内单个文字按钮 —— 不再有三个满宽按钮抢视线。 */}
      <section className="space-y-5">
        <Ledger
          gridClass="grid-cols-1 sm:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)_auto]"
          columns={["", "", "text-right"]}
          header={["能力域 / 说明", "可用端点与凭据", "操作"]}
        >
          {[
            {
              icon: Network,
              eyebrow: "接入",
              title: "后端接口",
              desc: "网关暴露的只读端点与转发端点，用于连通性排查与链路验证。",
              lines: ["GET /health", "GET /api/v1/logs", "POST /api/v1/chat/completions"],
              action: "检测连接",
              onClick: () => void checkHealth(),
              primary: true,
            },
            {
              icon: KeyRound,
              eyebrow: "凭据",
              title: "鉴权方式",
              desc: "三种凭据来源，按优先级依次回退；推荐为每个调用方签发独立密钥。",
              lines: ["Bearer Token（登录后台自动获取）", "托管 API Key（按用户/服务签发）", "兼容 Key 兜底（仅当前会话）"],
              action: "密钥中心",
              onClick: () => navigateTo("keys"),
              primary: false,
            },
            {
              icon: Bell,
              eyebrow: "运维",
              title: "运营动作",
              desc: "日常巡检与告警联动的入口。",
              lines: ["日志筛选与导出", "策略与自定义规则切换", "网关验证场景测试"],
              action: "开始测试",
              onClick: () => navigateTo("gateway"),
              primary: false,
            },
          ].map((item) => (
            <div
              key={item.title}
              className={`grid grid-cols-1 items-start gap-x-4 gap-y-3 px-4 py-4 sm:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)_auto] sm:items-center sm:px-5 ${ledgerRowClass}`}
            >
              <div className="col-start-1 min-w-0">
                <div className="flex items-center gap-2.5">
                  <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-[var(--radius-sm)] bg-[var(--tone-accent-surface)]">
                    <item.icon className="h-3.5 w-3.5 text-[var(--tone-accent-text)]" aria-hidden />
                  </span>
                  <span className="text-[length:var(--text-micro)] font-semibold uppercase tracking-[0.1em] text-[var(--text-muted)]">
                    {item.eyebrow}
                  </span>
                  <h2 className="text-[length:var(--text-body)] font-semibold text-[var(--text-primary)]">{item.title}</h2>
                </div>
                <p className="mt-1.5 text-[length:var(--text-caption)] leading-5 text-[var(--text-secondary)]">{item.desc}</p>
              </div>
              <dl className="col-start-1 min-w-0 sm:col-start-2">
                {item.lines.map((line) => (
                  <div key={line} className="truncate font-mono text-[length:var(--text-micro)] leading-6 text-[var(--text-secondary)]" title={line}>
                    {line}
                  </div>
                ))}
              </dl>
              <div className="col-start-1 sm:col-start-3 sm:justify-self-end">
                {item.primary ? (
                  <button type="button" onClick={item.onClick} className={`${buttonClass("primary")} w-full sm:w-auto`}>
                    {item.action}
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={item.onClick}
                    className="inline-flex min-h-9 w-full items-center justify-center gap-1.5 rounded-[var(--radius-sm)] px-3 text-[length:var(--text-caption)] font-medium text-[var(--tone-accent-text)] transition-colors duration-[var(--dur-fast)] hover:bg-[var(--tone-accent-surface)] focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--tone-accent)] sm:w-auto"
                  >
                    {item.action}
                    <ArrowRight className="h-3.5 w-3.5" aria-hidden />
                  </button>
                )}
              </div>
            </div>
          ))}
        </Ledger>
      </section>

      <aside className="space-y-4">
        <section className={`${glassPanelClass} p-5`}>
          <h2 className="text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">使用建议</h2>
          <ul className="mt-3 space-y-2 text-[length:var(--text-body)] leading-6 text-[var(--text-secondary)]">
            <li>· 先用 <span className="font-mono text-[var(--text-primary)]">client</span> / <span className="font-mono text-[var(--text-primary)]">gateway</span> 凭据跑正常与高风险场景，确认业务可用且权限克制。</li>
            <li>· 再切到 <span className="font-mono text-[var(--text-primary)]">admin</span>，查看日志、审批、回放与证据包导出的完整闭环。</li>
            <li>· 自定义规则创建前先用测试面板试跑，避免误伤正常流量。</li>
          </ul>
        </section>

        <section className={`${glassPanelClass} p-5`}>
          <h2 className="text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">环境变量</h2>
          <dl className="mt-3 divide-y divide-[var(--divider)] border-y border-[var(--divider)] text-[length:var(--text-body)]">
            {[
              { key: "SHADOW_AGENT_SEMANTIC_MODE", note: "语义检测档位" },
              { key: "SHADOW_AGENT_SEMANTIC_THRESHOLD", note: "阻断阈值" },
              { key: "SHADOW_AGENT_RESPONSE_DLP_MODE", note: "响应侧 DLP 档位" },
            ].map((item) => (
              <div key={item.key} className="flex flex-col gap-0.5 py-3 sm:flex-row sm:items-baseline sm:justify-between sm:gap-3">
                <dt className="break-all font-mono text-[length:var(--text-micro)] text-[var(--text-primary)]">{item.key}</dt>
                <dd className="shrink-0 text-[length:var(--text-micro)] text-[var(--text-muted)]">{item.note}</dd>
              </div>
            ))}
          </dl>
        </section>
      </aside>
    </div>
  );
}
