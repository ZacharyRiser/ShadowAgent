"use client";

// 策略视图：前端单体拆解阶段 1，JSX 自 page.tsx renderPolicies 逐字搬出（AST 定位，零手抄）。
// 状态与副作用仍归 page.tsx 所有（阶段 2 再归仓）；本组件纯展示 + 回调上抛。

import type { Dispatch, FormEvent, SetStateAction } from "react";
import { Plus, RefreshCcw, Save, Trash2 } from "lucide-react";
import { GlassSelect, type GlassSelectOption } from "../components/glass-select";
import { Switch } from "../components/page-widgets";
import { buttonClass, glassPanelClass, glassPanelMotionClass, inputBase } from "../components/ui-kit";
import { severityTick } from "../app-meta";
import type { PolicyRule, ToolPermission } from "../types";

export function PoliciesView({
  addPolicy,
  policies,
  policyDraft,
  policyDraftOpen,
  removePolicy,
  resetPolicies,
  savePolicies,
  setPolicies,
  setPolicyDraft,
  setPolicyDraftOpen,
  setTools,
  severityOptions,
  tools,
}: {
  addPolicy: (event: FormEvent<HTMLFormElement>) => void;
  policies: PolicyRule[];
  policyDraft: { name: string; pattern: string; description: string; severity: PolicyRule["severity"]; scope: string };
  policyDraftOpen: boolean;
  removePolicy: (policyId: string) => void;
  resetPolicies: () => void;
  savePolicies: () => void;
  setPolicies: Dispatch<SetStateAction<PolicyRule[]>>;
  setPolicyDraft: Dispatch<SetStateAction<{ name: string; pattern: string; description: string; severity: PolicyRule["severity"]; scope: string }>>;
  setPolicyDraftOpen: Dispatch<SetStateAction<boolean>>;
  setTools: Dispatch<SetStateAction<ToolPermission[]>>;
  severityOptions: GlassSelectOption[];
  tools: ToolPermission[];
}) {
  return (
    <div className="grid gap-5 2xl:grid-cols-[minmax(0,1fr)_minmax(320px,380px)]">
      <section className="space-y-4">
        <div className={`${glassPanelClass} ${glassPanelMotionClass} p-4 sm:flex sm:items-center sm:justify-between`}>
          <div className="relative">
            <h2 className="text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">审计策略</h2>
            <p className="mt-1 text-[length:var(--text-body)] text-[var(--text-secondary)]">切换后先保存在页面，点击保存后写入本地配置。</p>
          </div>
          <div className="relative mt-3 flex flex-wrap gap-2 sm:mt-0">
            <button type="button" onClick={() => setPolicyDraftOpen((value) => !value)} className={buttonClass("secondary")}>
              <Plus className="h-4 w-4" aria-hidden />
              新增策略
            </button>
            <button type="button" onClick={savePolicies} className={buttonClass("primary")}>
              <Save className="h-4 w-4" aria-hidden />
              保存策略
            </button>
            <button type="button" onClick={resetPolicies} className={buttonClass("secondary")}>
              <RefreshCcw className="h-4 w-4" aria-hidden />
              恢复默认
            </button>
          </div>
        </div>

        {policyDraftOpen ? (
          <form onSubmit={addPolicy} className={`${glassPanelClass} relative p-4`}>
            <div className="relative grid gap-3 md:grid-cols-2">
              <label>
                <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">策略名称</span>
                <input value={policyDraft.name} onChange={(event) => setPolicyDraft((current) => ({ ...current, name: event.target.value }))} className={inputBase} placeholder="自定义审计规则" />
              </label>
              <label>
                <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">作用域</span>
                <input value={policyDraft.scope} onChange={(event) => setPolicyDraft((current) => ({ ...current, scope: event.target.value }))} className={inputBase} placeholder="Prompt / Tool / Audit" />
              </label>
              <label className="md:col-span-2">
                <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">Pattern / Regex</span>
                <input
                  value={policyDraft.pattern}
                  onChange={(event) => setPolicyDraft((current) => ({ ...current, pattern: event.target.value }))}
                  className={`${inputBase} font-mono`}
                  placeholder="例如：\\b(api[_-]?key|token|secret)\\b"
                />
              </label>
              <label className="md:col-span-2">
                <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">描述</span>
                <input value={policyDraft.description} onChange={(event) => setPolicyDraft((current) => ({ ...current, description: event.target.value }))} className={inputBase} placeholder="这条规则要保护的边界" />
              </label>
              <label>
                <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">风险级别</span>
                <GlassSelect
                  value={policyDraft.severity}
                  onChange={(next) => setPolicyDraft((current) => ({ ...current, severity: next as PolicyRule["severity"] }))}
                  options={severityOptions}
                  ariaLabel="新增策略风险级别"
                />
              </label>
              <div className="flex items-end gap-2">
                <button type="submit" className={buttonClass("primary")}>
                  <Save className="h-4 w-4" aria-hidden />
                  添加
                </button>
                <button type="button" onClick={() => setPolicyDraftOpen(false)} className={buttonClass("secondary")}>
                  取消
                </button>
              </div>
            </div>
          </form>
        ) : null}

        {/* 策略列表：台账表格，不是卡片墙。
            frontend-dev：DENSITY > 7 时禁用通用卡片 —— 每条策略是一行，
            分隔靠 border-b，hover 靠底色。列：[竖条][名称+描述][范围][风险][启用][操作] */}
        <div className={`${glassPanelClass} overflow-hidden`}>
          <div className="grid grid-cols-[3px_minmax(0,1fr)_auto] items-center gap-x-3 border-b border-[var(--panel-border)] px-4 py-2 text-[length:var(--text-micro)] font-medium uppercase tracking-[0.08em] text-[var(--text-muted)] sm:px-5 lg:grid-cols-[3px_minmax(0,2.2fr)_minmax(0,0.9fr)_minmax(0,0.9fr)_auto_auto] lg:gap-x-4">
            <span aria-hidden />
            <span>策略</span>
            <span className="hidden lg:block">作用域</span>
            <span className="hidden lg:block">风险级别</span>
            <span className="hidden text-center lg:block">启用</span>
            <span className="text-right">操作</span>
          </div>
          <div>
            {policies.length === 0 ? (
              <p className="px-4 py-8 text-center text-[length:var(--text-body)] text-[var(--text-muted)] sm:px-5">
                还没有策略。点击「新增策略」定义第一条审计边界。
              </p>
            ) : null}
            {policies.map((policy) => (
              <div
                key={policy.id}
                className="group grid grid-cols-[3px_minmax(0,1fr)_auto] items-start gap-x-3 gap-y-2 border-b border-[var(--divider)] px-4 py-3.5 transition-colors duration-[var(--dur-fast)] ease-[var(--ease-out-quart)] last:border-b-0 hover:bg-[var(--surface-sunken)] sm:px-5 lg:grid-cols-[3px_minmax(0,2.2fr)_minmax(0,0.9fr)_minmax(0,0.9fr)_auto_auto] lg:items-center lg:gap-x-4 lg:gap-y-0"
              >
                <span
                  aria-hidden
                  className={`col-start-1 row-span-2 h-9 w-[3px] self-start rounded-full lg:row-span-1 lg:self-center ${
                    policy.enabled ? severityTick(policy.severity) : "bg-[var(--divider-strong)]"
                  }`}
                />
                <div className="col-start-2 row-start-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="text-[length:var(--text-body)] font-medium text-[var(--text-primary)]">{policy.name}</h3>
                    {policy.custom ? (
                      <span className="chip chip-neutral">自定义</span>
                    ) : (
                      <span className="chip chip-neutral">内置</span>
                    )}
                  </div>
                  <p className="mt-0.5 line-clamp-2 font-mono text-[length:var(--text-micro)] leading-5 text-[var(--text-muted)]">
                    {policy.description}
                  </p>
                </div>
                <span className="col-start-2 row-start-2 min-w-0 truncate text-[length:var(--text-caption)] text-[var(--text-secondary)] lg:col-start-3 lg:row-start-1">
                  {policy.scope}
                </span>
                <div className="col-start-3 row-start-1 flex justify-end lg:col-start-4 lg:justify-start">
                  <GlassSelect
                    value={policy.severity}
                    onChange={(next) =>
                      setPolicies((current) => current.map((item) => (item.id === policy.id ? { ...item, severity: next as PolicyRule["severity"] } : item)))
                    }
                    className="max-w-32"
                    options={severityOptions}
                    ariaLabel={`${policy.name} 风险级别`}
                  />
                </div>
                <div className="col-span-2 col-start-2 row-start-3 flex items-center gap-3 lg:col-span-1 lg:col-start-5 lg:row-start-1 lg:justify-center">
                  <Switch
                    label={`切换 ${policy.name}`}
                    checked={policy.enabled}
                    onChange={(value) => setPolicies((current) => current.map((item) => (item.id === policy.id ? { ...item, enabled: value } : item)))}
                  />
                </div>
                <div className="col-span-2 col-start-2 row-start-4 flex justify-end lg:col-span-1 lg:col-start-6 lg:row-start-1">
                  {policy.custom ? (
                    <button
                      type="button"
                      onClick={() => removePolicy(policy.id)}
                      className="tap-target inline-flex items-center justify-center rounded-[var(--radius-xs)] p-1.5 text-[var(--text-muted)] transition-colors duration-[var(--dur-fast)] hover:bg-[var(--tone-danger-surface)] hover:text-[var(--tone-danger-text)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--tone-accent)]"
                      aria-label={`删除策略 ${policy.name}`}
                      title="删除策略"
                    >
                      <Trash2 className="h-4 w-4" aria-hidden />
                    </button>
                  ) : (
                    <span className="text-[length:var(--text-micro)] text-[var(--text-muted)]">内置</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <aside className="space-y-4">
        <section className={`${glassPanelClass} ${glassPanelMotionClass} p-5`}>
          <h2 className="relative text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">工具权限</h2>
          <div className="relative mt-4 space-y-4">
            {tools.map((tool) => (
              <div key={tool.id} className="border-b border-[var(--divider)] pb-4 last:border-b-0 last:pb-0">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="font-mono text-[length:var(--text-body)] text-[var(--text-primary)]">{tool.name}</div>
                    <p className="mt-1 text-[length:var(--text-body)] leading-6 text-[var(--text-secondary)]">{tool.description}</p>
                  </div>
                  <Switch
                    label={`切换 ${tool.name}`}
                    checked={tool.allowed}
                    onChange={(value) => setTools((current) => current.map((item) => (item.id === tool.id ? { ...item, allowed: value } : item)))}
                  />
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className={`${glassPanelClass} ${glassPanelMotionClass} p-5`}>
          <h2 className="relative text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">策略摘要</h2>
          <div className="relative mt-4 space-y-3 text-[length:var(--text-body)]">
            <div className="flex justify-between border-b border-[var(--divider)] pb-3">
              <span className="text-[var(--text-secondary)]">启用策略</span>
              <span className="font-medium text-[var(--text-primary)]">{policies.filter((item) => item.enabled).length}</span>
            </div>
            <div className="flex justify-between border-b border-[var(--divider)] pb-3">
              <span className="text-[var(--text-secondary)]">高风险策略</span>
              <span className="font-medium text-[var(--text-primary)]">{policies.filter((item) => item.severity === "high").length}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[var(--text-secondary)]">允许工具</span>
              <span className="font-medium text-[var(--text-primary)]">{tools.filter((item) => item.allowed).length}</span>
            </div>
          </div>
        </section>
      </aside>
    </div>
  );
}
