"use client";

// 自定义规则视图：前端单体拆解阶段 1，JSX 自 page.tsx renderRules 逐字搬出（AST 定位，零手抄）。
// 状态与副作用仍归 page.tsx 所有（阶段 2 再归仓）；本组件纯展示 + 回调上抛。

import type { Dispatch, SetStateAction } from "react";
import { Pencil, Play, Plus, RefreshCcw, Save, Trash2 } from "lucide-react";
import { GlassSelect, type GlassSelectOption } from "../components/glass-select";
import { RuleListSkeleton, Switch } from "../components/page-widgets";
import { buttonClass, glassPanelClass, glassPanelMotionClass, inputBase } from "../components/ui-kit";
import type { CustomRuleAction, CustomRuleDraft, CustomRuleItem, CustomRuleItemType, CustomRuleTarget, DlpStatusInfo, RuleTestResult } from "../types";

export function RulesView({
  customRules,
  customRulesError,
  customRulesLoading,
  deleteCustomRule,
  dlpModeClass,
  dlpStatus,
  exportCustomRules,
  importCustomRules,
  loadCustomRules,
  ruleActionClass,
  ruleActionOptions,
  ruleActionText,
  ruleActionTick,
  ruleBusyId,
  ruleDraft,
  ruleDraftOpen,
  ruleEditingId,
  ruleTargetOptions,
  ruleTargetText,
  ruleTestBusy,
  ruleTestResult,
  ruleTestText,
  ruleTypeOptions,
  setRuleDraft,
  setRuleDraftOpen,
  setRuleEditingId,
  setRuleTestResult,
  setRuleTestText,
  submitCustomRule,
  testCustomRule,
  toggleCustomRule,
}: {
  customRules: CustomRuleItem[];
  customRulesError: string;
  customRulesLoading: boolean;
  deleteCustomRule: (item: CustomRuleItem) => Promise<void>;
  dlpModeClass: (mode: string) => string;
  dlpStatus: DlpStatusInfo | null;
  exportCustomRules: () => Promise<void>;
  importCustomRules: (file: File) => Promise<void>;
  loadCustomRules: (showFeedback?: boolean) => Promise<void>;
  ruleActionClass: (action: string) => string;
  ruleActionOptions: GlassSelectOption[];
  ruleActionText: (action: string) => string;
  ruleActionTick: (action: string) => string;
  ruleBusyId: number | null;
  ruleDraft: CustomRuleDraft;
  ruleDraftOpen: boolean;
  ruleEditingId: number | null;
  ruleTargetOptions: GlassSelectOption[];
  ruleTargetText: (target: string) => string;
  ruleTestBusy: boolean;
  ruleTestResult: RuleTestResult | null;
  ruleTestText: string;
  ruleTypeOptions: GlassSelectOption[];
  setRuleDraft: Dispatch<SetStateAction<CustomRuleDraft>>;
  setRuleDraftOpen: Dispatch<SetStateAction<boolean>>;
  setRuleEditingId: Dispatch<SetStateAction<number | null>>;
  setRuleTestResult: Dispatch<SetStateAction<RuleTestResult | null>>;
  setRuleTestText: Dispatch<SetStateAction<string>>;
  submitCustomRule: () => Promise<void>;
  testCustomRule: () => Promise<void>;
  toggleCustomRule: (item: CustomRuleItem, enabled: boolean) => Promise<void>;
}) {
  return (
    <div className="grid gap-5 2xl:grid-cols-[minmax(0,1fr)_minmax(320px,380px)]">
      <section className="space-y-4">
        <div className={`${glassPanelClass} ${glassPanelMotionClass} p-4 sm:flex sm:items-center sm:justify-between`}>
          <div className="relative">
            <h2 className="text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">自定义检测规则</h2>
            <p className="mt-1 text-[length:var(--text-body)] text-[var(--text-secondary)]">
              规则由网关引擎实时执行：请求侧拦截可疑提示词，响应侧对模型输出做 DLP 脱敏。
            </p>
          </div>
          <div className="relative mt-3 flex flex-wrap gap-2 sm:mt-0">
            <button
              type="button"
              onClick={() => {
                setRuleDraftOpen((value) => !value);
                setRuleEditingId(null);
                setRuleTestResult(null);
                setRuleDraft({
                  name: "",
                  description: "",
                  rule_type: "regex",
                  pattern: "",
                  target: "prompt",
                  action: "block",
                  risk_score: 0.8,
                  enabled: true,
                });
              }}
              className={buttonClass("secondary")}
            >
              <Plus className="h-4 w-4" aria-hidden />
              新增规则
            </button>
            <button type="button" onClick={() => void loadCustomRules(true)} className={buttonClass("secondary")}>
              <RefreshCcw className="h-4 w-4" aria-hidden />
              刷新
            </button>
            <button type="button" onClick={() => void exportCustomRules()} className={buttonClass("secondary")}>
              导出
            </button>
            <label className={`${buttonClass("secondary")} cursor-pointer`}>
              导入
              <input
                type="file"
                accept="application/json"
                className="hidden"
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  event.target.value = "";
                  if (file) void importCustomRules(file);
                }}
              />
            </label>
          </div>
        </div>

        {ruleDraftOpen ? (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void submitCustomRule();
            }}
            className={`${glassPanelClass} relative p-4`}
          >
            <div className="relative grid gap-3 md:grid-cols-2">
              <label>
                <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">规则名称</span>
                <input
                  value={ruleDraft.name}
                  onChange={(event) => setRuleDraft((current) => ({ ...current, name: event.target.value }))}
                  className={inputBase}
                  placeholder="例如：内部代号泄露防护"
                />
              </label>
              <label>
                <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">匹配方式</span>
                <GlassSelect
                  value={ruleDraft.rule_type}
                  onChange={(next) => setRuleDraft((current) => ({ ...current, rule_type: next as CustomRuleItemType }))}
                  options={ruleTypeOptions}
                  ariaLabel="规则匹配方式"
                />
              </label>
              <label className="md:col-span-2">
                <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">
                  {ruleDraft.rule_type === "regex" ? "正则表达式（不区分大小写）" : "关键词（子串匹配）"}
                </span>
                <input
                  value={ruleDraft.pattern}
                  onChange={(event) => setRuleDraft((current) => ({ ...current, pattern: event.target.value }))}
                  className={`${inputBase} font-mono`}
                  placeholder={ruleDraft.rule_type === "regex" ? "例如：INTERNAL[- ]PROJECT[- ]CODE[- ]\\d+" : "例如：PROJECT-XRAY"}
                />
              </label>
              <label>
                <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">作用位置</span>
                <GlassSelect
                  value={ruleDraft.target}
                  onChange={(next) => {
                    const target = next as CustomRuleTarget;
                    setRuleDraft((current) => ({
                      ...current,
                      target,
                      action: target === "prompt" && current.action === "redact" ? "block" : current.action,
                    }));
                  }}
                  options={ruleTargetOptions}
                  ariaLabel="规则作用位置"
                />
              </label>
              <label>
                <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">命中后动作</span>
                <GlassSelect
                  value={ruleDraft.action}
                  onChange={(next) => setRuleDraft((current) => ({ ...current, action: next as CustomRuleAction }))}
                  options={
                    ruleDraft.target === "prompt"
                      ? ruleActionOptions.filter((option) => option.value !== "redact")
                      : ruleActionOptions
                  }
                  ariaLabel="命中后动作"
                />
              </label>
              <label>
                <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">风险评分（{ruleDraft.risk_score.toFixed(2)}）</span>
                <input
                  type="range"
                  min={0.1}
                  max={0.99}
                  step={0.01}
                  value={ruleDraft.risk_score}
                  onChange={(event) => setRuleDraft((current) => ({ ...current, risk_score: Number(event.target.value) }))}
                  className="h-10 w-full accent-[var(--tone-accent)]"
                />
              </label>
              <label>
                <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">描述</span>
                <input
                  value={ruleDraft.description}
                  onChange={(event) => setRuleDraft((current) => ({ ...current, description: event.target.value }))}
                  className={inputBase}
                  placeholder="这条规则防护什么（可选）"
                />
              </label>
              <label className="md:col-span-2">
                <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">测试样例文本（可选，保存前先试跑）</span>
                <textarea
                  value={ruleTestText}
                  onChange={(event) => setRuleTestText(event.target.value)}
                  className={`${inputBase} min-h-20 font-mono`}
                  placeholder="粘贴一段提示词或模型输出，验证规则是否命中…"
                />
              </label>
              <div className="flex flex-wrap items-center gap-2">
                <button type="submit" disabled={ruleTestBusy} className={buttonClass("primary")}>
                  <Save className="h-4 w-4" aria-hidden />
                  {ruleEditingId !== null ? "保存修改" : "创建规则"}
                </button>
                <button
                  type="button"
                  onClick={() => void testCustomRule()}
                  disabled={ruleTestBusy}
                  className={buttonClass("secondary")}
                >
                  <Play className="h-4 w-4" aria-hidden />
                  测试规则
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setRuleDraftOpen(false);
                    setRuleEditingId(null);
                    setRuleTestResult(null);
                  }}
                  className={buttonClass("secondary")}
                >
                  取消
                </button>
              </div>
            </div>
            {ruleTestResult ? (
              <div className="relative mt-4 rounded-[var(--radius-lg)] border border-[var(--panel-border)] bg-[var(--surface-raised)] p-4 text-[length:var(--text-body)]">
                {ruleTestResult.matched ? (
                  <>
                    <p className="text-[var(--tone-success-text)]">命中 {ruleTestResult.match_count} 处：</p>
                    <ul className="mt-2 space-y-1">
                      {ruleTestResult.matches.map((match, index) => (
                        <li key={index} className="font-mono text-[length:var(--text-micro)] text-[var(--text-secondary)]">
                          <span className="mr-2 text-[var(--text-muted)]">[{match.span[0]}:{match.span[1]}]</span>
                          {match.matched_text}
                        </li>
                      ))}
                    </ul>
                  </>
                ) : (
                  <p className="text-[var(--text-secondary)]">未命中：样例文本中没有匹配该模式的内容。</p>
                )}
              </div>
            ) : null}
          </form>
        ) : null}

        {customRulesError ? (
          <div className={`${glassPanelClass} border-[color-mix(in_oklab,var(--tone-danger)_28%,transparent)] p-4 text-[length:var(--text-body)] text-[var(--tone-danger-text)]`}>{customRulesError}</div>
        ) : null}

        {customRulesLoading && customRules.length === 0 ? (
          <RuleListSkeleton rows={5} />
        ) : null}

        {!customRulesLoading && customRules.length === 0 && !customRulesError ? (
          <div className={`${glassPanelClass} px-6 py-10 text-center`}>
            <p className="text-[length:var(--text-body)] font-medium text-[var(--text-primary)]">还没有自定义规则</p>
            <p className="mt-1 text-[length:var(--text-caption)] text-[var(--text-muted)]">
              点击「新增规则」创建第一条，或导入规则包。
            </p>
          </div>
        ) : null}

        {customRulesError && customRules.length === 0 ? (
          <div role="alert" className={`${glassPanelClass} px-6 py-10 text-center`}>
            <p className="text-[length:var(--text-body)] font-medium text-[var(--tone-danger-text)]">规则加载失败</p>
            <p className="mt-1 text-[length:var(--text-caption)] text-[var(--text-muted)]">{customRulesError}</p>
            <button type="button" onClick={() => void loadCustomRules(true)} className={`${buttonClass("secondary")} mt-3`}>
              <RefreshCcw className="h-4 w-4" aria-hidden />
              重试
            </button>
          </div>
        ) : null}

        {customRules.length > 0 ? (
          <div className={`${glassPanelClass} overflow-hidden`}>
            <div className="hidden grid-cols-[3px_minmax(0,2fr)_minmax(0,0.7fr)_minmax(0,0.8fr)_minmax(0,0.7fr)_auto_auto] items-center gap-x-4 border-b border-[var(--panel-border)] px-5 py-2 text-[length:var(--text-micro)] font-medium uppercase tracking-[0.08em] text-[var(--text-muted)] lg:grid">
              <span aria-hidden />
              <span>规则 / 匹配式</span>
              <span>方式</span>
              <span>作用位置</span>
              <span>动作</span>
              <span className="text-center">启用</span>
              <span className="text-right">操作</span>
            </div>
            {customRules.map((rule) => {
              const score = Number(rule.risk_score);
              return (
                <div
                  key={rule.id}
                  className="group grid grid-cols-[3px_minmax(0,1fr)_auto] items-start gap-x-3 gap-y-2 border-b border-[var(--divider)] px-4 py-3.5 transition-colors duration-[var(--dur-fast)] ease-[var(--ease-out-quart)] last:border-b-0 hover:bg-[var(--surface-sunken)] sm:px-5 lg:grid-cols-[3px_minmax(0,2fr)_minmax(0,0.7fr)_minmax(0,0.8fr)_minmax(0,0.7fr)_auto_auto] lg:items-center lg:gap-x-4 lg:gap-y-0"
                >
                  <span
                    aria-hidden
                    className={`col-start-1 row-span-2 h-9 w-[3px] self-start rounded-full lg:row-span-1 lg:self-center ${
                      rule.enabled ? ruleActionTick(String(rule.action)) : "bg-[var(--divider-strong)]"
                    }`}
                  />
                  <div className="col-start-2 row-start-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-[length:var(--text-body)] font-medium text-[var(--text-primary)]">{rule.name}</h3>
                      <span className={`${ruleActionClass(String(rule.action))}`}>{ruleActionText(String(rule.action))}</span>
                      <span className="text-[length:var(--text-micro)] tabular-nums text-[var(--text-muted)]">风险 {score.toFixed(2)}</span>
                    </div>
                    <p className="mt-0.5 break-all font-mono text-[length:var(--text-micro)] leading-5 text-[var(--text-muted)]">{rule.pattern}</p>
                    {rule.description ? (
                      <p className="mt-0.5 line-clamp-1 text-[length:var(--text-micro)] text-[var(--text-secondary)]">{rule.description}</p>
                    ) : null}
                  </div>
                  <span className="col-start-2 row-start-2 text-[length:var(--text-caption)] text-[var(--text-secondary)] lg:col-start-3 lg:row-start-1">
                    {rule.rule_type === "keyword" ? "关键词" : "正则"}
                  </span>
                  <span className="col-start-3 row-start-2 text-right text-[length:var(--text-caption)] text-[var(--text-secondary)] lg:col-start-4 lg:row-start-1 lg:text-left">
                    {ruleTargetText(String(rule.target))}
                  </span>
                  <div className="col-span-2 col-start-2 row-start-3 flex items-center gap-3 lg:col-span-1 lg:col-start-6 lg:row-start-1 lg:justify-center">
                    <Switch label={`切换 ${rule.name}`} checked={rule.enabled} onChange={(value) => void toggleCustomRule(rule, value)} />
                  </div>
                  <div className="col-span-2 col-start-2 row-start-4 flex justify-end gap-1 lg:col-span-1 lg:col-start-7 lg:row-start-1">
                    <button
                      type="button"
                      onClick={() => {
                        setRuleDraftOpen(true);
                        setRuleEditingId(rule.id);
                        setRuleTestResult(null);
                        setRuleDraft({
                          name: rule.name,
                          description: rule.description,
                          rule_type: (rule.rule_type === "keyword" ? "keyword" : "regex") as CustomRuleItemType,
                          pattern: rule.pattern,
                          target: String(rule.target) as CustomRuleTarget,
                          action: String(rule.action) as CustomRuleAction,
                          risk_score: Number(rule.risk_score),
                          enabled: rule.enabled,
                        });
                      }}
                      className="tap-target inline-flex items-center justify-center rounded-[var(--radius-xs)] p-1.5 text-[var(--text-muted)] transition-colors duration-[var(--dur-fast)] hover:bg-[var(--surface-raised)] hover:text-[var(--text-primary)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--tone-accent)]"
                      aria-label={`编辑规则 ${rule.name}`}
                      title="编辑规则"
                    >
                      <Pencil className="h-4 w-4" aria-hidden />
                    </button>
                    <button
                      type="button"
                      onClick={() => void deleteCustomRule(rule)}
                      disabled={ruleBusyId === rule.id}
                      className="tap-target inline-flex items-center justify-center rounded-[var(--radius-xs)] p-1.5 text-[var(--text-muted)] transition-colors duration-[var(--dur-fast)] hover:bg-[var(--tone-danger-surface)] hover:text-[var(--tone-danger-text)] disabled:opacity-40 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--tone-accent)]"
                      aria-label={`删除规则 ${rule.name}`}
                      title="删除规则"
                    >
                      <Trash2 className="h-4 w-4" aria-hidden />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        ) : null}

      </section>

      <aside className="space-y-4">
        <section className={`${glassPanelClass} ${glassPanelMotionClass} p-5`}>
          <h2 className="relative text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">响应侧 DLP 引擎</h2>
          <p className="relative mt-2 text-[length:var(--text-body)] leading-6 text-[var(--text-secondary)]">
            对模型输出做敏感数据扫描（AWS/GitHub/OpenAI/Slack/Google 密钥、JWT、私钥块、密钥赋值等）。
          </p>
          {dlpStatus ? (
            <div className="relative mt-4 space-y-3">
              <div className="flex items-center justify-between border-b border-[var(--divider)] pb-3">
                <span className="text-[length:var(--text-body)] text-[var(--text-secondary)]">当前模式</span>
                <span className={dlpModeClass(String(dlpStatus.mode))}>
                  {dlpStatus.mode === "off"
                    ? "已关闭"
                    : dlpStatus.mode === "monitor"
                      ? "monitor（只记录）"
                      : dlpStatus.mode === "block"
                        ? "block（阻断）"
                        : "redact（脱敏）"}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[length:var(--text-body)] text-[var(--text-secondary)]">内置检测模式</span>
                <span className="text-[length:var(--text-body)] font-medium text-[var(--text-primary)]">{dlpStatus.builtin_patterns.length} 类</span>
              </div>
              <div className="space-y-1.5 pt-1">
                {dlpStatus.builtin_patterns.map((pattern) => (
                  <div key={pattern.type} className="flex items-center justify-between gap-3 text-[length:var(--text-micro)]">
                    <span className="font-mono text-[var(--text-secondary)]">{pattern.type}</span>
                    <span className="shrink-0 text-[var(--text-muted)]">风险 {pattern.risk_score.toFixed(2)}</span>
                  </div>
                ))}
              </div>
              <p className="pt-2 text-[length:var(--text-micro)] leading-5 text-[var(--text-muted)]">
                通过环境变量 SHADOW_AGENT_RESPONSE_DLP_MODE 调整（off / monitor / redact / block）。
              </p>
            </div>
          ) : (
            <p className="relative mt-4 text-[length:var(--text-body)] text-[var(--text-muted)]">加载中…</p>
          )}
        </section>

        <section className={`${glassPanelClass} ${glassPanelMotionClass} p-5`}>
          <h2 className="relative text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">编写建议</h2>
          <ul className="relative mt-3 space-y-2 text-[length:var(--text-body)] leading-6 text-[var(--text-secondary)]">
            <li>· 请求侧规则作用于完整会话文本与外部上下文，适合拦截内部代号、竞品关键词等。</li>
            <li>· 响应侧规则参与 DLP 扫描，「脱敏」动作会把命中内容替换为 [REDACTED:规则名]。</li>
            <li>· 正则不区分大小写，长度上限 512 字符；创建前先用测试面板试跑。</li>
            <li>· 规则变更实时生效，全部改动会写入管理员审计日志。</li>
          </ul>
        </section>
      </aside>
    </div>
  );
}
