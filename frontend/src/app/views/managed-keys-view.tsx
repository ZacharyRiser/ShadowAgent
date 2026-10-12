"use client";

// 托管密钥视图：前端单体拆解阶段 1，JSX 自 page.tsx renderManagedKeys 逐字搬出（AST 定位，零手抄）。
// 状态与副作用仍归 page.tsx 所有（阶段 2 再归仓）；本组件纯展示 + 回调上抛。

import type { Dispatch, FormEvent, SetStateAction } from "react";
import { CheckCircle2, Copy, KeyRound, Plus, RefreshCcw, Settings, Shield, Trash2, X } from "lucide-react";
import { GlassSelect } from "../components/glass-select";
import { EmptyState, buttonClass, formatTime, glassPanelClass, glassPanelMotionClass, glassPanelSoftClass, inputBase } from "../components/ui-kit";
import { Switch } from "../components/page-widgets";
import { MANAGED_KEY_ROLE_OPTIONS, describeSource, isAdminRole, managedKeyRoleLabel, managedKeyStatus } from "../app-meta";
import { buildTimeTooltip, formatRelativeTime } from "../time-utils";
import type { AppSettings, ManagedApiKeyIssueState, ManagedApiKeyItem, ManagedApiKeyRole, ViewKey } from "../types";

export function ManagedKeysView({
  applyIssuedKeyToSettings,
  copyText,
  createManagedKey,
  hasAdminAccess,
  hasConsoleToken,
  includeInactiveKeys,
  loadManagedApiKeys,
  managedKeyBusyId,
  managedKeyDraft,
  managedKeyDraftOpen,
  managedKeyIssueState,
  managedKeys,
  managedKeysError,
  managedKeysLoading,
  navigateTo,
  rotateManagedKey,
  setIncludeInactiveKeys,
  setManagedKeyDraft,
  setManagedKeyDraftOpen,
  setManagedKeyIssueState,
  settings,
  updateManagedKeyLifecycle,
}: {
  applyIssuedKeyToSettings: (item: ManagedApiKeyItem, apiKey: string) => void;
  copyText: (value: string, successMessage: string) => Promise<void>;
  createManagedKey: (event: FormEvent<HTMLFormElement>) => Promise<void>;
  hasAdminAccess: boolean;
  hasConsoleToken: boolean;
  includeInactiveKeys: boolean;
  loadManagedApiKeys: (showFeedback?: boolean) => Promise<void>;
  managedKeyBusyId: number | null;
  managedKeyDraft: { name: string; role: ManagedApiKeyRole; description: string; expiresInDays: string };
  managedKeyDraftOpen: boolean;
  managedKeyIssueState: ManagedApiKeyIssueState | null;
  managedKeys: ManagedApiKeyItem[];
  managedKeysError: string;
  managedKeysLoading: boolean;
  navigateTo: (target: ViewKey) => void;
  rotateManagedKey: (item: ManagedApiKeyItem) => Promise<void>;
  setIncludeInactiveKeys: Dispatch<SetStateAction<boolean>>;
  setManagedKeyDraft: Dispatch<SetStateAction<{ name: string; role: ManagedApiKeyRole; description: string; expiresInDays: string }>>;
  setManagedKeyDraftOpen: Dispatch<SetStateAction<boolean>>;
  setManagedKeyIssueState: Dispatch<SetStateAction<ManagedApiKeyIssueState | null>>;
  settings: AppSettings;
  updateManagedKeyLifecycle: (item: ManagedApiKeyItem, action: "revoke" | "activate" | "delete") => Promise<void>;
}) {
  return (
    <div className="grid gap-5 2xl:grid-cols-[minmax(0,1fr)_minmax(320px,380px)]">
      <section className={`${glassPanelClass} relative space-y-4 p-5`}>
        <div className="relative flex flex-col gap-3 border-b border-[var(--divider)] pb-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0">
            <h2 className="text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">托管密钥列表</h2>
            <p className="mt-1 text-[length:var(--text-body)] text-[var(--text-secondary)]">每个调用方都应拥有独立密钥，便于单独轮换、停用和追踪最近使用情况。</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button type="button" onClick={() => void loadManagedApiKeys(true)} className={buttonClass("secondary")} disabled={managedKeysLoading || !hasAdminAccess}>
              <RefreshCcw className={`h-4 w-4 ${managedKeysLoading ? "animate-spin" : ""}`} aria-hidden />
              刷新列表
            </button>
            <button type="button" onClick={() => setManagedKeyDraftOpen((value) => !value)} className={buttonClass("primary")} disabled={!hasAdminAccess}>
              <Plus className="h-4 w-4" aria-hidden />
              {managedKeyDraftOpen ? "收起创建表单" : "签发新密钥"}
            </button>
          </div>
        </div>

        <div className="relative flex flex-col gap-3 rounded-[var(--radius-lg)] border border-[var(--panel-border)] bg-[var(--surface-raised)] px-4.5 py-3.5 sm:flex-row sm:items-center sm:justify-between">
          <div className="text-[length:var(--text-body)] text-[var(--text-secondary)]">
            <span className="font-medium text-[var(--text-primary)]">推荐路径：</span>
            管理员登录后台后，在这里创建每个用户或服务自己的密钥，不再继续共用一个环境变量里的总钥匙。
          </div>
          <Switch
            label="切换是否显示停用密钥"
            checked={includeInactiveKeys}
            onChange={(value) => setIncludeInactiveKeys(value)}
          />
        </div>

        {!hasAdminAccess ? (
          <div className="relative p-5">
            <EmptyState icon={Shield} title="当前无后台管理权限">
              <p className="mt-3 text-[length:var(--text-body)] leading-6 text-[var(--text-secondary)]">
                先使用管理员账号登录，或在设置页填入兼容的 Admin API Key，随后这里才会连接后端的托管密钥接口。
              </p>
              <button type="button" onClick={() => navigateTo("settings")} className={`${buttonClass("primary")} mt-4`}>
                <Settings className="h-4 w-4" aria-hidden />
                去设置鉴权
              </button>
            </EmptyState>
          </div>
        ) : (
          <>
            {managedKeyDraftOpen ? (
              <form onSubmit={createManagedKey} className={`${glassPanelSoftClass} relative grid gap-4 p-4`}>
                <div className="grid gap-4 md:grid-cols-2">
                  <label className="block">
                    <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">密钥名称</span>
                    <input
                      value={managedKeyDraft.name}
                      onChange={(event) => setManagedKeyDraft((current) => ({ ...current, name: event.target.value }))}
                      className={inputBase}
                      placeholder="例如：小组演示客户端 / 生产网关 A"
                    />
                  </label>
                  <label className="block">
                    <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">角色</span>
                    <GlassSelect
                      value={managedKeyDraft.role}
                      onChange={(next) => setManagedKeyDraft((current) => ({ ...current, role: next as ManagedApiKeyRole }))}
                      options={MANAGED_KEY_ROLE_OPTIONS}
                      ariaLabel="选择托管密钥角色"
                    />
                  </label>
                </div>

                <label className="block">
                  <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">说明备注</span>
                  <input
                    value={managedKeyDraft.description}
                    onChange={(event) => setManagedKeyDraft((current) => ({ ...current, description: event.target.value }))}
                    className={inputBase}
                    placeholder="记录用途、负责人或接入系统，便于后续排查和轮换"
                  />
                </label>

                <div className="grid gap-4 md:grid-cols-[180px_minmax(0,1fr)]">
                  <label className="block">
                    <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">过期天数</span>
                    <input
                      value={managedKeyDraft.expiresInDays}
                      onChange={(event) => setManagedKeyDraft((current) => ({ ...current, expiresInDays: event.target.value }))}
                      className={inputBase}
                      min={1}
                      type="number"
                      placeholder="30"
                    />
                  </label>
                  <div className={`${glassPanelSoftClass} p-4 text-[length:var(--text-body)] text-[var(--text-secondary)]`}>
                    <p className="font-medium text-[var(--text-primary)]">签发建议</p>
                    <p className="mt-2 leading-6 text-[var(--text-secondary)]">
                      给个人或脚本单独发密钥，优先使用 `client` 或 `gateway`。只有确实要管理后台、审批或策略时，才发 `security_admin` / `admin`。
                    </p>
                  </div>
                </div>

                <div className="flex flex-wrap gap-2">
                  <button type="submit" className={buttonClass("primary")} disabled={managedKeyBusyId === 0}>
                    <KeyRound className="h-4 w-4" aria-hidden />
                    {managedKeyBusyId === 0 ? "签发中..." : "签发并显示明文"}
                  </button>
                  <button type="button" onClick={() => setManagedKeyDraftOpen(false)} className={buttonClass("secondary")}>
                    收起
                  </button>
                </div>
              </form>
            ) : null}

            {managedKeysError ? (
              <div className="relative rounded-[var(--radius-lg)] border border-[color-mix(in_oklab,var(--tone-danger)_28%,transparent)] bg-[var(--tone-danger-surface)] px-4.5 py-3.5 text-[length:var(--text-body)] text-[var(--tone-danger-text)]">
                密钥列表加载失败：{managedKeysError}
              </div>
            ) : null}

            {managedKeys.length === 0 && !managedKeysLoading ? (
              <div className="relative p-5">
                <EmptyState icon={KeyRound} title="还没有托管密钥">
                  <p className="mt-3 text-[length:var(--text-body)] leading-6 text-[var(--text-secondary)]">先签发第一把独立密钥，后面每个接入方都按用途和角色分别管理。</p>
                </EmptyState>
              </div>
            ) : (
              /* 密钥是高密度台账：用表格而非卡片墙。
                 原来每把密钥是一个嵌套 4 层小卡的圆角面板，
                 5 把密钥就要渲染 25 个圆角容器 —— 视觉噪音淹没信息。
                 arrange.md / frontend-dev：DENSITY 高时禁用通用卡片。 */
              <div className="relative overflow-hidden rounded-[var(--radius-md)] border border-[var(--panel-border-soft)]">
                <div className="grid grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)_auto] items-center gap-x-4 border-b border-[var(--panel-border)] bg-[var(--surface-sunken)] px-4 py-2.5 text-[length:var(--text-micro)] font-medium uppercase tracking-[0.08em] text-[var(--text-muted)]">
                  <span>密钥</span>
                  <span>前缀</span>
                  <span>到期</span>
                  <span>最近使用</span>
                  <span className="text-right">操作</span>
                </div>
                {managedKeys.map((item) => {
                  const status = managedKeyStatus(item);
                  const busy = managedKeyBusyId === item.id;
                  const hasFreshSecret = managedKeyIssueState?.item.id === item.id;
                  const sourceInfo = describeSource(item.last_used_by);

                  return (
                    <div
                      key={item.id}
                      className="grid grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)_auto] items-start gap-x-4 border-b border-[var(--divider)] px-4 py-3.5 transition-colors duration-[var(--dur-fast)] last:border-b-0 hover:bg-[var(--surface-sunken)]"
                    >
                      {/* 名称 + 角色 + 状态 + 备注 */}
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="truncate text-[length:var(--text-caption)] font-medium text-[var(--text-primary)]">{item.name}</span>
                          <span className={`chip ${status.chip}`}>{status.label}</span>
                        </div>
                        <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-[length:var(--text-micro)] text-[var(--text-muted)]">
                          <span className="font-mono">{managedKeyRoleLabel(item.role)}</span>
                          <span aria-hidden>·</span>
                          <span className="truncate" title={item.description || undefined}>
                            {item.description || "未填写备注"}
                          </span>
                        </div>
                        {hasFreshSecret ? (
                          <div className="mt-2 text-[length:var(--text-micro)] text-[var(--tone-warning-text)]">
                            明文仍在右侧展示区，离开页面后不再返回。
                          </div>
                        ) : null}
                      </div>

                      {/* 前缀 */}
                      <div className="min-w-0">
                        <div className="truncate font-mono text-[length:var(--text-caption)] text-[var(--text-secondary)]" title={item.masked_key}>
                          {item.masked_key}
                        </div>
                        <button
                          type="button"
                          onClick={() => void copyText(item.key_prefix, "密钥前缀已复制")}
                          className="mt-1 text-[length:var(--text-micro)] text-[var(--text-muted)] transition-colors duration-[var(--dur-fast)] hover:text-[var(--tone-accent-text)]"
                        >
                          复制前缀
                        </button>
                      </div>

                      {/* 到期 */}
                      <div className="min-w-0 text-[length:var(--text-caption)] text-[var(--text-secondary)]">
                        <div title={item.expires_at ? buildTimeTooltip(item.expires_at) : undefined}>
                          {item.expires_at ? `${formatTime(item.expires_at)} CST` : "未设置"}
                        </div>
                        <div className="mt-1 text-[length:var(--text-micro)] text-[var(--text-muted)]">
                          {item.expires_at ? formatRelativeTime(item.expires_at) : status.hint}
                        </div>
                      </div>

                      {/* 最近使用 */}
                      <div className="min-w-0 text-[length:var(--text-caption)] text-[var(--text-secondary)]">
                        <div title={item.last_used_at ? buildTimeTooltip(item.last_used_at) : undefined}>
                          {item.last_used_at ? `${formatTime(item.last_used_at)} CST` : "尚未使用"}
                        </div>
                        <div className="mt-1 truncate text-[length:var(--text-micro)] text-[var(--text-muted)]" title={sourceInfo.detail}>
                          {item.last_used_at ? `${formatRelativeTime(item.last_used_at)} · ${sourceInfo.label}` : "首次调用后显示来源"}
                        </div>
                      </div>

                      {/* 操作：图标按钮，保持行高稳定 */}
                      <div className="flex shrink-0 items-center justify-end gap-1">
                        <button
                          type="button"
                          onClick={() => void rotateManagedKey(item)}
                          disabled={busy}
                          className="tap-target rounded-[var(--radius-xs)] p-1.5 text-[var(--text-muted)] transition-colors duration-[var(--dur-fast)] hover:bg-[var(--surface-raised)] hover:text-[var(--text-primary)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--tone-accent)] disabled:cursor-not-allowed disabled:opacity-50"
                          aria-label={`轮换密钥 ${item.name}`}
                          title="轮换"
                        >
                          <RefreshCcw className={`h-4 w-4 ${busy ? "animate-spin" : ""}`} aria-hidden />
                        </button>
                        {item.is_active ? (
                          <button
                            type="button"
                            onClick={() => void updateManagedKeyLifecycle(item, "revoke")}
                            disabled={busy}
                            className="tap-target rounded-[var(--radius-xs)] p-1.5 text-[var(--text-muted)] transition-colors duration-[var(--dur-fast)] hover:bg-[var(--tone-warning-surface)] hover:text-[var(--tone-warning-text)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--tone-accent)] disabled:cursor-not-allowed disabled:opacity-50"
                            aria-label={`停用密钥 ${item.name}`}
                            title="停用"
                          >
                            <X className="h-4 w-4" aria-hidden />
                          </button>
                        ) : (
                          <button
                            type="button"
                            onClick={() => void updateManagedKeyLifecycle(item, "activate")}
                            disabled={busy}
                            className="tap-target rounded-[var(--radius-xs)] p-1.5 text-[var(--text-muted)] transition-colors duration-[var(--dur-fast)] hover:bg-[var(--tone-success-surface)] hover:text-[var(--tone-success-text)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--tone-accent)] disabled:cursor-not-allowed disabled:opacity-50"
                            aria-label={`恢复密钥 ${item.name}`}
                            title="恢复"
                          >
                            <CheckCircle2 className="h-4 w-4" aria-hidden />
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => void updateManagedKeyLifecycle(item, "delete")}
                          disabled={busy}
                          className="tap-target rounded-[var(--radius-xs)] p-1.5 text-[var(--text-muted)] transition-colors duration-[var(--dur-fast)] hover:bg-[var(--tone-danger-surface)] hover:text-[var(--tone-danger-text)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--tone-accent)] disabled:cursor-not-allowed disabled:opacity-50"
                          aria-label={`删除密钥 ${item.name}`}
                          title="删除"
                        >
                          <Trash2 className="h-4 w-4" aria-hidden />
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </>
        )}
      </section>

      <aside className="space-y-4">
        <section className={`${glassPanelClass} ${glassPanelMotionClass} p-5`}>
          <div className="relative flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <h2 className="min-w-0 text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">最新明文密钥</h2>
            <span className="self-start whitespace-nowrap rounded-full border border-[color-mix(in_oklab,var(--tone-warning)_28%,transparent)] bg-[var(--tone-warning-surface)] px-2.5 py-0.5 text-[length:var(--text-micro)] text-[var(--tone-warning-text)] sm:self-auto">
              只返回一次
            </span>
          </div>
          {managedKeyIssueState ? (
            <div className="relative mt-4 space-y-4">
              <div className={`${glassPanelSoftClass} p-4`}>
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0">
                    <div className="text-[length:var(--text-body)] font-medium text-[var(--text-primary)]">
                      {managedKeyIssueState.action === "created" ? "刚创建的新密钥" : "刚轮换出的新密钥"}
                    </div>
                    <div className="mt-1 break-words text-[length:var(--text-micro)] text-[var(--text-muted)]">
                      {managedKeyIssueState.item.name} · {managedKeyRoleLabel(managedKeyIssueState.item.role)}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setManagedKeyIssueState(null)}
                    className="flex h-9 w-9 items-center justify-center rounded-[var(--radius-md)] text-[var(--text-secondary)] transition-[color,background-color,border-color,box-shadow,transform,opacity] duration-[var(--dur-fast)] hover:bg-[var(--surface-raised)] hover:text-[var(--text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--tone-accent)] active:scale-[0.98]"
                    aria-label="清除最新明文密钥展示"
                  >
                    <X className="h-4 w-4" aria-hidden />
                  </button>
                </div>
                <div className="mt-4 rounded-[var(--radius-md)] border border-[var(--panel-border)] bg-[var(--surface-raised)] p-3.5 font-mono text-[length:var(--text-micro)] leading-6 break-all text-[var(--tone-accent-text)]">
                  {managedKeyIssueState.apiKey}
                </div>
                <p className="mt-3 text-[length:var(--text-micro)] leading-6 text-[var(--text-secondary)]">
                  后台出于安全原因不会再次返回这串明文。请现在就复制，或直接写入右侧的兼容 API Key 设置中供联调使用。
                </p>
              </div>

              <div className="grid gap-2">
                <button
                  type="button"
                  onClick={() => void copyText(managedKeyIssueState.apiKey, "明文密钥已复制")}
                  className={buttonClass("primary")}
                >
                  <Copy className="h-4 w-4" aria-hidden />
                  复制明文密钥
                </button>
                <button
                  type="button"
                  onClick={() => applyIssuedKeyToSettings(managedKeyIssueState.item, managedKeyIssueState.apiKey)}
                  className={buttonClass("secondary")}
                >
                  <KeyRound className="h-4 w-4" aria-hidden />
                  {isAdminRole(managedKeyIssueState.item.role) ? "写入当前会话的 Admin API Key" : "写入当前会话的 Client API Key"}
                </button>
              </div>
            </div>
          ) : (
            <div className="relative mt-4">
              <EmptyState icon={Copy} title="尚未产生新密钥">
                <p className="mt-3 text-[length:var(--text-body)] leading-6 text-[var(--text-secondary)]">
                  当你创建或轮换一把托管密钥后，它的明文只会在这里显示一次，适合当场复制给接入方或写入当前会话的兼容设置。
                </p>
              </EmptyState>
            </div>
          )}
        </section>

        <section className={`${glassPanelClass} ${glassPanelMotionClass} p-5`}>
          <h2 className="relative text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">发放建议</h2>
          <div className="relative mt-4 space-y-3 text-[length:var(--text-body)] text-[var(--text-secondary)]">
            <div className={`${glassPanelSoftClass} p-3`}>
              <div className="font-medium text-[var(--text-primary)]">个人调试</div>
              <div className="mt-1 leading-6">优先发 `client`，并设置 7 到 30 天有效期。</div>
            </div>
            <div className={`${glassPanelSoftClass} p-3`}>
              <div className="font-medium text-[var(--text-primary)]">服务接入</div>
              <div className="mt-1 leading-6">给每个网关、脚本或后端任务单独发一把密钥，避免泄漏后需要全局换钥。</div>
            </div>
            <div className={`${glassPanelSoftClass} p-3`}>
              <div className="font-medium text-[var(--text-primary)]">后台管理</div>
              <div className="mt-1 leading-6">`admin` 与 `security_admin` 只给少量运营或安全成员，优先通过登录 Token 使用后台。</div>
            </div>
          </div>
        </section>

        <section className={`${glassPanelClass} ${glassPanelMotionClass} p-5`}>
          <h2 className="relative text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">当前兼容模式</h2>
          <div className="relative mt-4 space-y-3 text-[length:var(--text-body)] text-[var(--text-secondary)]">
            <div className="flex items-center justify-between border-b border-[var(--divider)] pb-3">
              <span>后台 Token</span>
              <span className={hasConsoleToken ? "text-[var(--tone-success-text)]" : "text-[var(--text-primary)]"}>{hasConsoleToken ? "已生效" : "未登录"}</span>
            </div>
            <div className="flex items-center justify-between border-b border-[var(--divider)] pb-3">
              <span>Admin API Key</span>
              <span className={settings.adminApiKey ? "text-[var(--tone-success-text)]" : "text-[var(--text-primary)]"}>{settings.adminApiKey ? "已填" : "留空"}</span>
            </div>
            <div className="flex items-center justify-between">
              <span>Client / Gateway API Key</span>
              <span className={settings.clientApiKey ? "text-[var(--tone-success-text)]" : "text-[var(--text-primary)]"}>{settings.clientApiKey ? "已填" : "留空"}</span>
            </div>
          </div>
          <button type="button" onClick={() => navigateTo("settings")} className={`${buttonClass("secondary")} relative mt-5 w-full`}>
            <Settings className="h-4 w-4" aria-hidden />
            打开设置页
          </button>
        </section>
      </aside>
    </div>
  );
}
