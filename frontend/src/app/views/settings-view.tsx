"use client";

// 设置视图：前端单体拆解阶段 1，JSX 自 page.tsx renderSettings 逐字搬出（AST 定位，零手抄）。
// 状态与副作用仍归 page.tsx 所有（阶段 2 再归仓）；本组件纯展示 + 回调上抛。

import type { Dispatch, SetStateAction } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Check, Eye, EyeOff, KeyRound, LogOut, Network, RefreshCcw, Save, Trash2 } from "lucide-react";
import { Switch, ThemePreview } from "../components/page-widgets";
import { buttonClass, glassPanelClass, glassPanelMotionClass, inputBase } from "../components/ui-kit";
import { DEFAULT_API_BASE, THEME_OPTIONS, floatingGlassMenuClass } from "../app-meta";
import type { AppSettings, InterceptLog, SessionUser, ViewKey } from "../types";
import type { ValidationRunRecord } from "../demo-scenarios";

export function SettingsView({
  adminKeyError,
  adminKeyVerified,
  checkHealth,
  clearLocalData,
  hasConsoleAdmin,
  hasConsoleToken,
  keysVisible,
  logout,
  logs,
  navigateTo,
  resetSettings,
  resolvedTheme,
  saveSettings,
  setKeysVisible,
  setSettings,
  setThemePickerOpen,
  settings,
  themePickerOpen,
  user,
  validationHistory,
}: {
  adminKeyError: string;
  adminKeyVerified: boolean;
  checkHealth: () => Promise<unknown>;
  clearLocalData: () => void;
  hasConsoleAdmin: boolean;
  hasConsoleToken: boolean;
  keysVisible: boolean;
  logout: () => void;
  logs: InterceptLog[];
  navigateTo: (target: ViewKey) => void;
  resetSettings: () => void;
  resolvedTheme: "light" | "dark";
  saveSettings: () => void;
  setKeysVisible: Dispatch<SetStateAction<boolean>>;
  setSettings: Dispatch<SetStateAction<AppSettings>>;
  setThemePickerOpen: Dispatch<SetStateAction<boolean>>;
  settings: AppSettings;
  themePickerOpen: boolean;
  user: SessionUser | null;
  validationHistory: ValidationRunRecord[];
}) {
  return (
    <div className="grid gap-5 2xl:grid-cols-[minmax(0,1fr)_minmax(320px,380px)]">
      {/* 原来是一张巨型玻璃面板，内部又套了两张 glassPanelSoftClass 提示卡
         （「当前会话」「主路径已切换为托管密钥」）——这正是「卡片套卡片」。
         现在拆成：刊头（无卡）+ 两组字段台账 + 一条动作栏。 */}
      <section className="space-y-5">
        <header className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0">
            <p className="text-[length:var(--text-micro)] font-semibold uppercase tracking-[0.12em] text-[var(--text-muted)]">配置</p>
            <h2 className="mt-1 text-[length:var(--text-title)] font-semibold tracking-[-0.012em] text-[var(--text-primary)]">接口配置</h2>
            <p className="mt-1.5 max-w-2xl text-[length:var(--text-body)] leading-6 text-[var(--text-secondary)]">
              登录后自动使用后台签发的 Token；API Key 仅作为兼容方式保留在当前浏览器会话，不会写入长期本地存储。
            </p>
          </div>
          <button type="button" onClick={() => setKeysVisible((value) => !value)} className={`${buttonClass("secondary")} w-full sm:w-auto`}>
            {keysVisible ? <EyeOff className="h-4 w-4" aria-hidden /> : <Eye className="h-4 w-4" aria-hidden />}
            {keysVisible ? "隐藏 Key" : "显示 Key"}
          </button>
        </header>

        {/* 凭据字段台账：一行一个字段，标签在左、控件在右，不再用两列卡片栅格 */}
        <div className={`${glassPanelClass} overflow-hidden`}>
          <div className="border-b border-[var(--panel-border)] px-4 py-2 text-[length:var(--text-micro)] font-medium uppercase tracking-[0.08em] text-[var(--text-muted)] sm:px-5">
            连接与凭据
          </div>
          <div className="divide-y divide-[var(--divider)]">
            <label className="flex flex-col gap-2 px-4 py-4 sm:flex-row sm:items-center sm:gap-4 sm:px-5">
              <span className="shrink-0 text-[length:var(--text-body)] text-[var(--text-secondary)] sm:w-48">后端 API Base</span>
              <input value={settings.apiBase || DEFAULT_API_BASE} onChange={(event) => setSettings((current) => ({ ...current, apiBase: event.target.value }))} className={`${inputBase} min-w-0 flex-1`} placeholder="http://localhost:8000" />
            </label>
            <label className="flex flex-col gap-2 px-4 py-4 sm:flex-row sm:items-start sm:gap-4 sm:px-5">
              <span className="shrink-0 text-[length:var(--text-body)] text-[var(--text-secondary)] sm:w-48 sm:pt-2.5">Admin API Key<span className="ml-1 text-[length:var(--text-micro)] text-[var(--text-muted)]">兼容备用</span></span>
              <span className="min-w-0 flex-1">
                <input value={settings.adminApiKey} onChange={(event) => setSettings((current) => ({ ...current, adminApiKey: event.target.value }))} className={inputBase} type={keysVisible ? "text" : "password"} autoComplete="off" />
                {settings.adminApiKey.trim() && !hasConsoleAdmin ? (
                  <span className={`mt-2 block text-[length:var(--text-micro)] ${adminKeyVerified ? "text-[var(--tone-success-text)]" : "text-[var(--tone-warning-text)]"}`}>
                    {adminKeyVerified ? "✓ Key 已通过后端验证，管理面板已解锁" : adminKeyError || "正在向后端验证 Key…"}
                  </span>
                ) : null}
              </span>
            </label>
            <label className="flex flex-col gap-2 px-4 py-4 sm:flex-row sm:items-center sm:gap-4 sm:px-5">
              <span className="shrink-0 text-[length:var(--text-body)] text-[var(--text-secondary)] sm:w-48">Client / Gateway Key<span className="ml-1 text-[length:var(--text-micro)] text-[var(--text-muted)]">兼容备用</span></span>
              <input value={settings.clientApiKey} onChange={(event) => setSettings((current) => ({ ...current, clientApiKey: event.target.value }))} className={`${inputBase} min-w-0 flex-1`} type={keysVisible ? "text" : "password"} autoComplete="off" />
            </label>
            <label className="flex flex-col gap-2 px-4 py-4 sm:flex-row sm:items-center sm:gap-4 sm:px-5">
              <span className="shrink-0 text-[length:var(--text-body)] text-[var(--text-secondary)] sm:w-48">刷新间隔（秒）</span>
              <input value={settings.refreshInterval} onChange={(event) => setSettings((current) => ({ ...current, refreshInterval: Number(event.target.value) }))} className={`${inputBase} min-w-0 flex-1 sm:max-w-40`} min={10} type="number" />
            </label>
            <div className="flex flex-col gap-2 px-4 py-4 sm:flex-row sm:items-center sm:gap-4 sm:px-5">
              <span className="shrink-0 text-[length:var(--text-body)] text-[var(--text-secondary)] sm:w-48">当前会话</span>
              <span className={`text-[length:var(--text-body)] ${hasConsoleToken ? "text-[var(--tone-success-text)]" : "text-[var(--text-muted)]"}`}>
                {hasConsoleToken ? "后台 Token 已生效" : "未登录 Token（可留空 Key）"}
              </span>
            </div>
          </div>
        </div>

        {/* 偏好开关台账：主题选择器与三个 Switch 同构成行 */}
        <div className={`${glassPanelClass} overflow-hidden`}>
          <div className="border-b border-[var(--panel-border)] px-4 py-2 text-[length:var(--text-micro)] font-medium uppercase tracking-[0.08em] text-[var(--text-muted)] sm:px-5">
            界面偏好
          </div>
          <div className="divide-y divide-[var(--divider)]">
            <div className="flex flex-col gap-3 px-4 py-4 sm:flex-row sm:items-center sm:gap-4 sm:px-5">
              <span className="shrink-0 text-[length:var(--text-body)] text-[var(--text-secondary)] sm:w-48">
                主题<span className="ml-1.5 text-[length:var(--text-micro)] text-[var(--text-muted)]">
                  {settings.themeMode === "system" ? `跟随系统 · 当前${resolvedTheme === "dark" ? "深色" : "浅色"}` : ""}
                </span>
              </span>
              <div className="relative min-w-0 flex-1 sm:max-w-80">
                <ThemePreview selected={settings.themeMode} active={themePickerOpen} onClick={() => setThemePickerOpen((value) => !value)} />
                <AnimatePresence initial={false}>
                  {themePickerOpen ? (
                    <motion.div
                      initial={{ opacity: 0, y: 6, scale: 0.98 }}
                      animate={{ opacity: 1, y: 0, scale: 1, transition: { duration: 0.18, ease: [0.16, 1, 0.3, 1] } }}
                      exit={{ opacity: 0, y: 4, scale: 0.98, transition: { duration: 0.14, ease: [0.16, 1, 0.3, 1] } }}
                      className={floatingGlassMenuClass}
                    >
                      {THEME_OPTIONS.map((option) => {
                        const Icon = option.icon;
                        const selected = settings.themeMode === option.id;
                        return (
                          <button
                            key={option.id}
                            type="button"
                            onClick={() => {
                              setSettings((current) => ({ ...current, themeMode: option.id }));
                              setThemePickerOpen(false);
                            }}
                            className={`flex w-full items-center justify-between rounded-[var(--radius-md)] border px-3 py-2.5 text-left transition-[color,background-color,border-color,box-shadow,transform,opacity] duration-[var(--dur-fast)] active:scale-[0.98] ${
                              selected
                                ? "border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--surface-raised)] text-[var(--text-primary)] shadow-[var(--panel-shadow-soft)]"
                                : "border-transparent text-[var(--text-secondary)] hover:border-[var(--panel-border)] hover:bg-[var(--surface-raised)] hover:text-[var(--text-primary)]"
                            }`}
                          >
                            <span className="inline-flex items-center gap-3">
                              <span className="flex h-7 w-7 items-center justify-center rounded-[var(--radius-sm)] border border-[var(--panel-border)] bg-[var(--surface-raised)]">
                                <Icon className="h-4 w-4" aria-hidden />
                              </span>
                              <span>
                                <span className="block text-[length:var(--text-body)]">{option.label}</span>
                                <span className="block text-[length:var(--text-micro)] text-[var(--text-secondary)]">{option.description}</span>
                              </span>
                            </span>
                            <span
                              className={`flex h-6 w-6 items-center justify-center rounded-full border transition ${
                                selected
                                  ? "border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--tone-accent-surface)] text-[var(--tone-accent-text)] shadow-[var(--panel-shadow-soft)]"
                                  : "border-transparent text-transparent"
                              }`}
                            >
                              <Check className="h-3.5 w-3.5" aria-hidden />
                            </span>
                          </button>
                        );
                      })}
                    </motion.div>
                  ) : null}
                </AnimatePresence>
              </div>
            </div>
            <div className="flex items-center justify-between gap-4 px-4 py-4 sm:px-5">
              <span className="text-[length:var(--text-body)] text-[var(--text-secondary)]">自动刷新日志</span>
              <Switch label="切换自动刷新日志" checked={settings.autoRefresh} onChange={(value) => setSettings((current) => ({ ...current, autoRefresh: value }))} />
            </div>
            <div className="flex items-center justify-between gap-4 px-4 py-4 sm:px-5">
              <span className="text-[length:var(--text-body)] text-[var(--text-secondary)]">紧凑模式</span>
              <Switch label="切换紧凑模式" checked={settings.compactMode} onChange={(value) => setSettings((current) => ({ ...current, compactMode: value }))} />
            </div>
            <div className="flex items-center justify-between gap-4 px-4 py-4 sm:px-5">
              <span className="text-[length:var(--text-body)] text-[var(--text-secondary)]">桌面通知</span>
              <Switch
                label="切换桌面通知"
                checked={settings.desktopNotifications}
                onChange={(value) => {
                  setSettings((current) => ({ ...current, desktopNotifications: value }));
                  if (value && "Notification" in window) void Notification.requestPermission();
                }}
              />
            </div>
          </div>
        </div>

        {/* 动作栏：原来三颗按钮平铺在同一张卡底部，现在独立成条 + 左对齐主操作 */}
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={saveSettings} className={buttonClass("primary")}>
            <Save className="h-4 w-4" aria-hidden />
            保存设置
          </button>
          <button type="button" onClick={() => void checkHealth()} className={buttonClass("secondary")}>
            <Network className="h-4 w-4" aria-hidden />
            测试连接
          </button>
          <button type="button" onClick={resetSettings} className={buttonClass("secondary")}>
            <RefreshCcw className="h-4 w-4" aria-hidden />
            恢复默认
          </button>
          <button type="button" onClick={() => navigateTo("keys")} className={buttonClass("secondary")}>
            <KeyRound className="h-4 w-4" aria-hidden />
            密钥中心
          </button>
        </div>
      </section>

      <aside className="space-y-4">
        <section className={`${glassPanelClass} ${glassPanelMotionClass} flex flex-col p-5`}>
          <div className="relative flex items-center justify-between gap-2">
            <p className="text-[length:var(--text-micro)] font-semibold uppercase tracking-[0.12em] text-[var(--text-muted)]">账号</p>
            {!hasConsoleToken && user ? (
              <span className="chip chip-warning">演示身份</span>
            ) : (
              <span className="chip chip-success">已登录</span>
            )}
          </div>
          <div className="relative mt-4 flex items-center gap-3 border-b border-[var(--divider)] pb-4">
            <span aria-hidden className="grid h-10 w-10 shrink-0 place-items-center rounded-full border border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--tone-accent-surface)] text-[length:var(--text-subhead)] font-semibold text-[var(--tone-accent-text)]">
              {(user?.name || "?").trim().slice(0, 1).toUpperCase()}
            </span>
            <div className="min-w-0">
              <p className="truncate text-[length:var(--text-body)] font-semibold text-[var(--text-primary)]">{user?.name}</p>
              <p className="truncate text-[length:var(--text-micro)] text-[var(--text-muted)]">{user?.email}</p>
            </div>
          </div>
          <dl className="relative mt-4 space-y-3 text-[length:var(--text-body)]">
            <div className="flex items-baseline justify-between gap-3">
              <dt className="text-[var(--text-muted)]">角色</dt>
              <dd className="text-right font-medium text-[var(--text-primary)]">
                {user?.role}
                {!hasConsoleToken && user ? "（演示）" : ""}
              </dd>
            </div>
          </dl>
          <div className="flex-1" />
          <button type="button" onClick={logout} className={`${buttonClass("secondary")} relative mt-5 w-full`}>
            <LogOut className="h-4 w-4" aria-hidden />
            退出登录
          </button>
        </section>

        <section className={`${glassPanelClass} ${glassPanelMotionClass} flex flex-col p-5`}>
          <p className="relative text-[length:var(--text-micro)] font-semibold uppercase tracking-[0.12em] text-[var(--text-muted)]">本地</p>
          <h2 className="relative mt-1 text-[length:var(--text-title)] font-semibold tracking-[-0.012em] text-[var(--text-primary)]">本地数据</h2>
          <dl className="relative mt-4 divide-y divide-[var(--divider)] border-y border-[var(--divider)] text-[length:var(--text-body)]">
            <div className="flex items-baseline justify-between gap-3 py-3">
              <dt className="text-[var(--text-secondary)]">本地验证日志</dt>
              <dd className="tnum font-medium text-[var(--text-primary)]">{logs.filter((log) => log.id < 0).length}</dd>
            </div>
            <div className="flex items-baseline justify-between gap-3 py-3">
              <dt className="text-[var(--text-secondary)]">验证快照</dt>
              <dd className="tnum font-medium text-[var(--text-primary)]">{validationHistory.length}</dd>
            </div>
            <div className="flex items-baseline justify-between gap-3 py-3">
              <dt className="text-[var(--text-secondary)]">本地会话</dt>
              <dd className="text-right font-medium text-[var(--text-primary)]">{hasConsoleToken ? "Token 登录" : user ? "本地验证模式" : "无"}</dd>
            </div>
          </dl>
          <div className="flex-1" />
          <button type="button" onClick={clearLocalData} className={`${buttonClass("danger")} relative mt-5 w-full`}>
            <Trash2 className="h-4 w-4" aria-hidden />
            清除本地数据
          </button>
        </section>
      </aside>
    </div>
  );
}
