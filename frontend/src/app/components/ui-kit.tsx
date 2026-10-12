// 共享 UI 原语：语义类常量、按钮变体、空态、通用格式化助手。
// 从 page.tsx 原样搬出（前端单体拆解阶段 1）。零第三方依赖；
// 颜色一律语义 token（双主题成立），新代码禁止再写硬编码色类。

import type { ReactNode } from "react";
import { formatBeijingTime } from "../time-utils";
import type { SeverityLevel } from "../demo-scenarios";

export type IconComponent = React.ComponentType<{
  className?: string;
  "aria-hidden"?: boolean;
}>;

export const buttonBase =
  /* 结构层：颜色 / 悬停 / 按压 / 阴影全部由 globals.css 的 .btn-* 语义类承担，
     两套按钮体系已合并 —— 这里的变体只决定用哪个语义类。
     group 供图标微动效使用；spot 挂鼠标跟随光斑（globals.css .spot::before）。
     焦点态不在此声明：CSS 类的 box-shadow 会压掉 Tailwind ring，
     统一走 globals.css 的全局 :focus-visible outline（unlayered，优先级可靠）。 */
  "group spot inline-flex min-h-9 max-w-full shrink-0 items-center justify-center gap-2 rounded-[var(--radius-sm)] px-3.5 py-1.5 text-[length:var(--text-caption)] font-medium whitespace-nowrap disabled:cursor-not-allowed disabled:opacity-50";

export const inputBase =
  "min-h-9 w-full min-w-0 rounded-[var(--radius-sm)] border border-[var(--field-border)] bg-[var(--field-bg)] px-3 py-1.5 text-[length:var(--text-caption)] text-[var(--text-primary)] outline-none transition-colors duration-[var(--dur-fast)] placeholder:text-[var(--text-muted)] hover:border-[var(--field-border-strong)] focus:border-[var(--tone-accent)] focus:ring-2 focus:ring-[var(--tone-accent-surface)]";

export const glassPanelClass =
  "rounded-[var(--radius-lg)] border border-[var(--panel-border)] bg-[var(--panel-bg)] shadow-[var(--panel-shadow)] backdrop-blur-[var(--blur-glass)]";

export const glassPanelSoftClass =
  "rounded-[var(--radius-md)] border border-[var(--panel-border-soft)] bg-[var(--panel-bg-soft)] shadow-[var(--panel-shadow-soft)]";

export const glassPanelMotionClass =
  "group relative overflow-hidden transition-[border-color,background-color,box-shadow,transform] duration-[240ms] ease-[var(--ease-out-quart)] hover:-translate-y-0.5 hover:border-[var(--panel-border-strong)] hover:bg-[var(--panel-hover-bg)] hover:shadow-[var(--panel-shadow-hover)]";

export function buttonClass(variant: "primary" | "secondary" | "ghost" | "danger" = "secondary") {
  // 交互态（hover 抬升 / 按压 / 主按钮光泽扫过）统一收敛在 globals.css 的 .btn-*，
  // 此处不再用 Tailwind 重复定义颜色 —— 双轨合并后行为全站一致。
  return `${buttonBase} btn-${variant}`;
}

export function EmptyState({ icon: Icon, title, children }: { icon: IconComponent; title: string; children: ReactNode }) {
  return (
    <div className="flex min-h-48 flex-col items-center justify-center rounded-[var(--radius-lg)] border border-dashed border-[var(--panel-border)] bg-[var(--surface-raised)] px-5 py-8 text-center backdrop-blur-[14px]">
      <Icon className="h-8 w-8 text-[var(--text-muted)]" aria-hidden />
      <h3 className="mt-3 text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">{title}</h3>
      <div className="mt-2 max-w-xl text-[length:var(--text-body)] leading-6 text-[var(--text-secondary)]">{children}</div>
    </div>
  );
}

export function asNumber(value: unknown, fallback = 0) {
  const next = Number(value);
  return Number.isFinite(next) ? next : fallback;
}

export function formatTime(value: string) {
  return formatBeijingTime(value);
}

export function riskTone(score = 0) {
  if (score >= 0.9) return "border-[color-mix(in_oklab,var(--tone-danger)_28%,transparent)] bg-[var(--tone-danger-surface)] text-[var(--tone-danger-text)]";
  if (score >= 0.75) return "border-[color-mix(in_oklab,var(--tone-warning)_28%,transparent)] bg-[var(--tone-warning-surface)] text-[var(--tone-warning-text)]";
  return "border-[color-mix(in_oklab,var(--tone-success)_28%,transparent)] bg-[var(--tone-success-surface)] text-[var(--tone-success-text)]";
}

export function riskLabel(score = 0) {
  if (score >= 0.9) return "高危";
  if (score >= 0.75) return "中危";
  return "低危";
}

export function severityClass(severity: SeverityLevel) {
  if (severity === "high") return "chip chip-danger";
  if (severity === "medium") return "chip chip-warning";
  return "chip chip-success";
}

export function categoryLabel(category: string | undefined) {
  switch (category) {
    case "prompt_injection":
      return "提示词注入";
    case "tool_permission":
      return "未授权工具调用";
    case "secret_exfiltration":
      return "敏感信息外传";
    case "sensitive_file_access":
      return "敏感文件访问";
    case "internal_network_access":
      return "内网或元数据访问";
    case "credential_access":
      return "凭据访问";
    case "command_execution":
      return "危险命令执行";
    case "destructive_action":
      return "破坏性操作";
    case "privilege_escalation":
      return "权限提升";
    case "security_evasion":
      return "安全规避";
    case "persistence":
      return "持久化行为";
    default:
      return "";
  }
}

export function reasonLabel(reason: string | undefined, category?: string) {
  switch (reason) {
    case "dangerous_behavior_detected":
      return categoryLabel(category) || "检测到高风险危险行为。";
    case "prompt_injection_detected":
      return "检测到提示词注入迹象。";
    case "blacklisted_prompt_pattern_detected":
      return "命中了黑名单提示词规则。";
    case "tool_not_permitted":
      return "当前工具不在允许名单中。";
    case "admin_permission_required":
      return "该操作需要管理员权限。";
    case "admin_approval_required":
      return "该操作需要管理员审批。";
    default:
      return reason || "";
  }
}

export function friendlyDecisionReason(reason: string | undefined, category?: string) {
  const normalized = reasonLabel(reason, category);
  if (!normalized) return "系统判定该请求存在安全风险，已阻断。";
  if (normalized === categoryLabel(category) && normalized) {
    return `${normalized}，请求已被阻断。`;
  }
  return normalized;
}

