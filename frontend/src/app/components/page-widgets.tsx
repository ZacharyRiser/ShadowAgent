"use client";

// 页面级小组件：前端单体拆解阶段 1 自 page.tsx 原样搬出（逐字未改）。
// 颜色一律语义 token；Switch 滑块按选中态分叉（见其注释内的对比度实测记录）。

import type * as React from "react";
import { ChevronDown } from "lucide-react";
import { THEME_OPTIONS } from "../app-meta";
import { glassPanelClass } from "./ui-kit";

export function Sparkline({
  points,
  className = "",
  strokeWidth = 2,
}: {
  points: number[];
  className?: string;
  strokeWidth?: number;
}) {
  if (points.length < 2) {
    return <div className={`h-full w-full rounded-[inherit] bg-[var(--surface-raised)] ${className}`} aria-hidden />;
  }

  const width = 100;
  const height = 30;
  const max = Math.max(...points, 1);
  const step = width / (points.length - 1);
  const coords = points.map((value, index) => {
    const x = index * step;
    const y = height - (value / max) * (height - 2) - 1;
    return `${x.toFixed(2)},${y.toFixed(2)}`;
  });
  const linePoints = coords.join(" ");
  const areaPoints = `0,${height} ${linePoints} ${width},${height}`;

  return (
    <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" className={`h-full w-full ${className}`} aria-hidden>
      <defs>
        <linearGradient id="sparkline-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="rgba(45,212,191,0.35)" />
          <stop offset="100%" stopColor="rgba(45,212,191,0)" />
        </linearGradient>
      </defs>
      <polygon points={areaPoints} fill="url(#sparkline-fill)" />
      <polyline
        points={linePoints}
        fill="none"
        stroke="rgba(94,234,212,0.9)"
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}

export function Switch({
  checked,
  onChange,
  label,
  disabled = false,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      aria-pressed={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border transition duration-[var(--dur-fast)] focus:outline-none focus:ring-2 focus:ring-[var(--tone-accent)] disabled:cursor-not-allowed disabled:opacity-50 ${
        checked
          ? "border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--accent-solid)] shadow-[var(--panel-shadow-hover)]"
          : "border-[var(--panel-border)] bg-[var(--surface-raised)]"
      }`}
    >
      {/* 滑块配色必须**按选中态分叉**，单一颜色在 4 组（2 主题 × 2 状态）里必然有一组不达标：
          · 未选中：轨道 = --surface-raised（深色主题 oklch24% 深灰 / 浅色主题 纯白）
            → 滑块用 --text-primary（深色主题亮 95% / 浅色主题暗 24%）恒有对比。
          · 选中：轨道 = --accent-solid（深色主题亮青 66% / 浅色主题深青 43%）
            → 滑块必须用 --accent-on-solid（其语义本就是「实心强调色底上的前景色」）。
          ⚠️ 曾把两种情况都用 --text-primary：实测选中态对比度 深色主题 2.52:1、浅色主题 2.16:1，
          均低于 WCAG 1.4.11 对非文本 UI 组件要求的 3:1（浅色主题下近黑滑块压深青轨道，几乎看不见边界）。
          改后 4 组分别为 6.26 / 14.20 / 7.44 / 16.51，全部达标。改这两个值前请重算这 4 组对比度。 */}
      <span
        aria-hidden
        className={`h-5 w-5 rounded-full shadow-[var(--panel-shadow-soft)] transition-transform duration-[var(--dur-fast)] ease-[var(--ease-out-quart)] ${
          checked ? "bg-[var(--accent-on-solid)] translate-x-5" : "bg-[var(--text-primary)] translate-x-0.5"
        }`}
      />
    </button>
  );
}

export function PanelGlow() {
  // 面板顶部的 1px 高光分界线：编辑风的「栏线」，不是装饰性发光。
  // 用语义 token 而非 teal/rose 硬编码 —— 浅色主题下同样成立。
  return (
    <div
      aria-hidden
      className="pointer-events-none absolute inset-x-6 top-0 h-px bg-gradient-to-r from-transparent via-[color-mix(in_oklab,var(--tone-accent)_45%,transparent)] to-transparent"
    />
  );
}

export function ThemePreview({
  selected,
  active,
  onClick,
}: {
  selected: "system" | "light" | "dark";
  active: boolean;
  onClick: () => void;
}) {
  const option = THEME_OPTIONS.find((item) => item.id === selected) ?? THEME_OPTIONS[0];
  const Icon = option.icon;

  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex w-full items-center justify-between rounded-[var(--radius-md)] border px-3.5 py-3 text-left transition-[color,background-color,border-color,box-shadow,transform,opacity] duration-[var(--dur-fast)] ease-[var(--ease-out-quart)] active:scale-[0.98] ${
        active
          ? "border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--tone-accent-surface)] text-[var(--text-primary)] shadow-[var(--panel-shadow-soft)]"
          : "border-[var(--panel-border-soft)] bg-[var(--surface-elevated)] text-[var(--text-primary)] hover:border-[var(--panel-border-strong)] hover:bg-[var(--panel-bg-soft)]"
      }`}
      aria-expanded={active}
    >
      <span className="inline-flex items-center gap-3">
        <span className="flex h-10 w-10 items-center justify-center rounded-[var(--radius-md)] border border-[var(--panel-border-soft)] bg-[var(--field-bg)]">
          <Icon className="h-5 w-5" aria-hidden />
        </span>
        <span>
          <span className="block text-[length:var(--text-body)] font-medium">{option.label}</span>
          <span className="block text-[length:var(--text-micro)] text-[var(--text-secondary)]">{option.description}</span>
        </span>
      </span>
      <ChevronDown className={`h-4 w-4 transition-transform duration-[var(--dur-fast)] ${active ? "rotate-180" : ""}`} aria-hidden />
    </button>
  );
}

export const ledgerRowClass =
  "border-b border-[var(--divider)] transition-colors duration-[var(--dur-fast)] ease-[var(--ease-out-quart)] last:border-b-0 hover:bg-[var(--surface-sunken)]";

export const Ledger = ({
    columns,
    gridClass,
    header,
    children,
    empty,
    className = "",
  }: {
    columns?: string[];
    gridClass: string;
    header: React.ReactNode[];
    children: React.ReactNode;
    empty?: React.ReactNode;
    className?: string;
  }) => (
    <div className={`${glassPanelClass} overflow-hidden ${className}`}>
      <div className={`grid ${gridClass} items-center gap-x-4 border-b border-[var(--panel-border)] px-4 py-2 text-[length:var(--text-micro)] font-medium uppercase tracking-[0.08em] text-[var(--text-muted)] sm:px-5`}>
        {header.map((cell, index) => (
          <span key={index} className={columns?.[index] ?? ""}>
            {cell}
          </span>
        ))}
      </div>
      {empty ? (
        <p className="px-4 py-8 text-center text-[length:var(--text-body)] text-[var(--text-muted)] sm:px-5">{empty}</p>
      ) : null}
      {children}
    </div>
  );

export const RuleListSkeleton = ({ rows = 5 }: { rows?: number }) => (
    <div className={`${glassPanelClass} overflow-hidden`} role="status" aria-label="规则加载中">
      <span className="sr-only">正在加载自定义规则</span>
      <div className="hidden grid-cols-[3px_minmax(0,2fr)_minmax(0,0.7fr)_minmax(0,0.8fr)_minmax(0,0.7fr)_auto_auto] items-center gap-x-4 border-b border-[var(--panel-border)] px-5 py-2 lg:grid">
        <span /> <span /> <span /> <span /> <span /> <span /> <span />
      </div>
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          aria-hidden
          className="grid grid-cols-[3px_minmax(0,1fr)_auto] items-start gap-x-3 gap-y-2 border-b border-[var(--divider)] px-4 py-3.5 last:border-b-0 sm:px-5 lg:grid-cols-[3px_minmax(0,2fr)_minmax(0,0.7fr)_minmax(0,0.8fr)_minmax(0,0.7fr)_auto_auto] lg:items-center lg:gap-x-4 lg:gap-y-0"
        >
          <span className="col-start-1 h-9 w-[3px] self-start rounded-full skeleton lg:self-center" />
          <div className="col-start-2 flex flex-col gap-1.5">
            <span className="skeleton h-4 w-2/5" />
            <span className="skeleton h-3 w-4/5" />
          </div>
          <span className="skeleton col-start-2 h-3.5 w-16 lg:col-start-3" />
          <span className="skeleton col-start-3 h-3.5 w-14 justify-self-end lg:col-start-4 lg:justify-self-start" />
          <span className="skeleton col-start-2 mt-1.5 h-6 w-16 lg:col-start-6 lg:mt-0 lg:justify-self-center" />
          <span className="skeleton col-start-3 mt-1.5 h-6 w-16 justify-self-end lg:col-start-7 lg:mt-0" />
        </div>
      ))}
    </div>
  );
