"use client";

import { AnimatePresence, motion, type Variants } from "framer-motion";
import { AlertTriangle, Copy, Fingerprint } from "lucide-react";
import type { KeyboardEvent } from "react";
import { buildTimeTooltip, formatBeijingTime } from "../time-utils";

export type InterceptLogCardData = {
  id: number;
  timestamp: string;
  threat_type: string;
  action_taken: string;
  original_prompt: string;
  details: Record<string, unknown>;
};

type AnimatedInterceptLogListProps = {
  logs: InterceptLogCardData[];
  onSelect: (log: InterceptLogCardData) => void;
  onCopyRequestId?: (requestId: string) => void;
  compact?: boolean;
  /** 窄容器（登录样例卡 / 侧栏）恒用堆叠 3 列，不随视口变化。 */
  dense?: boolean;
};

type GlassInterceptLogCardProps = {
  log: InterceptLogCardData;
  index?: number;
  compact?: boolean;
  /** 窄容器（登录样例卡 / 侧栏）恒用堆叠 3 列，不随视口变化。 */
  dense?: boolean;
  onSelect: (log: InterceptLogCardData) => void;
  onCopyRequestId?: (requestId: string) => void;
};

/* 列表级错峰：总时长受限（10 行约 200ms），不随条数线性增长。
   motion-design.md：错峰要用 --i 变量并限制总时长。 */
const listVariants: Variants = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.02, delayChildren: 0.02 },
  },
};

/* 行入场：只动 opacity 与 transform（GPU 友好）。
   不用 spring —— motion-design.md 明确避免回弹。 */
const rowVariants: Variants = {
  hidden: { opacity: 0, y: 6 },
  show: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.22, ease: [0.16, 1, 0.3, 1] },
  },
  exit: { opacity: 0, transition: { duration: 0.14, ease: [0.4, 0, 1, 1] } },
};

function detailText(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map(detailText).filter(Boolean).join(", ");
  if (value && typeof value === "object") return JSON.stringify(value);
  return "";
}

function categoryLabel(category: string): string {
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

function friendlyReason(reason: string, category: string): string {
  switch (reason) {
    case "dangerous_behavior_detected":
      return categoryLabel(category) ? `${categoryLabel(category)}，请求已被阻断。` : "检测到高风险危险行为。";
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
      return reason;
  }
}

function asNumber(value: unknown, fallback = 0): number {
  const next = Number(value);
  return Number.isFinite(next) ? next : fallback;
}

/* 风险分档：只保留"档位 + 语义色"两件事。
   不要发光、不要渐变、不要多层描边 —— 数据表里 40 行同时发光就是噪音。
   档位靠左侧 2px 竖条 + 文字色传达，不靠整块着色。 */
function riskMeta(score: number) {
  if (score >= 0.9) {
    return {
      label: "高危",
      tick: "bg-[var(--tone-danger)]",
      text: "text-[var(--tone-danger-text)]",
      reason: "检测到覆盖系统指令、泄露隐藏上下文、绕过工具权限或诱导代理执行越权动作的强信号。",
    };
  }

  if (score >= 0.65) {
    return {
      label: "中危",
      tick: "bg-[var(--tone-warning)]",
      text: "text-[var(--tone-warning-text)]",
      reason: "命中了可疑提示模式，需要结合来源、上下文隔离和工具权限继续审计。",
    };
  }

  return {
    label: "低危",
    tick: "bg-[var(--tone-success)]",
    text: "text-[var(--tone-success-text)]",
    reason: "当前风险信号较弱，但仍保留审计记录，便于追踪间接提示词注入链路。",
  };
}

function buildTooltip(log: InterceptLogCardData, fallback: string): string {
  const details = log.details;
  const reason = friendlyReason(detailText(details.reason), detailText(details.category)) || detailText(details.block_reason) || fallback;
  const rules = detailText(details.matched_rules) || detailText(details.rule_name) || detailText(details.triggered_rule);
  const excerpt = detailText(details.source_excerpt) || detailText(details.evidence);
  const layer = detailText(details.layer);

  return [
    reason,
    rules ? `命中规则: ${rules}` : "",
    layer ? `检测层: ${layer}` : "",
    excerpt ? `证据片段: ${excerpt}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

function getRequestId(log: InterceptLogCardData): string {
  return detailText(log.details.request_id) || `local-${log.id}`;
}

function safeDomId(value: string): string {
  return value.replace(/[^a-zA-Z0-9_-]/g, "-").slice(0, 80);
}

/* 布局策略：显式 `dense` 开关，不猜容器宽度。

   为什么不用 @container：Tailwind v4 的容器查询变体要求**父级**声明 `@container`，
   而列模板与「谁是容器」分散在两处，改动一处就会静默失配（上一版就是这么崩的）。
   为什么不用 md:/lg: 视口断点：这个组件同时出现在
   (a) 全宽日志页、(b) 约 360px 宽的登录样例卡、(c) 总览侧栏 ——
   同一个视口宽度下三者宽度可能相差 3 倍，视口断点必然猜错其中一种。

   → 由调用方显式声明版面：
     · dense=false（默认）：台账 5 列，`md:` 以下退化为堆叠 3 列
     · dense=true：恒为堆叠 3 列（竖条 / 内容 / 风险分），窄容器专用
   列模板字符串集中在本文件，表头与行共用同一常量，结构上不可能错位。 */
const DENSE_GRID =
  "grid grid-cols-[3px_minmax(0,1fr)_auto] items-start gap-x-3 gap-y-1.5";
const WIDE_GRID =
  "grid grid-cols-[3px_minmax(0,1fr)_auto] items-start gap-x-3 gap-y-1.5 md:grid-cols-[3px_minmax(0,1.1fr)_minmax(0,1.9fr)_minmax(0,0.85fr)_5.25rem] md:items-center md:gap-y-0 md:gap-x-4";

function rowGrid(dense: boolean) {
  return dense ? DENSE_GRID : WIDE_GRID;
}

/* 窄容器（dense）与宽容器（wide）下的行内定位。
   所有跨列/起始行列都显式声明 —— 不依赖自动流（auto-flow）猜位置，
   否则某个单元格的 col-span 一变，后面的单元格就会被推走（踩过）。

   栅格列： [① 3px 竖条] [② 内容] [③ 风险分]
   dense 三行：①|② 类型 + ③ 风险分 → ② 载荷（跨 2 列）→ ② 处置（跨 2 列）
   wide  一行：①|② 类型|② 载荷|② 处置|③ 风险分 对齐全宽台账列宽 */
function cellsClass(dense: boolean) {
  return dense
    ? {
        tick: "col-start-1 row-span-3 h-8 w-[3px] self-start rounded-full",
        threat: "col-start-2 row-start-1 min-w-0 truncate",
        prompt: "col-span-2 col-start-2 row-start-2 min-w-0",
        action: "col-span-2 col-start-2 row-start-3 flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1",
        score: "col-start-3 row-start-1 flex justify-end",
      }
    : {
        tick: "col-start-1 row-span-3 h-8 w-[3px] self-start rounded-full md:row-span-1 md:self-center",
        threat: "col-start-2 row-start-1 min-w-0 truncate md:row-start-auto",
        prompt: "col-span-2 col-start-2 row-start-2 min-w-0 md:col-span-1 md:col-start-3 md:row-start-auto",
        action:
          "col-span-2 col-start-2 row-start-3 flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 md:col-span-1 md:col-start-4 md:row-start-auto md:flex-col md:items-start md:gap-1",
        score: "col-start-3 row-start-1 flex justify-end md:col-start-5 md:row-start-auto",
      };
}

function LogListHeader({ dense = false }: { dense?: boolean }) {
  const cells = cellsClass(dense);
  return (
    <div
      className={`${rowGrid(dense)} sticky top-0 z-[var(--z-sticky)] border-b border-[var(--panel-border)] bg-[var(--panel-bg-solid)] px-4 py-2 text-[length:var(--text-micro)] font-medium uppercase tracking-[0.08em] text-[var(--text-muted)] sm:px-5`}
      aria-hidden
    >
      <span />
      <span className={cells.threat}>威胁类型</span>
      {dense ? null : (
        <>
          <span className="hidden md:block">原始载荷</span>
          <span className="hidden md:block">处置 / 请求 ID</span>
        </>
      )}
      <span className={`${dense ? "col-start-3" : "md:col-start-5"} text-right`}>风险</span>
    </div>
  );
}

export function AnimatedInterceptLogList({
  logs,
  compact = false,
  dense = false,
  onSelect,
  onCopyRequestId,
}: AnimatedInterceptLogListProps) {
  return (
    <motion.div
      variants={listVariants}
      initial="hidden"
      animate="show"
      className="overflow-hidden"
      role="table"
      aria-label="拦截日志列表"
    >
      <LogListHeader dense={dense} />
      <AnimatePresence mode="popLayout">
        {logs.map((log, index) => (
          <GlassInterceptLogCard
            key={`${log.id}-${getRequestId(log)}`}
            log={log}
            index={index}
            compact={compact}
            dense={dense}
            onSelect={onSelect}
            onCopyRequestId={onCopyRequestId}
          />
        ))}
      </AnimatePresence>
    </motion.div>
  );
}

/* 骨架屏：加载中也要保持与真实行完全一致的栅格，
   这样数据到达时不会发生布局跳动（CLS）。
   interaction-design.md：骨架屏优于 spinner。 */
export function LogListSkeleton({ rows = 8, dense = false }: { rows?: number; dense?: boolean }) {
  const cells = cellsClass(dense);
  return (
    <div role="status" aria-label="日志加载中" className="overflow-hidden">
      <LogListHeader dense={dense} />
      <span className="sr-only">正在加载拦截日志</span>
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          aria-hidden
          className={`${rowGrid(dense)} border-b border-[var(--divider)] px-4 py-3 last:border-b-0 sm:px-5`}
        >
          <span className={`${cells.tick} skeleton`} />
          <span className="skeleton h-4 w-4/5" />
          <span className={`${cells.prompt} flex flex-col gap-1.5`}>
            <span className="skeleton h-3.5 w-full" />
            <span className="skeleton h-3.5 w-3/5" />
          </span>
          <span className={`${cells.action} !flex-col gap-1.5`}>
            <span className="skeleton h-3.5 w-2/3" />
            <span className="skeleton h-3 w-4/5" />
          </span>
          <span className={cells.score}>
            <span className="skeleton h-5 w-14" />
          </span>
        </div>
      ))}
    </div>
  );
}

export function GlassInterceptLogCard({
  log,
  index = 0,
  compact = false,
  dense = false,
  onSelect,
  onCopyRequestId,
}: GlassInterceptLogCardProps) {
  const score = Math.max(0, Math.min(1, asNumber(log.details.risk_score)));
  const meta = riskMeta(score);
  const cells = cellsClass(dense);
  const requestId = getRequestId(log);
  const tooltip = buildTooltip(log, meta.reason);
  const tooltipId = `risk-tip-${log.id}-${safeDomId(requestId)}`;

  const handleKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(log);
    }
  };

  return (
    <motion.div
      layout
      variants={rowVariants}
      exit="exit"
      custom={index}
      tabIndex={0}
      role="row"
      aria-label={`查看拦截日志 ${requestId}`}
      onClick={() => onSelect(log)}
      onKeyDown={handleKeyDown}
      /* 行不是卡片：没有圆角、没有阴影、没有边框。
         分隔靠 border-b，hover 靠底色变化。
         列模板由 rowGrid(dense) 统一提供，表头与行共用，不可能错位。 */
      className={`${rowGrid(dense)} group relative cursor-pointer border-b border-[var(--divider)] px-4 py-3 outline-none transition-colors duration-[var(--dur-fast)] ease-[var(--ease-out-quart)] last:border-b-0 hover:bg-[var(--surface-sunken)] focus-visible:bg-[var(--surface-sunken)] focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-[var(--tone-accent)] sm:px-5`}
    >
      {/* 风险档位竖条：唯一的颜色信号源；hover 时伸长 25%，随行反馈 */}
      <span
        aria-hidden
        className={`${cells.tick} ${meta.tick} origin-center transition-transform duration-[var(--dur-fast)] ease-[var(--ease-out-quart)] group-hover:scale-y-125`}
      />

      {/* 威胁类型（窄容器下与风险分同行） */}
      <span className={`${cells.threat} text-[length:var(--text-caption)] font-medium text-[var(--text-primary)]`}>
        {log.threat_type || "Prompt Injection"}
      </span>

      {/* 原始载荷：窄容器下占第二行整宽 */}
      <span
        className={`${cells.prompt} font-mono text-[length:var(--text-caption)] leading-6 text-[var(--text-secondary)] line-clamp-2 md:line-clamp-2`}
        title={log.original_prompt}
      >
        {log.original_prompt || "No prompt payload captured."}
      </span>

      {/* 处置 + 请求 ID：窄容器下占第三行 */}
      <span className={cells.action}>
        <span className="inline-flex min-w-0 items-center gap-1.5 text-[length:var(--text-caption)] font-medium text-[var(--tone-danger-text)]">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden />
          <span className="truncate">{log.action_taken || "Blocked"}</span>
        </span>
        <span className="inline-flex min-w-0 items-center gap-1.5 text-[length:var(--text-micro)] text-[var(--text-muted)]">
          <Fingerprint className="h-3 w-3 shrink-0" aria-hidden />
          <span className="truncate font-mono" title={requestId}>
            {requestId}
          </span>
          {onCopyRequestId ? (
            <button
              type="button"
              onClick={(event) => {
                event.stopPropagation();
                onCopyRequestId(requestId);
              }}
              className="tap-target shrink-0 rounded-[var(--radius-xs)] p-0.5 text-[var(--text-muted)] opacity-0 transition-opacity duration-[var(--dur-fast)] hover:text-[var(--tone-accent-text)] focus-visible:opacity-100 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--tone-accent)] group-hover:opacity-100"
              aria-label={`复制请求 ID ${requestId}`}
              title="复制请求 ID"
            >
              <Copy className="h-3 w-3" aria-hidden />
            </button>
          ) : null}
        </span>
      </span>

      {/* 风险分：窄容器下与类型同行（第一行右端） */}
      <span className={cells.score}>
        <span className="relative inline-flex">
          <button
            type="button"
            onClick={(event) => {
              event.stopPropagation();
              onSelect(log);
            }}
            className={`peer inline-flex items-center gap-1.5 whitespace-nowrap rounded-[var(--radius-xs)] px-2 py-1 font-mono text-[length:var(--text-caption)] font-semibold tabular-nums outline-none transition-colors duration-[var(--dur-fast)] hover:bg-[var(--surface-raised)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--tone-accent)] ${meta.text}`}
            aria-describedby={tooltipId}
          >
            <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${meta.tick}`} aria-hidden />
            {score.toFixed(2)}
            <span className="font-sans text-[length:var(--text-micro)] font-medium whitespace-nowrap text-[var(--text-muted)]">
              {meta.label}
            </span>
          </button>
          <span
            id={tooltipId}
            role="tooltip"
            className="pointer-events-none absolute right-0 top-[calc(100%+0.5rem)] z-[var(--z-tooltip)] w-72 translate-y-1 whitespace-pre-line rounded-[var(--radius-md)] border border-[var(--tooltip-border)] bg-[var(--tooltip-bg)] px-3.5 py-3 text-left text-[length:var(--text-micro)] leading-5 text-[var(--tooltip-fg)] opacity-0 shadow-[var(--tooltip-shadow)] transition-[opacity,transform] duration-[var(--dur-fast)] ease-[var(--ease-out-quart)] peer-hover:translate-y-0 peer-hover:opacity-100 peer-focus-visible:translate-y-0 peer-focus-visible:opacity-100"
          >
            <span className="mb-1.5 block font-medium text-[var(--text-primary)]">{meta.label}风险说明</span>
            {tooltip}
          </span>
        </span>
      </span>
    </motion.div>
  );
}
