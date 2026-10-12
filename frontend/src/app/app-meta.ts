// 控制台域常量与纯函数：前端单体拆解阶段 1 自 page.tsx 原样搬出（逐字未改）。
// 依赖：语义 token 类常量见 ui-kit；存储读写不触碰任何网络。

import { KeyRound, Monitor, MoonStar, Network, Shield, ShieldCheck, SunMedium } from "lucide-react";
import { parseDateValue } from "./time-utils";
import type { AppSettings, ManagedApiKeyItem, PolicyRule, RoleShowcaseDefinition, ToolPermission } from "./types";
import type { GlassSelectOption } from "./components/glass-select";

export const STORAGE_KEYS = {
  users: "shadow-agent-users",
  session: "shadow-agent-session",
  authSession: "shadow-agent-auth-session",
  settings: "shadow-agent-settings",
  policies: "shadow-agent-policies",
  tools: "shadow-agent-tools",
  localLogs: "shadow-agent-local-logs",
  validationRuns: "shadow-agent-validation-runs",
};

export const DEFAULT_API_BASE = process.env.NEXT_PUBLIC_SHADOW_AGENT_API_BASE ?? "http://localhost:8000";

export const DEFAULT_SETTINGS: AppSettings = {
  apiBase: DEFAULT_API_BASE,
  adminApiKey: "",
  clientApiKey: "",
  themeMode: "system",
  autoRefresh: false,
  refreshInterval: 30,
  compactMode: false,
  desktopNotifications: false,
};

export const DEFAULT_POLICIES: PolicyRule[] = [
  {
    id: "instruction-data",
    name: "指令与数据隔离",
    description: "把用户可信指令与检索结果、插件输出、工具返回值分层审计，重点防御间接提示词注入。",
    enabled: true,
    severity: "high",
    scope: "Prompt",
  },
  {
    id: "semantic-intent",
    name: "语义意图审计",
    description: "识别忽略系统指令、泄露隐藏提示词、越权执行和角色劫持等高风险语义。",
    enabled: true,
    severity: "high",
    scope: "Prompt",
  },
  {
    id: "tool-permission",
    name: "工具权限控制",
    description: "按工具名与参数约束 Agent 可调用的外部能力，避免被外部内容诱导执行危险动作。",
    enabled: true,
    severity: "medium",
    scope: "Tool",
  },
  {
    id: "log-redaction",
    name: "敏感字段脱敏",
    description: "在审计日志展示与导出前弱化 token、密钥、密码等敏感内容。",
    enabled: true,
    severity: "medium",
    scope: "Audit",
  },
];

export const DEFAULT_TOOLS: ToolPermission[] = [
  {
    id: "search_web",
    name: "search_web",
    description: "允许代理读取公开网页搜索结果，外部内容仍必须作为不可信数据处理。",
    allowed: true,
  },
  {
    id: "read_file",
    name: "read_file",
    description: "读取本地文件，默认关闭，防止被注入内容诱导泄露环境信息。",
    allowed: false,
  },
  {
    id: "execute_shell",
    name: "execute_shell",
    description: "执行系统命令，默认关闭，需要单独授权与参数审计。",
    allowed: false,
  },
];

export const THEME_OPTIONS = [
  { id: "system", label: "系统", description: "跟随设备外观", icon: Monitor },
  { id: "light", label: "浅色", description: "更通透、更温润", icon: SunMedium },
  { id: "dark", label: "深色", description: "更沉浸、更聚焦", icon: MoonStar },
] as const;

export const MANAGED_KEY_ROLE_OPTIONS: GlassSelectOption[] = [
  { value: "client", label: "Client", description: "适合普通调用方与业务接入方", icon: KeyRound },
  { value: "gateway", label: "Gateway", description: "适合受限网关、代理层或中间服务", icon: Network },
  { value: "security_admin", label: "Security Admin", description: "适合安全运营与策略管理人员", icon: ShieldCheck },
  { value: "admin", label: "Admin", description: "完整后台管理权限，仅少量发放", icon: Shield },
] as const;

export const ROLE_SHOWCASE_DEFINITIONS: RoleShowcaseDefinition[] = [
  {
    id: "admin",
    label: "Admin",
    badge: "全链路运营",
    description: "用于演示审批、策略、密钥和证据导出，适合评委查看完整闭环。",
    icon: ShieldCheck,
    tone: "border-[color-mix(in_oklab,var(--tone-danger)_28%,transparent)] bg-[var(--tone-danger-surface)] text-[var(--tone-danger-text)]",
    authHint: "控制台管理员登录，或签发 admin / security_admin 托管密钥。",
    judgeFocus: "看“攻击进入后如何被识别、拦截、留痕并复盘”的完整运营链路。",
    suitableFor: "答辩演示、SOC 运维、安全管理员、策略维护人员。",
    allowed: ["运行 /api/v1/analyze 与 /api/v1/chat/completions", "查看日志、审批、告警与回放", "签发、停用、删除托管密钥与调整策略"],
    restricted: ["不建议直接发给普通业务脚本", "不适合作为长期共享的接入身份"],
  },
  {
    id: "client",
    label: "Client",
    badge: "业务调用",
    description: "面向普通业务接入方，只保留安全网关调用能力，避免接触后台运营面。",
    icon: KeyRound,
    tone: "border-[color-mix(in_oklab,var(--tone-success)_28%,transparent)] bg-[var(--tone-success-surface)] text-[var(--tone-success-text)]",
    authHint: "登录后的普通用户 Token，或独立签发的 client 托管密钥。",
    judgeFocus: "看“正常业务可通过、危险请求被阻断”，同时避免误开放管理权限。",
    suitableFor: "业务系统、测试同学、普通 Agent 调用方。",
    allowed: ["运行 /api/v1/analyze 与 /api/v1/chat/completions", "载入验证场景并查看当前响应", "以最小权限完成常规业务请求"],
    restricted: ["不能查看日志、审批、告警与回放", "不能改策略，也不能管理托管密钥"],
  },
  {
    id: "gateway",
    label: "Gateway",
    badge: "代理入口",
    description: "适合作为统一代理层或中间服务身份，在转发前先完成安全审计。",
    icon: Network,
    tone: "border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--tone-accent-surface)] text-[var(--tone-info-text)]",
    authHint: "独立签发的 gateway 托管密钥，适合服务到服务调用。",
    judgeFocus: "看“代理层先拦截后转发”，并把来源标记和证据链沉淀下来。",
    suitableFor: "API Gateway、代理层、中间件、统一接入服务。",
    allowed: ["运行 /api/v1/analyze 与 /api/v1/chat/completions", "作为代理层统一承接高频调用", "把场景验证复用为入口安全回归"],
    restricted: ["不能查看日志、审批、告警与回放", "不能改策略，也不能管理托管密钥"],
  },
];

export const ROLE_PERMISSION_MATRIX = [
  { capability: "网关预检 /api/v1/analyze", admin: true, client: true, gateway: true },
  { capability: "真实网关调用 /api/v1/chat/completions", admin: true, client: true, gateway: true },
  { capability: "日志与证据查看", admin: true, client: false, gateway: false },
  { capability: "审批 / 告警 / 回放", admin: true, client: false, gateway: false },
  { capability: "策略与密钥治理", admin: true, client: false, gateway: false },
] as const;

export const floatingGlassMenuClass =
  "overflow-hidden rounded-[var(--radius-md)] border border-[var(--panel-border-strong)] bg-[var(--tooltip-bg)] p-1.5 shadow-[var(--tooltip-shadow)] backdrop-blur-[var(--blur-glass-lg)]";

export function canUseStorage() {
  return typeof window !== "undefined" && typeof window.localStorage !== "undefined";
}

export function writeStorage<T>(key: string, value: T) {
  if (canUseStorage()) {
    window.localStorage.setItem(key, JSON.stringify(value));
  }
}

export function removeStorage(key: string) {
  if (canUseStorage()) {
    window.localStorage.removeItem(key);
  }
}

export function describeSource(value: string) {
  const raw = (value || "").trim();
  if (!raw || raw === "unknown" || raw === "unknown|unknown") {
    return {
      label: "未知来源",
      detail: "后端暂时没有拿到可识别的调用来源。",
    };
  }

  const [hostPart, sourcePart = "direct"] = raw.split("|");
  const host = hostPart.trim();
  const source = sourcePart.trim();
  const via =
    source === "x-forwarded-for"
      ? "经代理转发"
      : source === "x-real-ip"
        ? "由上游网关透传"
        : source === "forwarded"
          ? "由标准 Forwarded 头传入"
          : "由当前连接直接识别";

  if (host === "127.0.0.1" || host === "::1" || host.toLowerCase() === "localhost") {
    return {
      label: "本机浏览器",
      detail: `${host} · ${via}`,
    };
  }

  if (host.startsWith("169.254.")) {
    return {
      label: "本机链路地址",
      detail: `${host} · ${via}`,
    };
  }

  if (isPrivateIpv4(host)) {
    return {
      label: "局域网设备",
      detail: `${host} · ${via}`,
    };
  }

  if (host.includes(":")) {
    return {
      label: "IPv6 来源",
      detail: `${host} · ${via}`,
    };
  }

  if (isIpv4Address(host)) {
    return {
      label: "公网或外部地址",
      detail: `${host} · ${via}`,
    };
  }

  return {
    label: "主机来源",
    detail: `${host} · ${via}`,
  };
}

export function managedKeyRoleLabel(role: string) {
  switch (role) {
    case "admin":
      return "管理员";
    case "security_admin":
      return "安全管理员";
    case "gateway":
      return "网关";
    case "client":
      return "客户端";
    default:
      return role || "未知角色";
  }
}

export function managedKeyStatus(item: ManagedApiKeyItem) {
  const expiresDate = parseDateValue(item.expires_at);
  const expiresAt = expiresDate ? expiresDate.getTime() : Number.POSITIVE_INFINITY;
  if (!item.is_active) {
    return {
      tone: "border-[color-mix(in_oklab,var(--tone-danger)_28%,transparent)] bg-[var(--tone-danger-surface)] text-[var(--tone-danger-text)]",
      chip: "chip-danger",
      label: "已停用",
      hint: "当前密钥已被后台停用，无法再调用受保护接口。",
    };
  }
  if (Number.isFinite(expiresAt) && expiresAt <= Date.now()) {
    return {
      tone: "border-[color-mix(in_oklab,var(--tone-warning)_28%,transparent)] bg-[var(--tone-warning-surface)] text-[var(--tone-warning-text)]",
      chip: "chip-warning",
      label: "已过期",
      hint: "当前密钥已经过期，需要轮换后才会重新签发新密钥。",
    };
  }
  return {
    tone: "border-[color-mix(in_oklab,var(--tone-success)_28%,transparent)] bg-[var(--tone-success-surface)] text-[var(--tone-success-text)]",
    chip: "chip-success",
    label: "生效中",
    hint: "当前密钥可正常使用。",
  };
}

export function severityChipClass(severity: PolicyRule["severity"]) {
  if (severity === "high") return "chip-danger";
  if (severity === "medium") return "chip-warning";
  return "chip-success";
}

export function severityTick(severity: PolicyRule["severity"]) {
  if (severity === "high") return "bg-[var(--tone-danger)]";
  if (severity === "medium") return "bg-[var(--tone-warning)]";
  return "bg-[var(--tone-success)]";
}

export function sanitizeSettingsForStorage(settings: AppSettings): AppSettings {
  // 关键：localStorage 里可能存着旧版本、被手改、或部分字段缺失的对象。
  // 之前直接 {...settings} 会让缺失的 apiBase 变成 undefined，
  // 然后 settings.apiBase.replace(...) 直接抛异常把整页打挂。
  // 这里对每个字段做兜底，保证返回的一定是结构完整的 AppSettings。
  const merged = { ...DEFAULT_SETTINGS, ...(settings ?? {}) };
  return {
    ...merged,
    apiBase: typeof merged.apiBase === "string" && merged.apiBase.trim() ? merged.apiBase : DEFAULT_API_BASE,
    themeMode:
      merged.themeMode === "light" || merged.themeMode === "dark" ? merged.themeMode : "system",
    refreshInterval:
      Number.isFinite(merged.refreshInterval) && merged.refreshInterval > 0
        ? merged.refreshInterval
        : DEFAULT_SETTINGS.refreshInterval,
    adminApiKey: "",
    clientApiKey: "",
  };
}

export function formatMetricsCount(value: number): string {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M`;
  if (value >= 10_000) return `${(value / 1_000).toFixed(1)}k`;
  return value.toLocaleString("zh-CN");
}

export function formatMetricsLatency(seconds: number): string {
  const ms = seconds * 1000;
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)}s`;
  if (ms >= 100) return `${ms.toFixed(0)}ms`;
  return `${ms.toFixed(1)}ms`;
}

export function isAdminRole(role: string | undefined) {
  return role === "admin" || role === "security_admin";
}

export function isIpv4Address(value: string) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value);
}

export function isPrivateIpv4(value: string) {
  if (!isIpv4Address(value)) return false;
  const parts = value.split(".").map(Number);
  if (parts.some((part) => Number.isNaN(part) || part < 0 || part > 255)) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  return false;
}

export function makeId(prefix: string) {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return `${prefix}-${crypto.randomUUID()}`;
  }

  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function readStorage<T>(key: string, fallback: T): T {
  if (!canUseStorage()) return fallback;
  const raw = window.localStorage.getItem(key);
  if (!raw) return fallback;

  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

