// 页面共享类型：前端单体拆解阶段 1 自 page.tsx 原样搬出（逐字未改）。
// IconComponent 来自 ui-kit；视图组件与本文件相互独立，无运行时依赖。

import type { IconComponent } from "./components/ui-kit";

export type ViewKey = "chat" | "overview" | "metrics" | "logs" | "policies" | "rules" | "keys" | "orgs" | "gateway" | "settings" | "help";

export type SessionUser = {
  id: string;
  name: string;
  email: string;
  role: string;
  createdAt: string;
};

export type AuthSession = {
  accessToken: string;
  expiresAt: number;
  tokenType: "bearer";
  user: SessionUser;
};

export type OrgInfo = {
  id: number;
  slug: string;
  name: string;
  is_default: boolean;
  role: string;
};

export type OrgListItem = OrgInfo & {
  member_count?: number;
  sso_enabled?: boolean;
  sso_provider?: string;
};

export type OrgMemberItem = {
  user_id: number;
  name: string;
  email: string;
  platform_role: string;
  is_active: boolean;
  org_role: string;
  joined_at: string;
};

export type SsoConfigItem = {
  org_id: number;
  provider_name: string;
  client_id: string;
  client_secret_masked: string;
  issuer_url: string;
  scopes: string;
  jit_enabled: boolean;
  default_role: string;
  enabled: boolean;
};

export type SsoHandoff = {
  access_token: string;
  token_type: string;
  expires_at: number;
};

export type InterceptLog = {
  id: number;
  timestamp: string;
  threat_type: string;
  action_taken: string;
  original_prompt: string;
  details: Record<string, unknown>;
};

export type PolicyRule = {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: "low" | "medium" | "high";
  scope: string;
  pattern?: string;
  systemManaged?: boolean;
  custom?: boolean;
};

export type ToolPermission = {
  id: string;
  name: string;
  description: string;
  allowed: boolean;
  requiresAdminApproval?: boolean;
  systemManaged?: boolean;
};

export type AppSettings = {
  apiBase: string;
  adminApiKey: string;
  clientApiKey: string;
  themeMode: "system" | "light" | "dark";
  autoRefresh: boolean;
  refreshInterval: number;
  compactMode: boolean;
  desktopNotifications: boolean;
};

export type Toast = {
  id: string;
  type: "success" | "error" | "info";
  message: string;
};

export type ChatMessage = {
  id: string;
  role: "user" | "assistant";
  content: string;
};

export type HealthState = {
  status: "unknown" | "checking" | "online" | "offline";
  message: string;
};

export type LocalDecision = {
  allowed: boolean;
  riskScore: number;
  reason: string;
  matchedRules: string[];
  layer: string;
  category?: string;
  recommendedAction?: string;
};

export type BackendPolicy = {
  id: number;
  name: string;
  blacklist_keyword: string;
  description: string;
  severity: string;
  scope: string;
  enabled: boolean;
  system_managed: boolean;
};

export type BackendToolPolicy = {
  id: number;
  tool_name: string;
  description: string;
  allowed: boolean;
  requires_admin_approval: boolean;
  system_managed: boolean;
};

export type AnalyzeResponse = {
  decision: "allowed" | "blocked";
  risk_score: number;
  category: string;
  recommended_action: string;
  blocked_checks: Array<Record<string, unknown>>;
  checks: Record<string, Record<string, unknown>>;
  separation?: Record<string, string>;
};

export type ApprovalItem = {
  id: number;
  request_id: string;
  status: string;
  threat_type: string;
  reason: string;
  recommended_action: string;
  original_prompt: string;
  tool_name: string;
  categories: string[];
  evidence: string[];
  details: Record<string, unknown>;
  reviewed_by: string;
  review_comment: string;
  created_at: string;
  updated_at: string;
};

export type AlertItem = {
  id: number;
  request_id: string;
  severity: string;
  channel: string;
  title: string;
  summary: string;
  status: string;
  details: Record<string, unknown>;
  created_at: string;
};

export type ReplayItem = {
  id: number;
  source_request_id: string;
  replay_request_id: string;
  triggered_by: string;
  verdict: string;
  risk_score: string;
  category: string;
  details: Record<string, unknown>;
  created_at: string;
};

export type ManagedApiKeyRole = "admin" | "security_admin" | "client" | "gateway";

export type ManagedApiKeyItem = {
  id: number;
  name: string;
  role: ManagedApiKeyRole | string;
  description: string;
  key_prefix: string;
  masked_key: string;
  created_by: string;
  is_active: boolean;
  expires_at: string | null;
  last_used_at: string | null;
  last_used_by: string;
  created_at: string;
  updated_at: string;
};

export type ManagedApiKeyIssueState = {
  action: "created" | "rotated";
  apiKey: string;
  item: ManagedApiKeyItem;
};

export type CustomRuleItemType = "regex" | "keyword";

export type CustomRuleTarget = "prompt" | "response" | "any";

export type CustomRuleAction = "block" | "redact" | "alert";

export type CustomRuleItem = {
  id: number;
  name: string;
  description: string;
  rule_type: CustomRuleItemType | string;
  pattern: string;
  target: CustomRuleTarget | string;
  action: CustomRuleAction | string;
  risk_score: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
};

export type CustomRuleDraft = {
  name: string;
  description: string;
  rule_type: CustomRuleItemType;
  pattern: string;
  target: CustomRuleTarget;
  action: CustomRuleAction;
  risk_score: number;
  enabled: boolean;
};

export type RuleTestMatch = {
  matched_text: string;
  span: [number, number];
};

export type RuleTestResult = {
  rule: { name: string; pattern: string; action: string; target: string };
  matched: boolean;
  match_count: number;
  matches: RuleTestMatch[];
};

export type DlpStatusInfo = {
  mode: "off" | "monitor" | "redact" | "block" | string;
  builtin_patterns: Array<{ type: string; risk_score: number; pattern: string }>;
};

export type RoleShowcaseId = "admin" | "client" | "gateway";

export type RoleShowcaseDefinition = {
  id: RoleShowcaseId;
  label: string;
  badge: string;
  description: string;
  icon: IconComponent;
  tone: string;
  authHint: string;
  judgeFocus: string;
  suitableFor: string;
  allowed: string[];
  restricted: string[];
};

export type MetricsRouteRow = {
  route: string;
  requests: number;
  statusCodes: Record<string, number>;
  latencySum: number;
  latencyCount: number;
};

export type ParsedMetrics = {
  totalRequests: number;
  blockedRequests: number;
  serverErrors: number;
  clientErrors: number;
  latencySum: number;
  latencyCount: number;
  routes: MetricsRouteRow[];
  retentionPurged: Record<string, number>;
};

export type MetricsHistoryPoint = {
  ts: number;
  totalRequests: number;
  blockedRequests: number;
  serverErrors: number;
  latencySum: number;
  latencyCount: number;
};
