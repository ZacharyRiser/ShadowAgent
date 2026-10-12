// 数据层（阶段 3）：所有后端请求的统一出入口。
//
// 设计约定：
// · buildHeaders 是唯一决定「带 Console Token 还是 API Key」的地方（此前散在 page.tsx）。
// · apiGet/apiSend 抛 ApiError（带 status 与后端 detail 原文）；调用方 catch 后既可读
//   err.detail 自行翻译，也可直接展示 err.message（已是 detailText(detail) || HTTP xx）。
// · readJsonResponse 保持与既有代码逐行等价的容错语义：非 JSON 响应回退为空对象，
//   绝不让 .json() 抛错吞掉真正的 HTTP 状态判断。
// · 网络层失败（fetch 抛 TypeError）不在这里翻译成文案 —— 「Failed to fetch」→
//   「无法连接后端服务」的翻译属于 UI 层职责（见 auth-logic / 各 handler 的 catch）。

import type { AppSettings, AuthSession } from "./types";

/** 后端返回 detail 的统一文字化：string 直用，message/error 字段优先，其余 JSON 化。 */
export function detailText(value: unknown) {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return "-";
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    if (typeof record.message === "string" && record.message.trim()) {
      return record.message;
    }
    if (typeof record.error === "string" && record.error.trim()) {
      return record.error;
    }
  }
  return JSON.stringify(value);
}

/** Console 会话是否仍然有效（expiresAt 为 unix 秒，与后端判定同源）。 */
export function isAuthSessionValid(session: AuthSession | null) {
  return Boolean(session?.accessToken && session.expiresAt * 1000 > Date.now());
}

/**
 * 请求头构造：admin/client 意图选对应 API Key，Bearer Token 优先于 X-API-Key。
 * （从 page.tsx 原样迁入，行为不变。）
 */
export function buildHeaders(
  settings: AppSettings,
  intent: "admin" | "client",
  json = false,
  authSession: AuthSession | null = null
) {
  const headers: Record<string, string> = {};
  const apiKey =
    intent === "admin"
      ? settings.adminApiKey.trim()
      : settings.clientApiKey.trim();
  const bearerToken = isAuthSessionValid(authSession) ? authSession?.accessToken ?? "" : "";

  if (json) headers["Content-Type"] = "application/json";
  if (bearerToken) {
    headers.Authorization = `Bearer ${bearerToken}`;
  } else if (apiKey) {
    headers["X-API-Key"] = apiKey;
  }

  return headers;
}

/** 带 HTTP 状态与后端 detail 的请求失败。 */
export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(status: number, detail: unknown) {
    // 与既有 handler 的 `detailText(detail) || \`HTTP ${status}\`` 逐字等价（含 detail 缺失时
    // detailText 返回 "-" 的历史怪癖 —— 采用方若要改 UX 文案，单独改，别夹在重构里）。
    super(detailText(detail) || `HTTP ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

/** 与 page.tsx 既有写法逐行等价的响应体读取：非 JSON / 空体回退空对象。 */
export async function readJsonResponse(response: Response): Promise<unknown> {
  return (await response.json().catch(() => ({}))) as unknown;
}

/** GET：非 2xx 抛 ApiError；响应体始终经 readJsonResponse 容错读取。 */
export async function apiGet<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, { cache: "no-store", ...init });
  const data = await readJsonResponse(response);
  if (!response.ok) {
    throw new ApiError(response.status, (data as { detail?: unknown }).detail ?? data);
  }
  return data as T;
}

/** 带 method/body 的请求（POST/PUT/DELETE）：语义同 apiGet。 */
export async function apiSend<T>(
  url: string,
  method: "POST" | "PUT" | "PATCH" | "DELETE",
  body?: unknown,
  init?: RequestInit
): Promise<T> {
  const response = await fetch(url, {
    cache: "no-store",
    ...init,
    method,
    ...(body !== undefined ? { body: typeof body === "string" ? body : JSON.stringify(body) } : {}),
  });
  const data = await readJsonResponse(response);
  if (!response.ok) {
    throw new ApiError(response.status, (data as { detail?: unknown }).detail ?? data);
  }
  return data as T;
}
