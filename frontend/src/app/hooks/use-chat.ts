// 模型对话（chat）域：状态 + 提交流程 + 上游响应解析归仓（阶段 2）。
// submitChat 走网关的 /api/v1/chat/completions（client 意图鉴权），行为与拆出前逐行等价。

import { useMemo, useState } from "react";
import type { AppSettings, AuthSession, ChatMessage, Toast } from "../types";
import { buildHeaders, detailText } from "../api-client";
import { makeId } from "../app-meta";
import type { GlassSelectOption } from "../components/glass-select";

export const DEFAULT_CHAT_MODEL = process.env.NEXT_PUBLIC_SHADOW_AGENT_DEFAULT_MODEL ?? "deepseek-chat";

export const CHAT_MODEL_OPTIONS: GlassSelectOption[] = [
  { value: "deepseek-chat", label: "DeepSeek Chat" },
  { value: "deepseek-reasoner", label: "DeepSeek Reasoner" },
  { value: "deepseek-v4-flash", label: "DeepSeek V4 Flash" },
];

function extractChatContent(value: unknown) {
  if (!value || typeof value !== "object") return "";
  const choices = (value as Record<string, unknown>).choices;
  if (!Array.isArray(choices) || !choices[0] || typeof choices[0] !== "object") return "";

  const message = (choices[0] as Record<string, unknown>).message;
  if (!message || typeof message !== "object") return "";
  const content = (message as Record<string, unknown>).content;
  if (typeof content === "string") return content.trim();
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (typeof part === "string") return part;
        if (part && typeof part === "object") return detailText((part as Record<string, unknown>).text);
        return "";
      })
      .filter(Boolean)
      .join("\n")
      .trim();
  }
  return "";
}

export function useChat({
  apiBaseUrl,
  settings,
  authSession,
  addToast,
  hasGatewayAccess,
}: {
  apiBaseUrl: string;
  settings: AppSettings;
  authSession: AuthSession | null;
  addToast: (message: string, type?: Toast["type"]) => void;
  hasGatewayAccess: boolean;
}) {
  const [chatModel, setChatModel] = useState(DEFAULT_CHAT_MODEL);
  const [chatInput, setChatInput] = useState("");
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatLoading, setChatLoading] = useState(false);
  const [chatError, setChatError] = useState("");

  const chatModelOptions = useMemo<GlassSelectOption[]>(
    () =>
      CHAT_MODEL_OPTIONS.some((option) => option.value === chatModel)
        ? CHAT_MODEL_OPTIONS
        : [{ value: chatModel, label: chatModel }, ...CHAT_MODEL_OPTIONS],
    [chatModel],
  );

  const submitChat = async (event: { preventDefault(): void }) => {
    event.preventDefault();
    const prompt = chatInput.trim();

    if (!hasGatewayAccess) {
      setChatError("当前账号没有模型调用权限，请先登录或配置 Client / Gateway API Key。\nDeepSeek Key 不需要填写在这里。\n");
      return;
    }
    if (!prompt || chatLoading) return;

    const userMessage: ChatMessage = { id: makeId("chat-user"), role: "user", content: prompt };
    const requestMessages = [...chatMessages, userMessage].map(({ role, content }) => ({ role, content }));
    setChatMessages((current) => [...current, userMessage]);
    setChatInput("");
    setChatError("");
    setChatLoading(true);

    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 60_000);

    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/chat/completions`, {
        method: "POST",
        headers: buildHeaders(settings, "client", true, authSession),
        signal: controller.signal,
        body: JSON.stringify({
          model: chatModel,
          messages: requestMessages,
          stream: false,
        }),
      });
      const data = (await response.json().catch(() => ({}))) as Record<string, unknown>;
      if (!response.ok) {
        const detail = data.detail && typeof data.detail === "object" ? data.detail : data;
        throw new Error(detailText(detail) || `HTTP ${response.status}`);
      }

      const content = extractChatContent(data);
      if (!content) throw new Error("模型返回了空内容，请检查模型配置和上游响应。 ");
      setChatMessages((current) => [...current, { id: makeId("chat-assistant"), role: "assistant", content }]);
      addToast("模型已回复", "success");
    } catch (error) {
      const message =
        error instanceof Error && error.name === "AbortError"
          ? "请求超时，请检查后端和上游模型连接。"
          : error instanceof Error
            ? error.message
            : "模型请求失败。";
      setChatError(message);
      addToast(`模型请求失败：${message}`, "error");
    } finally {
      window.clearTimeout(timer);
      setChatLoading(false);
    }
  };

  return {
    chatModel,
    setChatModel,
    chatInput,
    setChatInput,
    chatMessages,
    setChatMessages,
    chatLoading,
    chatError,
    setChatError,
    submitChat,
    chatModelOptions,
  };
}
