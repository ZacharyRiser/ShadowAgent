"use client";

// 模型对话视图：前端单体拆解阶段 1，JSX 自 page.tsx renderChat 逐字搬出（AST 定位，零手抄）。
// 状态与副作用仍归 page.tsx 所有（阶段 2 再归仓）；本组件纯展示 + 回调上抛。

import type { Dispatch, FormEvent, SetStateAction } from "react";
import { Bot, MessageSquare, Send, Settings, Trash2 } from "lucide-react";
import { motion } from "framer-motion";
import { GlassSelect, type GlassSelectOption } from "../components/glass-select";
import { buttonClass, glassPanelClass, inputBase } from "../components/ui-kit";
import type { ChatMessage, SessionUser, ViewKey } from "../types";

export function ChatView({
  chatError,
  chatInput,
  chatLoading,
  chatMessages,
  chatModel,
  chatModelOptions,
  hasGatewayAccess,
  navigateTo,
  setChatError,
  setChatInput,
  setChatMessages,
  setChatModel,
  submitChat,
  user,
}: {
  chatError: string;
  chatInput: string;
  chatLoading: boolean;
  chatMessages: ChatMessage[];
  chatModel: string;
  chatModelOptions: GlassSelectOption[];
  hasGatewayAccess: boolean;
  navigateTo: (target: ViewKey) => void;
  setChatError: Dispatch<SetStateAction<string>>;
  setChatInput: Dispatch<SetStateAction<string>>;
  setChatMessages: Dispatch<SetStateAction<ChatMessage[]>>;
  setChatModel: Dispatch<SetStateAction<string>>;
  submitChat: (event: FormEvent<HTMLFormElement>) => Promise<void>;
  user: SessionUser | null;
}) {
  return (
    <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_300px]">
      <section className={`${glassPanelClass} relative overflow-hidden p-5`}>
        <div className="relative flex min-h-[620px] flex-col">
          <div className="flex flex-col gap-4 border-b border-[var(--divider)] pb-5 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <div className="flex items-center gap-2 text-[length:var(--text-body)] font-medium text-[var(--tone-accent-text)]">
                <MessageSquare className="h-4 w-4" aria-hidden />
                安全对话入口
              </div>
              <h2 className="mt-2 text-[length:var(--text-title)] font-semibold text-[var(--text-primary)]">开始与模型对话</h2>
              <p className="mt-2 max-w-2xl text-[length:var(--text-body)] leading-6 text-[var(--text-secondary)]">
                每条消息都会先经过 Shadow Agent 审计，再转发给已配置的模型。你的上游 API Key 不会出现在这里。
              </p>
            </div>
            <button
              type="button"
              onClick={() => {
                setChatMessages([]);
                setChatInput("");
                setChatError("");
              }}
              disabled={!chatMessages.length && !chatInput}
              className={buttonClass("secondary")}
            >
              <Trash2 className="h-4 w-4" aria-hidden />
              新建对话
            </button>
          </div>

          <div className="relative mt-5 min-h-[380px] flex-1 overflow-y-auto rounded-[var(--radius-lg)] border border-[var(--panel-border-soft)] bg-[var(--surface-raised)] p-5" aria-live="polite">
            {!chatMessages.length && !chatLoading ? (
              <div className="flex min-h-[340px] flex-col items-center justify-center px-5 text-center">
                <div className="flex h-16 w-16 items-center justify-center rounded-[var(--radius-lg)] border border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--tone-accent-surface)] text-[var(--tone-accent-text)] shadow-[var(--panel-shadow-soft)]">
                  <MessageSquare className="h-7 w-7" aria-hidden />
                </div>
                <h3 className="mt-4 text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">还没有消息</h3>
                <p className="mt-2 max-w-md text-[length:var(--text-body)] leading-6 text-[var(--text-secondary)]">
                  输入你的问题，Shadow Agent 会在安全检查通过后请求模型。
                </p>
              </div>
            ) : (
              <div className="space-y-5">
                {chatMessages.map((message) => (
                  <motion.div
                    key={message.id}
                    initial={{ opacity: 0, y: 12, scale: 0.98 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1] }}
                    className={`flex ${message.role === "user" ? "justify-end" : "justify-start"}`}
                  >
                    <div className={`max-w-[min(760px,90%)] ${message.role === "user" ? "items-end" : "items-start"}`}>
                      <div className="mb-1.5 px-1.5 text-[length:var(--text-micro)] text-[var(--text-muted)]">{message.role === "user" ? "你" : "Shadow Agent"}</div>
                      <div
                        className={`whitespace-pre-wrap break-words border px-4.5 py-3.5 text-[length:var(--text-body)] leading-7 ${
                          message.role === "user"
                            ? "rounded-[var(--radius-lg)] rounded-tr-xs border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-gradient-to-br from-[color-mix(in_oklab,var(--tone-accent)_16%,transparent)] to-[color-mix(in_oklab,var(--tone-accent)_8%,transparent)] text-[var(--text-primary)] shadow-[var(--panel-shadow-soft)]"
                            : "rounded-[var(--radius-lg)] rounded-tl-xs border-[var(--panel-border-soft)] bg-[var(--surface-elevated)] text-[var(--text-primary)] shadow-[var(--panel-shadow-soft)]"
                        }`}
                      >
                        {message.content}
                      </div>
                    </div>
                  </motion.div>
                ))}
                {chatLoading ? (
                  <div className="flex justify-start">
                    <div className="flex items-center gap-2.5 rounded-[var(--radius-lg)] rounded-tl-xs border border-[var(--panel-border-soft)] bg-[var(--surface-elevated)] px-4.5 py-3 text-[length:var(--text-body)] text-[var(--text-secondary)] shadow-[var(--panel-shadow-soft)]">
                      <span className="flex gap-1">
                        <span className="chat-dot h-2 w-2 rounded-full bg-[var(--tone-accent-surface)]" />
                        <span className="chat-dot h-2 w-2 rounded-full bg-[var(--tone-accent-surface)]" />
                        <span className="chat-dot h-2 w-2 rounded-full bg-[var(--tone-accent-surface)]" />
                      </span>
                      <span>正在请求模型...</span>
                    </div>
                  </div>
                ) : null}
              </div>
            )}
          </div>

          {chatError ? (
            <div className="relative mt-4 rounded-[var(--radius-md)] border border-[color-mix(in_oklab,var(--tone-danger)_28%,transparent)] bg-[var(--tone-danger-surface)] px-4 py-3 text-[length:var(--text-body)] leading-6 text-[var(--tone-danger-text)]" role="alert">
              {chatError}
            </div>
          ) : null}

          <form onSubmit={submitChat} className="relative mt-4 flex flex-col gap-3 sm:flex-row sm:items-end">
            <label className="min-w-0 flex-1">
              <span className="sr-only">输入消息</span>
              <textarea
                value={chatInput}
                onChange={(event) => setChatInput(event.target.value)}
                className={`${inputBase} min-h-24 resize-y py-3 leading-6`}
                placeholder="输入你想咨询的问题"
                disabled={chatLoading}
              />
            </label>
            <button type="submit" disabled={chatLoading || !chatInput.trim()} className={`${buttonClass("primary")} min-h-24 shrink-0 sm:w-28`}>
              <Send className="h-4 w-4 transition-transform duration-[var(--dur-fast)] ease-[var(--ease-out-quart)] group-hover:translate-x-0.5" aria-hidden />
              {chatLoading ? "处理中" : "发送"}
            </button>
          </form>
        </div>
      </section>

      <aside className="space-y-5">
        <section className={`${glassPanelClass} relative overflow-hidden p-5`}>
          <div className="relative flex items-center gap-2 text-[length:var(--text-body)] font-semibold text-[var(--text-primary)]">
            <Bot className="h-4 w-4 text-[var(--tone-accent-text)]" aria-hidden />
            对话设置
          </div>
          <label className="relative mt-5 block">
            <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">模型</span>
            <GlassSelect value={chatModel} onChange={setChatModel} options={chatModelOptions} ariaLabel="选择对话模型" />
          </label>
          <div className="relative mt-5 space-y-3 border-t border-[var(--divider)] pt-4 text-[length:var(--text-body)]">
            <div className="flex items-center justify-between gap-3">
              <span className="text-[var(--text-secondary)]">安全审计</span>
              <span className="rounded-full border border-[color-mix(in_oklab,var(--tone-success)_28%,transparent)] bg-[var(--tone-success-surface)] px-2.5 py-0.5 text-[length:var(--text-micro)] text-[var(--tone-success-text)]">已启用</span>
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-[var(--text-secondary)]">当前账号</span>
              <span className="max-w-[150px] truncate text-[var(--text-primary)]">{user?.email}</span>
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-[var(--text-secondary)]">网关访问</span>
              <span className={hasGatewayAccess ? "text-[var(--tone-success-text)]" : "text-[var(--tone-danger-text)]"}>{hasGatewayAccess ? "可用" : "未配置"}</span>
            </div>
          </div>
        </section>

        <section className={`${glassPanelClass} relative overflow-hidden p-5`}>
          <h2 className="relative text-[length:var(--text-body)] font-semibold text-[var(--text-primary)]">调用链路</h2>
          <div className="relative mt-4 space-y-2.5 text-[length:var(--text-body)]">
            {["你的消息", "Shadow Agent 安全审计", "已配置的大模型"].map((item, index) => (
              <div key={item} className="flex items-center gap-3">
                <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-[var(--radius-md)] border border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)] bg-[var(--tone-accent-surface)] text-[length:var(--text-micro)] font-semibold text-[var(--tone-accent-text)]">{index + 1}</span>
                <span className="text-[var(--text-secondary)]">{item}</span>
              </div>
            ))}
          </div>
          <button type="button" onClick={() => navigateTo("settings")} className={`${buttonClass("secondary")} relative mt-5 w-full`}>
            <Settings className="h-4 w-4" aria-hidden />
            配置连接
          </button>
        </section>
      </aside>
    </div>
  );
}
