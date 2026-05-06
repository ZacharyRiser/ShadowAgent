"""Shadow Agent FastAPI gateway prototype."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from security_engine import (
    AuditDecision,
    permission_control,
    semantic_intent_check,
    separate_instruction_and_data,
)


logger = logging.getLogger("shadow_agent.gateway")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

app = FastAPI(
    title="Shadow Agent Gateway",
    description="Middleware sandbox prototype for LLM agent runtime security.",
    version="0.1.0",
)


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str


class ChatCompletionRequest(BaseModel):
    model: str = Field(default="shadow-agent-simulated")
    messages: list[ChatMessage]
    external_context: str | None = Field(
        default=None,
        description="Untrusted retrieval/API/plugin result to be purified before LLM use.",
    )
    tool_name: str | None = Field(
        default=None,
        description="Optional downstream tool name requested by the agent runtime.",
    )
    parameters: dict[str, Any] | None = Field(
        default=None,
        description="Optional downstream tool parameters for permission checks.",
    )
    stream: bool = False


def _latest_user_prompt(messages: list[ChatMessage]) -> str:
    for message in reversed(messages):
        if message.role == "user":
            return message.content
    raise HTTPException(
        status_code=400,
        detail={
            "error": "missing_user_message",
            "message": "At least one user message is required.",
        },
    )


def _raise_if_blocked(
    request_id: str,
    layer: str,
    decision: AuditDecision,
    source_excerpt: str,
) -> None:
    if decision.allowed:
        return

    logger.warning(
        "ShadowAgent intercepted request_id=%s layer=%s reason=%s risk_score=%.2f matched_rules=%s source_excerpt=%r",
        request_id,
        layer,
        decision.reason,
        decision.risk_score,
        decision.matched_rules,
        source_excerpt[:200],
    )
    raise HTTPException(
        status_code=403,
        detail={
            "error": "shadow_agent_intercepted",
            "request_id": request_id,
            "layer": layer,
            "reason": decision.reason,
            "risk_score": decision.risk_score,
            "matched_rules": decision.matched_rules,
        },
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "shadow-agent-gateway"}


@app.post("/api/v1/chat/completions")
async def chat_completions(
    payload: ChatCompletionRequest,
    request: Request,
) -> dict[str, Any]:
    request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
    started_at = time.perf_counter()
    prompt = _latest_user_prompt(payload.messages)

    separated = separate_instruction_and_data(prompt, payload.external_context)

    prompt_decision = semantic_intent_check(separated["trusted_instruction"])
    _raise_if_blocked(
        request_id=request_id,
        layer="trusted_instruction",
        decision=prompt_decision,
        source_excerpt=separated["trusted_instruction"],
    )

    external_decision = semantic_intent_check(separated["untrusted_data"])
    _raise_if_blocked(
        request_id=request_id,
        layer="untrusted_external_data",
        decision=external_decision,
        source_excerpt=separated["untrusted_data"],
    )

    permission_decision = permission_control(payload.tool_name, payload.parameters)
    _raise_if_blocked(
        request_id=request_id,
        layer="tool_permission",
        decision=permission_decision,
        source_excerpt=payload.tool_name or "",
    )

    latency_ms = round((time.perf_counter() - started_at) * 1000, 3)
    logger.info(
        "ShadowAgent allowed request_id=%s latency_ms=%.3f model=%s",
        request_id,
        latency_ms,
        payload.model,
    )

    return {
        "id": f"chatcmpl-shadow-{request_id}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": payload.model,
        "shadow_agent": {
            "request_id": request_id,
            "decision": "allowed",
            "latency_ms": latency_ms,
            "checks": {
                "instruction_data_separation": "applied",
                "semantic_intent": "allowed",
                "permission_control": "allowed",
            },
        },
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Shadow Agent gateway allowed this request. Downstream LLM call is simulated in Task 1.",
                },
                "finish_reason": "stop",
            }
        ],
    }
