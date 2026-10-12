"""Gateway core: /analyze inspection and /chat/completions enforcement."""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.audit import (
    _decision_payload,
    _log_semantic_monitor_event,
    _raise_if_blocked,
    _submit_audit_log,
    _threat_label_from_decision,
)
from app.config import (
    _allow_simulated_responses,
    _env_text,
    _unknown_tool_allowed,
    _upstream_proxy_enabled,
)
from app.custom_rules import custom_prompt_check
from app.dlp import apply_response_dlp
from app.schemas import AnalyzeRequest, ChatCompletionRequest, ChatMessage
from app.upstream import (
    _attach_shadow_agent_metadata,
    _forward_to_upstream,
    _resolved_upstream_model,
    _stream_upstream_response,
)
from database import get_db
from security_controls import (
    Principal,
    require_client,
    sanitize_json,
    sanitize_request_id,
)
from security_engine import (
    behavior_risk_check,
    inspect_prompt,
    permission_control,
    semantic_intent_check,
    separate_instruction_and_data,
)

logger = logging.getLogger("shadow_agent.gateway")

router = APIRouter(prefix="/api/v1", tags=["gateway"])


def _conversation_text(messages: list[ChatMessage]) -> str:
    """Build the non-system conversation transcript for history-wide auditing.

    System messages are treated as trusted client-side configuration; user,
    assistant, and tool history can carry smuggled injection payloads that
    last-user-message checks alone would miss. Assistant ``tool_calls`` belong
    to that same untrusted history: their arguments are the text the agent
    runtime is about to execute, so omitting them would leave a blind spot.
    """
    lines: list[str] = []
    for message in messages:
        if message.role == "system":
            continue
        lines.append(f"[{message.role}] {message.text}")
        for call in message.tool_calls or []:
            lines.append(
                f"[tool_call:{call.function.name}] {call.function.arguments}"
            )
    return "\n".join(lines)


def _run_semantic_checks(
    request_id: str,
    layer: str,
    text: str,
    original_prompt: str,
    db: Session,
    details: dict[str, Any] | None = None,
    org_id: int | None = None,
) -> None:
    """Run the fused regex+ML semantic layer over one text slice.

    Blocking decisions raise through ``_raise_if_blocked`` (403 + audit
    trail); monitor-mode suspicions are persisted as ``Monitored`` events.
    """

    decision = semantic_intent_check(text)
    _raise_if_blocked(
        request_id=request_id,
        layer=layer,
        decision=decision,
        source_excerpt=text,
        original_prompt=original_prompt,
        threat_type=_threat_label_from_decision(decision, layer),
        db=db,
        details=details,
        org_id=org_id,
    )
    _log_semantic_monitor_event(
        request_id=request_id,
        layer=layer,
        decision=decision,
        source_excerpt=text,
        original_prompt=original_prompt,
        details=details,
        org_id=org_id,
    )


def _latest_user_prompt(messages: list[ChatMessage]) -> str:
    for message in reversed(messages):
        if message.role == "user":
            return message.text
    raise HTTPException(
        status_code=400,
        detail={
            "error": "missing_user_message",
            "message": "At least one user message is required.",
        },
    )


@router.post("/analyze")
async def analyze_request(
    payload: AnalyzeRequest,
    principal: Principal = Depends(require_client),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    separated = separate_instruction_and_data(payload.prompt, payload.external_context)
    org_id = principal.org_id

    checks = {
        "prompt_blacklist": _decision_payload(
            inspect_prompt(separated["trusted_instruction"], db, org_id)
        ),
        "external_blacklist": _decision_payload(
            inspect_prompt(separated["untrusted_data"], db, org_id)
        ),
        "semantic_prompt": _decision_payload(
            semantic_intent_check(separated["trusted_instruction"])
        ),
        "semantic_external": _decision_payload(
            semantic_intent_check(separated["untrusted_data"])
        ),
        "permission_control": _decision_payload(
            permission_control(
                payload.tool_name,
                payload.parameters,
                db,
                org_id,
                unknown_tool_allowed=_unknown_tool_allowed(),
            )
        ),
        "behavior_risk": _decision_payload(
            behavior_risk_check(
                payload.prompt,
                payload.external_context,
                payload.tool_name,
                payload.parameters,
            )
        ),
        "custom_rules": _decision_payload(
            custom_prompt_check(
                f"{payload.prompt}\n{payload.external_context or ''}".strip(), db, org_id
            )
        ),
    }

    blocked_checks = [
        {"name": name, **decision}
        for name, decision in checks.items()
        if not bool(decision["allowed"])
    ]
    final_score = max([0.0, *[float(item["risk_score"]) for item in checks.values()]])
    final_category = blocked_checks[0]["category"] if blocked_checks else "none"
    final_recommended_action = (
        blocked_checks[0]["recommended_action"] if blocked_checks else "allow"
    )

    return {
        "decision": "blocked" if blocked_checks else "allowed",
        "risk_score": final_score,
        "category": final_category,
        "recommended_action": final_recommended_action,
        "blocked_checks": blocked_checks,
        "checks": checks,
        "separation": separated,
    }


@router.get("/models")
async def list_models(
    principal: Principal = Depends(require_client),
) -> dict[str, Any]:
    """OpenAI-compatible model listing so SDKs can point base_url here.

    Returns the configured upstream model plus the simulated model when
    simulated responses are enabled; de-duplicated and order-stable.
    """
    candidates: list[str] = []
    upstream_model = _env_text("SHADOW_AGENT_UPSTREAM_MODEL")
    if upstream_model:
        candidates.append(upstream_model)
    if _allow_simulated_responses():
        candidates.append("shadow-agent-simulated")

    seen: set[str] = set()
    data: list[dict[str, Any]] = []
    for model in candidates:
        if model in seen:
            continue
        seen.add(model)
        data.append(
            {
                "id": model,
                "object": "model",
                "created": 0,
                "owned_by": "shadow-agent",
            }
        )
    return {"object": "list", "data": data}


@router.post("/chat/completions")
async def chat_completions(
    payload: ChatCompletionRequest,
    request: Request,
    principal: Principal = Depends(require_client),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    request_id = (
        sanitize_request_id(request.headers.get("x-request-id")) or str(uuid.uuid4())
    )
    started_at = time.perf_counter()
    org_id = principal.org_id
    prompt = _latest_user_prompt(payload.messages)
    conversation_text = _conversation_text(payload.messages)

    separated = separate_instruction_and_data(prompt, payload.external_context)

    prompt_audit_decision = inspect_prompt(separated["trusted_instruction"], db, org_id)
    _submit_audit_log(
        request_id=request_id,
        layer="trusted_instruction",
        source_text=separated["trusted_instruction"],
        decision=prompt_audit_decision,
        org_id=org_id,
    )
    _raise_if_blocked(
        request_id=request_id,
        layer="trusted_instruction",
        decision=prompt_audit_decision,
        source_excerpt=separated["trusted_instruction"],
        original_prompt=prompt,
        threat_type=_threat_label_from_decision(prompt_audit_decision, "trusted_instruction"),
        db=db,
        details={
            "model": payload.model,
            "principal": principal.subject,
            "audit_source": "database_blacklist_policy",
        },
        org_id=org_id,
    )

    external_audit_decision = inspect_prompt(separated["untrusted_data"], db, org_id)
    _submit_audit_log(
        request_id=request_id,
        layer="untrusted_external_data",
        source_text=separated["untrusted_data"],
        decision=external_audit_decision,
        org_id=org_id,
    )
    _raise_if_blocked(
        request_id=request_id,
        layer="untrusted_external_data",
        decision=external_audit_decision,
        source_excerpt=separated["untrusted_data"],
        original_prompt=prompt,
        threat_type=_threat_label_from_decision(external_audit_decision, "untrusted_external_data"),
        db=db,
        details={
            "model": payload.model,
            "principal": principal.subject,
            "audit_source": "database_blacklist_policy",
            "indirect_prompt_injection": True,
        },
        org_id=org_id,
    )

    _run_semantic_checks(
        request_id=request_id,
        layer="trusted_instruction",
        text=separated["trusted_instruction"],
        original_prompt=prompt,
        db=db,
        details={"model": payload.model, "principal": principal.subject},
        org_id=org_id,
    )

    _run_semantic_checks(
        request_id=request_id,
        layer="untrusted_external_data",
        text=separated["untrusted_data"],
        original_prompt=prompt,
        db=db,
        details={"model": payload.model, "principal": principal.subject},
        org_id=org_id,
    )

    conversation_blacklist_decision = inspect_prompt(conversation_text, db, org_id)
    _submit_audit_log(
        request_id=request_id,
        layer="conversation_history",
        source_text=conversation_text,
        decision=conversation_blacklist_decision,
        org_id=org_id,
    )
    _raise_if_blocked(
        request_id=request_id,
        layer="conversation_history",
        decision=conversation_blacklist_decision,
        source_excerpt=conversation_text,
        original_prompt=prompt,
        threat_type=_threat_label_from_decision(
            conversation_blacklist_decision,
            "conversation_history",
        ),
        db=db,
        details={
            "model": payload.model,
            "principal": principal.subject,
            "audit_source": "database_blacklist_policy",
            "indirect_prompt_injection": True,
            "conversation_history_audit": True,
        },
        org_id=org_id,
    )

    _run_semantic_checks(
        request_id=request_id,
        layer="conversation_history",
        text=conversation_text,
        original_prompt=prompt,
        db=db,
        details={
            "model": payload.model,
            "principal": principal.subject,
            "conversation_history_audit": True,
        },
        org_id=org_id,
    )

    # Tool permission + behaviour risk, evaluated once per tool invocation.
    #
    # Real agent traffic declares tools with the OpenAI-native
    # ``messages[].tool_calls`` form, so reading only the legacy
    # ``tool_name``/``parameters`` fields left both engines dormant on
    # production traffic. When the caller declares no tool at all we still run
    # one pass with ``(None, None)``: ``behavior_risk_check`` inspects the
    # prompt text in that case, which is how in-prompt dangerous commands are
    # caught today.
    tool_invocations = payload.tool_invocations() or [(None, None)]
    tool_source = (
        "tool_calls"
        if any(message.tool_calls for message in payload.messages)
        else "legacy_fields"
    )
    unknown_tool_allowed = _unknown_tool_allowed()
    for invocation_index, (invoked_tool, invoked_parameters) in enumerate(tool_invocations):
        sanitized_parameters = sanitize_json(invoked_parameters or {})

        permission_decision = permission_control(
            invoked_tool,
            invoked_parameters,
            db,
            org_id,
            unknown_tool_allowed=unknown_tool_allowed,
        )
        _raise_if_blocked(
            request_id=request_id,
            layer="tool_permission",
            decision=permission_decision,
            source_excerpt=invoked_tool or "",
            original_prompt=prompt,
            threat_type=_threat_label_from_decision(permission_decision, "tool_permission"),
            db=db,
            details={
                "model": payload.model,
                "tool_name": invoked_tool,
                "parameters": sanitized_parameters,
                "principal": principal.subject,
                "tool_source": tool_source,
                "tool_invocation_index": invocation_index,
            },
            org_id=org_id,
        )

        behavior_decision = behavior_risk_check(
            prompt=conversation_text,
            external_context=payload.external_context,
            tool_name=invoked_tool,
            parameters=invoked_parameters,
        )
        _raise_if_blocked(
            request_id=request_id,
            layer="behavior_risk",
            decision=behavior_decision,
            source_excerpt=json.dumps(sanitized_parameters, ensure_ascii=False),
            original_prompt=prompt,
            threat_type=_threat_label_from_decision(behavior_decision, "behavior_risk"),
            db=db,
            details={
                "model": payload.model,
                "tool_name": invoked_tool,
                "parameters": sanitized_parameters,
                "principal": principal.subject,
                "tool_source": tool_source,
                "tool_invocation_index": invocation_index,
                "external_context_present": bool((payload.external_context or "").strip()),
            },
            org_id=org_id,
        )

    custom_rule_decision = custom_prompt_check(
        f"{prompt}\n{payload.external_context or ''}".strip(), db, org_id
    )
    _raise_if_blocked(
        request_id=request_id,
        layer="custom_rule",
        decision=custom_rule_decision,
        source_excerpt=prompt,
        original_prompt=prompt,
        threat_type="Custom Rule Match",
        db=db,
        details={
            "model": payload.model,
            "principal": principal.subject,
        },
        org_id=org_id,
    )

    latency_ms = round((time.perf_counter() - started_at) * 1000, 3)
    logger.info(
        "ShadowAgent allowed request_id=%s latency_ms=%.3f model=%s",
        request_id,
        latency_ms,
        payload.model,
    )

    if payload.stream:
        if _upstream_proxy_enabled():
            return await _stream_upstream_response(
                payload,
                request_id=request_id,
                separated=separated,
                db=db,
                org_id=org_id,
            )
        if not _allow_simulated_responses():
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "streaming_requires_upstream",
                    "message": "Streaming mode requires a configured upstream LLM provider.",
                },
            )

    if _upstream_proxy_enabled():
        upstream_response = await _forward_to_upstream(
            payload,
            request_id=request_id,
            separated=separated,
        )
        apply_response_dlp(
            upstream_response,
            request_id=request_id,
            db=db,
            details={"model": payload.model, "principal": principal.subject, "mode": "proxy"},
            org_id=org_id,
        )
        return _attach_shadow_agent_metadata(
            upstream_response,
            request_id=request_id,
            latency_ms=latency_ms,
            upstream_model=_resolved_upstream_model(payload.model),
        )

    if not _allow_simulated_responses():
        raise HTTPException(
            status_code=503,
            detail={
                "error": "upstream_not_configured",
                "message": (
                    "Configure SHADOW_AGENT_UPSTREAM_BASE_URL or "
                    "SHADOW_AGENT_UPSTREAM_CHAT_COMPLETIONS_URL to enable real LLM proxying. "
                    "Set SHADOW_AGENT_ALLOW_SIMULATED_RESPONSES=true only for local demos."
                ),
            },
        )

    return {
        "id": f"chatcmpl-shadow-{request_id}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": payload.model,
        "shadow_agent": {
            "request_id": request_id,
            "decision": "allowed",
            "mode": "simulated",
            "latency_ms": latency_ms,
            "checks": {
                "instruction_data_separation": "applied",
                "semantic_intent": "allowed",
                "permission_control": "allowed",
                "behavior_risk": "allowed",
            },
        },
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Shadow Agent gateway allowed this request. Downstream LLM call is simulated in this prototype.",
                },
                "finish_reason": "stop",
            }
        ],
    }
