"""Audit trail: intercept logging, approvals, alerts, admin action records."""

from __future__ import annotations

import json
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.alerts import enqueue_alert
from app.auth_helpers import _principal_label
from app.dlp import redact_for_log
from app.events import publish_event
from app.metrics import record_security_decision
from database import SessionLocal
from models import AlertEvent, ApprovalRequest, AuditLog, InterceptLog
from security_controls import Principal, redact_text, sanitize_json
from security_engine import AuditDecision

logger = logging.getLogger("shadow_agent.gateway")

audit_log_executor = ThreadPoolExecutor(max_workers=2)


def _threat_label_from_decision(decision: AuditDecision, layer: str) -> str:
    if decision.category == "tool_permission":
        return "Unauthorized Tool Use"
    if decision.category == "secret_exfiltration":
        return "Data Exfiltration"
    if decision.category == "sensitive_file_access":
        return "Sensitive File Access"
    if decision.category == "internal_network_access":
        return "Internal Network Access"
    if decision.category == "credential_access":
        return "Credential Access"
    if decision.category == "command_execution":
        return "Dangerous Command Execution"
    if decision.category == "destructive_action":
        return "Destructive Command"
    if decision.category == "privilege_escalation":
        return "Privilege Escalation"
    if decision.category == "security_evasion":
        return "Security Evasion"
    if decision.category == "persistence":
        return "Persistence"
    if layer == "tool_permission":
        return "Unauthorized Tool Use"
    return "Prompt Injection"


def _risk_level(score: float) -> str:
    if score >= 0.9:
        return "high"
    if score >= 0.75:
        return "medium"
    return "low"


def _decision_payload(decision: AuditDecision) -> dict[str, Any]:
    return {
        "allowed": decision.allowed,
        "reason": decision.reason,
        "risk_score": decision.risk_score,
        "matched_rules": decision.matched_rules,
        "category": decision.category,
        "categories": decision.categories,
        "evidence": decision.evidence,
        "recommended_action": decision.recommended_action,
    }


def _persist_audit_log(
    request_id: str,
    original_instruction: str,
    decision: AuditDecision,
    reason: str,
    org_id: int | None = None,
) -> None:
    db = SessionLocal()
    try:
        db.add(
            AuditLog(
                org_id=org_id,
                request_id=request_id,
                original_instruction=redact_for_log(original_instruction),
                risk_level=_risk_level(decision.risk_score),
                triggered_rule_name=", ".join(decision.matched_rules) or "none",
                intercept_reason=reason,
            )
        )
        db.commit()
    finally:
        db.close()


def _record_admin_action(
    db: Session,
    *,
    action: str,
    target: str,
    principal: Principal,
    details: dict[str, Any] | None = None,
    org_id: int | None = None,
) -> None:
    """Persist an audit entry for privileged management operations."""
    db.add(
        AuditLog(
            org_id=org_id if org_id is not None else principal.org_id,
            request_id=f"admin-{uuid.uuid4()}",
            original_instruction=redact_text(f"{action} {target}"),
            risk_level="info",
            triggered_rule_name=action[:128],
            intercept_reason=json.dumps(
                sanitize_json(
                    {
                        "action": action,
                        "target": target,
                        "actor": _principal_label(principal, db),
                        **(details or {}),
                    }
                ),
                ensure_ascii=False,
            ),
        )
    )


def _record_auth_event(db: Session, action: str, email: str) -> None:
    """Persist console authentication events for accountability.

    Uses plain ``redact_text`` rather than ``redact_for_log``: the account is an
    identity field, not payload. Masking it would erase who did what, which is
    the only thing this record is for. Payload redaction (``redact_for_log``) is
    for prompt and context text, where a secret may have been pasted by accident.
    """
    db.add(
        AuditLog(
            request_id=f"auth-{uuid.uuid4()}",
            original_instruction=redact_text(f"{action} {email}"),
            risk_level="info" if action == "login_success" else "medium",
            triggered_rule_name=action,
            intercept_reason=json.dumps(
                sanitize_json({"action": action, "account": email}),
                ensure_ascii=False,
            ),
        )
    )


def _submit_audit_log(
    request_id: str,
    layer: str,
    source_text: str,
    decision: AuditDecision,
    org_id: int | None = None,
) -> None:
    if decision.allowed:
        return

    reason = (
        "indirect_prompt_injection_detected_in_untrusted_external_context"
        if layer == "untrusted_external_data"
        else decision.reason
    )
    audit_log_executor.submit(
        _persist_audit_log,
        request_id,
        source_text,
        decision,
        reason,
        org_id,
    )


def _should_create_approval(decision: AuditDecision) -> bool:
    high_risk_categories = {
        "tool_permission",
        "command_execution",
        "destructive_action",
        "privilege_escalation",
        "security_evasion",
        "persistence",
        "secret_exfiltration",
        "credential_access",
        "internal_network_access",
        "sensitive_file_access",
    }
    return (
        not decision.allowed
        and (
            decision.risk_score >= 0.85
            or decision.category in high_risk_categories
            or any(category in high_risk_categories for category in decision.categories)
        )
    )


def _create_approval_request(
    *,
    request_id: str,
    decision: AuditDecision,
    threat_type: str,
    original_prompt: str,
    tool_name: str | None,
    details: dict[str, Any],
    db: Session,
    org_id: int | None = None,
) -> None:
    if not _should_create_approval(decision):
        return

    existing = (
        db.query(ApprovalRequest)
        .filter(ApprovalRequest.request_id == request_id, ApprovalRequest.status == "pending")
        .one_or_none()
    )
    if existing is not None:
        return

    db.add(
        ApprovalRequest(
            org_id=org_id,
            request_id=request_id,
            status="pending",
            threat_type=threat_type,
            reason=decision.reason,
            recommended_action=decision.recommended_action,
            original_prompt=redact_for_log(original_prompt),
            tool_name=(tool_name or "").strip(),
            categories=json.dumps(decision.categories, ensure_ascii=False),
            evidence=json.dumps(decision.evidence, ensure_ascii=False),
            details=json.dumps(sanitize_json(details), ensure_ascii=False),
        )
    )


def _create_alert_event(
    *,
    request_id: str,
    decision: AuditDecision,
    threat_type: str,
    details: dict[str, Any],
    db: Session,
    org_id: int | None = None,
) -> None:
    severity = _risk_level(decision.risk_score)
    if severity == "low":
        return

    db.add(
        AlertEvent(
            org_id=org_id,
            request_id=request_id,
            severity=severity,
            channel="console",
            title=f"{threat_type} intercepted",
            summary=decision.reason,
            status="triggered",
            details=json.dumps(
                sanitize_json(
                    {
                        "category": decision.category,
                        "categories": decision.categories,
                        "risk_score": decision.risk_score,
                        "matched_rules": decision.matched_rules,
                        **details,
                    }
                ),
                ensure_ascii=False,
            ),
        )
    )


def _raise_if_blocked(
    request_id: str,
    layer: str,
    decision: AuditDecision,
    source_excerpt: str,
    original_prompt: str,
    threat_type: str,
    db: Session,
    details: dict[str, Any] | None = None,
    org_id: int | None = None,
) -> None:
    if decision.allowed:
        return

    log_details = {
        "request_id": request_id,
        "layer": layer,
        "reason": decision.reason,
        "risk_score": decision.risk_score,
        "matched_rules": decision.matched_rules,
        "category": decision.category,
        "categories": decision.categories,
        "evidence": decision.evidence,
        "recommended_action": decision.recommended_action,
        "source_excerpt": redact_for_log(source_excerpt, max_chars=500),
        **(details or {}),
    }
    db.add(
        InterceptLog(
            org_id=org_id,
            request_id=request_id,
            threat_type=threat_type,
            action_taken="Blocked",
            original_prompt=redact_for_log(original_prompt),
            details=json.dumps(sanitize_json(log_details), ensure_ascii=False),
        )
    )
    _create_approval_request(
        request_id=request_id,
        decision=decision,
        threat_type=threat_type,
        original_prompt=original_prompt,
        tool_name=(details or {}).get("tool_name"),
        details=log_details,
        db=db,
        org_id=org_id,
    )
    _create_alert_event(
        request_id=request_id,
        decision=decision,
        threat_type=threat_type,
        details=log_details,
        db=db,
        org_id=org_id,
    )
    db.commit()

    record_security_decision(layer=layer, threat_type=threat_type, action="Blocked")

    logger.warning(
        "ShadowAgent intercepted request_id=%s layer=%s reason=%s category=%s risk_score=%.2f matched_rules=%s source_excerpt=%r",
        request_id,
        layer,
        decision.reason,
        decision.category,
        decision.risk_score,
        decision.matched_rules,
        source_excerpt[:200],
    )
    intercept_event = {
        "type": "intercept",
        "org_id": org_id,
        "request_id": request_id,
        "layer": layer,
        "threat_type": threat_type,
        "category": decision.category,
        "categories": decision.categories,
        "risk_score": decision.risk_score,
        "reason": decision.reason,
        "recommended_action": decision.recommended_action,
        "action_taken": "Blocked",
    }
    publish_event(intercept_event)
    enqueue_alert(intercept_event)
    raise HTTPException(
        status_code=403,
        detail={
            "error": "shadow_agent_intercepted",
            "request_id": request_id,
            "layer": layer,
            "reason": decision.reason,
            "risk_score": decision.risk_score,
            "matched_rules": decision.matched_rules,
            "category": decision.category,
            "categories": decision.categories,
            "evidence": decision.evidence,
            "recommended_action": decision.recommended_action,
        },
    )


def _log_semantic_monitor_event(
    *,
    request_id: str,
    layer: str,
    decision: AuditDecision,
    source_excerpt: str,
    original_prompt: str,
    details: dict[str, Any] | None = None,
    org_id: int | None = None,
) -> None:
    """Persist an intercept record for monitor-mode semantic suspicions.

    Monitor mode lets flagged traffic through on purpose (evaluation), but the
    suspicion must still land in the audit trail and live console feed —
    mirroring how the response-side DLP engine logs ``Monitored`` events.
    """

    if not decision.allowed or decision.reason != "semantic_injection_suspected":
        return

    threat_label = _threat_label_from_decision(decision, layer)
    record_security_decision(layer=layer, threat_type=threat_label, action="Monitored")

    log_details = {
        "request_id": request_id,
        "layer": layer,
        "reason": decision.reason,
        "risk_score": decision.risk_score,
        "matched_rules": decision.matched_rules,
        "category": decision.category,
        "categories": decision.categories,
        "evidence": decision.evidence,
        "recommended_action": decision.recommended_action,
        "source_excerpt": redact_for_log(source_excerpt, max_chars=500),
        "action_taken": "Monitored",
        **(details or {}),
    }
    db = SessionLocal()
    try:
        db.add(
            InterceptLog(
                org_id=org_id,
                request_id=request_id,
                threat_type=threat_label,
                action_taken="Monitored",
                original_prompt=redact_for_log(original_prompt),
                details=json.dumps(sanitize_json(log_details), ensure_ascii=False),
            )
        )
        db.commit()
    finally:
        db.close()

    logger.info(
        "ShadowAgent semantic monitor flag request_id=%s layer=%s risk_score=%.2f",
        request_id,
        layer,
        decision.risk_score,
    )
    monitor_event = {
        "type": "intercept",
        "org_id": org_id,
        "request_id": request_id,
        "layer": layer,
        "threat_type": threat_label,
        "category": decision.category,
        "categories": decision.categories,
        "risk_score": decision.risk_score,
        "reason": decision.reason,
        "recommended_action": decision.recommended_action,
        "action_taken": "Monitored",
    }
    publish_event(monitor_event)
    enqueue_alert(monitor_event)
