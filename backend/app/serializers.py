"""ORM row serializers shared across routers."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from app.schemas import (
    AlertEventResponse,
    ApprovalRequestResponse,
    CustomRuleResponse,
    ManagedApiKeyResponse,
    ReplayRunResponse,
    SecurityPolicyResponse,
    ToolPolicyResponse,
)
from app.utils import _json_loads_safe, _utc_timestamp
from models import (
    AlertEvent,
    ApprovalRequest,
    CustomRule,
    ManagedApiKey,
    ReplayRun,
    SecurityPolicy,
    ToolPolicy,
)


def _serialize_policy(policy: SecurityPolicy) -> dict[str, Any]:
    return SecurityPolicyResponse(
        id=policy.id,
        name=policy.name,
        blacklist_keyword=policy.blacklist_keyword,
        description=policy.description,
        severity=policy.severity,
        scope=policy.scope,
        enabled=policy.enabled,
        system_managed=policy.system_managed,
    ).model_dump()


def _serialize_tool_policy(policy: ToolPolicy) -> dict[str, Any]:
    return ToolPolicyResponse(
        id=policy.id,
        tool_name=policy.tool_name,
        description=policy.description,
        allowed=policy.allowed,
        requires_admin_approval=policy.requires_admin_approval,
        system_managed=policy.system_managed,
    ).model_dump()


def _serialize_custom_rule(rule: CustomRule) -> dict[str, Any]:
    return CustomRuleResponse(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        rule_type=rule.rule_type,
        pattern=rule.pattern,
        target=rule.target,
        action=rule.action,
        risk_score=float(rule.risk_score),
        enabled=rule.enabled,
        created_at=_utc_timestamp(rule.created_at),
        updated_at=_utc_timestamp(rule.updated_at),
    ).model_dump()


def _serialize_approval_request(item: ApprovalRequest) -> dict[str, Any]:
    return ApprovalRequestResponse(
        id=item.id,
        request_id=item.request_id,
        status=item.status,
        threat_type=item.threat_type,
        reason=item.reason,
        recommended_action=item.recommended_action,
        original_prompt=item.original_prompt,
        tool_name=item.tool_name,
        categories=_json_loads_safe(item.categories, []),
        evidence=_json_loads_safe(item.evidence, []),
        details=_json_loads_safe(item.details, {}),
        reviewed_by=item.reviewed_by,
        review_comment=item.review_comment,
        created_at=_utc_timestamp(item.created_at) or "",
        updated_at=_utc_timestamp(item.updated_at) or "",
    ).model_dump()


def _serialize_alert_event(item: AlertEvent) -> dict[str, Any]:
    return AlertEventResponse(
        id=item.id,
        request_id=item.request_id,
        severity=item.severity,
        channel=item.channel,
        title=item.title,
        summary=item.summary,
        status=item.status,
        details=_json_loads_safe(item.details, {}),
        created_at=_utc_timestamp(item.created_at) or "",
    ).model_dump()


def _serialize_replay_run(item: ReplayRun) -> dict[str, Any]:
    return ReplayRunResponse(
        id=item.id,
        source_request_id=item.source_request_id,
        replay_request_id=item.replay_request_id,
        triggered_by=item.triggered_by,
        verdict=item.verdict,
        risk_score=item.risk_score,
        category=item.category,
        details=_json_loads_safe(item.details, {}),
        created_at=_utc_timestamp(item.created_at) or "",
    ).model_dump()


def _serialize_managed_api_key(item: ManagedApiKey) -> dict[str, Any]:
    return ManagedApiKeyResponse(
        id=item.id,
        name=item.name,
        role=item.role,
        description=item.description,
        key_prefix=item.key_prefix,
        masked_key=f"{item.key_prefix}.<redacted>",
        created_by=item.created_by,
        is_active=item.is_active,
        expires_at=_utc_timestamp(item.expires_at),
        last_used_at=_utc_timestamp(item.last_used_at),
        last_used_by=item.last_used_by,
        created_at=_utc_timestamp(item.created_at) or "",
        updated_at=_utc_timestamp(item.updated_at) or "",
    ).model_dump()


def _resolve_managed_api_key_expiration(
    *,
    expires_in_days: int | None,
    clear_expiration: bool = False,
    fallback: datetime | None = None,
) -> datetime | None:
    if clear_expiration:
        return None
    if expires_in_days is None:
        return fallback
    return datetime.utcnow() + timedelta(days=expires_in_days)
