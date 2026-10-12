"""Custom detection rule engine: validation, compilation, evaluation.

Custom rules complement the built-in engines. On the prompt side a matching
``block`` rule rejects the request (layer ``custom_rule``); ``alert`` rules
only annotate the decision. On the response side rules feed the DLP scanner
(``app.dlp``) where ``redact`` is additionally supported.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING

from fastapi import HTTPException
from sqlalchemy import or_
from sqlalchemy.orm import Session

from models import CustomRule
from security_engine import AuditDecision

if TYPE_CHECKING:
    pass

RULE_TYPES = {"regex", "keyword"}
RULE_TARGETS = {"prompt", "response", "any"}
RULE_ACTIONS = {"block", "redact", "alert"}
MAX_PATTERN_LENGTH = 512
MAX_CUSTOM_RULES = 200


@dataclass(frozen=True, slots=True)
class RuleHit:
    rule: CustomRule
    matched_text: str
    span: tuple[int, int]


def validate_rule_fields(
    *,
    rule_type: str,
    pattern: str,
    target: str,
    action: str,
    risk_score: float,
) -> None:
    """Raise HTTP 400 for anything that would break or confuse the engine."""
    if rule_type not in RULE_TYPES:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_rule_type",
                "message": f"rule_type must be one of {sorted(RULE_TYPES)}.",
            },
        )
    if target not in RULE_TARGETS:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_rule_target",
                "message": f"target must be one of {sorted(RULE_TARGETS)}.",
            },
        )
    if action not in RULE_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_rule_action",
                "message": f"action must be one of {sorted(RULE_ACTIONS)}.",
            },
        )
    if action == "redact" and target == "prompt":
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_rule_action_for_target",
                "message": "action 'redact' only applies to response-side rules; use 'block' or 'alert' for prompts.",
            },
        )
    if not pattern.strip():
        raise HTTPException(
            status_code=400,
            detail={"error": "empty_pattern", "message": "pattern must not be empty."},
        )
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "pattern_too_long",
                "message": f"pattern must be at most {MAX_PATTERN_LENGTH} characters.",
            },
        )
    if not 0.0 <= risk_score <= 1.0:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_risk_score",
                "message": "risk_score must be between 0.0 and 1.0.",
            },
        )
    if rule_type == "regex":
        try:
            re.compile(pattern, re.IGNORECASE | re.DOTALL)
        except re.error as exc:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_regex_pattern",
                    "message": f"pattern is not a valid regular expression: {exc}",
                },
            )


@lru_cache(maxsize=512)
def _compiled_rule(rule_type: str, pattern: str) -> re.Pattern[str] | None:
    try:
        if rule_type == "keyword":
            return re.compile(re.escape(pattern), re.IGNORECASE)
        return re.compile(pattern, re.IGNORECASE | re.DOTALL)
    except re.error:
        return None


def enabled_rules(
    db: Session,
    *,
    target: str,
    org_id: int | None = None,
) -> list[CustomRule]:
    """Enabled rules relevant for a scan target (exact match or 'any').

    With ``org_id`` the organization's own rules plus platform-shared
    (``org_id IS NULL``) rules apply; without it every enabled rule does
    (platform principals).
    """
    query = db.query(CustomRule).filter(
        CustomRule.enabled.is_(True),
        CustomRule.target.in_([target, "any"]),
    )
    if org_id is not None:
        query = query.filter(or_(CustomRule.org_id == org_id, CustomRule.org_id.is_(None)))
    return query.order_by(CustomRule.id.asc()).all()


def match_rules(text: str, rules: list[CustomRule]) -> list[RuleHit]:
    """Return every rule hit on ``text`` (rule-level first match as evidence)."""
    if not text:
        return []
    hits: list[RuleHit] = []
    for rule in rules:
        pattern = _compiled_rule(rule.rule_type, rule.pattern)
        if pattern is None:
            continue
        match = pattern.search(text)
        if match:
            hits.append(RuleHit(rule=rule, matched_text=match.group(0)[:200], span=match.span()))
    return hits


def custom_prompt_check(
    text: str,
    db: Session,
    org_id: int | None = None,
) -> AuditDecision:
    """Evaluate prompt-side custom rules (target prompt/any) on ``text``.

    block rules reject the request; alert (and response-only redact) rules
    annotate the decision without blocking.
    """
    rules = enabled_rules(db, target="prompt", org_id=org_id)
    if not rules or not text.strip():
        return AuditDecision(allowed=True, risk_score=0.0)

    hits = match_rules(text, rules)
    if not hits:
        return AuditDecision(allowed=True, risk_score=0.0)

    blocking = [hit for hit in hits if hit.rule.action == "block"]
    matched_names = [hit.rule.name for hit in hits]
    evidence = [hit.matched_text for hit in hits][:6]
    risk_score = max(hit.rule.risk_score for hit in hits)

    if blocking:
        return AuditDecision(
            allowed=False,
            reason="custom_rule_match",
            risk_score=max(0.1, risk_score),
            matched_rules=matched_names,
            category="custom_rule",
            categories=["custom_rule"],
            evidence=evidence,
            recommended_action="block",
        )

    return AuditDecision(
        allowed=True,
        reason="custom_rule_alert",
        risk_score=risk_score,
        matched_rules=matched_names,
        category="custom_rule",
        categories=["custom_rule"],
        evidence=evidence,
        recommended_action="allow",
    )
