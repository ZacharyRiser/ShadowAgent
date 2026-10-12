"""Custom detection rule management (CRUD, dry-run test, import/export)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.audit import _record_admin_action
from app.custom_rules import (
    MAX_CUSTOM_RULES,
    _compiled_rule,
    validate_rule_fields,
)
from app.dlp import BUILTIN_DLP_PATTERNS, DLP_MODES, response_dlp_mode
from app.schemas import CustomRuleImportRequest, CustomRuleTestRequest, CustomRuleUpsert
from app.serializers import _serialize_custom_rule
from app.tenancy import (
    can_manage_row,
    exact_org_filter,
    new_row_org_id,
    org_scope_filter,
    scoped_query,
)
from database import get_db
from models import CustomRule
from security_controls import Principal, require_admin

router = APIRouter(prefix="/api/v1/rules", tags=["custom-rules"])


def _load_rule(rule_id: int, db: Session, principal: Principal) -> CustomRule:
    rule = (
        scoped_query(db, CustomRule, principal)
        .filter(CustomRule.id == rule_id)
        .one_or_none()
    )
    if rule is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "rule_not_found", "message": f"Rule {rule_id} does not exist."},
        )
    return rule


def _assert_rule_capacity(
    db: Session,
    principal: Principal,
    *,
    exclude_id: int | None = None,
) -> None:
    """Rule budget is enforced per scope (org-owned rules / platform rules)."""
    query = db.query(CustomRule).filter(
        exact_org_filter(CustomRule, principal.org_id)
    )
    if exclude_id is not None:
        query = query.filter(CustomRule.id != exclude_id)
    if query.count() >= MAX_CUSTOM_RULES:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "rule_limit_reached",
                "message": f"At most {MAX_CUSTOM_RULES} custom rules are supported.",
            },
        )


def _assert_name_available(
    db: Session,
    principal: Principal,
    name: str,
    *,
    exclude_id: int | None = None,
) -> None:
    query = db.query(CustomRule).filter(
        org_scope_filter(CustomRule, principal.org_id),
        CustomRule.name == name,
    )
    if exclude_id is not None:
        query = query.filter(CustomRule.id != exclude_id)
    if query.one_or_none() is not None:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "rule_conflict",
                "message": f"Rule {name!r} already exists.",
            },
        )


def _assert_manageable(principal: Principal, rule: CustomRule) -> None:
    """Org principals cannot modify platform-shared rules."""
    if not can_manage_row(principal, rule):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "rule_read_only",
                "message": "Platform-shared rules are read-only for organization admins.",
            },
        )


def _apply_rule_fields(rule: CustomRule, payload: CustomRuleUpsert) -> None:
    validate_rule_fields(
        rule_type=payload.rule_type,
        pattern=payload.pattern,
        target=payload.target,
        action=payload.action,
        risk_score=payload.risk_score,
    )
    rule.name = payload.name.strip()
    rule.description = payload.description.strip()
    rule.rule_type = payload.rule_type
    rule.pattern = payload.pattern.strip()
    rule.target = payload.target
    rule.action = payload.action
    rule.risk_score = payload.risk_score
    rule.enabled = payload.enabled


@router.get("")
async def list_rules(
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rules = scoped_query(db, CustomRule, principal).order_by(CustomRule.id.asc()).all()
    return {"items": [_serialize_custom_rule(rule) for rule in rules]}


@router.get("/dlp-status")
async def dlp_status(
    principal: Principal = Depends(require_admin),
) -> dict[str, Any]:
    """Response-side DLP runtime status for the console."""
    return {
        "mode": response_dlp_mode(),
        "available_modes": list(DLP_MODES),
        "builtin_patterns": [
            {"type": match_type, "risk_score": risk, "pattern": pattern.pattern}
            for match_type, pattern, risk in BUILTIN_DLP_PATTERNS
        ],
    }


@router.post("")
async def create_rule(
    payload: CustomRuleUpsert,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _assert_rule_capacity(db, principal)
    _assert_name_available(db, principal, payload.name.strip())
    rule = CustomRule(org_id=new_row_org_id(principal))
    _apply_rule_fields(rule, payload)
    db.add(rule)
    _record_admin_action(db, action="custom_rule_created", target=rule.name, principal=principal)
    db.commit()
    db.refresh(rule)
    return {"item": _serialize_custom_rule(rule)}


@router.put("/{rule_id}")
async def update_rule(
    rule_id: int,
    payload: CustomRuleUpsert,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rule = _load_rule(rule_id, db, principal)
    _assert_manageable(principal, rule)
    _assert_name_available(db, principal, payload.name.strip(), exclude_id=rule_id)
    _apply_rule_fields(rule, payload)
    _record_admin_action(db, action="custom_rule_updated", target=rule.name, principal=principal)
    db.commit()
    db.refresh(rule)
    return {"item": _serialize_custom_rule(rule)}


@router.delete("/{rule_id}")
async def delete_rule(
    rule_id: int,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rule = _load_rule(rule_id, db, principal)
    _assert_manageable(principal, rule)
    name = rule.name
    db.delete(rule)
    _record_admin_action(db, action="custom_rule_deleted", target=name, principal=principal)
    db.commit()
    return {"deleted": True, "id": rule_id, "name": name}


@router.post("/test")
async def test_rule(
    payload: CustomRuleTestRequest,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Dry-run a rule against sample text; never enforces anything."""
    if payload.rule_id is None and payload.draft is None:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "missing_rule_reference",
                "message": "Provide either rule_id or draft.",
            },
        )

    if payload.rule_id is not None:
        rule = _load_rule(payload.rule_id, db, principal)
    else:
        draft = payload.draft
        assert draft is not None
        validate_rule_fields(
            rule_type=draft.rule_type,
            pattern=draft.pattern,
            target=draft.target,
            action=draft.action,
            risk_score=draft.risk_score,
        )
        rule = CustomRule(
            name=draft.name.strip(),
            description=draft.description,
            rule_type=draft.rule_type,
            pattern=draft.pattern.strip(),
            target=draft.target,
            action=draft.action,
            risk_score=draft.risk_score,
            enabled=draft.enabled,
        )

    pattern = _compiled_rule(rule.rule_type, rule.pattern)
    matches: list[dict[str, Any]] = []
    if pattern is not None:
        for match in pattern.finditer(payload.sample_text):
            matches.append(
                {
                    "matched_text": match.group(0)[:200],
                    "span": [match.start(), match.end()],
                }
            )

    return {
        "rule": {
            "name": rule.name,
            "rule_type": rule.rule_type,
            "pattern": rule.pattern,
            "target": rule.target,
            "action": rule.action,
            "risk_score": float(rule.risk_score),
        },
        "matched": bool(matches),
        "match_count": len(matches),
        "matches": matches[:50],
    }


@router.get("/export")
async def export_rules(
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rules = scoped_query(db, CustomRule, principal).order_by(CustomRule.id.asc()).all()
    return {
        "version": 1,
        "exported_rules": [
            {
                "name": rule.name,
                "description": rule.description,
                "rule_type": rule.rule_type,
                "pattern": rule.pattern,
                "target": rule.target,
                "action": rule.action,
                "risk_score": float(rule.risk_score),
                "enabled": rule.enabled,
            }
            for rule in rules
        ],
    }


@router.post("/import")
async def import_rules(
    payload: CustomRuleImportRequest,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if payload.mode == "replace":
        replace_targets = (
            db.query(CustomRule)
            .filter(exact_org_filter(CustomRule, principal.org_id))
            .all()
        )
        for rule in replace_targets:
            db.delete(rule)

    created = 0
    updated = 0
    skipped: list[str] = []
    for item in payload.rules:
        existing = (
            db.query(CustomRule)
            .filter(
                org_scope_filter(CustomRule, principal.org_id),
                CustomRule.name == item.name.strip(),
            )
            .one_or_none()
        )
        if existing is not None and payload.mode == "merge":
            if not can_manage_row(principal, existing):
                # Platform-shared rule: read-only for org admins.
                skipped.append(item.name)
                continue
            try:
                _apply_rule_fields(existing, item)
                updated += 1
            except HTTPException:
                skipped.append(item.name)
            continue
        try:
            _assert_rule_capacity(db, principal)
            rule = CustomRule(org_id=new_row_org_id(principal))
            _apply_rule_fields(rule, item)
            db.add(rule)
            created += 1
        except HTTPException:
            skipped.append(item.name)

    _record_admin_action(
        db,
        action="custom_rules_imported",
        target=f"created={created} updated={updated} skipped={len(skipped)}",
        principal=principal,
    )
    db.commit()
    return {"created": created, "updated": updated, "skipped": skipped}
