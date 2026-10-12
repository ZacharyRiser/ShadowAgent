"""Security (blacklist) policy management."""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.audit import _record_admin_action
from app.schemas import SecurityPolicyUpsert
from app.serializers import _serialize_policy
from app.tenancy import (
    can_manage_row,
    exact_org_filter,
    new_row_org_id,
    org_scope_filter,
    scoped_query,
)
from database import get_db
from models import SecurityPolicy
from security_controls import Principal, require_admin
from security_engine import ensure_default_security_policies

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])


def _validate_policy_pattern(pattern_text: str) -> None:
    """Reject invalid blacklist regex at write time instead of silently skipping."""
    try:
        re.compile(pattern_text, re.IGNORECASE | re.DOTALL)
    except re.error as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_regex_pattern",
                "message": f"blacklist_keyword is not a valid regular expression: {exc}",
            },
        )


def _name_taken(db: Session, principal: Principal, name: str, *, exclude_id: int | None = None) -> bool:
    """Name collision within the principal's visible scope (org + shared)."""
    query = db.query(SecurityPolicy).filter(
        org_scope_filter(SecurityPolicy, principal.org_id),
        SecurityPolicy.name == name,
    )
    if exclude_id is not None:
        query = query.filter(SecurityPolicy.id != exclude_id)
    return query.one_or_none() is not None


def _load_policy(db: Session, principal: Principal, policy_id: int) -> SecurityPolicy:
    policy = (
        scoped_query(db, SecurityPolicy, principal)
        .filter(SecurityPolicy.id == policy_id)
        .one_or_none()
    )
    if policy is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "policy_not_found", "message": "Policy does not exist."},
        )
    return policy


def _assert_manageable(principal: Principal, policy: SecurityPolicy) -> None:
    """Org principals cannot modify platform-shared rows."""
    if not can_manage_row(principal, policy):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "policy_read_only",
                "message": "Platform-shared policies are read-only for organization admins.",
            },
        )


@router.get("")
async def list_policies(
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ensure_default_security_policies(db)
    policies = (
        scoped_query(db, SecurityPolicy, principal)
        .order_by(SecurityPolicy.id.asc())
        .all()
    )
    return {
        "items": [
            _serialize_policy(policy)
            for policy in policies
        ]
    }


@router.post("")
async def create_policy(
    payload: SecurityPolicyUpsert,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ensure_default_security_policies(db)
    if _name_taken(db, principal, payload.name.strip()):
        raise HTTPException(
            status_code=409,
            detail={
                "error": "policy_conflict",
                "message": f"Policy {payload.name!r} already exists.",
            },
        )

    _validate_policy_pattern(payload.blacklist_keyword.strip())
    policy = SecurityPolicy(
        org_id=new_row_org_id(principal),
        name=payload.name.strip(),
        blacklist_keyword=payload.blacklist_keyword.strip(),
        description=payload.description.strip(),
        severity=payload.severity.strip().lower() or "medium",
        scope=payload.scope.strip() or "Prompt",
        enabled=payload.enabled,
        system_managed=False,
    )
    db.add(policy)
    _record_admin_action(
        db,
        action="security_policy_created",
        target=policy.name,
        principal=principal,
    )
    db.commit()
    db.refresh(policy)
    return {"item": _serialize_policy(policy)}


@router.put("/{policy_id}")
async def update_policy(
    policy_id: int,
    payload: SecurityPolicyUpsert,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ensure_default_security_policies(db)
    policy = _load_policy(db, principal, policy_id)

    if _name_taken(db, principal, payload.name.strip(), exclude_id=policy_id):
        raise HTTPException(
            status_code=409,
            detail={
                "error": "policy_conflict",
                "message": f"Policy {payload.name!r} already exists.",
            },
        )

    _assert_manageable(principal, policy)
    _validate_policy_pattern(payload.blacklist_keyword.strip())
    policy.name = payload.name.strip()
    policy.blacklist_keyword = payload.blacklist_keyword.strip()
    policy.description = payload.description.strip()
    policy.severity = payload.severity.strip().lower() or "medium"
    policy.scope = payload.scope.strip() or "Prompt"
    policy.enabled = payload.enabled
    _record_admin_action(
        db,
        action="security_policy_updated",
        target=policy.name,
        principal=principal,
    )
    db.commit()
    db.refresh(policy)
    return {"item": _serialize_policy(policy)}


@router.delete("/{policy_id}")
async def delete_policy(
    policy_id: int,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    policy = _load_policy(db, principal, policy_id)
    _assert_manageable(principal, policy)
    if policy.system_managed:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "policy_delete_blocked",
                "message": "System-managed policies cannot be deleted. Disable or reset them instead.",
            },
        )

    _record_admin_action(
        db,
        action="security_policy_deleted",
        target=policy.name,
        principal=principal,
    )
    db.delete(policy)
    db.commit()
    return {"deleted": True, "id": policy_id}


@router.post("/reset")
async def reset_policies(
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    custom_policies = (
        db.query(SecurityPolicy)
        .filter(
            exact_org_filter(SecurityPolicy, principal.org_id),
            SecurityPolicy.system_managed.is_(False),
        )
        .all()
    )
    for policy in custom_policies:
        db.delete(policy)
    _record_admin_action(
        db,
        action="security_policies_reset",
        target="all",
        principal=principal,
        details={"deleted_count": len(custom_policies)},
    )
    db.commit()
    ensure_default_security_policies(db)
    policies = (
        scoped_query(db, SecurityPolicy, principal)
        .order_by(SecurityPolicy.id.asc())
        .all()
    )
    return {"items": [_serialize_policy(policy) for policy in policies]}
