"""Managed API key lifecycle: create, list, rotate, revoke, activate, delete."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.audit import _record_admin_action
from app.auth_helpers import _principal_label, _require_platform_role
from app.schemas import ManagedApiKeyCreateRequest, ManagedApiKeyRotateRequest
from app.serializers import (
    _resolve_managed_api_key_expiration,
    _serialize_managed_api_key,
)
from app.tenancy import (
    new_row_org_id,
    org_owned_query,
    require_org_admin,
)
from database import get_db
from models import ManagedApiKey
from security_controls import (
    Principal,
    generate_managed_api_key,
    require_admin,
)

router = APIRouter(prefix="/api/v1/api-keys", tags=["api-keys"])


def _load_managed_api_key(
    db: Session,
    principal: Principal,
    api_key_id: int,
) -> ManagedApiKey:
    """Load a managed key visible to the principal (404 across tenant bounds)."""
    item = (
        org_owned_query(db, ManagedApiKey, principal)
        .filter(ManagedApiKey.id == api_key_id)
        .one_or_none()
    )
    if item is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "api_key_not_found", "message": "Managed API key does not exist."},
        )
    return item


@router.get("")
async def list_managed_api_keys(
    include_inactive: bool = True,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = org_owned_query(db, ManagedApiKey, principal).order_by(
        ManagedApiKey.created_at.desc(),
        ManagedApiKey.id.desc(),
    )
    if not include_inactive:
        query = query.filter(ManagedApiKey.is_active.is_(True))
    items = query.limit(200).all()
    return {"items": [_serialize_managed_api_key(item) for item in items]}


@router.post("")
async def create_managed_api_key_endpoint(
    payload: ManagedApiKeyCreateRequest,
    principal: Principal = Depends(require_org_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    name = payload.name.strip()
    if not name:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_name", "message": "API key name cannot be empty."},
        )

    role = _require_platform_role(payload.role)
    raw_api_key, key_prefix, key_hash = generate_managed_api_key(role)
    item = ManagedApiKey(
        org_id=new_row_org_id(principal),
        name=name,
        role=role,
        description=payload.description.strip(),
        key_prefix=key_prefix,
        key_hash=key_hash,
        created_by=_principal_label(principal, db),
        is_active=True,
        expires_at=_resolve_managed_api_key_expiration(
            expires_in_days=payload.expires_in_days,
        ),
    )
    db.add(item)
    _record_admin_action(
        db,
        action="managed_api_key_created",
        target=item.key_prefix,
        principal=principal,
        details={"name": name, "role": role},
    )
    db.commit()
    db.refresh(item)
    return {
        "item": _serialize_managed_api_key(item),
        "api_key": raw_api_key,
    }


@router.post("/{api_key_id}/rotate")
async def rotate_managed_api_key(
    api_key_id: int,
    payload: ManagedApiKeyRotateRequest,
    principal: Principal = Depends(require_org_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    item = _load_managed_api_key(db, principal, api_key_id)

    raw_api_key, key_prefix, key_hash = generate_managed_api_key(item.role)
    item.key_prefix = key_prefix
    item.key_hash = key_hash
    item.is_active = True
    item.last_used_at = None
    item.last_used_by = ""
    item.expires_at = _resolve_managed_api_key_expiration(
        expires_in_days=payload.expires_in_days,
        clear_expiration=payload.clear_expiration,
        fallback=item.expires_at,
    )
    _record_admin_action(
        db,
        action="managed_api_key_rotated",
        target=item.key_prefix,
        principal=principal,
    )
    db.commit()
    db.refresh(item)
    return {
        "item": _serialize_managed_api_key(item),
        "api_key": raw_api_key,
    }


@router.post("/{api_key_id}/revoke")
async def revoke_managed_api_key(
    api_key_id: int,
    principal: Principal = Depends(require_org_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    item = _load_managed_api_key(db, principal, api_key_id)

    item.is_active = False
    _record_admin_action(
        db,
        action="managed_api_key_revoked",
        target=item.key_prefix,
        principal=principal,
    )
    db.commit()
    db.refresh(item)
    return {"item": _serialize_managed_api_key(item)}


@router.post("/{api_key_id}/activate")
async def activate_managed_api_key(
    api_key_id: int,
    principal: Principal = Depends(require_org_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    item = _load_managed_api_key(db, principal, api_key_id)
    if item.expires_at is not None and item.expires_at <= datetime.utcnow():
        raise HTTPException(
            status_code=400,
            detail={
                "error": "api_key_expired",
                "message": "This managed API key is already expired. Rotate it to issue a fresh secret.",
            },
        )

    item.is_active = True
    _record_admin_action(
        db,
        action="managed_api_key_activated",
        target=item.key_prefix,
        principal=principal,
    )
    db.commit()
    db.refresh(item)
    return {"item": _serialize_managed_api_key(item)}


@router.delete("/{api_key_id}")
async def delete_managed_api_key(
    api_key_id: int,
    principal: Principal = Depends(require_org_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    item = _load_managed_api_key(db, principal, api_key_id)

    deleted_summary = {
        "id": item.id,
        "name": item.name,
        "role": item.role,
        "key_prefix": item.key_prefix,
        "is_active": False,
    }
    _record_admin_action(
        db,
        action="managed_api_key_deleted",
        target=item.key_prefix,
        principal=principal,
        details={"name": item.name, "role": item.role},
    )
    db.delete(item)
    db.commit()
    return {"deleted": deleted_summary}
