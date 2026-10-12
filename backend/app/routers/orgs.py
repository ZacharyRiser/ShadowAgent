"""Organization management: CRUD, members, per-org SSO connections.

Access model
------------
- Platform principals (static env keys) administer every organization.
- Console admins operate on the organizations they hold the ``owner`` /
  ``admin`` org role in; regular members have read access to their orgs.
- Creating a new organization requires being a platform admin or an owner
  of at least one existing organization; the creator becomes its owner.

Every mutation lands in the audit trail via ``_record_admin_action``.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.audit import _record_admin_action
from app.auth_helpers import _normalize_console_role
from app.schemas import (
    OrgCreateRequest,
    OrgMemberAddRequest,
    OrgMemberUpdateRequest,
    OrgUpdateRequest,
    SsoUpsertRequest,
)
from app.tenancy import (
    ORG_ROLES,
    normalize_org_slug,
    principal_user_id,
    require_org_admin,
    require_org_admin_for,
    serialize_org,
    user_memberships,
)
from app.utils import _normalized_email
from database import get_db
from models import (
    AlertEvent,
    ApprovalRequest,
    AuditLog,
    ConsoleUser,
    CustomRule,
    InterceptLog,
    ManagedApiKey,
    Organization,
    OrganizationMembership,
    ReplayRun,
    SecurityPolicy,
    SsoConnection,
    ToolPolicy,
)
from security_controls import Principal, require_admin, require_client

router = APIRouter(prefix="/api/v1/orgs", tags=["organizations"])

# Tables whose org-owned rows are purged when an organization is deleted.
_ORG_DATA_MODELS = (
    InterceptLog,
    AuditLog,
    SecurityPolicy,
    ApprovalRequest,
    AlertEvent,
    ReplayRun,
    CustomRule,
    ManagedApiKey,
    ToolPolicy,
)


def _serialize_member(user: ConsoleUser, membership: OrganizationMembership) -> dict[str, Any]:
    return {
        "user_id": user.id,
        "name": user.name,
        "email": user.email,
        "platform_role": user.role,
        "is_active": bool(user.is_active),
        "org_role": membership.role,
        "joined_at": membership.created_at.isoformat() + "Z" if membership.created_at else "",
    }


def _serialize_sso(connection: SsoConnection) -> dict[str, Any]:
    """SSO config for API responses — the client secret never leaves the DB."""
    return {
        "org_id": connection.org_id,
        "provider_name": connection.provider_name,
        "client_id": connection.client_id,
        # Masked hint so operators can confirm which secret is configured.
        "client_secret_masked": f"••••{connection.client_secret[-4:]}" if connection.client_secret else "",
        "issuer_url": connection.issuer_url,
        "scopes": connection.scopes,
        "jit_enabled": bool(connection.jit_enabled),
        "default_role": connection.default_role,
        "enabled": bool(connection.enabled),
        "created_at": connection.created_at.isoformat() + "Z" if connection.created_at else "",
        "updated_at": connection.updated_at.isoformat() + "Z" if connection.updated_at else "",
    }


def _org_owned_row_count(db: Session, org_id: int) -> int:
    total = 0
    for model in _ORG_DATA_MODELS:
        total += db.query(model).filter(model.org_id == org_id).count()
    return total


def _owner_count(db: Session, org_id: int) -> int:
    return (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.org_id == org_id,
            OrganizationMembership.role == "owner",
        )
        .count()
    )


def _assert_can_act_on_roles(
    db: Session,
    principal: Principal,
    org: Organization,
    *,
    touching_owner_role: bool,
) -> None:
    """Owner-level changes (grant/remove/demote owners) need owner or platform."""
    if principal.org_id is None:
        return
    if not touching_owner_role:
        return
    if principal.org_role != "owner":
        raise HTTPException(
            status_code=403,
            detail={
                "error": "owner_role_required",
                "message": "Only organization owners (or platform admins) may manage owner roles.",
            },
        )


@router.post("")
async def create_organization(
    payload: OrgCreateRequest,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Create an organization (platform admin or an owner of another org)."""
    creator_user_id = principal_user_id(principal)
    if principal.org_id is not None:
        if principal.org_role != "owner" or creator_user_id is None:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "owner_role_required",
                    "message": "Creating organizations requires platform admin or organization owner role.",
                },
            )

    try:
        slug = normalize_org_slug(payload.slug)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_slug", "message": str(exc)},
        ) from exc

    if db.query(Organization).filter(Organization.slug == slug).one_or_none() is not None:
        raise HTTPException(
            status_code=409,
            detail={"error": "org_conflict", "message": f"Organization slug '{slug}' already exists."},
        )

    org = Organization(slug=slug, name=payload.name.strip(), is_default=False)
    db.add(org)
    db.commit()
    db.refresh(org)

    if creator_user_id is not None:
        db.add(
            OrganizationMembership(
                user_id=creator_user_id,
                org_id=org.id,
                role="owner",
            )
        )

    _record_admin_action(
        db,
        action="organization_created",
        target=f"org:{org.slug}",
        principal=principal,
        org_id=org.id,
        details={"name": org.name},
    )
    db.commit()
    return {"item": serialize_org(org)}


@router.get("")
async def list_organizations(
    principal: Principal = Depends(require_client),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Platform principals see every org; org principals see their memberships."""
    if principal.org_id is None:
        orgs = db.query(Organization).order_by(Organization.id.asc()).all()
        return {"items": [serialize_org(org) for org in orgs]}

    user_id = principal_user_id(principal)
    if user_id is None:
        return {"items": []}
    memberships = user_memberships(db, user_id)
    org_ids = [membership.org_id for membership in memberships]
    if not org_ids:
        return {"items": []}
    orgs_by_id = {
        org.id: org
        for org in db.query(Organization).filter(Organization.id.in_(org_ids)).all()
    }
    items = []
    for membership in memberships:
        org = orgs_by_id.get(membership.org_id)
        if org is not None:
            items.append({**serialize_org(org), "role": membership.role})
    return {"items": items}


@router.get("/{org_id}")
async def get_organization(
    org_id: int,
    principal: Principal = Depends(require_client),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    org = require_org_admin_for(db, principal, org_id, allow_member=True)
    member_count = (
        db.query(OrganizationMembership)
        .filter(OrganizationMembership.org_id == org.id)
        .count()
    )
    sso = (
        db.query(SsoConnection)
        .filter(SsoConnection.org_id == org.id)
        .one_or_none()
    )
    return {
        "item": {
            **serialize_org(org),
            "member_count": member_count,
            "sso_enabled": bool(sso.enabled) if sso else False,
            "sso_provider": sso.provider_name if sso else "",
        }
    }


@router.patch("/{org_id}")
async def update_organization(
    org_id: int,
    payload: OrgUpdateRequest,
    principal: Principal = Depends(require_org_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    org = require_org_admin_for(db, principal, org_id)
    previous_name = org.name
    org.name = payload.name.strip()
    _record_admin_action(
        db,
        action="organization_updated",
        target=f"org:{org.slug}",
        principal=principal,
        org_id=org.id,
        details={"previous_name": previous_name, "name": org.name},
    )
    db.commit()
    db.refresh(org)
    return {"item": serialize_org(org)}


@router.delete("/{org_id}")
async def delete_organization(
    org_id: int,
    force: bool = False,
    principal: Principal = Depends(require_org_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    org = require_org_admin_for(db, principal, org_id)
    if org.is_default:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "default_org_delete_blocked",
                "message": "The default organization cannot be deleted.",
            },
        )

    if principal.org_id is not None and principal.org_role != "owner":
        raise HTTPException(
            status_code=403,
            detail={
                "error": "owner_role_required",
                "message": "Only organization owners (or platform admins) may delete an organization.",
            },
        )

    owned_rows = _org_owned_row_count(db, org.id)
    if owned_rows > 0 and not force:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "org_not_empty",
                "message": (
                    f"Organization still owns {owned_rows} rows (logs, policies, rules, keys...). "
                    "Pass force=true to purge them together with the organization."
                ),
            },
        )

    purged = 0
    for model in _ORG_DATA_MODELS:
        purged += db.query(model).filter(model.org_id == org.id).delete(synchronize_session=False)
    db.query(OrganizationMembership).filter(
        OrganizationMembership.org_id == org.id
    ).delete(synchronize_session=False)
    db.query(SsoConnection).filter(SsoConnection.org_id == org.id).delete(
        synchronize_session=False
    )

    _record_admin_action(
        db,
        action="organization_deleted",
        target=f"org:{org.slug}",
        principal=principal,
        details={"purged_rows": purged},
    )
    db.delete(org)
    db.commit()
    return {"deleted": True, "id": org_id, "purged_rows": purged}


@router.get("/{org_id}/members")
async def list_organization_members(
    org_id: int,
    principal: Principal = Depends(require_client),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    require_org_admin_for(db, principal, org_id, allow_member=True)
    memberships = (
        db.query(OrganizationMembership)
        .filter(OrganizationMembership.org_id == org_id)
        .order_by(OrganizationMembership.id.asc())
        .all()
    )
    user_ids = [membership.user_id for membership in memberships]
    users_by_id = (
        {
            user.id: user
            for user in db.query(ConsoleUser).filter(ConsoleUser.id.in_(user_ids)).all()
        }
        if user_ids
        else {}
    )
    items = [
        _serialize_member(users_by_id[membership.user_id], membership)
        for membership in memberships
        if membership.user_id in users_by_id
    ]
    return {"items": items}


@router.post("/{org_id}/members")
async def add_organization_member(
    org_id: int,
    payload: OrgMemberAddRequest,
    principal: Principal = Depends(require_org_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    org = require_org_admin_for(db, principal, org_id)
    _assert_can_act_on_roles(
        db, principal, org, touching_owner_role=payload.role == "owner"
    )

    email = _normalized_email(payload.email)
    user = db.query(ConsoleUser).filter(ConsoleUser.email == email).one_or_none()
    if user is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "user_not_found",
                "message": (
                    "No console account exists for that email. Accounts are created via "
                    "registration or SSO just-in-time provisioning."
                ),
            },
        )

    existing = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.org_id == org.id,
        )
        .one_or_none()
    )
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "member_conflict",
                "message": "That user is already a member of this organization.",
            },
        )

    membership = OrganizationMembership(
        user_id=user.id,
        org_id=org.id,
        role=payload.role,
    )
    db.add(membership)
    _record_admin_action(
        db,
        action="org_member_added",
        target=f"org:{org.slug}:{email}",
        principal=principal,
        org_id=org.id,
        details={"org_role": payload.role},
    )
    db.commit()
    db.refresh(membership)
    return {"item": _serialize_member(user, membership)}


@router.patch("/{org_id}/members/{user_id}")
async def update_organization_member(
    org_id: int,
    user_id: int,
    payload: OrgMemberUpdateRequest,
    principal: Principal = Depends(require_org_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    org = require_org_admin_for(db, principal, org_id)
    membership = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.org_id == org.id,
        )
        .one_or_none()
    )
    if membership is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "member_not_found", "message": "That user is not a member of this organization."},
        )

    actor_user_id = principal_user_id(principal)
    touching_owner_role = membership.role == "owner" or payload.role == "owner"
    _assert_can_act_on_roles(db, principal, org, touching_owner_role=touching_owner_role)

    if (
        membership.role == "owner"
        and payload.role != "owner"
        and _owner_count(db, org.id) <= 1
    ):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "last_owner_protected",
                "message": "An organization must keep at least one owner.",
            },
        )
    if actor_user_id == user_id and payload.role != "owner" and membership.role == "owner":
        raise HTTPException(
            status_code=400,
            detail={
                "error": "self_demotion_blocked",
                "message": "Owners cannot demote themselves; promote another owner first.",
            },
        )

    previous_role = membership.role
    membership.role = payload.role
    user = db.query(ConsoleUser).filter(ConsoleUser.id == user_id).one_or_none()
    _record_admin_action(
        db,
        action="org_member_role_updated",
        target=f"org:{org.slug}:user:{user_id}",
        principal=principal,
        org_id=org.id,
        details={"previous_role": previous_role, "org_role": payload.role},
    )
    db.commit()
    db.refresh(membership)
    return {"item": _serialize_member(user, membership) if user else None}


@router.delete("/{org_id}/members/{user_id}")
async def remove_organization_member(
    org_id: int,
    user_id: int,
    principal: Principal = Depends(require_org_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    org = require_org_admin_for(db, principal, org_id)
    membership = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.org_id == org.id,
        )
        .one_or_none()
    )
    if membership is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "member_not_found", "message": "That user is not a member of this organization."},
        )

    _assert_can_act_on_roles(
        db, principal, org, touching_owner_role=membership.role == "owner"
    )
    if membership.role == "owner" and _owner_count(db, org.id) <= 1:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "last_owner_protected",
                "message": "An organization must keep at least one owner.",
            },
        )
    if principal_user_id(principal) == user_id:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "self_removal_blocked",
                "message": "Use switch-org or leave via another owner; you cannot remove yourself here.",
            },
        )

    db.delete(membership)
    _record_admin_action(
        db,
        action="org_member_removed",
        target=f"org:{org.slug}:user:{user_id}",
        principal=principal,
        org_id=org.id,
        details={"org_role": membership.role},
    )
    db.commit()
    return {"deleted": True, "user_id": user_id, "org_id": org_id}


@router.get("/{org_id}/sso")
async def get_organization_sso(
    org_id: int,
    principal: Principal = Depends(require_org_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    require_org_admin_for(db, principal, org_id)
    connection = (
        db.query(SsoConnection).filter(SsoConnection.org_id == org_id).one_or_none()
    )
    if connection is None:
        return {"item": None}
    return {"item": _serialize_sso(connection)}


@router.put("/{org_id}/sso")
async def upsert_organization_sso(
    org_id: int,
    payload: SsoUpsertRequest,
    principal: Principal = Depends(require_org_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    org = require_org_admin_for(db, principal, org_id)

    normalized_role = _normalize_console_role(payload.default_role, "client")
    connection = (
        db.query(SsoConnection).filter(SsoConnection.org_id == org_id).one_or_none()
    )
    if connection is None:
        connection = SsoConnection(org_id=org_id)
        db.add(connection)
        action = "org_sso_configured"
    else:
        action = "org_sso_updated"

    connection.provider_name = payload.provider_name.strip()
    connection.client_id = payload.client_id.strip()
    # Empty client_secret keeps the previously stored secret; a fresh non-empty
    # value rotates it. A new connection always requires a real secret.
    new_secret = payload.client_secret.strip()
    if new_secret:
        connection.client_secret = new_secret
    elif not connection.client_secret:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "client_secret_required",
                "message": "A client_secret is required when configuring the SSO connection.",
            },
        )
    connection.issuer_url = payload.issuer_url.strip().rstrip("/")
    connection.scopes = payload.scopes.strip() or "openid email profile"
    connection.jit_enabled = payload.jit_enabled
    connection.default_role = normalized_role
    connection.enabled = payload.enabled

    _record_admin_action(
        db,
        action=action,
        target=f"org:{org.slug}:sso",
        principal=principal,
        org_id=org.id,
        details={
            "provider_name": connection.provider_name,
            "issuer_url": connection.issuer_url,
            "jit_enabled": connection.jit_enabled,
            "enabled": connection.enabled,
        },
    )
    db.commit()
    db.refresh(connection)
    return {"item": _serialize_sso(connection)}


@router.delete("/{org_id}/sso")
async def delete_organization_sso(
    org_id: int,
    principal: Principal = Depends(require_org_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    org = require_org_admin_for(db, principal, org_id)
    connection = (
        db.query(SsoConnection).filter(SsoConnection.org_id == org_id).one_or_none()
    )
    if connection is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "sso_not_configured", "message": "No SSO connection is configured for this organization."},
        )

    db.delete(connection)
    _record_admin_action(
        db,
        action="org_sso_deleted",
        target=f"org:{org.slug}:sso",
        principal=principal,
        org_id=org.id,
    )
    db.commit()
    return {"deleted": True, "org_id": org_id}
