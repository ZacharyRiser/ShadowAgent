"""Console authentication: bootstrap, register, login, session introspection."""

from __future__ import annotations

import hmac
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.audit import _record_auth_event
from app.auth_helpers import (
    _DUMMY_PASSWORD_HASH,
    _auth_session_payload,
    _console_registration_role,
    _normalize_console_role,
    _principal_user_id,
    _serialize_console_user,
)
from app.config import (
    _allow_open_console_bootstrap,
    _allow_open_registration,
    _console_bootstrap_required,
    _console_bootstrap_status,
    _console_bootstrap_token,
    _console_invite_token,
    _login_lockout_seconds,
    _login_max_failures,
)
from app.schemas import AuthLoginRequest, AuthRegisterRequest, SwitchOrgRequest
from app.tenancy import (
    ensure_default_organization,
    membership_role,
    user_memberships,
)
from app.utils import _normalized_email, is_valid_email
from database import get_db
from models import ConsoleUser, Organization, OrganizationMembership
from security_controls import (
    Principal,
    hash_password,
    login_throttle,
    require_client,
    verify_password,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.get("/bootstrap-status")
async def get_console_bootstrap_status(
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return _console_bootstrap_status(db)


@router.post("/register")
async def register_console_user(
    payload: AuthRegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    email = _normalized_email(payload.email)

    # The email is the account's identity, so reject malformed shapes here
    # rather than storing them. Login stays permissive on purpose: accounts
    # created before this check must not be locked out.
    if not is_valid_email(email):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_email",
                "message": (
                    "Enter a valid email address, for example name@example.com."
                ),
            },
        )

    existing = db.query(ConsoleUser).filter(ConsoleUser.email == email).one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail={"error": "email_already_registered", "message": "This email is already registered."},
        )

    bootstrap_required = _console_bootstrap_required(db)
    role = _console_registration_role(db)
    if bootstrap_required:
        bootstrap_token = _console_bootstrap_token()
        provided_bootstrap_token = (
            request.headers.get("x-shadow-agent-bootstrap-token")
            or request.headers.get("x-bootstrap-token")
            or ""
        ).strip()
        if bootstrap_token:
            if not hmac.compare_digest(provided_bootstrap_token, bootstrap_token):
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "bootstrap_token_required",
                        "message": (
                            "First console admin registration requires the configured bootstrap token. "
                            "Provide it in X-Shadow-Agent-Bootstrap-Token."
                        ),
                    },
                )
        elif not _allow_open_console_bootstrap():
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "bootstrap_setup_required",
                    "message": (
                        "Console bootstrap is locked. Configure SHADOW_AGENT_CONSOLE_BOOTSTRAP_TOKEN "
                        "or explicitly enable SHADOW_AGENT_ALLOW_OPEN_CONSOLE_BOOTSTRAP=true for local demo-only setup."
                    ),
                },
            )
    else:
        # After the first admin exists, open self-registration is locked down by
        # default. Operators either opt back in explicitly for local demos, or
        # provision a shared invite token that new users must present.
        if not _allow_open_registration():
            invite_token = _console_invite_token()
            provided_invite_token = (
                request.headers.get("x-shadow-agent-invite-token")
                or request.headers.get("x-invite-token")
                or ""
            ).strip()
            if not invite_token:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "registration_disabled",
                        "message": (
                            "Open registration is disabled. Configure "
                            "SHADOW_AGENT_ALLOW_OPEN_REGISTRATION=true for local demos, or set "
                            "SHADOW_AGENT_CONSOLE_INVITE_TOKEN and require new users to provide "
                            "it in X-Shadow-Agent-Invite-Token."
                        ),
                    },
                )
            if not hmac.compare_digest(provided_invite_token, invite_token):
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "invite_token_required",
                        "message": (
                            "Registration requires a valid invite token. "
                            "Provide it in X-Shadow-Agent-Invite-Token."
                        ),
                    },
                )

    user = ConsoleUser(
        name=payload.name.strip(),
        email=email,
        password_hash=hash_password(payload.password),
        role=role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Enroll in the default organization: the very first member becomes its
    # owner so upgraded single-tenant deployments keep a full administrator.
    default_org = ensure_default_organization(db)
    existing_members = (
        db.query(OrganizationMembership)
        .filter(OrganizationMembership.org_id == default_org.id)
        .count()
    )
    db.add(
        OrganizationMembership(
            user_id=user.id,
            org_id=default_org.id,
            role="owner" if existing_members == 0 else "member",
        )
    )
    db.commit()
    return _auth_session_payload(user, db)


@router.post("/login")
async def login_console_user(
    payload: AuthLoginRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    email = _normalized_email(payload.email)
    max_failures = _login_max_failures()
    lockout_seconds = _login_lockout_seconds()

    lockout_remaining = login_throttle.locked_out_remaining(
        email,
        max_failures=max_failures,
        window_seconds=lockout_seconds,
    )
    if lockout_remaining:
        _record_auth_event(db, "login_locked_out", email)
        db.commit()
        raise HTTPException(
            status_code=429,
            detail={
                "error": "account_locked",
                "message": "Too many failed login attempts. Try again later.",
                "retry_after_seconds": lockout_remaining,
            },
        )

    user = db.query(ConsoleUser).filter(ConsoleUser.email == email).one_or_none()
    if user is None:
        # Equalize verification time so account existence cannot be probed.
        verify_password(payload.password, _DUMMY_PASSWORD_HASH)
        login_throttle.record_failure(email, window_seconds=lockout_seconds)
        _record_auth_event(db, "login_failed", email)
        db.commit()
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_credentials", "message": "Invalid email or password."},
        )

    if not user.is_active or not verify_password(payload.password, user.password_hash):
        login_throttle.record_failure(email, window_seconds=lockout_seconds)
        _record_auth_event(db, "login_failed", email)
        db.commit()
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_credentials", "message": "Invalid email or password."},
        )

    login_throttle.record_success(email)
    _record_auth_event(db, "login_success", email)
    db.commit()
    return _auth_session_payload(user, db)


def _org_context_payload(db: Session, user_id: int) -> dict[str, object]:
    """Organizations the console user belongs to, plus the active one."""
    memberships = user_memberships(db, user_id)
    org_ids = [membership.org_id for membership in memberships]
    orgs_by_id = {
        org.id: org
        for org in db.query(Organization).filter(Organization.id.in_(org_ids)).all()
    } if org_ids else {}

    orgs = [
        {
            "id": org.id,
            "slug": org.slug,
            "name": org.name,
            "is_default": bool(org.is_default),
            "role": membership.role,
        }
        for membership in memberships
        if (org := orgs_by_id.get(membership.org_id)) is not None
    ]
    return {"orgs": orgs}


@router.get("/me")
async def get_current_console_user(
    principal: Principal = Depends(require_client),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    user_id = _principal_user_id(principal)
    if user_id is None:
        raise HTTPException(
            status_code=403,
            detail={"error": "console_auth_required", "message": "Console user token required."},
        )

    user = db.query(ConsoleUser).filter(ConsoleUser.id == user_id, ConsoleUser.is_active.is_(True)).one_or_none()
    if user is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "user_not_found", "message": "Console user does not exist."},
        )

    return {
        "user": _serialize_console_user(user),
        "org_id": principal.org_id,
        "org_role": principal.org_role,
        **_org_context_payload(db, user_id),
    }


@router.post("/switch-org")
async def switch_active_organization(
    payload: SwitchOrgRequest,
    principal: Principal = Depends(require_client),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Re-issue the session token with another organization as active context."""
    user_id = _principal_user_id(principal)
    if user_id is None:
        raise HTTPException(
            status_code=403,
            detail={"error": "console_auth_required", "message": "Console user token required."},
        )

    user = db.query(ConsoleUser).filter(ConsoleUser.id == user_id, ConsoleUser.is_active.is_(True)).one_or_none()
    if user is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "user_not_found", "message": "Console user does not exist."},
        )

    target_role = membership_role(db, user_id, payload.org_id)
    if target_role is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "org_not_found",
                "message": "You are not a member of that organization.",
            },
        )

    _record_auth_event(db, "org_switched", user.email)
    db.commit()
    return _auth_session_payload_for_org(user, db, payload.org_id, target_role)


def _auth_session_payload_for_org(
    user: ConsoleUser,
    db: Session,
    org_id: int,
    org_role: str,
) -> dict[str, Any]:
    from security_controls import create_jwt

    token, expires_at = create_jwt(
        subject=f"console-user:{user.id}",
        role=user.role,
        extra_claims={
            "email": user.email,
            "name": user.name,
            "user_type": "console",
            "org_id": org_id,
            "org_role": org_role,
        },
    )
    org = db.query(Organization).filter(Organization.id == org_id).one_or_none()
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires_at,
        "user": _serialize_console_user(user),
        "org": (
            {
                "id": org.id,
                "slug": org.slug,
                "name": org.name,
                "is_default": bool(org.is_default),
                "role": org_role,
            }
            if org is not None
            else None
        ),
    }
