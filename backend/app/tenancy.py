"""Multi-tenancy helpers: default-organization seeding and query scoping.

Tenant model
------------
- Every console user is enrolled in at least one organization; the console
  JWT always carries the *active* organization (``org_id`` / ``org_role``
  claims) so requests stay org-scoped.
- Principals without an organization (static env API keys, platform-managed
  keys with ``org_id IS NULL``) are *platform* principals: they see and
  manage everything — this preserves pre-tenancy single-tenant behavior.
- ``org_id IS NULL`` rows on shared tables (policies, rules, logs) are
  platform-shared: visible to every tenant, read-only for org admins.

The ``default`` organization is seeded lazily on first boot after the
upgrade: existing console users become its owners/admins and pre-existing
``org_id IS NULL`` rows are backfilled into it, so existing deployments keep
working identically.
"""

from __future__ import annotations

import logging
import re

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from database import get_db
from models import Organization, OrganizationMembership
from security_controls import Principal, require_admin

logger = logging.getLogger("shadow_agent.tenancy")

DEFAULT_ORG_SLUG = "default"
DEFAULT_ORG_NAME = "Default Organization"
ORG_ROLES = ("owner", "admin", "member")
ORG_ADMIN_ROLES = ("owner", "admin")

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")

# Tables whose NULL-org rows are backfilled into the default organization on
# first boot. Managed API keys are NOT backfilled: a NULL-org key stays a
# platform-level key so static-key deployments keep platform scope.
# System-managed policy rows are also excluded: seeded defaults are
# platform-shared (org_id stays NULL) so every tenant inherits them and the
# seeding logic never produces duplicate rows.
_BACKFILL_TABLE_NAMES = (
    "intercept_logs",
    "audit_logs",
    "approval_requests",
    "alert_events",
    "replay_runs",
    "custom_rules",
)

# Rows in these tables are only backfilled when they are user-created
# (system_managed = 0); seeded defaults remain platform-shared.
_BACKFILL_USER_CREATED_ONLY = {
    "security_policies": True,
    "tool_policies": True,
}


def normalize_org_slug(value: str) -> str:
    slug = (value or "").strip().lower().replace("_", "-")
    if not _SLUG_RE.match(slug):
        raise ValueError(
            "slug must be 3-64 chars of lowercase letters, digits, and hyphens "
            "(start/end with a letter or digit)"
        )
    return slug


def ensure_default_organization(db: Session) -> Organization:
    """Seed the default org once and enroll existing users; idempotent."""

    existing = (
        db.query(Organization).filter(Organization.is_default.is_(True)).one_or_none()
    )
    if existing is not None:
        return existing

    any_org = db.query(Organization).order_by(Organization.id.asc()).first()
    if any_org is not None:
        # Non-default orgs exist (e.g. partial seed); promote nothing, just
        # create the default org for console enrollment.
        default = Organization(
            slug=DEFAULT_ORG_SLUG,
            name=DEFAULT_ORG_NAME,
            is_default=True,
        )
        db.add(default)
        db.commit()
        db.refresh(default)
        return default

    default = Organization(
        slug=DEFAULT_ORG_SLUG,
        name=DEFAULT_ORG_NAME,
        is_default=True,
    )
    db.add(default)
    db.commit()
    db.refresh(default)

    from models import ConsoleUser

    # Existing users: the first (bootstrap) user becomes owner, the rest
    # become members of the default organization.
    users = db.query(ConsoleUser).order_by(ConsoleUser.id.asc()).all()
    for position, user in enumerate(users):
        db.add(
            OrganizationMembership(
                user_id=user.id,
                org_id=default.id,
                role="owner" if position == 0 else "member",
            )
        )

    backfilled = _backfill_null_org_rows(db, default.id)
    db.commit()

    logger.info(
        "Seeded default organization id=%s users=%s backfilled_rows=%s",
        default.id,
        len(users),
        backfilled,
    )
    return default


def _backfill_null_org_rows(db: Session, org_id: int) -> int:
    """Assign pre-existing platform rows to the default organization."""

    from database import engine
    from sqlalchemy import text

    total = 0
    with engine.begin() as connection:
        for table in _BACKFILL_TABLE_NAMES:
            result = connection.execute(
                text(f"UPDATE {table} SET org_id = :org_id WHERE org_id IS NULL"),
                {"org_id": org_id},
            )
            total += result.rowcount or 0
        for table in _BACKFILL_USER_CREATED_ONLY:
            # Keep seeded system-managed rows platform-shared (org_id NULL);
            # only user-created rows move into the default organization.
            result = connection.execute(
                text(
                    f"UPDATE {table} SET org_id = :org_id "
                    "WHERE org_id IS NULL AND system_managed = 0"
                ),
                {"org_id": org_id},
            )
            total += result.rowcount or 0
    db.expire_all()
    return total


def default_organization(db: Session) -> Organization | None:
    return (
        db.query(Organization).filter(Organization.is_default.is_(True)).one_or_none()
    )


def is_platform_principal(principal: Principal) -> bool:
    """Platform principals see and manage everything (pre-tenancy behavior)."""
    return principal.org_id is None


def scoped_query(db: Session, model, principal: Principal):
    """Read query for ``model`` respecting tenant visibility.

    Platform principals get an unfiltered query. Org principals see their own
    rows plus ``org_id IS NULL`` platform-shared rows (e.g. seeded default
    policies) — mirroring what a single-tenant deployment showed before.
    """
    query = db.query(model)
    if principal.org_id is None:
        return query
    return query.filter(
        or_(model.org_id == principal.org_id, model.org_id.is_(None))
    )


def org_owned_query(db: Session, model, principal: Principal):
    """Query restricted to rows owned by the principal's organization.

    Used for assets that are strictly tenant-owned (managed API keys):
    platform-shared rows are NOT visible to org principals.
    """
    query = db.query(model)
    if principal.org_id is None:
        return query
    return query.filter(model.org_id == principal.org_id)


def org_scope_filter(model, org_id: int | None):
    """Filter matching rows visible to ``org_id`` (own rows + shared NULLs)."""
    if org_id is None:
        return model.org_id.is_(None)
    return or_(model.org_id == org_id, model.org_id.is_(None))


def exact_org_filter(model, org_id: int | None):
    """Filter matching rows owned exactly by ``org_id`` (NULL means platform)."""
    if org_id is None:
        return model.org_id.is_(None)
    return model.org_id == org_id


def new_row_org_id(principal: Principal) -> int | None:
    """Organization a newly created row belongs to (None = platform-shared)."""
    return principal.org_id


def can_manage_row(principal: Principal, row) -> bool:
    """Whether ``principal`` may modify/delete ``row``.

    Platform principals manage everything; org principals only their own
    organization's rows (never platform-shared ``org_id IS NULL`` rows).
    """
    if principal.org_id is None:
        return True
    return getattr(row, "org_id", None) == principal.org_id


def user_memberships(db: Session, user_id: int) -> list[OrganizationMembership]:
    return (
        db.query(OrganizationMembership)
        .filter(OrganizationMembership.user_id == user_id)
        .order_by(OrganizationMembership.id.asc())
        .all()
    )


def membership_role(db: Session, user_id: int, org_id: int) -> str | None:
    row = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.org_id == org_id,
        )
        .one_or_none()
    )
    return row.role if row else None


def default_org_context(db: Session, user_id: int) -> tuple[int | None, str | None]:
    """Pick the active org for a fresh login: highest role wins, then age."""
    memberships = user_memberships(db, user_id)
    if not memberships:
        return None, None
    role_rank = {"owner": 0, "admin": 1, "member": 2}
    best = sorted(
        memberships,
        key=lambda item: (role_rank.get(item.role, 9), item.id),
    )[0]
    return best.org_id, best.role


# --- access-control helpers -------------------------------------------------


def _forbidden(message: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"error": "forbidden", "message": message},
    )


def _not_found(message: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"error": "not_found", "message": message},
    )


async def require_org_admin(
    request: Request,
    db: Session = Depends(get_db),
) -> Principal:
    """Require an admin principal that also administers its active organization.

    Platform admins (static keys, org_id None) pass unconditionally. Console
    admins must hold the ``owner`` or ``admin`` role in their active org.
    """
    principal = await require_admin(request)
    if principal.org_id is None:
        return principal
    if principal.org_role not in ORG_ADMIN_ROLES:
        raise _forbidden("Organization owner or admin role required.")
    return principal


def require_org_admin_for(
    db: Session,
    principal: Principal,
    org_id: int,
    *,
    allow_member: bool = False,
) -> Organization:
    """Load ``org_id`` and verify the principal may act on it.

    Platform admins act on any organization. Org principals must be a member
    (``allow_member``) or an owner/admin of that specific organization.
    Unknown orgs raise 404; foreign orgs raise 404 as well so tenant
    existence is not leaked across boundaries.
    """
    org = db.query(Organization).filter(Organization.id == org_id).one_or_none()
    if org is None:
        raise _not_found("Organization does not exist.")
    if principal.org_id is None:
        return org
    if principal.org_id != org_id:
        raise _not_found("Organization does not exist.")
    if allow_member:
        return org
    if principal.org_role not in ORG_ADMIN_ROLES:
        raise _forbidden("Organization owner or admin role required.")
    return org


def principal_user_id(principal: Principal) -> int | None:
    """Console user id from the principal subject (None for non-console auth)."""
    prefix = "console-user:"
    if not principal.subject.startswith(prefix):
        return None
    try:
        return int(principal.subject[len(prefix):])
    except ValueError:
        return None


def serialize_org(org: Organization) -> dict:
    return {
        "id": org.id,
        "slug": org.slug,
        "name": org.name,
        "is_default": bool(org.is_default),
        "created_at": org.created_at.isoformat() + "Z" if org.created_at else "",
        "updated_at": org.updated_at.isoformat() + "Z" if org.updated_at else "",
    }
