"""SQLAlchemy models for Shadow Agent."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class Organization(Base):
    """Tenant entity: scopes policies, rules, keys, and runtime artifacts.

    The seeded ``default`` organization (``is_default=True``) preserves
    single-tenant behavior — every pre-existing row is backfilled into it on
    first boot after the upgrade.
    """

    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class OrganizationMembership(Base):
    """User ↔ organization link with an org-level role.

    role: ``owner`` (full control, includes deleting the org), ``admin``
    (manage members/rules/keys/SSO), ``member`` (console access, no admin).
    """

    __tablename__ = "organization_memberships"
    __table_args__ = (
        UniqueConstraint("user_id", "org_id", name="uq_org_membership_user_org"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("console_users.id"), nullable=False, index=True
    )
    org_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("organizations.id"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(String(32), default="member", nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )


class SsoConnection(Base):
    """Per-organization OIDC identity provider (Authorization Code + PKCE).

    ``client_secret`` is write-only through the API (never returned). It is
    stored as-is at rest in v1 — deployments should protect the database
    volume (documented in the launch checklist).
    """

    __tablename__ = "sso_connections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    org_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("organizations.id"), nullable=False, unique=True, index=True
    )
    provider_name: Mapped[str] = mapped_column(String(128), nullable=False)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    client_secret: Mapped[str] = mapped_column(String(512), nullable=False)
    issuer_url: Mapped[str] = mapped_column(String(512), nullable=False)
    scopes: Mapped[str] = mapped_column(String(255), default="openid email profile", nullable=False)
    jit_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    default_role: Mapped[str] = mapped_column(String(32), default="client", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class InterceptLog(Base):
    __tablename__ = "intercept_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    org_id: Mapped[int] = mapped_column(Integer, nullable=True, index=True)
    request_id: Mapped[str] = mapped_column(
        String(96),
        default="",
        nullable=False,
        index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )
    threat_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action_taken: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    original_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    org_id: Mapped[int] = mapped_column(Integer, nullable=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )
    request_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    original_instruction: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    triggered_rule_name: Mapped[str] = mapped_column(String(128), nullable=False)
    intercept_reason: Mapped[str] = mapped_column(Text, nullable=False)


class SecurityPolicy(Base):
    __tablename__ = "security_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    org_id: Mapped[int] = mapped_column(Integer, nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    blacklist_keyword: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)
    scope: Mapped[str] = mapped_column(String(64), default="Prompt", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    system_managed: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )


class ToolPolicy(Base):
    """Tool access policy.

    ``org_id IS NULL`` rows are platform defaults shared by every tenant; an
    org-scoped row with the same ``tool_name`` overrides the default for that
    organization's traffic only.
    """

    __tablename__ = "tool_policies"
    __table_args__ = (
        UniqueConstraint("org_id", "tool_name", name="uq_tool_policy_org_tool"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    org_id: Mapped[int] = mapped_column(Integer, nullable=True, index=True)
    tool_name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    allowed: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
    )
    requires_admin_approval: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    system_managed: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    org_id: Mapped[int] = mapped_column(Integer, nullable=True, index=True)
    request_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)
    threat_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    recommended_action: Mapped[str] = mapped_column(String(32), default="block", nullable=False)
    original_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    tool_name: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    categories: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    evidence: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    details: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    reviewed_by: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    review_comment: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class AlertEvent(Base):
    __tablename__ = "alert_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    org_id: Mapped[int] = mapped_column(Integer, nullable=True, index=True)
    request_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), default="medium", nullable=False, index=True)
    channel: Mapped[str] = mapped_column(String(32), default="console", nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="triggered", nullable=False, index=True)
    details: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )


class ReplayRun(Base):
    __tablename__ = "replay_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    org_id: Mapped[int] = mapped_column(Integer, nullable=True, index=True)
    source_request_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    replay_request_id: Mapped[str] = mapped_column(String(96), nullable=False, unique=True, index=True)
    triggered_by: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False, index=True)
    risk_score: Mapped[str] = mapped_column(String(32), default="0", nullable=False)
    category: Mapped[str] = mapped_column(String(64), default="none", nullable=False, index=True)
    details: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )


class CustomRule(Base):
    """User-defined detection rule evaluated by the gateway engines.

    rule_type: "regex" (Python re, case-insensitive) or "keyword" (substring).
    target: "prompt" (request side), "response" (model output / DLP), or "any".
    action: "block" (403 / terminate stream), "redact" (response side only,
    replaces the match with a placeholder), or "alert" (log only).

    Names are unique per organization (``uq_custom_rule_org_name``); NULL-org
    rows are platform-shared, whose name uniqueness is enforced at the
    application layer because SQL NULL semantics exempt them from the index.
    """

    __tablename__ = "custom_rules"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_custom_rule_org_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    org_id: Mapped[int] = mapped_column(Integer, nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    rule_type: Mapped[str] = mapped_column(String(16), default="regex", nullable=False, index=True)
    pattern: Mapped[str] = mapped_column(String(512), nullable=False)
    target: Mapped[str] = mapped_column(String(16), default="prompt", nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(16), default="block", nullable=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.8, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class ConsoleUser(Base):
    __tablename__ = "console_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="admin", nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class ManagedApiKey(Base):
    __tablename__ = "managed_api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    org_id: Mapped[int] = mapped_column(Integer, nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(32), default="client", nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    created_by: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    last_used_by: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )
