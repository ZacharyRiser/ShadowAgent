"""multi-tenancy: organizations, memberships, SSO connections, org_id columns

Revision ID: a7c4e9f1b3d6
Revises: b2e5c8d1a4f7
Create Date: 2026-09-08

Adds the tenant model (organizations, organization_memberships,
sso_connections) plus a nullable ``org_id`` column to every tenant-scoped
table. Existing rows keep ``org_id IS NULL`` (platform-shared); the default
organization is seeded and rows are backfilled lazily at startup
(``app.tenancy.ensure_default_organization``) so the migration itself stays
pure schema.

The tool_policies.tool_name global unique constraint becomes
(org_id, tool_name) so an organization can override a shared default for the
same tool without collisions. Likewise custom_rules.name becomes
(org_id, name): rule names may repeat across organizations; uniqueness of
platform-shared (NULL org) names stays an application-level check because
SQL NULL semantics exempt those rows from the index.
"""

from alembic import op
import sqlalchemy as sa

revision = "a7c4e9f1b3d6"
down_revision = "b2e5c8d1a4f7"
branch_labels = None
depends_on = None

_ORG_SCOPED_TABLES = (
    "intercept_logs",
    "audit_logs",
    "security_policies",
    "approval_requests",
    "alert_events",
    "replay_runs",
    "managed_api_keys",
)


def _custom_rule_columns(include_org_id: bool) -> list[sa.Column]:
    columns = [sa.Column("id", sa.Integer(), primary_key=True)]
    if include_org_id:
        columns.append(sa.Column("org_id", sa.Integer(), nullable=True))
    columns.extend(
        [
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("rule_type", sa.String(length=16), nullable=False),
            sa.Column("pattern", sa.String(length=512), nullable=False),
            sa.Column("target", sa.String(length=16), nullable=False),
            sa.Column("action", sa.String(length=16), nullable=False),
            sa.Column("risk_score", sa.Float(), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        ]
    )
    return columns


def _custom_rule_indexes(include_org_id: bool) -> list[sa.Index]:
    indexes = [
        sa.Index("ix_custom_rules_id", "id"),
        sa.Index("ix_custom_rules_name", "name"),
        sa.Index("ix_custom_rules_rule_type", "rule_type"),
        sa.Index("ix_custom_rules_target", "target"),
        sa.Index("ix_custom_rules_action", "action"),
        sa.Index("ix_custom_rules_enabled", "enabled"),
    ]
    if include_org_id:
        indexes.append(sa.Index("ix_custom_rules_org_id", "org_id"))
        indexes.append(sa.Index("uq_custom_rule_org_name", "org_id", "name", unique=True))
    return indexes


def _upgrade_custom_rules_tenancy() -> None:
    """custom_rules: add org_id and swap the global UNIQUE(name) constraint
    (inline in the baseline schema, hence an unnamed SQLite autoindex /
    ``custom_rules_name_key`` on Postgres) for a per-organization
    (org_id, name) unique index."""
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        pre_state = sa.Table(
            "custom_rules",
            sa.MetaData(),
            *(_custom_rule_columns(include_org_id=False)),
            sa.UniqueConstraint("name", name="uq_custom_rules_name_legacy"),
            *_custom_rule_indexes(include_org_id=False),
        )
        with op.batch_alter_table("custom_rules", copy_from=pre_state) as batch:
            batch.drop_constraint("uq_custom_rules_name_legacy", type_="unique")
            batch.add_column(sa.Column("org_id", sa.Integer(), nullable=True))
            batch.create_index("ix_custom_rules_org_id", ["org_id"])
            batch.create_index("uq_custom_rule_org_name", ["org_id", "name"], unique=True)
    else:
        op.drop_constraint("custom_rules_name_key", "custom_rules", type_="unique")
        op.add_column("custom_rules", sa.Column("org_id", sa.Integer(), nullable=True))
        op.create_index("ix_custom_rules_org_id", "custom_rules", ["org_id"])
        op.create_index("uq_custom_rule_org_name", "custom_rules", ["org_id", "name"], unique=True)


def _downgrade_custom_rules_tenancy() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        post_state = sa.Table(
            "custom_rules",
            sa.MetaData(),
            *(_custom_rule_columns(include_org_id=True)),
            *_custom_rule_indexes(include_org_id=True),
        )
        with op.batch_alter_table("custom_rules", copy_from=post_state) as batch:
            batch.drop_index("uq_custom_rule_org_name")
            batch.drop_index("ix_custom_rules_org_id")
            batch.drop_column("org_id")
            batch.create_unique_constraint("uq_custom_rules_name_legacy", ["name"])
    else:
        op.drop_index("uq_custom_rule_org_name", table_name="custom_rules")
        op.drop_index("ix_custom_rules_org_id", table_name="custom_rules")
        op.drop_column("custom_rules", "org_id")
        op.create_unique_constraint("uq_custom_rules_name_legacy", "custom_rules", ["name"])


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("is_default", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_index("ix_organizations_id", "organizations", ["id"])
    op.create_index("ix_organizations_slug", "organizations", ["slug"])
    op.create_index("ix_organizations_is_default", "organizations", ["is_default"])

    op.create_table(
        "organization_memberships",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("org_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["console_users.id"]),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "org_id", name="uq_org_membership_user_org"),
    )
    op.create_index("ix_organization_memberships_id", "organization_memberships", ["id"])
    op.create_index("ix_organization_memberships_user_id", "organization_memberships", ["user_id"])
    op.create_index("ix_organization_memberships_org_id", "organization_memberships", ["org_id"])
    op.create_index("ix_organization_memberships_role", "organization_memberships", ["role"])

    op.create_table(
        "sso_connections",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("org_id", sa.Integer(), nullable=False),
        sa.Column("provider_name", sa.String(length=128), nullable=False),
        sa.Column("client_id", sa.String(length=255), nullable=False),
        sa.Column("client_secret", sa.String(length=512), nullable=False),
        sa.Column("issuer_url", sa.String(length=512), nullable=False),
        sa.Column("scopes", sa.String(length=255), nullable=False),
        sa.Column("jit_enabled", sa.Boolean(), nullable=False),
        sa.Column("default_role", sa.String(length=32), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id"),
    )
    op.create_index("ix_sso_connections_id", "sso_connections", ["id"])
    op.create_index("ix_sso_connections_org_id", "sso_connections", ["org_id"])
    op.create_index("ix_sso_connections_enabled", "sso_connections", ["enabled"])

    for table in _ORG_SCOPED_TABLES:
        # SQLite requires table rebuilds for constraint changes but accepts
        # plain ADD COLUMN + index for nullable columns — batch mode keeps
        # both dialects working.
        with op.batch_alter_table(table) as batch:
            batch.add_column(sa.Column("org_id", sa.Integer(), nullable=True))
            batch.create_index(f"ix_{table}_org_id", ["org_id"])

    # tool_policies: org_id column + swap the global tool_name unique index
    # for a per-organization (org_id, tool_name) unique index. NULL org_id
    # rows (platform defaults) are excluded by SQLite/Postgres NULL semantics,
    # so uniqueness of shared rows stays an application-level check.
    with op.batch_alter_table("tool_policies") as batch:
        batch.add_column(sa.Column("org_id", sa.Integer(), nullable=True))
        batch.create_index("ix_tool_policies_org_id", ["org_id"])
        batch.drop_index("ix_tool_policies_tool_name")
    op.create_index(
        "uq_tool_policy_org_tool",
        "tool_policies",
        ["org_id", "tool_name"],
        unique=True,
    )

    _upgrade_custom_rules_tenancy()


def downgrade() -> None:
    _downgrade_custom_rules_tenancy()

    op.drop_index("uq_tool_policy_org_tool", table_name="tool_policies")
    with op.batch_alter_table("tool_policies") as batch:
        batch.create_index("ix_tool_policies_tool_name", ["tool_name"], unique=True)
        batch.drop_index("ix_tool_policies_org_id")
        batch.drop_column("org_id")

    for table in reversed(_ORG_SCOPED_TABLES):
        with op.batch_alter_table(table) as batch:
            batch.drop_index(f"ix_{table}_org_id")
            batch.drop_column("org_id")

    op.drop_index("ix_sso_connections_enabled", table_name="sso_connections")
    op.drop_index("ix_sso_connections_org_id", table_name="sso_connections")
    op.drop_index("ix_sso_connections_id", table_name="sso_connections")
    op.drop_table("sso_connections")

    op.drop_index("ix_organization_memberships_role", table_name="organization_memberships")
    op.drop_index("ix_organization_memberships_org_id", table_name="organization_memberships")
    op.drop_index("ix_organization_memberships_user_id", table_name="organization_memberships")
    op.drop_index("ix_organization_memberships_id", table_name="organization_memberships")
    op.drop_table("organization_memberships")

    op.drop_index("ix_organizations_is_default", table_name="organizations")
    op.drop_index("ix_organizations_slug", table_name="organizations")
    op.drop_index("ix_organizations_id", table_name="organizations")
    op.drop_table("organizations")
