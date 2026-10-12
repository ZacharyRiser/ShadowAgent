"""custom rules table

Revision ID: b2e5c8d1a4f7
Revises: 8f95773ab0c6
Create Date: 2026-09-07

User-defined detection rules (regex/keyword) evaluated on the prompt side,
the response side (DLP), or both.
"""

from alembic import op
import sqlalchemy as sa

revision = "b2e5c8d1a4f7"
down_revision = "8f95773ab0c6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "custom_rules",
        sa.Column("id", sa.Integer(), nullable=False),
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_custom_rules_id", "custom_rules", ["id"])
    op.create_index("ix_custom_rules_name", "custom_rules", ["name"])
    op.create_index("ix_custom_rules_rule_type", "custom_rules", ["rule_type"])
    op.create_index("ix_custom_rules_target", "custom_rules", ["target"])
    op.create_index("ix_custom_rules_action", "custom_rules", ["action"])
    op.create_index("ix_custom_rules_enabled", "custom_rules", ["enabled"])


def downgrade() -> None:
    op.drop_index("ix_custom_rules_enabled", table_name="custom_rules")
    op.drop_index("ix_custom_rules_action", table_name="custom_rules")
    op.drop_index("ix_custom_rules_target", table_name="custom_rules")
    op.drop_index("ix_custom_rules_rule_type", table_name="custom_rules")
    op.drop_index("ix_custom_rules_name", table_name="custom_rules")
    op.drop_index("ix_custom_rules_id", table_name="custom_rules")
    op.drop_table("custom_rules")
