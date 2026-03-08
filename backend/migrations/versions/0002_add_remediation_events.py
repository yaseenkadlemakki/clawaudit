"""Add remediation_events table.

Revision ID: 0002
Revises: 0ae4843244bc
Create Date: 2026-03-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | Sequence[str] | None = "0ae4843244bc"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the remediation_events table."""
    op.create_table(
        "remediation_events",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("proposal_id", sa.String(), nullable=False),
        sa.Column("skill_name", sa.String(), nullable=False),
        sa.Column("check_id", sa.String(), nullable=False),
        sa.Column("action_type", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("diff_preview", sa.Text(), nullable=False, server_default=""),
        sa.Column("impact", sa.Text(), nullable=False, server_default=""),
        sa.Column("snapshot_path", sa.String(), nullable=True),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
    )
    op.create_index("ix_remediation_events_proposal_id", "remediation_events", ["proposal_id"])
    op.create_index("ix_remediation_events_skill_name", "remediation_events", ["skill_name"])
    op.create_index("ix_remediation_events_applied_at", "remediation_events", ["applied_at"])


def downgrade() -> None:
    """Drop the remediation_events table."""
    op.drop_index("ix_remediation_events_applied_at", table_name="remediation_events")
    op.drop_index("ix_remediation_events_skill_name", table_name="remediation_events")
    op.drop_index("ix_remediation_events_proposal_id", table_name="remediation_events")
    op.drop_table("remediation_events")
