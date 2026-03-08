"""Add skill_installs audit log table.

Revision ID: 0003
Revises: 0002
Create Date: 2026-03-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the skill_installs audit log table."""
    op.create_table(
        "skill_installs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("skill_name", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("source", sa.String(), nullable=True),
        sa.Column("content_hash", sa.String(), nullable=True),
        sa.Column("performed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
    )
    op.create_index("ix_skill_installs_skill_name", "skill_installs", ["skill_name"])


def downgrade() -> None:
    """Drop the skill_installs table."""
    op.drop_index("ix_skill_installs_skill_name", table_name="skill_installs")
    op.drop_table("skill_installs")
