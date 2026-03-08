"""Add tool_events table for runtime hook integration.

Revision ID: 0005
Revises: 0004
Create Date: 2026-03-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | Sequence[str] | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add tool_events table."""
    op.create_table(
        "tool_events",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("session_id", sa.Text(), nullable=False),
        sa.Column("skill_name", sa.Text(), nullable=True),
        sa.Column("tool_name", sa.Text(), nullable=False),
        sa.Column("params_summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("timestamp", sa.Text(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("outcome", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("alert_triggered", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("alert_reasons", sa.Text(), nullable=False, server_default="[]"),
    )
    op.create_index("ix_tool_events_session_id", "tool_events", ["session_id"])
    op.create_index("ix_tool_events_skill_name", "tool_events", ["skill_name"])
    op.create_index("ix_tool_events_alert", "tool_events", ["alert_triggered"])


def downgrade() -> None:
    """Remove tool_events table."""
    op.drop_index("ix_tool_events_alert", table_name="tool_events")
    op.drop_index("ix_tool_events_skill_name", table_name="tool_events")
    op.drop_index("ix_tool_events_session_id", table_name="tool_events")
    op.drop_table("tool_events")
