"""Add content_hash column to skills table.

Revision ID: 0004
Revises: 0003
Create Date: 2026-03-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add content_hash to skills table."""
    op.add_column("skills", sa.Column("content_hash", sa.String(), nullable=True))


def downgrade() -> None:
    """Remove content_hash from skills table."""
    op.drop_column("skills", "content_hash")
