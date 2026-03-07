"""ORM model for remediation events."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base


class RemediationEvent(Base):
    """Persists every remediation action taken (apply or rollback)."""

    __tablename__ = "remediation_events"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    proposal_id: Mapped[str] = mapped_column(String, index=True)
    skill_name: Mapped[str] = mapped_column(String, index=True)
    check_id: Mapped[str] = mapped_column(String)
    action_type: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)  # applied | rolled_back | failed
    description: Mapped[str] = mapped_column(Text, default="")
    diff_preview: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")  # JSON array stored as text
    snapshot_path: Mapped[str | None] = mapped_column(String, nullable=True)
    applied_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
