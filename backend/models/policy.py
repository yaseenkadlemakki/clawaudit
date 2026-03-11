"""Policy ORM model."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base


class PolicyRecord(Base):
    """Persisted policy rule."""

    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String, unique=True)
    domain: Mapped[str] = mapped_column(String, index=True)
    check: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)
    action: Mapped[str] = mapped_column(String)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    # Phase 8 extensions
    condition: Mapped[str] = mapped_column(String, default="equals")
    value: Mapped[str] = mapped_column(String, default="")
    priority: Mapped[int] = mapped_column(Integer, default=0)
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    tags: Mapped[str | None] = mapped_column(String, nullable=True)  # JSON array
    violation_count: Mapped[int] = mapped_column(Integer, default=0)
    last_triggered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "domain": self.domain,
            "check": self.check,
            "severity": self.severity,
            "action": self.action,
            "enabled": self.enabled,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "condition": self.condition,
            "value": self.value,
            "priority": self.priority,
            "builtin": self.builtin,
            "tags": self.tags,
            "violation_count": self.violation_count,
            "last_triggered_at": (
                self.last_triggered_at.isoformat() if self.last_triggered_at else None
            ),
        }
