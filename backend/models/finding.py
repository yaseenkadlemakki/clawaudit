"""FindingRecord ORM model."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base


class FindingRecord(Base):
    """Persisted security finding from a scan."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scan_runs.id"), index=True)
    check_id: Mapped[str] = mapped_column(String)
    domain: Mapped[str] = mapped_column(String)
    title: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String, index=True)
    result: Mapped[str] = mapped_column(String)
    evidence: Mapped[str] = mapped_column(String)
    location: Mapped[str] = mapped_column(String)
    remediation: Mapped[str] = mapped_column(String)
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    skill_name: Mapped[str | None] = mapped_column(String, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "check_id": self.check_id,
            "domain": self.domain,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "result": self.result,
            "evidence": self.evidence,
            "location": self.location,
            "remediation": self.remediation,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
            "skill_name": self.skill_name,
        }
