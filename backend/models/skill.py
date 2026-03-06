"""SkillRecord ORM model."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base


class SkillRecord(Base):
    """Persisted skill security profile from a scan."""

    __tablename__ = "skills"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scan_runs.id"), index=True)
    name: Mapped[str] = mapped_column(String, index=True)
    source: Mapped[str] = mapped_column(String, default="")
    path: Mapped[str] = mapped_column(String)
    shell_access: Mapped[bool] = mapped_column(Boolean, default=False)
    outbound_domains: Mapped[str] = mapped_column(String, default="[]")  # JSON list
    injection_risk: Mapped[str] = mapped_column(String, default="LOW")
    trust_score: Mapped[str] = mapped_column(String, default="TRUSTED")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(String, default="Low")
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> dict:
        import json

        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "name": self.name,
            "source": self.source,
            "path": self.path,
            "shell_access": self.shell_access,
            "outbound_domains": json.loads(self.outbound_domains) if self.outbound_domains else [],
            "injection_risk": self.injection_risk,
            "trust_score": self.trust_score,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
        }
