"""Finding data model."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Finding:
    """Represents a single security finding from a check or scan."""

    check_id: str
    domain: str
    title: str
    description: str
    severity: str
    result: str
    evidence: str
    location: str
    remediation: str
    run_id: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    detected_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: datetime | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "check_id": self.check_id,
            "domain": self.domain,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "result": self.result,
            "evidence": self.evidence,
            "location": self.location,
            "remediation": self.remediation,
            "run_id": self.run_id,
            "detected_at": self.detected_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }
