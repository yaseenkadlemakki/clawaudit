"""Event data model."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Event:
    """Represents a security event emitted by a collector."""

    source: str
    event_type: str
    severity: str
    entity: str
    evidence: str
    action_taken: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ts: datetime = field(default_factory=datetime.utcnow)
    policy_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ts": self.ts.isoformat(),
            "source": self.source,
            "event_type": self.event_type,
            "severity": self.severity,
            "entity": self.entity,
            "evidence": self.evidence,
            "policy_refs": self.policy_refs,
            "action_taken": self.action_taken,
        }
