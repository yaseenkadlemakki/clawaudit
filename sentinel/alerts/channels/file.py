"""File-based alert channel — writes alerts to a JSONL file."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.models.finding import Finding
    from sentinel.models.policy import PolicyDecision


class FileAlertChannel:
    """Writes alert records to a JSONL file."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def send(self, message: str, finding: Finding, decision: PolicyDecision) -> None:
        """Append alert to the JSONL file."""
        record = {
            "ts": datetime.utcnow().isoformat(),
            "finding_id": finding.id,
            "check_id": finding.check_id,
            "severity": finding.severity,
            "action": decision.action,
            "message": message,
            "policy_ids": decision.policy_ids,
        }
        with self._path.open("a") as fh:
            fh.write(json.dumps(record) + "\n")
