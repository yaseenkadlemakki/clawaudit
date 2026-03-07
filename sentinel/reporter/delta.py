"""Delta report — new vs resolved findings."""

from __future__ import annotations

import json
from pathlib import Path

from sentinel.models.finding import Finding


def load_findings_from_jsonl(path: Path) -> list[Finding]:
    """Load findings from a JSONL file."""
    if not path.exists():
        return []
    findings = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            from datetime import datetime

            findings.append(
                Finding(
                    id=data.get("id", ""),
                    check_id=data.get("check_id", ""),
                    domain=data.get("domain", ""),
                    title=data.get("title", ""),
                    description=data.get("description", ""),
                    severity=data.get("severity", "INFO"),
                    result=data.get("result", "UNKNOWN"),
                    evidence=data.get("evidence", ""),
                    location=data.get("location", ""),
                    remediation=data.get("remediation", ""),
                    run_id=data.get("run_id", ""),
                    detected_at=datetime.fromisoformat(
                        data.get("detected_at", datetime.utcnow().isoformat())
                    ),
                )
            )
        except (json.JSONDecodeError, KeyError):
            continue
    return findings


def compute_delta(
    previous: list[Finding],
    current: list[Finding],
) -> tuple[list[Finding], list[Finding]]:
    """Return (new_findings, resolved_findings)."""
    prev_keys = {f.check_id + f.location for f in previous if f.result == "FAIL"}
    curr_keys = {f.check_id + f.location for f in current if f.result == "FAIL"}

    new_findings = [
        f for f in current if (f.check_id + f.location) not in prev_keys and f.result == "FAIL"
    ]
    resolved_keys = prev_keys - curr_keys
    resolved = [f for f in previous if (f.check_id + f.location) in resolved_keys]

    return new_findings, resolved
