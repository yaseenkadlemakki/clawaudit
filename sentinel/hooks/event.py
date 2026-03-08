"""ToolEvent dataclass for runtime hook events."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone  # noqa: UP017

# Patterns to redact from params summaries
_REDACT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}", re.I)),
    ("OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9]{20,}", re.I)),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "Generic token",
        re.compile(
            r'(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*["\']?[A-Za-z0-9+/=_\-]{16,}["\']?'
        ),
    ),
    ("GitHub PAT", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("Private key header", re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----")),
]

MAX_PARAMS_LEN = 200


def sanitize_params(raw: str) -> str:
    """Truncate and redact secrets from a params summary string."""
    text = raw[:MAX_PARAMS_LEN]
    for _label, pattern in _REDACT_PATTERNS:
        text = pattern.sub("<REDACTED>", text)
    return text


@dataclass
class ToolEvent:
    """Represents a single tool call event from the OpenClaw runtime."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    skill_name: str | None = None
    tool_name: str = ""
    params_summary: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))  # noqa: UP017
    duration_ms: int | None = None
    outcome: str = "pending"
    alert_triggered: bool = False
    alert_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "session_id": self.session_id,
            "skill_name": self.skill_name,
            "tool_name": self.tool_name,
            "params_summary": self.params_summary,
            "timestamp": self.timestamp.isoformat(),
            "duration_ms": self.duration_ms,
            "outcome": self.outcome,
            "alert_triggered": self.alert_triggered,
            "alert_reasons": self.alert_reasons,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ToolEvent:
        """Deserialize from a dictionary."""
        ts = data.get("timestamp", "")
        if isinstance(ts, str) and ts:
            parsed_ts = datetime.fromisoformat(ts)
            if parsed_ts.tzinfo is None:
                parsed_ts = parsed_ts.replace(tzinfo=timezone.utc)  # noqa: UP017
        else:
            parsed_ts = datetime.now(timezone.utc)  # noqa: UP017

        reasons = data.get("alert_reasons", [])
        if isinstance(reasons, str):
            reasons = json.loads(reasons)

        return cls(
            id=data.get("id", str(uuid.uuid4())),
            session_id=data.get("session_id", ""),
            skill_name=data.get("skill_name"),
            tool_name=data.get("tool_name", ""),
            params_summary=data.get("params_summary", ""),
            timestamp=parsed_ts,
            duration_ms=data.get("duration_ms"),
            outcome=data.get("outcome", "pending"),
            alert_triggered=bool(data.get("alert_triggered", False)),
            alert_reasons=reasons,
        )
