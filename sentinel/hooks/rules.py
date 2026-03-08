"""Alert rule engine for runtime hook events."""

from __future__ import annotations

import re
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.hooks.event import ToolEvent

# Regex for PTY detection — must match pty=true or pty: true as a discrete setting
_PTY_PATTERN = re.compile(r"""(?<![a-zA-Z_])["']?pty["']?\s*[:=]\s*true\b""", re.IGNORECASE)

# Sensitive paths that should trigger alerts when accessed
_SENSITIVE_PATHS = [
    Path.home() / ".ssh",
    Path.home() / ".aws",
    Path.home() / ".openclaw" / "openclaw.json",
    Path.home() / ".gnupg",
    Path("/etc/passwd"),
    Path("/etc/shadow"),
]

# Domains considered safe for browser navigation
SAFE_BROWSER_DOMAINS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "github.com",
        "docs.python.org",
        "pypi.org",
        "npmjs.com",
        "stackoverflow.com",
    }
)

# Workspace prefixes where writes are allowed
_ALLOWED_WRITE_DIRS = [
    Path.home() / "Desktop",
    Path("/tmp"),
    Path(tempfile.gettempdir()),
]

# High-frequency threshold
HIGH_FREQ_LIMIT = 20
HIGH_FREQ_WINDOW_SECONDS = 60


def _normalize_path(raw: str) -> Path | None:
    """Try to extract and normalize a path from summary text."""
    match = re.search(r"(?:path|file|read|write)[=:\s]+([^\s,\]]+)", raw, re.IGNORECASE)
    if match:
        try:
            return Path(match.group(1)).expanduser().resolve()
        except Exception:
            return None
    return None


def rule_exec_pty(event: ToolEvent) -> list[str]:
    """Flag exec calls with pty:true (interactive shell access)."""
    if event.tool_name != "exec":
        return []
    if _PTY_PATTERN.search(event.params_summary):
        return ["exec called with pty:true — interactive shell access detected"]
    return []


def rule_sensitive_path_read(event: ToolEvent) -> list[str]:
    """Flag reads of sensitive paths like ~/.ssh, ~/.aws, ~/.gnupg."""
    if event.tool_name not in ("read", "write", "exec"):
        return []
    p = _normalize_path(event.params_summary)
    if p is None:
        # Fall back to expanded string matching
        for sp in _SENSITIVE_PATHS:
            resolved = str(sp.resolve())
            if resolved in event.params_summary:
                return [f"sensitive path access: {sp}"]
        return []
    for sensitive in _SENSITIVE_PATHS:
        try:
            resolved_sensitive = sensitive.resolve()
            if p == resolved_sensitive or str(p).startswith(str(resolved_sensitive) + "/"):
                return [f"sensitive path access: {sensitive}"]
        except Exception:
            pass
    return []


def rule_write_outside_workspace(event: ToolEvent) -> list[str]:
    """Flag writes to paths outside the workspace or /tmp."""
    if event.tool_name != "write":
        return []
    p = _normalize_path(event.params_summary)
    if p is None:
        return []
    allowed = [d.resolve() for d in _ALLOWED_WRITE_DIRS]
    if not any(p == a or str(p).startswith(str(a) + "/") for a in allowed):
        return [f"write outside workspace: {p}"]
    return []


def rule_browser_navigate(event: ToolEvent) -> list[str]:
    """Flag browser navigation to non-safe domains."""
    if event.tool_name != "browser":
        return []
    summary = event.params_summary.lower()
    if "navigate" not in summary:
        return []
    # Check if any safe domain is in the URL
    for domain in SAFE_BROWSER_DOMAINS:
        if domain in summary:
            return []
    return [f"browser navigation to potentially unsafe domain: {summary[:100]}"]


def rule_high_frequency(
    event: ToolEvent,
    recent: list[ToolEvent] | None = None,
) -> list[str]:
    """Flag if >20 tool calls in the last 60 seconds for this session."""
    if recent is None:
        return []
    cutoff = event.timestamp - timedelta(seconds=HIGH_FREQ_WINDOW_SECONDS)
    count = sum(1 for e in recent if e.timestamp >= cutoff and e.session_id == event.session_id)
    if count >= HIGH_FREQ_LIMIT:
        return [f"high frequency: {count} tool calls in {HIGH_FREQ_WINDOW_SECONDS}s"]
    return []


# All single-event rules (no extra context needed)
_SINGLE_RULES = [
    rule_exec_pty,
    rule_sensitive_path_read,
    rule_write_outside_workspace,
    rule_browser_navigate,
]


def evaluate_rules(
    event: ToolEvent,
    recent: list[ToolEvent] | None = None,
) -> list[str]:
    """Run all alert rules against an event. Returns list of alert reasons."""
    reasons: list[str] = []
    for rule in _SINGLE_RULES:
        reasons.extend(rule(event))
    reasons.extend(rule_high_frequency(event, recent))
    return reasons
