"""Alert rule engine for runtime hook events."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.hooks.event import ToolEvent

# Sensitive paths that should trigger alerts when read
SENSITIVE_PATHS = (
    "~/.ssh",
    "~/.aws",
    "~/.openclaw/openclaw.json",
    "~/.gnupg",
)

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
WORKSPACE_PREFIXES = ("~/Desktop", "/tmp", "/var/folders")

# High-frequency threshold
HIGH_FREQ_LIMIT = 20
HIGH_FREQ_WINDOW_SECONDS = 60


def rule_exec_pty(event: ToolEvent) -> list[str]:
    """Flag exec calls with pty:true (interactive shell access)."""
    if event.tool_name != "exec":
        return []
    summary = event.params_summary.lower()
    if "pty" in summary and "true" in summary:
        return ["exec called with pty:true — interactive shell access detected"]
    return []


def rule_sensitive_path_read(event: ToolEvent) -> list[str]:
    """Flag reads of sensitive paths like ~/.ssh, ~/.aws, ~/.gnupg."""
    if event.tool_name != "read":
        return []
    summary = event.params_summary
    reasons: list[str] = []
    for sp in SENSITIVE_PATHS:
        if sp in summary:
            reasons.append(f"sensitive path read: {sp}")
    return reasons


def rule_write_outside_workspace(event: ToolEvent) -> list[str]:
    """Flag writes to paths outside the workspace or /tmp."""
    if event.tool_name != "write":
        return []
    summary = event.params_summary
    # If any workspace prefix is present, it's allowed
    for prefix in WORKSPACE_PREFIXES:
        if prefix in summary:
            return []
    return [f"write outside workspace: {summary[:100]}"]


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
