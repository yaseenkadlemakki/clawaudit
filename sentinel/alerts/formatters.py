"""Alert message formatters."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.models.event import Event
    from sentinel.models.finding import Finding
    from sentinel.models.policy import PolicyDecision

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}

LINE = "━" * 28


def format_finding_alert(finding: Finding, decision: PolicyDecision) -> str:
    """Format a finding into an alert message string."""
    emoji = SEVERITY_EMOJI.get(finding.severity, "⚠️")
    policy_ids = ", ".join(decision.policy_ids) if decision.policy_ids else "default"
    ts = finding.detected_at.strftime("%Y-%m-%dT%H:%M:%SZ")

    lines = [
        f"{emoji} [SENTINEL] {finding.severity} — {finding.title}",
        LINE,
        f"Check: {finding.check_id} / Policy: {policy_ids}",
        f"Finding: {finding.evidence}",
        f"Location: {finding.location}",
        f"Time: {ts}",
        LINE,
        "Run: `sentinel audit --fix` to remediate",
    ]
    if finding.remediation:
        lines.insert(-1, f"Remediation: {finding.remediation}")

    return "\n".join(lines)


def format_event_alert(event: Event, decision: PolicyDecision) -> str:
    """Format an event into an alert message string."""
    emoji = SEVERITY_EMOJI.get(event.severity, "⚠️")
    policy_ids = ", ".join(decision.policy_ids) if decision.policy_ids else "default"
    ts = event.ts.strftime("%Y-%m-%dT%H:%M:%SZ")

    lines = [
        f"{emoji} [SENTINEL] {event.severity} — {event.event_type}",
        LINE,
        f"Source: {event.source} / Policy: {policy_ids}",
        f"Entity: {event.entity}",
        f"Evidence: {event.evidence}",
        f"Action taken: {decision.action}",
        f"Time: {ts}",
        LINE,
        f"Reason: {decision.reason}",
    ]
    return "\n".join(lines)
