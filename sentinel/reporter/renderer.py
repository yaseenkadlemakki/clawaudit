"""Markdown and JSON report rendering."""

from __future__ import annotations

import json
from datetime import datetime

from sentinel.models.finding import Finding

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def render_markdown(findings: list[Finding], run_id: str) -> str:
    """Render findings as a Markdown compliance report."""
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.result] = counts.get(f.result, 0) + 1

    lines = [
        "# ClawAudit Sentinel — Compliance Report",
        "",
        f"**Run ID:** `{run_id}`  ",
        f"**Generated:** {ts}  ",
        f"**Total findings:** {len(findings)}  ",
        "",
        "## Summary",
        "",
        "| Result | Count |",
        "|--------|-------|",
    ]
    for result, count in sorted(counts.items()):
        lines.append(f"| {result} | {count} |")

    lines += ["", "## Findings", ""]

    for f in sorted_findings:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(
            f.severity, "⚪"
        )
        lines.append(f"### {icon} [{f.severity}] {f.check_id} — {f.title}")
        lines.append("")
        lines.append(f"**Result:** {f.result}  ")
        lines.append(f"**Domain:** {f.domain}  ")
        lines.append(f"**Location:** `{f.location}`  ")
        lines.append(f"**Evidence:** {f.evidence}  ")
        lines.append(f"**Description:** {f.description}  ")
        if f.remediation:
            lines.append(f"**Remediation:** {f.remediation}  ")
        lines.append("")

    return "\n".join(lines)


def render_json(findings: list[Finding], run_id: str) -> str:
    """Render findings as JSON."""
    return json.dumps(
        {
            "run_id": run_id,
            "generated_at": datetime.utcnow().isoformat(),
            "total": len(findings),
            "findings": [f.to_dict() for f in findings],
        },
        indent=2,
    )
