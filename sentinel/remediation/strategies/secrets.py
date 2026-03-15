"""Strategy for ADV-005 — Credentials exposed in SKILL.md."""

from __future__ import annotations

import difflib
import re
from pathlib import Path

from sentinel.remediation.actions import ActionType, RemediationProposal

# Patterns matching secret values — redact the value, keep the key
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    # Anthropic / OpenAI keys — require value context (after =, :, ", or whitespace start)
    re.compile(r"(?<=[=:\"\'\s])(sk-[A-Za-z0-9\-]{20,})", re.IGNORECASE),
    # AWS keys
    re.compile(r"(AKIA[A-Z0-9]{16})", re.IGNORECASE),
    # GitHub tokens
    re.compile(r"(gh[pousr]_[A-Za-z0-9]{36,})", re.IGNORECASE),
    # Generic API key assignments  (api_key = 'value', token: "value")
    re.compile(
        r'((?:api[_\-]?key|token|password|secret|credential)\s*[=:]\s*["\']?)([A-Za-z0-9/+_\-]{16,})',
        re.IGNORECASE,
    ),
    # Bearer tokens
    re.compile(r"(Bearer\s+)([A-Za-z0-9._\-]{20,})", re.IGNORECASE),
]

_REDACTED = "[REDACTED]"


def _redact_line(line: str) -> tuple[str, bool]:
    """Redact secrets in a single line. Returns (new_line, changed)."""
    changed = False
    for pattern in _SECRET_PATTERNS:
        # For patterns with two groups, replace group 2 only
        if pattern.groups == 2:
            new_line = pattern.sub(lambda m: m.group(1) + _REDACTED, line)
        else:
            new_line = pattern.sub(_REDACTED, line)
        if new_line != line:
            line = new_line
            changed = True
    return line, changed


def propose(
    skill_name: str,
    skill_path: Path,
    finding_id: str,
    check_id: str = "ADV-005",
    **kwargs: object,
) -> RemediationProposal | None:
    """Propose a remediation for ADV-005 (exposed secrets)."""
    skill_md = skill_path / "SKILL.md"
    if not skill_md.exists():
        return None

    original_lines = skill_md.read_text(encoding="utf-8").splitlines(keepends=True)
    patched_lines = []
    secrets_found = 0

    for line in original_lines:
        new_line, changed = _redact_line(line)
        patched_lines.append(new_line)
        if changed:
            secrets_found += 1

    if secrets_found == 0:
        return None

    diff = "".join(
        difflib.unified_diff(
            original_lines,
            patched_lines,
            fromfile=f"a/{skill_name}/SKILL.md",
            tofile=f"b/{skill_name}/SKILL.md",
            lineterm="",
        )
    )

    return RemediationProposal.create(
        finding_id=finding_id,
        check_id=check_id,
        skill_name=skill_name,
        skill_path=skill_path,
        description=(
            f"Redact {secrets_found} exposed credential(s) in '{skill_name}/SKILL.md'. "
            "Secret values replaced with [REDACTED]."
        ),
        action_type=ActionType.REDACT_SECRET,
        diff_preview=diff,
        impact=[
            f"{secrets_found} credential(s) will be replaced with [REDACTED].",
            "Any documentation referencing these credentials will need to be updated separately.",
            "IMPORTANT: Rotate any exposed credentials immediately — they may already be compromised.",
        ],
    )


def apply_patch(skill_path: Path, **kwargs: object) -> str:
    """Apply the secret-redaction patch in-place. Returns new file content."""
    skill_md = skill_path / "SKILL.md"
    lines = skill_md.read_text(encoding="utf-8").splitlines(keepends=True)
    patched = [_redact_line(line)[0] for line in lines]
    content = "".join(patched)
    tmp = skill_md.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(skill_md)
    return content
