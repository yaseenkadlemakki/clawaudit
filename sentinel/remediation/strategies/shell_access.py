"""Strategy for ADV-001 — Unrestricted shell execution."""

from __future__ import annotations

import difflib
import re
from pathlib import Path

from sentinel.remediation.actions import ActionType, RemediationProposal

# Lines containing these patterns will be annotated as restricted
_SHELL_PATTERNS = [
    (re.compile(r"(pty\s*:\s*)true", re.IGNORECASE), r"\1false"),
    (re.compile(r"(\bsecurity\s*:\s*)(full)", re.IGNORECASE), r"\1allowlist"),
]

_SHELL_KEYWORDS = re.compile(
    r"\b(exec|bash|sh\s+-c|subprocess|os\.system|curl|wget)\b", re.IGNORECASE
)


def propose(
    skill_name: str,
    skill_path: Path,
    finding_id: str,
    check_id: str = "ADV-001",
    **kwargs: object,
) -> RemediationProposal | None:
    """Propose a remediation for ADV-001 (unrestricted shell execution).

    Returns None if the skill file cannot be read or has no applicable patterns.
    """
    skill_md = skill_path / "SKILL.md"
    if not skill_md.exists():
        return None

    original_lines = skill_md.read_text(encoding="utf-8").splitlines(keepends=True)
    patched_lines = list(original_lines)
    changes_made = 0

    for i, line in enumerate(patched_lines):
        # Replace pty:true → pty:false, security:full → security:allowlist
        for pattern, replacement in _SHELL_PATTERNS:
            new_line, n = pattern.subn(replacement, line)
            if n:
                patched_lines[i] = new_line
                changes_made += n
                break

    if changes_made == 0:
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
            f"Restrict shell execution capability in '{skill_name}': "
            "set pty:false and downgrade security profile from 'full' to 'allowlist'."
        ),
        action_type=ActionType.RESTRICT_SHELL,
        diff_preview=diff,
        impact=[
            "Skill can no longer run in a pseudo-terminal (PTY).",
            "Shell-based tool calls may fail or require explicit allow-listing.",
            "System security risk from this skill is reduced.",
        ],
    )


def apply_patch(skill_path: Path, **kwargs: object) -> str:
    """Apply the shell-restriction patch in-place. Returns new file content."""
    skill_md = skill_path / "SKILL.md"
    lines = skill_md.read_text(encoding="utf-8").splitlines(keepends=True)
    patched = list(lines)
    for i, line in enumerate(patched):
        for pattern, replacement in _SHELL_PATTERNS:
            new_line, n = pattern.subn(replacement, line)
            if n:
                patched[i] = new_line
                break
    content = "".join(patched)
    # Atomic write
    tmp = skill_md.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(skill_md)
    return content
