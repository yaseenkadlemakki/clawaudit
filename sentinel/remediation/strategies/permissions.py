"""Strategy for overly-broad tool permissions."""

from __future__ import annotations

import difflib
import re
from pathlib import Path

from sentinel.remediation.actions import ActionType, RemediationProposal

# Patterns for wildcard permission declarations
_WILDCARD_PATTERNS = [
    re.compile(r"(allowed[-_]?tools\s*:\s*)['\"]?\*['\"]?", re.IGNORECASE),
    re.compile(r"(permissions\s*:\s*)['\"]?all['\"]?", re.IGNORECASE),
    re.compile(r"(tool[-_]?access\s*:\s*)['\"]?unrestricted['\"]?", re.IGNORECASE),
]

_SAFE_DEFAULT = "# [ClawAudit] Restrict to specific tools needed by this skill"


def propose(
    skill_name: str,
    skill_path: Path,
    finding_id: str,
    **kwargs: object,
) -> RemediationProposal | None:
    """Propose a remediation for overly-broad tool permissions."""
    skill_md = skill_path / "SKILL.md"
    if not skill_md.exists():
        return None

    original_lines = skill_md.read_text(encoding="utf-8").splitlines(keepends=True)
    patched_lines = list(original_lines)
    changes_made = 0

    for i, line in enumerate(patched_lines):
        for pattern in _WILDCARD_PATTERNS:
            if pattern.search(line):
                # Comment out the wildcard line and add a restriction notice
                patched_lines[i] = f"# RESTRICTED: {line.rstrip()}  {_SAFE_DEFAULT}\n"
                changes_made += 1
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
        check_id="PERM-001",
        skill_name=skill_name,
        skill_path=skill_path,
        description=(
            f"Comment out wildcard tool permissions in '{skill_name}'. "
            "Wildcard access grants the skill unrestricted tool usage."
        ),
        action_type=ActionType.RESTRICT_PERMISSIONS,
        diff_preview=diff,
        impact=[
            "Wildcard tool permission lines will be commented out.",
            "You must manually specify the exact tools this skill requires.",
            "Skill may stop functioning until explicit permissions are added.",
        ],
    )


def apply_patch(skill_path: Path, **kwargs: object) -> str:
    """Apply the permissions-restriction patch in-place."""
    skill_md = skill_path / "SKILL.md"
    lines = skill_md.read_text(encoding="utf-8").splitlines(keepends=True)
    patched = list(lines)
    for i, line in enumerate(patched):
        for pattern in _WILDCARD_PATTERNS:
            if pattern.search(line):
                patched[i] = f"# RESTRICTED: {line.rstrip()}  {_SAFE_DEFAULT}\n"
                break
    content = "".join(patched)
    tmp = skill_md.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(skill_md)
    return content
