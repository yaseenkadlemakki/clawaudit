"""RemediationEngine — orchestrates proposal generation, application, and rollback."""

from __future__ import annotations

import logging
from pathlib import Path

from sentinel.remediation.actions import (
    RemediationProposal,
    RemediationResult,
    RemediationStatus,
)
from sentinel.remediation.rollback import create_snapshot, restore_snapshot
from sentinel.remediation.strategies import permissions, secrets, shell_access

logger = logging.getLogger(__name__)

# Mapping from check_id to (strategy module, apply_patch function)
_STRATEGY_MAP: dict[str, object] = {
    "ADV-001": shell_access,
    "ADV-005": secrets,
    "PERM-001": permissions,
}

# Paths that are considered protected (core system skills — never modify)
_PROTECTED_PREFIXES: list[Path] = [
    Path("/opt/homebrew/lib/node_modules/openclaw"),
    Path("/usr/local/lib/node_modules/openclaw"),
    Path("/usr/lib/node_modules/openclaw"),
]


class RemediationEngine:
    """Generates and applies remediations for ClawAudit findings.

    Args:
        skills_dir: Root directory containing skill folders. Defaults to OpenClaw
                    workspace. Used as fallback for path resolution.
        dry_run: When True (default), proposals are generated but never applied.
    """

    def __init__(
        self,
        skills_dir: Path | None = None,
        dry_run: bool = True,
        extra_protected_paths: list[Path] | None = None,
    ) -> None:
        self._skills_dir = skills_dir or Path.home() / ".openclaw" / "workspace"
        self._dry_run = dry_run
        self._protected = list(_PROTECTED_PREFIXES) + (extra_protected_paths or [])

    # ── Protection ────────────────────────────────────────────────────────────

    def is_protected(self, skill_path: Path) -> bool:
        """Return True if the skill path is a core system skill (read-only)."""
        resolved = skill_path.resolve()
        return any(str(resolved).startswith(str(p)) for p in self._protected)

    # ── Proposal generation ───────────────────────────────────────────────────

    def proposals_for_finding(
        self,
        finding_id: str,
        check_id: str,
        skill_name: str,
        skill_path: Path,
    ) -> list[RemediationProposal]:
        """Generate proposals for a single finding."""
        strategy = _STRATEGY_MAP.get(check_id)
        if strategy is None:
            logger.debug("No strategy for check_id=%s", check_id)
            return []

        proposal = strategy.propose(  # type: ignore[attr-defined]
            skill_name=skill_name,
            skill_path=skill_path,
            finding_id=finding_id,
        )
        return [proposal] if proposal else []

    def scan_for_proposals(
        self,
        findings: list[dict],
        check_ids: list[str] | None = None,
        skill_names: list[str] | None = None,
    ) -> list[RemediationProposal]:
        """Generate proposals for a list of finding dicts.

        Args:
            findings: List of dicts with keys: id, check_id, skill_name, location.
            check_ids: If given, only generate proposals for these check IDs.
            skill_names: If given, only generate proposals for these skills.

        Returns:
            List of proposals (may be empty if no strategies match).
        """
        proposals: list[RemediationProposal] = []

        for finding in findings:
            fid = finding.get("id", "")
            check_id = finding.get("check_id", "")
            skill_name = finding.get("skill_name", "")
            skill_path_str = finding.get("location", "")

            if check_ids and check_id not in check_ids:
                continue
            if skill_names and skill_name not in skill_names:
                continue
            if not skill_name or not skill_path_str:
                continue

            skill_path = Path(skill_path_str)
            if not skill_path.is_dir():
                # Try resolving relative to skills_dir
                skill_path = self._skills_dir / skill_name
            if not skill_path.is_dir():
                logger.debug("Skill directory not found: %s", skill_path)
                continue

            if self.is_protected(skill_path):
                logger.info("Skipping protected skill: %s", skill_name)
                continue

            new_proposals = self.proposals_for_finding(fid, check_id, skill_name, skill_path)
            proposals.extend(new_proposals)

        return proposals

    # ── Application ───────────────────────────────────────────────────────────

    def apply_proposal(self, proposal: RemediationProposal) -> RemediationResult:
        """Apply a single remediation proposal.

        Returns a RemediationResult. If dry_run=True, returns success=False with
        an error message explaining that dry-run mode is active.
        """
        if self._dry_run:
            return RemediationResult(
                proposal=proposal,
                success=False,
                error="dry_run=True — pass --apply to make changes.",
            )

        if self.is_protected(proposal.skill_path):
            return RemediationResult(
                proposal=proposal,
                success=False,
                error=f"Skill '{proposal.skill_name}' is a protected system skill and cannot be modified.",
            )

        # Snapshot before modifying
        snapshot_path: Path | None = None
        try:
            snapshot_path = create_snapshot(proposal.skill_path, proposal.skill_name)
        except Exception as exc:
            logger.warning("Could not create snapshot for %s: %s", proposal.skill_name, exc)

        # Apply the strategy patch
        try:
            strategy = _STRATEGY_MAP.get(proposal.check_id)
            if strategy is None:
                raise ValueError(f"No strategy for check_id={proposal.check_id}")

            strategy.apply_patch(proposal.skill_path)  # type: ignore[attr-defined]
            proposal.status = RemediationStatus.APPLIED
            logger.info(
                "Applied remediation %s for %s (%s)",
                proposal.action_type,
                proposal.skill_name,
                proposal.check_id,
            )
            return RemediationResult(
                proposal=proposal,
                success=True,
                snapshot_path=snapshot_path,
            )
        except Exception as exc:
            proposal.status = RemediationStatus.FAILED
            logger.error("Remediation failed for %s: %s", proposal.skill_name, exc)
            return RemediationResult(
                proposal=proposal,
                success=False,
                snapshot_path=snapshot_path,
                error=str(exc),
            )

    def apply_all(self, proposals: list[RemediationProposal]) -> list[RemediationResult]:
        """Apply all proposals in sequence."""
        return [self.apply_proposal(p) for p in proposals]

    # ── Rollback ──────────────────────────────────────────────────────────────

    def rollback(self, snapshot_path: Path) -> bool:
        """Restore a skill from a snapshot. Returns True on success."""
        try:
            target_parent = snapshot_path.parent.parent  # snapshots/<ts>-<name>.tar.gz → ...
            restore_snapshot(snapshot_path, target_parent)
            logger.info("Rolled back from snapshot: %s", snapshot_path)
            return True
        except Exception as exc:
            logger.error("Rollback failed: %s", exc)
            return False
