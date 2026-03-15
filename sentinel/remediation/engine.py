"""RemediationEngine — orchestrates proposal generation, application, and rollback."""

from __future__ import annotations

import logging
from pathlib import Path

from sentinel.remediation.actions import (
    ActionType,
    RemediationProposal,
    RemediationResult,
    RemediationStatus,
)
from sentinel.remediation.rollback import create_snapshot, restore_snapshot
from sentinel.remediation.strategies import (
    config_patch,
    permissions,
    secrets,
    shell_access,
)

logger = logging.getLogger(__name__)


class _Strategy:
    """Structural type for strategy modules (propose + apply_patch)."""

    propose: staticmethod
    apply_patch: staticmethod


# Mapping from check_id to strategy module.
# Config checks (CONF-xx) target openclaw.json via config_patch.
# Skill checks use existing strategies.
_STRATEGY_MAP: dict[str, _Strategy] = {
    # Skill-level strategies
    "ADV-001": shell_access,  # type: ignore[dict-item]
    "ADV-005": secrets,  # type: ignore[dict-item]
    "PERM-001": permissions,  # type: ignore[dict-item]
    "SKILL-01": permissions,  # type: ignore[dict-item]
    # Config hardening strategies
    # CONF-00 (config not found) and CONF-05 (credentials in config) are not
    # auto-remediable and therefore excluded from the strategy map.
    "CONF-01": config_patch,  # type: ignore[dict-item]
    "CONF-02": config_patch,  # type: ignore[dict-item]
    "CONF-03": config_patch,  # type: ignore[dict-item]
    "CONF-04": config_patch,  # type: ignore[dict-item]
    "CONF-06": config_patch,  # type: ignore[dict-item]
    "CONF-07": config_patch,  # type: ignore[dict-item]
    "CONF-08": config_patch,  # type: ignore[dict-item]
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

    # Advisory text for check IDs that may not have an automated strategy or
    # whose strategy returns None (e.g. clean SKILL.md files).  These produce
    # guidance-only proposals with apply_available=False.
    _ADVISORY: dict[str, dict[str, object]] = {
        "ADV-001": {
            "description": (
                "Restrict shell execution: set pty:false and downgrade the "
                "security profile from 'full' to 'allowlist'."
            ),
            "impact": [
                "Skill can no longer run in a pseudo-terminal (PTY).",
                "Shell-based tool calls may fail or require explicit allow-listing.",
            ],
        },
        "ADV-002": {
            "description": (
                "Unknown publisher: add an 'author' field to SKILL.md with a verified identity."
            ),
            "impact": ["Skill provenance remains unverified."],
        },
        "ADV-003": {
            "description": (
                "Unknown outbound domains detected. Review each domain and "
                "add trusted ones to an allowlist."
            ),
            "impact": ["Unreviewed domains may exfiltrate data."],
        },
        "ADV-004": {
            "description": (
                "Unsigned skill. Sign skills using the OpenClaw signing "
                "mechanism to establish integrity."
            ),
            "impact": ["Skill integrity cannot be verified."],
        },
        "ADV-005": {
            "description": (
                "Exposed credential detected. Rotate the exposed key "
                "immediately and remove it from source."
            ),
            "impact": ["Credential may already be compromised."],
        },
        "SKILL-01": {
            "description": (
                "Skill has shell access. Scope access with an allowed-tools "
                "constraint in the skill manifest."
            ),
            "impact": ["Unrestricted shell access increases attack surface."],
        },
        "SKILL-02": {
            "description": (
                "High injection risk detected. Validate and sanitise all "
                "user input before passing to tools."
            ),
            "impact": ["Prompt or command injection may be possible."],
        },
        "SCR-004": {
            "description": (
                "Credential file access pattern detected. Remove or refactor "
                "to use a secrets manager."
            ),
            "impact": ["Credential files may be read by untrusted code."],
        },
        "SCR-005": {
            "description": (
                "Hardcoded external IP or domain detected. Externalise into "
                "configuration or an allowlist."
            ),
            "impact": ["Hardcoded endpoints cannot be audited centrally."],
        },
        "PERM-001": {
            "description": (
                "Wildcard tool permission detected. Replace with an explicit "
                "list of required tools."
            ),
            "impact": ["Wildcard grants access to every tool, current and future."],
        },
        "CONF-01": {
            "description": (
                "Review the OpenClaw groupPolicy setting and apply the "
                "recommended hardening configuration."
            ),
            "impact": ["Misconfigured group policy may weaken isolation."],
        },
    }

    def __init__(
        self,
        skills_dir: Path | None = None,
        dry_run: bool = True,
        extra_protected_paths: list[Path] | None = None,
        config_dir: Path | None = None,
    ) -> None:
        self._skills_dir = skills_dir or Path.home() / ".openclaw" / "workspace"
        self._config_dir = config_dir or Path.home() / ".openclaw"
        self._dry_run = dry_run
        self._protected = list(_PROTECTED_PREFIXES) + (extra_protected_paths or [])

    # ── Protection ────────────────────────────────────────────────────────────

    def is_protected(self, skill_path: Path) -> bool:
        """Return True if the skill path is a core system skill (read-only)."""
        resolved = skill_path.resolve()
        return any(resolved == p or resolved.is_relative_to(p) for p in self._protected)

    # ── Advisory helper ─────────────────────────────────────────────────────

    def _advisory_proposal(
        self,
        finding_id: str,
        check_id: str,
        skill_name: str,
        skill_path: Path,
        severity: str = "",
    ) -> RemediationProposal | None:
        """Create a guidance-only advisory proposal if text exists for *check_id*."""
        advisory = self._ADVISORY.get(check_id)
        if advisory is None:
            return None
        proposal = RemediationProposal.create(
            finding_id=finding_id,
            check_id=check_id,
            skill_name=skill_name,
            skill_path=skill_path,
            description=str(advisory["description"]),
            action_type=ActionType.ADVISORY,
            diff_preview="",
            impact=list(advisory.get("impact", [])),  # type: ignore[arg-type]
            reversible=False,
            apply_available=False,
            severity=severity,
        )
        return proposal

    # ── Proposal generation ───────────────────────────────────────────────────

    def proposals_for_finding(
        self,
        finding_id: str,
        check_id: str,
        skill_name: str,
        skill_path: Path,
        severity: str = "",
    ) -> list[RemediationProposal]:
        """Generate proposals for a single finding.

        Fallback chain:
        1. If a strategy exists, try strategy.propose().
        2. If the strategy returns None, fall back to an advisory proposal.
        3. If no strategy exists, fall back to an advisory proposal.
        4. If no advisory text exists, return [].
        """
        strategy = _STRATEGY_MAP.get(check_id)
        proposal: RemediationProposal | None = None

        if strategy is not None:
            proposal = strategy.propose(
                skill_name=skill_name,
                skill_path=skill_path,
                finding_id=finding_id,
                check_id=check_id,
            )
            if proposal and severity:
                proposal.severity = severity

        # Fallback to advisory when no strategy or strategy returned None
        if proposal is None:
            proposal = self._advisory_proposal(
                finding_id, check_id, skill_name, skill_path, severity
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
        seen: set[tuple[str, str]] = set()  # (check_id, resolved_path) dedup

        for finding in findings:
            fid = finding.get("id", "")
            check_id = finding.get("check_id", "")
            skill_name = finding.get("skill_name", "")
            skill_path_str = finding.get("location", "")
            severity = finding.get("severity", "")

            if check_ids and check_id not in check_ids:
                continue

            # Config findings have no skill_name — handle before skill_names filter.
            # Dispatch via strategy map identity rather than string prefix.
            strategy = _STRATEGY_MAP.get(check_id)
            if strategy is config_patch:
                if skill_names and "openclaw-config" not in skill_names:
                    continue
                config_path = self._config_dir / "openclaw.json"
                dedup_key = (check_id, str(config_path))
                if dedup_key in seen:
                    continue
                if config_path.exists():
                    new_proposals = self.proposals_for_finding(
                        fid,
                        check_id,
                        "openclaw-config",
                        config_path,
                        severity=severity,
                    )
                    proposals.extend(new_proposals)
                    seen.add(dedup_key)
                continue

            if skill_names and skill_name not in skill_names:
                continue

            # Skill/ADV findings require a skill name to identify the target
            if not skill_name:
                continue

            skill_path = Path(skill_path_str)
            # Location may point to a file (e.g. /path/to/SKILL.md) — use parent
            if skill_path.is_file():
                skill_path = skill_path.parent
            elif not skill_path.is_dir():
                # Try resolving relative to skills_dir
                skill_path = self._skills_dir / skill_name
            if not skill_path.is_dir():
                logger.debug("Skill directory not found: %s", skill_path)
                continue

            protected = self.is_protected(skill_path)

            dedup_key = (check_id, str(skill_path))
            if dedup_key in seen:
                continue

            new_proposals = self.proposals_for_finding(
                fid,
                check_id,
                skill_name,
                skill_path,
                severity=severity,
            )
            if protected:
                for p in new_proposals:
                    p.apply_available = False
            proposals.extend(new_proposals)
            seen.add(dedup_key)

        return proposals

    # ── Application ───────────────────────────────────────────────────────────

    def apply_proposal(self, proposal: RemediationProposal) -> RemediationResult:
        """Apply a single remediation proposal.

        Returns a RemediationResult. If dry_run=True, returns success=False with
        an error message explaining that dry-run mode is active.
        """
        if proposal.action_type == ActionType.ADVISORY:
            return RemediationResult(
                proposal=proposal,
                success=False,
                error="Advisory-only — no automated patch available.",
            )

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

            strategy.apply_patch(proposal.skill_path, check_id=proposal.check_id)
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

    def rollback(self, snapshot_path: Path, target_parent: Path | None = None) -> bool:
        """Restore a skill from a snapshot. Returns True on success.

        Args:
            snapshot_path: Path to the .tar.gz snapshot file.
            target_parent: Directory to extract into. Defaults to skills_dir.
        """
        try:
            restore_target = target_parent or self._skills_dir
            restore_snapshot(snapshot_path, restore_target)
            logger.info("Rolled back from snapshot: %s", snapshot_path)
            return True
        except Exception as exc:
            logger.error("Rollback failed: %s", exc)
            return False
