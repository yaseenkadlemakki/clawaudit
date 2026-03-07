"""Remediation data models — proposals, results, and status."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class RemediationStatus(str, Enum):
    PENDING = "pending"
    APPLIED = "applied"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


class ActionType(str, Enum):
    RESTRICT_SHELL = "restrict_shell"
    REDACT_SECRET = "redact_secret"
    RESTRICT_PERMISSIONS = "restrict_permissions"
    REMOVE_ENV_VAR = "remove_env_var"


@dataclass
class RemediationProposal:
    """A proposed fix for a single finding."""

    proposal_id: str
    finding_id: str
    check_id: str  # e.g. ADV-001, ADV-005
    skill_name: str
    skill_path: Path
    description: str  # human-readable: what will change
    action_type: ActionType
    diff_preview: str  # unified diff of proposed change
    impact: list[str] = field(default_factory=list)
    reversible: bool = True
    status: RemediationStatus = RemediationStatus.PENDING

    @classmethod
    def create(
        cls,
        finding_id: str,
        check_id: str,
        skill_name: str,
        skill_path: Path,
        description: str,
        action_type: ActionType,
        diff_preview: str,
        impact: list[str] | None = None,
        reversible: bool = True,
    ) -> RemediationProposal:
        return cls(
            proposal_id=str(uuid.uuid4()),
            finding_id=finding_id,
            check_id=check_id,
            skill_name=skill_name,
            skill_path=skill_path,
            description=description,
            action_type=action_type,
            diff_preview=diff_preview,
            impact=impact or [],
            reversible=reversible,
        )


@dataclass
class RemediationResult:
    """Result of applying a remediation proposal."""

    proposal: RemediationProposal
    success: bool
    snapshot_path: Path | None = None
    error: str | None = None
