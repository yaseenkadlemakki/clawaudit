"""REST API routes for the Remediation Engine."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.models.remediation import RemediationEvent
from backend.storage.repository import FindingRepository, ScanRepository
from sentinel.remediation.engine import RemediationEngine

logger = logging.getLogger(__name__)

# Allowed parent directories for skill paths and snapshots.
# Config patches target ~/.openclaw/openclaw.json — validated separately
# in apply_proposal() via action_type-aware check (not in this broad list).
_ALLOWED_SKILL_PARENTS = [
    Path.home() / ".openclaw" / "workspace",
    Path.home() / ".openclaw" / "skills",
]
_ALLOWED_SNAPSHOT_DIR = Path.home() / ".openclaw" / "sentinel" / "snapshots"
_ALLOWED_CONFIG_DIR = Path.home() / ".openclaw"


def _validate_skill_path(raw_path: str) -> Path:
    """Validate that a skill path is within allowed directories.

    Uses ``is_relative_to`` instead of string prefix matching to prevent
    path-traversal bypasses (e.g. ``~/.openclaw-evil/payload``).
    """
    path = Path(raw_path).resolve()
    if not any(path.is_relative_to(p.resolve()) for p in _ALLOWED_SKILL_PARENTS):
        raise HTTPException(
            status_code=400,
            detail="Skill path must be within an allowed skills directory.",
        )
    return path


def _validate_snapshot_path(raw_path: str) -> Path:
    """Validate that a snapshot path is within the snapshots directory."""
    path = Path(raw_path).resolve()
    if not path.is_relative_to(_ALLOWED_SNAPSHOT_DIR.resolve()):
        raise HTTPException(
            status_code=400,
            detail="Snapshot path must be within the snapshots directory.",
        )
    return path


router = APIRouter(prefix="/api/v1/remediation", tags=["remediation"])


# ── Request / Response schemas ─────────────────────────────────────────────


class ProposalResponse(BaseModel):
    proposal_id: str
    finding_id: str
    check_id: str
    skill_name: str
    skill_path: str
    description: str
    action_type: str
    diff_preview: str
    impact: list[str]
    reversible: bool
    apply_available: bool = True
    status: str
    severity: str = ""


class ApplyRequest(BaseModel):
    proposal_id: str
    diff_preview: str
    skill_name: str
    skill_path: str
    check_id: str
    action_type: str
    description: str
    impact: list[str] = []
    finding_id: str = ""


class RollbackRequest(BaseModel):
    snapshot_path: str


class RemediationHistoryItem(BaseModel):
    id: str
    proposal_id: str
    skill_name: str
    check_id: str
    action_type: str
    status: str
    description: str
    snapshot_path: str | None
    applied_at: str
    error: str | None


# ── Helpers ────────────────────────────────────────────────────────────────


def _engine(dry_run: bool = True) -> RemediationEngine:
    return RemediationEngine(dry_run=dry_run)


# ── Routes ─────────────────────────────────────────────────────────────────


@router.get("/proposals", response_model=list[ProposalResponse])
async def get_proposals(
    check_id: str | None = None,
    skill_name: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> list[ProposalResponse]:
    """Generate remediation proposals for the latest completed scan."""
    # Get latest scan findings
    scan_repo = ScanRepository(db)
    scans = await scan_repo.list(limit=1)
    if not scans:
        return []

    latest_scan = scans[0]
    finding_repo = FindingRepository(db)
    findings_orm = await finding_repo.list(scan_id=latest_scan.id)

    # Convert ORM findings to dicts the engine expects
    findings = [
        {
            "id": f.id,
            "check_id": f.check_id,
            "skill_name": f.skill_name or "",
            "location": f.location or "",
            "severity": f.severity or "",
        }
        for f in findings_orm
    ]
    # Build severity lookup for enriching proposals
    severity_by_finding: dict[str, str] = {f["id"]: f["severity"] for f in findings}

    engine = _engine(dry_run=True)
    proposals = engine.scan_for_proposals(
        findings=findings,
        check_ids=[check_id] if check_id else None,
        skill_names=[skill_name] if skill_name else None,
    )

    return [
        ProposalResponse(
            proposal_id=p.proposal_id,
            finding_id=p.finding_id,
            check_id=p.check_id,
            skill_name=p.skill_name,
            skill_path=str(p.skill_path),
            description=p.description,
            action_type=p.action_type.value,
            diff_preview=p.diff_preview,
            impact=p.impact,
            reversible=p.reversible,
            apply_available=p.apply_available,
            status=p.status.value,
            severity=p.severity or severity_by_finding.get(p.finding_id, ""),
        )
        for p in proposals
    ]


@router.post("/apply")
async def apply_proposal(
    req: ApplyRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Apply a single remediation proposal."""
    from sentinel.remediation.actions import ActionType, RemediationProposal, RemediationStatus

    try:
        action_type = ActionType(req.action_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown action_type: {req.action_type}")

    # Config patches target ~/.openclaw/ — validated via exact match, not the
    # broad skill parents list (which would expose DB, sentinel config, etc.).
    if action_type == ActionType.CONFIG_PATCH:
        skill_path = Path(req.skill_path).resolve()
        if skill_path != _ALLOWED_CONFIG_DIR.resolve():
            raise HTTPException(
                status_code=400,
                detail="Config patches must target the OpenClaw config directory.",
            )
    else:
        skill_path = _validate_skill_path(req.skill_path)

    proposal = RemediationProposal(
        proposal_id=req.proposal_id,
        finding_id=req.finding_id,
        check_id=req.check_id,
        skill_name=req.skill_name,
        skill_path=skill_path,
        description=req.description,
        action_type=action_type,
        diff_preview=req.diff_preview,
        impact=req.impact,
        status=RemediationStatus.PENDING,
    )

    engine = _engine(dry_run=False)
    result = engine.apply_proposal(proposal)

    # Persist event
    event = RemediationEvent(
        proposal_id=proposal.proposal_id,
        skill_name=proposal.skill_name,
        check_id=proposal.check_id,
        action_type=proposal.action_type.value,
        status="applied" if result.success else "failed",
        description=proposal.description,
        diff_preview=proposal.diff_preview,
        impact=json.dumps(proposal.impact),
        snapshot_path=str(result.snapshot_path) if result.snapshot_path else None,
        applied_at=datetime.now(timezone.utc),  # noqa: UP017
        error=result.error,
    )
    db.add(event)
    await db.commit()

    return {
        "success": result.success,
        "snapshot_path": str(result.snapshot_path) if result.snapshot_path else None,
        "error": result.error,
    }


@router.post("/rollback")
async def rollback(
    req: RollbackRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Rollback a remediation using a snapshot path."""
    snapshot = _validate_snapshot_path(req.snapshot_path)
    if not snapshot.exists():
        raise HTTPException(status_code=404, detail=f"Snapshot not found: {req.snapshot_path}")

    engine = _engine(dry_run=False)
    success = engine.rollback(snapshot)

    # Persist rollback event
    event = RemediationEvent(
        proposal_id="rollback",
        skill_name=snapshot.stem,
        check_id="ROLLBACK",
        action_type="rollback",
        status="rolled_back" if success else "failed",
        description=f"Rollback from snapshot: {snapshot.name}",
        diff_preview="",
        impact="[]",
        snapshot_path=str(snapshot),
        applied_at=datetime.now(timezone.utc),  # noqa: UP017
        error=None if success else "Rollback failed — see server logs.",
    )
    db.add(event)
    await db.commit()

    return {"success": success, "snapshot_path": req.snapshot_path}


@router.get("/history", response_model=list[RemediationHistoryItem])
async def get_history(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
) -> list[RemediationHistoryItem]:
    """Return recent remediation events."""
    result = await db.execute(
        select(RemediationEvent).order_by(RemediationEvent.applied_at.desc()).limit(limit)
    )
    events = result.scalars().all()
    return [
        RemediationHistoryItem(
            id=e.id,
            proposal_id=e.proposal_id,
            skill_name=e.skill_name,
            check_id=e.check_id,
            action_type=e.action_type,
            status=e.status,
            description=e.description,
            snapshot_path=e.snapshot_path,
            applied_at=e.applied_at.isoformat() if e.applied_at else "",
            error=e.error,
        )
        for e in events
    ]
