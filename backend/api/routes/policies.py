"""Policy management routes."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas import (
    PolicyCreate,
    PolicyEvaluationResponse,
    PolicyResponse,
    PolicyStatsResponse,
    PolicyUpdate,
    ToolCallEvaluationRequest,
)
from backend.database import get_db
from backend.models.finding import FindingRecord
from backend.models.policy import PolicyRecord
from backend.models.scan import ScanRun
from backend.models.skill import SkillRecord
from backend.storage.repository import PolicyRepository
from sentinel.policy.engine import PolicyEngine, ToolCallContext

logger = logging.getLogger(__name__)

POLICY_ENGINE_SCAN_ID = "policy-engine"

router = APIRouter(tags=["policies"])


async def _write_violation_finding(
    db: AsyncSession,
    body: ToolCallEvaluationRequest,
    decision,
) -> None:
    """Write a FindingRecord for a policy violation."""
    from backend.models.policy import PolicyRecord as _PR  # local import to avoid circular

    for rule in decision.matched_rules:
        check_id = f"POL-{rule.id[:6]}"
        finding = FindingRecord(
            scan_id=POLICY_ENGINE_SCAN_ID,
            check_id=check_id,
            domain="policy",
            title=f"Policy {decision.action}: {rule.message or rule.check}",
            description=(
                f"Tool '{body.tool}' call matched policy '{rule.id}'. "
                f"Params: {body.params}"
            ),
            severity=rule.severity,
            result="FAIL",
            evidence=(
                f"tool={body.tool} params={body.params} "
                f"skill={body.skill_name or 'unknown'}"
            ),
            location=f"before_tool_call hook — skill: {body.skill_name or 'unknown'}",
            remediation="Review policy rule and tool call context",
            skill_name=body.skill_name,
        )
        db.add(finding)

    await db.flush()
    await db.commit()


async def _increment_violation_counts(
    db: AsyncSession,
    policy_ids: list[str],
) -> None:
    """Increment violation_count and set last_triggered_at for matched policies."""
    for pid in policy_ids:
        record = await db.get(PolicyRecord, pid)
        if record:
            record.violation_count = (record.violation_count or 0) + 1
            record.last_triggered_at = datetime.now(timezone.utc)  # noqa: UP017
    await db.flush()
    await db.commit()


# ── Evaluation endpoint — must come BEFORE /{policy_id} routes ──────────────

@router.post("/evaluate", response_model=PolicyEvaluationResponse)
async def evaluate_tool_call(
    body: ToolCallEvaluationRequest,
    db: AsyncSession = Depends(get_db),
):
    """Evaluate a tool call against all active policies.

    Called by the before_tool_call hook with <500ms SLA.
    """
    import backend.main as _main

    sync = _main.policy_sync
    rules = sync.get_rules() if sync is not None else []

    ctx = ToolCallContext(
        tool=body.tool,
        params=body.params,
        skill_name=body.skill_name,
        skill_signed=body.skill_signed or False,
        skill_publisher=body.skill_publisher,
        skill_path=body.skill_path,
    )

    engine = PolicyEngine.from_rules(rules)
    decision = engine.evaluate_tool_call(ctx)

    # Write finding for ALERT / BLOCK / QUARANTINE
    if decision.action in ("ALERT", "BLOCK", "QUARANTINE"):
        await _write_violation_finding(db, body, decision)
        await _increment_violation_counts(db, decision.policy_ids)

    # Handle QUARANTINE — mark skill as quarantined if skill_name provided
    if decision.action == "QUARANTINE" and body.skill_name:
        from backend.storage.repository import SkillRepository

        skill_repo = SkillRepository(db)
        skill = await skill_repo.get_by_name(body.skill_name)
        if skill:
            skill.quarantined = True
            skill.quarantined_at = datetime.now(timezone.utc)  # noqa: UP017
            skill.quarantine_reason = decision.reason
            await db.flush()
            await db.commit()

    return {
        "action": decision.action,
        "reason": decision.reason,
        "matched_rules": [r.id for r in decision.matched_rules],
    }


# ── Stats endpoint — must come BEFORE /{policy_id} routes ───────────────────

@router.get("/stats", response_model=PolicyStatsResponse)
async def get_policy_stats(db: AsyncSession = Depends(get_db)):
    """Return policy violation counts for the dashboard."""
    from datetime import timedelta

    now = datetime.now(timezone.utc)  # noqa: UP017
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # Active policy count
    active_result = await db.execute(
        select(func.count()).select_from(PolicyRecord).where(PolicyRecord.enabled == True)  # noqa: E712
    )
    active_count = active_result.scalar_one()

    # Violations today (findings with domain=policy, detected today)
    violations_result = await db.execute(
        select(func.count())
        .select_from(FindingRecord)
        .where(
            FindingRecord.domain == "policy",
            FindingRecord.detected_at >= today_start,
        )
    )
    violations_today = violations_result.scalar_one()

    # Blocked today — title contains "BLOCK"
    blocked_result = await db.execute(
        select(func.count())
        .select_from(FindingRecord)
        .where(
            FindingRecord.domain == "policy",
            FindingRecord.detected_at >= today_start,
            FindingRecord.title.contains("BLOCK"),
        )
    )
    blocked_today = blocked_result.scalar_one()

    # Alerted today
    alerted_result = await db.execute(
        select(func.count())
        .select_from(FindingRecord)
        .where(
            FindingRecord.domain == "policy",
            FindingRecord.detected_at >= today_start,
            FindingRecord.title.contains("ALERT"),
        )
    )
    alerted_today = alerted_result.scalar_one()

    # Quarantined skills
    quarantined_result = await db.execute(
        select(func.count()).select_from(SkillRecord).where(SkillRecord.quarantined == True)  # noqa: E712
    )
    quarantined_skills = quarantined_result.scalar_one()

    return {
        "active_count": active_count,
        "violations_today": violations_today,
        "blocked_today": blocked_today,
        "alerted_today": alerted_today,
        "quarantined_skills": quarantined_skills,
    }


# ── CRUD endpoints ────────────────────────────────────────────────────────────

@router.get("", response_model=list[PolicyResponse])
async def list_policies(limit: int = 100, offset: int = 0, db: AsyncSession = Depends(get_db)):
    """List all policies."""
    repo = PolicyRepository(db)
    records = await repo.list(limit=limit, offset=offset)
    return [r.to_dict() for r in records]


def _serialize_policy_data(data: dict) -> dict:
    """Serialize tags list to JSON string for DB storage."""
    import json

    if "tags" in data and isinstance(data["tags"], list):
        data = dict(data)
        data["tags"] = json.dumps(data["tags"])
    return data


@router.post("", response_model=PolicyResponse, status_code=201)
async def create_policy(body: PolicyCreate, db: AsyncSession = Depends(get_db)):
    """Create a new policy rule."""
    import backend.main as _main

    repo = PolicyRepository(db)
    record = await repo.create(_serialize_policy_data(body.model_dump()))
    sync = _main.policy_sync
    if sync is not None:
        await sync.reload()
    return record.to_dict()


@router.put("/{policy_id}", response_model=PolicyResponse)
async def update_policy(policy_id: str, body: PolicyUpdate, db: AsyncSession = Depends(get_db)):
    """Update an existing policy rule."""
    import backend.main as _main

    repo = PolicyRepository(db)
    data = {k: v for k, v in body.model_dump().items() if v is not None}
    record = await repo.update(policy_id, _serialize_policy_data(data))
    if not record:
        raise HTTPException(status_code=404, detail="Policy not found")
    sync = _main.policy_sync
    if sync is not None:
        await sync.reload()
    return record.to_dict()


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(policy_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a policy rule. Returns 403 for built-in policies."""
    import backend.main as _main

    repo = PolicyRepository(db)
    record = await repo.get(policy_id)
    if not record:
        raise HTTPException(status_code=404, detail="Policy not found")
    if record.builtin:
        raise HTTPException(status_code=403, detail="Cannot delete a built-in policy")
    deleted = await repo.delete(policy_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Policy not found")
    sync = _main.policy_sync
    if sync is not None:
        await sync.reload()
