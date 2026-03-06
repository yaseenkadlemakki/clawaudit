"""Repository layer unit tests — CRUD operations via SQLAlchemy async sessions."""
from __future__ import annotations

from datetime import datetime

import pytest
import pytest_asyncio

import backend.database as _db
from backend.models.finding import FindingRecord
from backend.models.policy import PolicyRecord
from backend.models.scan import ScanRun, ScanStatus
from backend.models.skill import SkillRecord
from backend.storage.repository import (
    FindingRepository,
    PolicyRepository,
    ScanRepository,
    SkillRepository,
)


# ── helpers ───────────────────────────────────────────────────────────────────

async def _seed_scan(db, scan_id: str = "scan-r01", status=ScanStatus.COMPLETED) -> ScanRun:
    scan = ScanRun(id=scan_id, status=status, triggered_by="test")
    db.add(scan)
    await db.commit()
    return scan


# ── ScanRepository ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scan_repo_get_and_list():
    async with _db.AsyncSessionLocal() as db:
        await _seed_scan(db, "scan-r01")
        await _seed_scan(db, "scan-r02")

        repo = ScanRepository(db)
        assert await repo.get("scan-r01") is not None
        assert await repo.get("missing-id") is None

        scans = await repo.list(limit=10)
        assert len(scans) == 2
        count = await repo.count()
        assert count == 2


# ── FindingRepository ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_finding_repo_list_and_filter():
    async with _db.AsyncSessionLocal() as db:
        await _seed_scan(db, "scan-f01")
        for i, severity in enumerate(["CRITICAL", "HIGH", "LOW"]):
            db.add(FindingRecord(
                id=f"f{i}",
                scan_id="scan-f01",
                check_id=f"CONF-0{i}",
                domain="config",
                title=f"Finding {i}",
                description="desc",
                severity=severity,
                result="FAIL",
                evidence="ev",
                location="/p",
                remediation="fix",
                detected_at=datetime.utcnow(),
            ))
        await db.commit()

        repo = FindingRepository(db)
        all_findings = await repo.list()
        assert len(all_findings) == 3

        critical = await repo.list(severity="CRITICAL")
        assert len(critical) == 1
        assert critical[0].severity == "CRITICAL"

        by_scan = await repo.list(scan_id="scan-f01")
        assert len(by_scan) == 3

        assert await repo.get("f0") is not None
        assert await repo.get("no-id") is None


# ── SkillRepository ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_skill_repo_list_and_get_by_name():
    import json
    async with _db.AsyncSessionLocal() as db:
        await _seed_scan(db, "scan-s01")
        db.add(SkillRecord(
            id="sk1",
            scan_id="scan-s01",
            name="my-skill",
            source="local",
            path="/skills/my-skill/SKILL.md",
            shell_access=False,
            outbound_domains=json.dumps([]),
            injection_risk="LOW",
            trust_score="TRUSTED",
            risk_score=10,
            risk_level="Low",
            detected_at=datetime.utcnow(),
        ))
        await db.commit()

        repo = SkillRepository(db)
        skills = await repo.list()
        assert len(skills) == 1

        found = await repo.get_by_name("my-skill")
        assert found is not None
        assert found.risk_score == 10

        missing = await repo.get_by_name("no-such-skill")
        assert missing is None


# ── PolicyRepository ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_policy_repo_crud():
    async with _db.AsyncSessionLocal() as db:
        repo = PolicyRepository(db)

        # create
        policy = await repo.create({
            "name": "p1",
            "domain": "config",
            "check": "CONF-01",
            "severity": "HIGH",
            "action": "ALERT",
            "enabled": True,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        })
        assert policy.id is not None
        policy_id = policy.id

        # list
        policies = await repo.list()
        assert len(policies) == 1

        # get
        fetched = await repo.get(policy_id)
        assert fetched is not None
        assert fetched.name == "p1"

        # update
        updated = await repo.update(policy_id, {"enabled": False})
        assert updated is not None
        assert updated.enabled is False

        # delete
        deleted = await repo.delete(policy_id)
        assert deleted is True

        # verify gone
        assert await repo.get(policy_id) is None
        assert await repo.delete(policy_id) is False
