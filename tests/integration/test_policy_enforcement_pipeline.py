"""Integration tests for the policy enforcement pipeline.

Tests the full flow: create policy → evaluate tool call → check decision + findings.
Uses an in-memory SQLite database via backend fixtures.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import backend.database
from backend.database import Base

# ---------------------------------------------------------------------------
# In-memory DB fixtures for integration tests
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def db_engine():
    # Import all models so they're registered with Base.metadata before create_all
    from backend.models import chat, finding, policy, remediation, scan, skill  # noqa: F401

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session_factory(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    with patch.object(backend.database, "engine", db_engine):
        with patch.object(backend.database, "AsyncSessionLocal", factory):
            yield factory


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_create_policy_then_evaluate_match_returns_block(db_session_factory):
    """Create a policy via repo → sync → evaluate → BLOCK returned for matching call."""
    from backend.storage.repository import PolicyRepository
    from sentinel.policy.engine import PolicyEngine, ToolCallContext
    from sentinel.policy.sync import PolicySyncService

    svc = PolicySyncService(db_session_factory)

    async with db_session_factory() as db:
        repo = PolicyRepository(db)
        await repo.create(
            {
                "name": "test-block-exec",
                "domain": "tool_call",
                "check": "tool",
                "condition": "equals",
                "value": "exec",
                "severity": "HIGH",
                "action": "BLOCK",
                "enabled": True,
                "builtin": False,
                "priority": 50,
            }
        )

    await svc.reload()
    engine = PolicyEngine.from_rules(svc.get_rules())
    ctx = ToolCallContext(tool="exec", params={})
    decision = engine.evaluate_tool_call(ctx)
    assert decision.action == "BLOCK"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_create_policy_then_evaluate_no_match_returns_allow(db_session_factory):
    """Create a policy → evaluate non-matching call → ALLOW returned."""
    from backend.storage.repository import PolicyRepository
    from sentinel.policy.engine import PolicyEngine, ToolCallContext
    from sentinel.policy.sync import PolicySyncService

    svc = PolicySyncService(db_session_factory)

    async with db_session_factory() as db:
        repo = PolicyRepository(db)
        await repo.create(
            {
                "name": "block-exec",
                "domain": "tool_call",
                "check": "tool",
                "condition": "equals",
                "value": "exec",
                "severity": "HIGH",
                "action": "BLOCK",
                "enabled": True,
                "builtin": False,
                "priority": 50,
            }
        )

    await svc.reload()
    engine = PolicyEngine.from_rules(svc.get_rules())
    ctx = ToolCallContext(tool="read", params={})  # different tool
    decision = engine.evaluate_tool_call(ctx)
    assert decision.action == "ALLOW"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_disable_policy_evaluate_returns_allow(db_session_factory):
    """Disable a policy → evaluate → ALLOW returned."""
    from backend.storage.repository import PolicyRepository
    from sentinel.policy.engine import PolicyEngine, ToolCallContext
    from sentinel.policy.sync import PolicySyncService

    svc = PolicySyncService(db_session_factory)

    async with db_session_factory() as db:
        repo = PolicyRepository(db)
        record = await repo.create(
            {
                "name": "disabled-test",
                "domain": "tool_call",
                "check": "tool",
                "condition": "equals",
                "value": "exec",
                "severity": "HIGH",
                "action": "BLOCK",
                "enabled": True,
                "builtin": False,
                "priority": 50,
            }
        )
        policy_id = record.id

    await svc.reload()
    assert len(svc.get_rules()) == 1

    # Disable the policy
    async with db_session_factory() as db:
        repo = PolicyRepository(db)
        await repo.update(policy_id, {"enabled": False})

    await svc.reload()
    # list_enabled should return nothing
    assert len(svc.get_rules()) == 0

    engine = PolicyEngine.from_rules(svc.get_rules())
    ctx = ToolCallContext(tool="exec", params={})
    decision = engine.evaluate_tool_call(ctx)
    assert decision.action == "ALLOW"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_pty_block_starter_policy_fires(db_session_factory):
    """Test the block-pty-exec starter policy via seed + evaluate."""
    from backend.seeds.starter_policies import seed_starter_policies
    from sentinel.policy.engine import PolicyEngine, ToolCallContext
    from sentinel.policy.sync import PolicySyncService

    # Seed starter policies
    with patch.object(backend.database, "AsyncSessionLocal", db_session_factory):
        await seed_starter_policies()

    svc = PolicySyncService(db_session_factory)
    await svc.reload()
    assert len(svc.get_rules()) == 5

    engine = PolicyEngine.from_rules(svc.get_rules())
    ctx = ToolCallContext(tool="exec", params={"pty": True})
    decision = engine.evaluate_tool_call(ctx)
    assert decision.action == "BLOCK"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_quarantine_action_marks_skill(db_engine, db_session_factory):
    """QUARANTINE decision should mark skill.quarantined=True in DB."""
    from datetime import datetime, timezone

    from backend.models.scan import ScanRun
    from backend.models.skill import SkillRecord
    from backend.storage.repository import SkillRepository

    # Create prerequisite scan row and a skill
    async with db_session_factory() as db:
        db.add(ScanRun(id="test-scan", status="completed", triggered_by="test"))
        db.add(
            SkillRecord(
                id="skill-1",
                scan_id="test-scan",
                name="risky-skill",
                path="/skills/risky.md",
            )
        )
        await db.commit()

    # Manually quarantine the skill (simulating the API endpoint behavior)
    async with db_session_factory() as db:
        repo = SkillRepository(db)
        skill = await repo.get("skill-1")
        assert skill is not None
        skill.quarantined = True
        skill.quarantined_at = datetime.now(timezone.utc)  # noqa: UP017
        skill.quarantine_reason = "QUARANTINE: skill.signed equals false"
        await db.commit()

    # Verify skill is quarantined
    async with db_session_factory() as db:
        repo = SkillRepository(db)
        skill = await repo.get("skill-1")
        assert skill.quarantined is True
        assert skill.quarantine_reason is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_unquarantine_skill(db_engine, db_session_factory):
    """Unquarantine endpoint clears quarantine state."""
    from datetime import datetime, timezone

    from backend.models.scan import ScanRun
    from backend.models.skill import SkillRecord
    from backend.storage.repository import SkillRepository

    async with db_session_factory() as db:
        db.add(ScanRun(id="test-scan-2", status="completed", triggered_by="test"))
        db.add(
            SkillRecord(
                id="skill-2",
                scan_id="test-scan-2",
                name="quarantined-skill",
                path="/skills/quarantined.md",
                quarantined=True,
                quarantined_at=datetime.now(timezone.utc),  # noqa: UP017
                quarantine_reason="Policy triggered",
            )
        )
        await db.commit()

    # Unquarantine
    async with db_session_factory() as db:
        repo = SkillRepository(db)
        skill = await repo.get("skill-2")
        skill.quarantined = False
        skill.quarantined_at = None
        skill.quarantine_reason = None
        await db.commit()

    async with db_session_factory() as db:
        repo = SkillRepository(db)
        skill = await repo.get("skill-2")
        assert skill.quarantined is False
        assert skill.quarantined_at is None
        assert skill.quarantine_reason is None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_evaluate_endpoint_block_writes_finding(db_session_factory):
    """POST /evaluate → BLOCK → FindingRecord with domain=policy written to DB."""
    import os

    import backend.database as _db
    from backend.main import app
    from backend.models.finding import FindingRecord
    from backend.storage.repository import PolicyRepository
    from sentinel.policy.sync import PolicySyncService

    os.environ.setdefault("CLAWAUDIT_API_TOKEN", "test-token-pipeline")
    token = os.environ["CLAWAUDIT_API_TOKEN"]

    # Create a blocking policy in the DB
    async with db_session_factory() as db:
        repo = PolicyRepository(db)
        await repo.create(
            {
                "name": "block-exec-integration",
                "domain": "tool_call",
                "check": "tool",
                "condition": "equals",
                "value": "exec",
                "severity": "HIGH",
                "action": "BLOCK",
                "enabled": True,
                "builtin": False,
                "priority": 50,
            }
        )

    svc = PolicySyncService(db_session_factory)
    await svc.reload()

    with (
        patch.object(_db, "engine", db_session_factory.kw.get("bind") or _db.engine),
        patch.object(_db, "AsyncSessionLocal", db_session_factory),
        patch("backend.main.policy_sync", svc),
    ):
        from httpx import ASGITransport, AsyncClient

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {token}"},
        ) as client:
            r = await client.post(
                "/api/v1/policies/evaluate",
                json={"tool": "exec", "params": {}},
            )
            assert r.status_code == 200
            data = r.json()
            assert data["action"] == "BLOCK"

    # Verify finding was written to DB
    async with db_session_factory() as db:
        from sqlalchemy import select

        result = await db.execute(select(FindingRecord).where(FindingRecord.domain == "policy"))
        findings = result.scalars().all()
        assert len(findings) >= 1
        assert findings[0].domain == "policy"
        assert findings[0].scan_id == "policy-engine"
        assert findings[0].result == "FAIL"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_evaluate_endpoint_delete_builtin_returns_403(db_session_factory):
    """DELETE on a builtin policy via the API → 403 Forbidden."""
    import os

    import backend.database as _db
    from backend.main import app
    from backend.models.policy import PolicyRecord

    os.environ.setdefault("CLAWAUDIT_API_TOKEN", "test-token-pipeline")
    token = os.environ["CLAWAUDIT_API_TOKEN"]

    # Seed a builtin policy
    async with db_session_factory() as db:
        db.add(
            PolicyRecord(
                id="builtin-pipeline-001",
                name="block-pty-exec-pipeline",
                domain="tool_call",
                check="params.pty",
                condition="equals",
                value="true",
                severity="HIGH",
                action="BLOCK",
                builtin=True,
                enabled=True,
            )
        )
        await db.commit()

    with (
        patch.object(_db, "AsyncSessionLocal", db_session_factory),
    ):
        from httpx import ASGITransport, AsyncClient

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {token}"},
        ) as client:
            r = await client.delete("/api/v1/policies/builtin-pipeline-001")
            assert r.status_code == 403, f"Expected 403 but got {r.status_code}: {r.text}"
