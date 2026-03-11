"""Tests for ScanManager._execute_scan and helpers — improves scan_manager.py coverage.

Placed in tests/unit/ to avoid the tests/backend/conftest.py's autouse
``isolated_db`` fixture, which patches ScanManager._execute_scan to a noop.
These tests set up their own isolated in-memory SQLite database.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import backend.database
import backend.engine.scan_manager
from backend.database import Base
from backend.engine.scan_manager import ScanManager, _count_severities
from backend.models.scan import ScanStatus

# ---------------------------------------------------------------------------
# Per-test isolated in-memory SQLite fixture
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
async def isolated_db():
    """In-memory SQLite for each test in this file."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    with (
        patch.object(backend.database, "engine", engine),
        patch.object(backend.database, "AsyncSessionLocal", Session),
        patch.object(backend.engine.scan_manager, "AsyncSessionLocal", Session),
    ):
        yield

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


# ---------------------------------------------------------------------------
# _count_severities helper (lines 258-261)
# ---------------------------------------------------------------------------


def _make_finding_mock(severity: str) -> MagicMock:
    f = MagicMock()
    f.severity = severity
    return f


def test_count_severities_empty():
    assert _count_severities([]) == {}


def test_count_severities_single():
    result = _count_severities([_make_finding_mock("HIGH")])
    assert result == {"HIGH": 1}


def test_count_severities_mixed():
    findings = [
        _make_finding_mock("CRITICAL"),
        _make_finding_mock("HIGH"),
        _make_finding_mock("HIGH"),
        _make_finding_mock("LOW"),
        _make_finding_mock("CRITICAL"),
    ]
    result = _count_severities(findings)
    assert result["CRITICAL"] == 2
    assert result["HIGH"] == 2
    assert result["LOW"] == 1


# ---------------------------------------------------------------------------
# Helpers for _execute_scan tests
# ---------------------------------------------------------------------------


def _make_skill_profile(name: str = "test-skill") -> MagicMock:
    profile = MagicMock()
    profile.name = name
    profile.source = "npm"
    profile.path = f"/opt/skills/{name}"
    profile.shell_access = False
    profile.outbound_domains = []
    profile.injection_risk = "LOW"
    profile.trust_score = "TRUSTED"
    profile.findings = []

    def to_dict():
        return {
            "name": profile.name,
            "source": profile.source,
            "path": profile.path,
            "shell_access": profile.shell_access,
            "outbound_domains": profile.outbound_domains,
            "injection_risk": profile.injection_risk,
            "trust_score": profile.trust_score,
        }

    profile.to_dict = to_dict
    return profile


def _make_finding_obj(
    check_id: str = "CHECK-01",
    severity: str = "HIGH",
    domain: str = "capability",
) -> MagicMock:
    f = MagicMock()
    import uuid

    f.id = str(uuid.uuid4())
    f.check_id = check_id
    f.domain = domain
    f.title = "Test"
    f.description = "desc"
    f.severity = severity
    f.result = "FAIL"
    f.evidence = "none"
    f.location = "/tmp"
    f.remediation = "fix it"
    f.detected_at = datetime.now(tz=timezone.utc)  # noqa: UP017

    def to_dict():
        return {"id": f.id, "severity": f.severity, "title": f.title, "domain": f.domain}

    f.to_dict = to_dict
    return f


# ---------------------------------------------------------------------------
# _execute_scan happy path (lines 128-254)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_execute_scan_completes_successfully():
    """_execute_scan should set status=COMPLETED and broadcast terminal event."""
    mgr = ScanManager()
    scan_dict = await mgr.start_scan(triggered_by="test-execute")
    scan_id = scan_dict["id"]

    profile = _make_skill_profile("good-skill")

    async def fake_run_full_audit(self, run_id, on_finding, on_skill, on_progress, stop_flag):
        # Don't call on_finding — avoids DB insert so test focuses on status/events
        on_skill(profile, 50, "Medium")
        on_progress(1, 1, "good-skill")
        return [], [(profile, 50, "Medium")]

    # Subscribe before executing so we can receive events
    q = mgr.subscribe(scan_id)

    from backend.engine.audit_engine import AuditEngine

    with patch.object(AuditEngine, "run_full_audit", new=fake_run_full_audit):
        await mgr._execute_scan(scan_id)

    # Verify the scan was marked COMPLETED in DB
    result = await mgr.get_scan(scan_id)
    assert result is not None
    assert result["status"] == ScanStatus.COMPLETED

    # Verify terminal event was cached
    assert scan_id in mgr._terminal_events
    assert mgr._terminal_events[scan_id]["type"] == "completed"

    # Verify events were broadcast
    events = []
    while not q.empty():
        events.append(q.get_nowait())

    types = {e["type"] for e in events}
    assert "skill" in types  # finding skipped in fake to avoid DB insert
    assert "progress" in types
    assert "completed" in types

    mgr.unsubscribe(scan_id, q)


@pytest.mark.asyncio
async def test_execute_scan_handles_failure():
    """_execute_scan should set status=FAILED and broadcast error event on exception."""
    mgr = ScanManager()
    scan_dict = await mgr.start_scan(triggered_by="test-failure")
    scan_id = scan_dict["id"]

    async def exploding_audit(self, run_id, on_finding, on_skill, on_progress, stop_flag):
        raise RuntimeError("Simulated audit failure")

    q = mgr.subscribe(scan_id)

    from backend.engine.audit_engine import AuditEngine

    with patch.object(AuditEngine, "run_full_audit", new=exploding_audit):
        await mgr._execute_scan(scan_id)

    result = await mgr.get_scan(scan_id)
    assert result is not None
    assert result["status"] == ScanStatus.FAILED
    assert "Simulated audit failure" in (result.get("error_message") or "")

    assert scan_id in mgr._terminal_events
    assert mgr._terminal_events[scan_id]["type"] == "error"

    events = []
    while not q.empty():
        events.append(q.get_nowait())
    assert any(e["type"] == "error" for e in events)

    mgr.unsubscribe(scan_id, q)


@pytest.mark.asyncio
async def test_execute_scan_stop_flag_respected():
    """_execute_scan should complete cleanly when stop_flag returns True."""
    mgr = ScanManager()
    scan_dict = await mgr.start_scan(triggered_by="test-stop")
    scan_id = scan_dict["id"]
    # Set stop flag immediately
    mgr._stop_flags[scan_id] = True

    async def audit_with_stop_check(self, run_id, on_finding, on_skill, on_progress, stop_flag):
        # stop_flag should be True
        assert stop_flag()
        return [], []

    from backend.engine.audit_engine import AuditEngine

    with patch.object(AuditEngine, "run_full_audit", new=audit_with_stop_check):
        await mgr._execute_scan(scan_id)

    result = await mgr.get_scan(scan_id)
    assert result is not None
    assert result["status"] == ScanStatus.COMPLETED


@pytest.mark.asyncio
async def test_execute_scan_multiple_findings_severity_counts():
    """Severity counts should be correctly stored after scan completion."""
    mgr = ScanManager()
    scan_dict = await mgr.start_scan(triggered_by="test-counts")
    scan_id = scan_dict["id"]

    findings = [
        _make_finding_obj("C1", "CRITICAL"),
        _make_finding_obj("C2", "CRITICAL"),
        _make_finding_obj("H1", "HIGH"),
        _make_finding_obj("M1", "MEDIUM"),
        _make_finding_obj("L1", "LOW"),
    ]

    async def multi_findings_audit(self, run_id, on_finding, on_skill, on_progress, stop_flag):
        for f in findings:
            on_finding(f, None)
        return findings, []

    from backend.engine.audit_engine import AuditEngine

    with patch.object(AuditEngine, "run_full_audit", new=multi_findings_audit):
        await mgr._execute_scan(scan_id)

    result = await mgr.get_scan(scan_id)
    assert result is not None
    assert result["total_findings"] == 5
    assert result["critical_count"] == 2
    assert result["high_count"] == 1
    assert result["medium_count"] == 1
    assert result["low_count"] == 1


@pytest.mark.asyncio
async def test_execute_scan_cleans_up_stop_flag():
    """Stop flag for scan_id should be removed after execution finishes (finally block)."""
    mgr = ScanManager()
    scan_dict = await mgr.start_scan(triggered_by="test-cleanup")
    scan_id = scan_dict["id"]
    mgr._stop_flags[scan_id] = False

    async def noop_audit(self, run_id, on_finding, on_skill, on_progress, stop_flag):
        return [], []

    from backend.engine.audit_engine import AuditEngine

    with patch.object(AuditEngine, "run_full_audit", new=noop_audit):
        await mgr._execute_scan(scan_id)

    # finally block must pop the stop flag
    assert scan_id not in mgr._stop_flags


@pytest.mark.asyncio
async def test_execute_scan_broadcasts_skill_events():
    """on_skill callback should broadcast skill events to WS subscribers."""
    mgr = ScanManager()
    scan_dict = await mgr.start_scan(triggered_by="test-skills")
    scan_id = scan_dict["id"]

    profile = _make_skill_profile("broadcast-skill")
    q = mgr.subscribe(scan_id)

    async def skill_audit(self, run_id, on_finding, on_skill, on_progress, stop_flag):
        on_skill(profile, 80, "High")
        return [], [(profile, 80, "High")]

    from backend.engine.audit_engine import AuditEngine

    with patch.object(AuditEngine, "run_full_audit", new=skill_audit):
        await mgr._execute_scan(scan_id)

    events = []
    while not q.empty():
        events.append(q.get_nowait())

    skill_events = [e for e in events if e.get("type") == "skill"]
    assert len(skill_events) >= 1
    assert skill_events[0]["data"]["risk_score"] == 80
    assert skill_events[0]["data"]["risk_level"] == "High"

    mgr.unsubscribe(scan_id, q)


# ---------------------------------------------------------------------------
# on_finding DB persistence (lines 134-158)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_on_finding_persists_finding_record():
    """on_finding callback must persist a FindingRecord row to the DB with correct fields."""
    import asyncio

    from sqlalchemy import select

    import backend.database
    from backend.models.finding import FindingRecord as FR

    mgr = ScanManager()
    scan_dict = await mgr.start_scan(triggered_by="test-db-insert")
    scan_id = scan_dict["id"]

    # Cancel the background task spawned by start_scan to avoid double-execution
    # (which would cause a UNIQUE constraint violation on finding.id).
    bg_task = mgr._active_tasks.pop(scan_id, None)
    if bg_task is not None:
        bg_task.cancel()
        await asyncio.sleep(0)  # allow cancellation to propagate

    finding = _make_finding_obj("DB-01", severity="CRITICAL", domain="capability")

    async def audit_with_finding(self, run_id, on_finding, on_skill, on_progress, stop_flag):
        on_finding(finding, "db-test-skill")
        return [finding], []

    from backend.engine.audit_engine import AuditEngine

    with patch.object(AuditEngine, "run_full_audit", new=audit_with_finding):
        await mgr._execute_scan(scan_id)

    # Query the patched in-memory DB for the inserted FindingRecord
    async with backend.database.AsyncSessionLocal() as db:
        result = await db.execute(select(FR).where(FR.scan_id == scan_id))
        records = result.scalars().all()

    assert len(records) == 1, f"Expected 1 FindingRecord, got {len(records)}"
    rec = records[0]
    assert rec.check_id == "DB-01"
    assert rec.severity == "CRITICAL"
    assert rec.domain == "capability"
    assert rec.skill_name == "db-test-skill"
    assert rec.scan_id == scan_id
    assert rec.title == "Test"
    assert rec.result == "FAIL"


# ---------------------------------------------------------------------------
# subscribe late-connect path (lines 121-122)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_subscribe_late_connect_delivers_terminal_event():
    """Subscribe after scan completion delivers cached terminal event immediately."""
    mgr = ScanManager()
    scan_id = "already-done"
    terminal = {"type": "completed", "summary": {"total_findings": 7}}
    mgr._terminal_events[scan_id] = terminal

    q = mgr.subscribe(scan_id)
    assert not q.empty()
    event = q.get_nowait()
    assert event["type"] == "completed"
    assert event["summary"]["total_findings"] == 7
    mgr.unsubscribe(scan_id, q)


@pytest.mark.asyncio
async def test_subscribe_no_terminal_event_queue_starts_empty():
    """Subscribe before scan completes — queue starts empty."""
    mgr = ScanManager()
    q = mgr.subscribe("pending-scan")
    assert q.empty()
    mgr.unsubscribe("pending-scan", q)
