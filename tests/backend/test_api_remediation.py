"""API tests for remediation endpoints."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import backend.database as _db
from backend.main import app
from backend.models.finding import FindingRecord
from backend.models.remediation import RemediationEvent
from backend.models.scan import ScanRun, ScanStatus


@pytest_asyncio.fixture
async def client():
    from tests.backend.conftest import TEST_API_TOKEN

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {TEST_API_TOKEN}"},
    ) as c:
        yield c


@pytest_asyncio.fixture
async def seeded_scan():
    """Insert a completed scan with a finding."""
    async with _db.AsyncSessionLocal() as db:
        scan = ScanRun(id="scan-rem-001", status=ScanStatus.COMPLETED, triggered_by="test")
        db.add(scan)
        finding = FindingRecord(
            id="finding-rem-001",
            scan_id="scan-rem-001",
            check_id="ADV-001",
            domain="skill",
            title="Shell access",
            description="Unrestricted shell",
            severity="HIGH",
            result="FAIL",
            evidence="pty: true",
            location="/tmp/test-skill",
            remediation="Restrict shell",
            detected_at=datetime.now(UTC),
            skill_name="test-skill",
        )
        db.add(finding)
        await db.commit()


@pytest_asyncio.fixture
async def seeded_history():
    """Insert remediation events for history endpoint."""
    async with _db.AsyncSessionLocal() as db:
        for i in range(3):
            event = RemediationEvent(
                id=f"evt-{i}",
                proposal_id=f"prop-{i}",
                skill_name=f"skill-{i}",
                check_id="ADV-001",
                action_type="restrict_shell",
                status="applied",
                description=f"Fix {i}",
                diff_preview="",
                impact="[]",
                applied_at=datetime.now(UTC),
            )
            db.add(event)
        await db.commit()


@pytest.mark.asyncio
class TestGetProposals:
    async def test_no_scans_returns_empty(self, client):
        resp = await client.get("/api/v1/remediation/proposals")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_proposals_with_scan(self, client, seeded_scan):
        # The proposals endpoint generates proposals from findings using the engine
        # With a non-existent skill path, it returns empty (no SKILL.md to analyze)
        resp = await client.get("/api/v1/remediation/proposals")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


@pytest.mark.asyncio
class TestApplyProposal:
    async def test_apply_invalid_action_type(self, client):
        resp = await client.post(
            "/api/v1/remediation/apply",
            json={
                "proposal_id": "p1",
                "diff_preview": "",
                "skill_name": "test",
                "skill_path": str(
                    __import__("pathlib").Path.home() / ".openclaw" / "workspace" / "test"
                ),
                "check_id": "ADV-001",
                "action_type": "INVALID",
                "description": "test",
            },
        )
        assert resp.status_code == 400
        assert "Unknown action_type" in resp.json()["detail"]

    async def test_apply_path_traversal_blocked(self, client):
        """Ensure paths outside allowed directories are rejected."""
        resp = await client.post(
            "/api/v1/remediation/apply",
            json={
                "proposal_id": "p1",
                "diff_preview": "",
                "skill_name": "test",
                "skill_path": "/etc/passwd",
                "check_id": "ADV-001",
                "action_type": "restrict_shell",
                "description": "test",
            },
        )
        assert resp.status_code == 400
        assert "allowed" in resp.json()["detail"].lower()

    async def test_apply_path_traversal_prefix_bypass_blocked(self, client):
        """Ensure .openclaw-evil style prefix bypasses are rejected (is_relative_to)."""
        evil_path = str(
            __import__("pathlib").Path.home() / ".openclaw-evil" / "payload"
        )
        resp = await client.post(
            "/api/v1/remediation/apply",
            json={
                "proposal_id": "p1",
                "diff_preview": "",
                "skill_name": "test",
                "skill_path": evil_path,
                "check_id": "ADV-001",
                "action_type": "restrict_shell",
                "description": "test",
            },
        )
        assert resp.status_code == 400
        assert "allowed" in resp.json()["detail"].lower()

    async def test_apply_config_patch_accepts_config_dir(self, client):
        """Config patches targeting ~/.openclaw/ should pass validation."""
        config_dir = str(__import__("pathlib").Path.home() / ".openclaw")
        resp = await client.post(
            "/api/v1/remediation/apply",
            json={
                "proposal_id": "p1",
                "diff_preview": "",
                "skill_name": "openclaw-config",
                "skill_path": config_dir,
                "check_id": "CONF-03",
                "action_type": "config_patch",
                "description": "Harden gateway binding",
            },
        )
        # Should not be 400 (validation passed). Actual result depends on
        # whether the config file exists and the strategy can apply, but
        # the path validation itself must succeed.
        assert resp.status_code != 400 or "allowed" not in resp.json().get("detail", "").lower()

    async def test_apply_advisory_returns_400(self, client):
        """POST /apply with action_type=advisory should return 400 without persisting an event."""
        from pathlib import Path

        resp = await client.post(
            "/api/v1/remediation/apply",
            json={
                "proposal_id": "p1",
                "diff_preview": "",
                "skill_name": "test",
                "skill_path": str(Path.home() / ".openclaw" / "workspace" / "test"),
                "check_id": "ADV-002",
                "action_type": "advisory",
                "description": "Advisory only",
            },
        )
        assert resp.status_code == 400
        assert "advisory" in resp.json()["detail"].lower()

    async def test_apply_config_patch_rejects_wrong_dir(self, client):
        """Config patches targeting a different directory should be rejected."""
        resp = await client.post(
            "/api/v1/remediation/apply",
            json={
                "proposal_id": "p1",
                "diff_preview": "",
                "skill_name": "openclaw-config",
                "skill_path": "/tmp/evil-config",
                "check_id": "CONF-03",
                "action_type": "config_patch",
                "description": "Harden gateway binding",
            },
        )
        assert resp.status_code == 400
        assert "config" in resp.json()["detail"].lower()


@pytest.mark.asyncio
class TestRollback:
    async def test_rollback_path_traversal_blocked(self, client):
        resp = await client.post(
            "/api/v1/remediation/rollback",
            json={
                "snapshot_path": "/etc/passwd",
            },
        )
        assert resp.status_code == 400
        assert "snapshot" in resp.json()["detail"].lower()

    async def test_rollback_nonexistent_snapshot(self, client):
        from sentinel.remediation.rollback import SNAPSHOT_DIR

        resp = await client.post(
            "/api/v1/remediation/rollback",
            json={
                "snapshot_path": str(SNAPSHOT_DIR / "nonexistent.tar.gz"),
            },
        )
        assert resp.status_code == 404


@pytest.mark.asyncio
class TestGetHistory:
    async def test_empty_history(self, client):
        resp = await client.get("/api/v1/remediation/history")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_history_returns_events(self, client, seeded_history):
        resp = await client.get("/api/v1/remediation/history")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 3
        assert all("skill_name" in item for item in data)
        assert all("applied_at" in item for item in data)

    async def test_history_limit_param(self, client, seeded_history):
        resp = await client.get("/api/v1/remediation/history?limit=2")
        assert resp.status_code == 200
        assert len(resp.json()) == 2
