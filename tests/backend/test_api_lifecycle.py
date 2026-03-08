"""API tests for lifecycle endpoints."""

from __future__ import annotations

import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from backend.main import app
from sentinel.lifecycle.registry import SkillRecord, SkillRegistry


@pytest_asyncio.fixture
async def client():
    from tests.backend.conftest import TEST_API_TOKEN

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {TEST_API_TOKEN}"},
    ) as c:
        yield c


@pytest.fixture
def mock_registry(tmp_path):
    """Create a real registry backed by tmp_path."""
    reg = SkillRegistry(registry_path=tmp_path / "registry.json")
    return reg


@pytest.fixture
def skill_dir(tmp_path):
    """Create a skill on disk for testing."""
    skill_path = tmp_path / "skills" / "test-skill"
    skill_path.mkdir(parents=True)
    (skill_path / "SKILL.md").write_text("name: test-skill\nversion: 1.0\nauthor: tester\n")
    return skill_path


@pytest.fixture
def registered_skill(mock_registry, skill_dir):
    """Register a skill in the registry."""
    rec = SkillRecord(
        name="test-skill",
        path=str(skill_dir),
        source="local",
        version="1.0",
        installed_at="2025-01-01T00:00:00+00:00",
        enabled=True,
    )
    mock_registry.register(rec)
    return rec


@pytest.fixture
def protected_skill(mock_registry):
    """Register a skill in a protected path."""
    rec = SkillRecord(
        name="protected-skill",
        path="/opt/homebrew/lib/node_modules/openclaw/skills/protected-skill",
        source="system",
        version="1.0",
        installed_at="2025-01-01T00:00:00+00:00",
        enabled=True,
    )
    mock_registry.register(rec)
    return rec


def _make_tarball(tmp_path: Path, name: str) -> Path:
    skill_dir = tmp_path / "build" / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(f"name: {name}\nversion: 1.0\n")
    tarball = tmp_path / f"{name}.skill"
    with tarfile.open(tarball, "w:gz") as tar:
        tar.add(skill_dir, arcname=name)
    return tarball


@pytest.mark.asyncio
@pytest.mark.backend
class TestLifecycleAPI:
    async def test_list_skills_returns_array(
        self, client, mock_registry, registered_skill, tmp_path
    ):
        # Point workspace_skills_dir at the parent of the registered skill's
        # directory so that sync() finds it on disk and does not prune it.
        mock_cfg = MagicMock()
        mock_cfg.skills_dir = tmp_path / "empty-sys-skills"
        mock_cfg.workspace_skills_dir = Path(registered_skill.path).parent
        with (
            patch("backend.api.routes.lifecycle._get_registry", return_value=mock_registry),
            patch("backend.api.routes.lifecycle.load_config", return_value=mock_cfg),
        ):
            resp = await client.get("/api/v1/lifecycle")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        names = [d["name"] for d in data]
        assert "test-skill" in names

    async def test_install_skill_from_file(self, client, mock_registry, tmp_path):
        skills_dir = tmp_path / "install-skills"
        tarball = _make_tarball(tmp_path, "new-skill")
        with (
            patch("backend.api.routes.lifecycle._get_registry", return_value=mock_registry),
            patch("backend.api.routes.lifecycle._get_skills_dir", return_value=skills_dir),
        ):
            resp = await client.post(
                "/api/v1/lifecycle/install",
                json={"source": "file", "path": str(tarball)},
            )
        assert resp.status_code == 200
        assert resp.json()["name"] == "new-skill"

    async def test_install_already_installed_409(
        self, client, mock_registry, tmp_path, registered_skill
    ):
        # Create tarball with same name as existing skill
        tarball = _make_tarball(tmp_path, "test-skill")
        with (
            patch("backend.api.routes.lifecycle._get_registry", return_value=mock_registry),
            patch(
                "backend.api.routes.lifecycle._get_skills_dir",
                return_value=Path(registered_skill.path).parent,
            ),
        ):
            resp = await client.post(
                "/api/v1/lifecycle/install",
                json={"source": "file", "path": str(tarball)},
            )
        assert resp.status_code == 409

    async def test_install_invalid_manifest_400(self, client, mock_registry, tmp_path):
        # Create a tarball with no SKILL.md
        bad_dir = tmp_path / "build" / "bad"
        bad_dir.mkdir(parents=True)
        (bad_dir / "README.md").write_text("no skill here")
        tarball = tmp_path / "bad.skill"
        with tarfile.open(tarball, "w:gz") as tar:
            tar.add(bad_dir, arcname="bad")

        skills_dir = tmp_path / "skills"
        with (
            patch("backend.api.routes.lifecycle._get_registry", return_value=mock_registry),
            patch("backend.api.routes.lifecycle._get_skills_dir", return_value=skills_dir),
        ):
            resp = await client.post(
                "/api/v1/lifecycle/install",
                json={"source": "file", "path": str(tarball)},
            )
        assert resp.status_code == 400

    async def test_enable_skill(self, client, mock_registry, skill_dir, registered_skill):
        # First disable it
        skill_md = skill_dir / "SKILL.md"
        skill_md.rename(skill_dir / "SKILL.md.disabled")
        rec = mock_registry.get("test-skill")
        rec.enabled = False
        mock_registry.register(rec)

        with patch("backend.api.routes.lifecycle._get_registry", return_value=mock_registry):
            resp = await client.post("/api/v1/lifecycle/test-skill/enable")
        assert resp.status_code == 200
        assert resp.json()["enabled"] is True

    async def test_disable_skill(self, client, mock_registry, registered_skill):
        with patch("backend.api.routes.lifecycle._get_registry", return_value=mock_registry):
            resp = await client.post("/api/v1/lifecycle/test-skill/disable")
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False

    async def test_disable_protected_403(self, client, mock_registry, protected_skill):
        with patch("backend.api.routes.lifecycle._get_registry", return_value=mock_registry):
            resp = await client.post("/api/v1/lifecycle/protected-skill/disable")
        assert resp.status_code == 403

    async def test_uninstall_skill(
        self, client, mock_registry, registered_skill, tmp_path, monkeypatch
    ):
        trash_dir = tmp_path / "trash"
        monkeypatch.setattr("sentinel.lifecycle.uninstaller.TRASH_DIR", trash_dir)
        with patch("backend.api.routes.lifecycle._get_registry", return_value=mock_registry):
            resp = await client.delete("/api/v1/lifecycle/test-skill")
        assert resp.status_code == 200
        assert resp.json()["name"] == "test-skill"

    async def test_uninstall_protected_403(self, client, mock_registry, protected_skill):
        with patch("backend.api.routes.lifecycle._get_registry", return_value=mock_registry):
            resp = await client.delete("/api/v1/lifecycle/protected-skill")
        assert resp.status_code == 403

    async def test_health_skill(self, client, mock_registry, registered_skill):
        with patch("backend.api.routes.lifecycle._get_registry", return_value=mock_registry):
            resp = await client.get("/api/v1/lifecycle/test-skill/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "test-skill"
        assert "risk_level" in data
        assert isinstance(data["findings"], list)
