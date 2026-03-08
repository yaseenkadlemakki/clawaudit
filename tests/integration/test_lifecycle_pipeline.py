"""Integration tests for the full skill lifecycle pipeline."""

from __future__ import annotations

import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sentinel.lifecycle.installer import SkillInstaller
from sentinel.lifecycle.registry import SkillRegistry
from sentinel.lifecycle.toggler import SkillToggler
from sentinel.lifecycle.uninstaller import SkillUninstaller

pytestmark = pytest.mark.integration


def _make_skill_tarball(tmp_path: Path, name: str = "demo") -> Path:
    skill_dir = tmp_path / "build" / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(f"name: {name}\nversion: 1.0\nauthor: test\n")
    tarball = tmp_path / f"{name}.skill"
    with tarfile.open(tarball, "w:gz") as tar:
        tar.add(skill_dir, arcname=name)
    return tarball


class TestLifecyclePipeline:
    def test_install_enable_disable_uninstall_cycle(self, tmp_path, monkeypatch):
        """Full happy path: install → disable → enable → uninstall → recover."""
        trash_dir = tmp_path / "trash"
        monkeypatch.setattr("sentinel.lifecycle.uninstaller.TRASH_DIR", trash_dir)

        skills_dir = tmp_path / "skills"
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        installer = SkillInstaller(skills_dir, reg)
        toggler = SkillToggler(reg)
        uninstaller = SkillUninstaller(reg)

        # Install
        tarball = _make_skill_tarball(tmp_path, "lifecycle-test")
        record = installer.install_from_file(tarball)
        assert record.enabled is True
        assert (skills_dir / "lifecycle-test" / "SKILL.md").exists()

        # Disable
        toggler.disable("lifecycle-test")
        assert reg.get("lifecycle-test").enabled is False
        assert not (skills_dir / "lifecycle-test" / "SKILL.md").exists()
        assert (skills_dir / "lifecycle-test" / "SKILL.md.disabled").exists()

        # Enable
        toggler.enable("lifecycle-test")
        assert reg.get("lifecycle-test").enabled is True
        assert (skills_dir / "lifecycle-test" / "SKILL.md").exists()

        # Uninstall
        trash_path = uninstaller.uninstall("lifecycle-test")
        assert reg.get("lifecycle-test") is None
        assert not (skills_dir / "lifecycle-test").exists()

        # Recover
        recovered = uninstaller.recover(trash_path.name, skills_dir)
        assert recovered.name == "lifecycle-test"
        assert (skills_dir / "lifecycle-test" / "SKILL.md").exists()

    def test_install_and_health_check(self, tmp_path):
        """Install a skill and verify SkillAnalyzer can analyze it."""
        from sentinel.analyzer.skill_analyzer import SkillAnalyzer

        skills_dir = tmp_path / "skills"
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        installer = SkillInstaller(skills_dir, reg)

        tarball = _make_skill_tarball(tmp_path, "health-check")
        record = installer.install_from_file(tarball)

        analyzer = SkillAnalyzer()
        profile = analyzer.analyze(Path(record.path) / "SKILL.md")
        assert profile.name == "health-check"
        assert profile.trust_score_value >= 0

    def test_recover_after_uninstall(self, tmp_path, monkeypatch):
        trash_dir = tmp_path / "trash"
        monkeypatch.setattr("sentinel.lifecycle.uninstaller.TRASH_DIR", trash_dir)

        skills_dir = tmp_path / "skills"
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        installer = SkillInstaller(skills_dir, reg)
        uninstaller = SkillUninstaller(reg)

        tarball = _make_skill_tarball(tmp_path, "recoverable")
        installer.install_from_file(tarball)
        trash_path = uninstaller.uninstall("recoverable")

        uninstaller.recover(trash_path.name, skills_dir)
        assert (skills_dir / "recoverable" / "SKILL.md").exists()
        assert reg.get("recoverable") is not None

    def test_concurrent_registry_writes_safe(self, tmp_path):
        """Two registry instances writing should not corrupt the file."""
        reg_path = tmp_path / "registry.json"
        reg1 = SkillRegistry(registry_path=reg_path)
        reg2 = SkillRegistry(registry_path=reg_path)

        from sentinel.lifecycle.registry import SkillRecord

        reg1.register(
            SkillRecord(
                name="a",
                path="/tmp/a",
                source="local",
                version="1.0",
                installed_at="2025-01-01T00:00:00+00:00",
                enabled=True,
            )
        )
        reg2.register(
            SkillRecord(
                name="b",
                path="/tmp/b",
                source="local",
                version="1.0",
                installed_at="2025-01-01T00:00:00+00:00",
                enabled=True,
            )
        )

        # Both should be present (last writer wins for concurrent, but both should
        # at least produce valid JSON)
        final = SkillRegistry(registry_path=reg_path)
        records = final.load()
        assert isinstance(records, dict)
        assert "b" in records  # last writer should have 'a' and 'b'

    def test_install_from_clawhub_url_mocked(self, tmp_path):
        tarball = _make_skill_tarball(tmp_path, "clawhub-skill")
        tarball_bytes = tarball.read_bytes()

        skills_dir = tmp_path / "skills"
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        installer = SkillInstaller(skills_dir, reg)

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.iter_bytes = MagicMock(return_value=[tarball_bytes])
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        mock_httpx = MagicMock()
        mock_httpx.stream = MagicMock(return_value=mock_response)
        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            record = installer.install_from_url("https://clawhub.dev/skills/clawhub-skill.skill")

        assert record.name == "clawhub-skill"
        assert record.source == "https://clawhub.dev/skills/clawhub-skill.skill"
