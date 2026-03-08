"""Unit tests for sentinel.lifecycle.uninstaller."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.lifecycle.registry import SkillRecord, SkillRegistry
from sentinel.lifecycle.uninstaller import SkillUninstaller

pytestmark = pytest.mark.unit


def _setup_skill(tmp_path: Path, name: str = "demo") -> tuple[SkillRegistry, SkillRecord, Path]:
    """Create a skill dir, register it, return (registry, record, skills_dir)."""
    skills_dir = tmp_path / "skills"
    skill_dir = skills_dir / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(f"name: {name}\n")

    reg = SkillRegistry(registry_path=tmp_path / "registry.json")
    rec = SkillRecord(
        name=name,
        path=str(skill_dir),
        source="local",
        version="1.0",
        installed_at="2025-01-01T00:00:00+00:00",
        enabled=True,
    )
    reg.register(rec)
    return reg, rec, skills_dir


class TestSkillUninstaller:
    def test_uninstall_moves_to_trash(self, tmp_path, monkeypatch):
        trash_dir = tmp_path / "trash"
        monkeypatch.setattr("sentinel.lifecycle.uninstaller.TRASH_DIR", trash_dir)
        reg, rec, _ = _setup_skill(tmp_path, "removeme")
        uninstaller = SkillUninstaller(reg)

        trash_path = uninstaller.uninstall("removeme")
        assert trash_path.exists()
        assert not Path(rec.path).exists()

    def test_uninstall_unregisters(self, tmp_path, monkeypatch):
        trash_dir = tmp_path / "trash"
        monkeypatch.setattr("sentinel.lifecycle.uninstaller.TRASH_DIR", trash_dir)
        reg, _, _ = _setup_skill(tmp_path, "gone")
        uninstaller = SkillUninstaller(reg)

        uninstaller.uninstall("gone")
        assert reg.get("gone") is None

    def test_recover_moves_back(self, tmp_path, monkeypatch):
        trash_dir = tmp_path / "trash"
        monkeypatch.setattr("sentinel.lifecycle.uninstaller.TRASH_DIR", trash_dir)
        reg, _, skills_dir = _setup_skill(tmp_path, "comeback")
        uninstaller = SkillUninstaller(reg)

        trash_path = uninstaller.uninstall("comeback")
        # Now recover
        record = uninstaller.recover(trash_path.name, skills_dir)
        assert record.name == "comeback"
        assert (skills_dir / "comeback" / "SKILL.md").exists()
        assert reg.get("comeback") is not None

    def test_protected_path_blocks_uninstall(self, tmp_path):
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        rec = SkillRecord(
            name="sys",
            path="/opt/homebrew/lib/node_modules/openclaw/skills/sys",
            source="system",
            version="1.0",
            installed_at="2025-01-01T00:00:00+00:00",
            enabled=True,
        )
        reg.register(rec)
        uninstaller = SkillUninstaller(reg)
        with pytest.raises(PermissionError, match="protected"):
            uninstaller.uninstall("sys")

    def test_list_trash_empty(self, tmp_path, monkeypatch):
        trash_dir = tmp_path / "trash"
        monkeypatch.setattr("sentinel.lifecycle.uninstaller.TRASH_DIR", trash_dir)
        uninstaller = SkillUninstaller(SkillRegistry(registry_path=tmp_path / "registry.json"))
        assert uninstaller.list_trash() == []

    def test_list_trash_after_uninstall(self, tmp_path, monkeypatch):
        trash_dir = tmp_path / "trash"
        monkeypatch.setattr("sentinel.lifecycle.uninstaller.TRASH_DIR", trash_dir)
        reg, _, _ = _setup_skill(tmp_path, "listed")
        uninstaller = SkillUninstaller(reg)
        uninstaller.uninstall("listed")
        assert len(uninstaller.list_trash()) == 1

    def test_uninstall_not_found_raises(self, tmp_path, monkeypatch):
        trash_dir = tmp_path / "trash"
        monkeypatch.setattr("sentinel.lifecycle.uninstaller.TRASH_DIR", trash_dir)
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        uninstaller = SkillUninstaller(reg)
        with pytest.raises(FileNotFoundError):
            uninstaller.uninstall("ghost")
