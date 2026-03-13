"""Unit tests for sentinel.lifecycle.toggler."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.lifecycle.registry import SkillRecord, SkillRegistry
from sentinel.lifecycle.toggler import SkillToggler

pytestmark = pytest.mark.unit


def _setup_skill(
    tmp_path: Path, name: str = "demo", enabled: bool = True
) -> tuple[SkillRegistry, SkillRecord]:
    """Create a skill dir and register it."""
    skill_dir = tmp_path / "skills" / name
    skill_dir.mkdir(parents=True)
    if enabled:
        (skill_dir / "SKILL.md").write_text(f"name: {name}\n")
    else:
        (skill_dir / "SKILL.md.disabled").write_text(f"name: {name}\n")

    reg = SkillRegistry(registry_path=tmp_path / "registry.json")
    rec = SkillRecord(
        name=name,
        path=str(skill_dir),
        source="local",
        version="1.0",
        installed_at="2025-01-01T00:00:00+00:00",
        enabled=enabled,
    )
    reg.register(rec)
    return reg, rec


class TestSkillToggler:
    def test_disable_renames_skill_md(self, tmp_path):
        reg, rec = _setup_skill(tmp_path, "myskill", enabled=True)
        toggler = SkillToggler(reg)
        toggler.disable("myskill")

        skill_dir = Path(rec.path)
        assert not (skill_dir / "SKILL.md").exists()
        assert (skill_dir / "SKILL.md.disabled").exists()
        assert reg.get("myskill").enabled is False

    def test_enable_renames_back(self, tmp_path):
        reg, rec = _setup_skill(tmp_path, "myskill", enabled=False)
        toggler = SkillToggler(reg)
        toggler.enable("myskill")

        skill_dir = Path(rec.path)
        assert (skill_dir / "SKILL.md").exists()
        assert not (skill_dir / "SKILL.md.disabled").exists()
        assert reg.get("myskill").enabled is True

    def test_disable_already_disabled_raises(self, tmp_path):
        reg, _ = _setup_skill(tmp_path, "off", enabled=False)
        toggler = SkillToggler(reg)
        with pytest.raises(ValueError, match="already disabled"):
            toggler.disable("off")

    def test_enable_already_enabled_raises(self, tmp_path):
        reg, _ = _setup_skill(tmp_path, "on", enabled=True)
        toggler = SkillToggler(reg)
        with pytest.raises(ValueError, match="already enabled"):
            toggler.enable("on")

    def test_system_skill_can_be_disabled(self, tmp_path):
        """System skills should be toggleable (enable/disable), not blocked."""
        skill_dir = tmp_path / "skills" / "sys"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("name: sys\n")

        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        rec = SkillRecord(
            name="sys",
            path=str(skill_dir),
            source="system",
            version="1.0",
            installed_at="2025-01-01T00:00:00+00:00",
            enabled=True,
        )
        reg.register(rec)
        toggler = SkillToggler(reg)
        toggler.disable("sys")
        assert reg.get("sys").enabled is False

    def test_system_skill_can_be_enabled(self, tmp_path):
        """System skills should be toggleable (enable/disable), not blocked."""
        skill_dir = tmp_path / "skills" / "sys"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md.disabled").write_text("name: sys\n")

        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        rec = SkillRecord(
            name="sys",
            path=str(skill_dir),
            source="system",
            version="1.0",
            installed_at="2025-01-01T00:00:00+00:00",
            enabled=False,
        )
        reg.register(rec)
        toggler = SkillToggler(reg)
        toggler.enable("sys")
        assert reg.get("sys").enabled is True

    def test_get_status_enabled(self, tmp_path):
        reg, rec = _setup_skill(tmp_path, "on", enabled=True)
        toggler = SkillToggler(reg)
        assert toggler.get_status(Path(rec.path)) is True

    def test_get_status_disabled(self, tmp_path):
        reg, rec = _setup_skill(tmp_path, "off", enabled=False)
        toggler = SkillToggler(reg)
        assert toggler.get_status(Path(rec.path)) is False
