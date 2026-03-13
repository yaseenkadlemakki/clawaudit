"""Unit tests for sentinel.lifecycle.registry."""

from __future__ import annotations

import pytest

from sentinel.lifecycle.registry import SkillRecord, SkillRegistry

pytestmark = pytest.mark.unit


def _make_record(name: str = "test-skill", **kwargs) -> SkillRecord:
    defaults = {
        "name": name,
        "path": f"/tmp/skills/{name}",
        "source": "local",
        "version": "1.0.0",
        "installed_at": "2025-01-01T00:00:00+00:00",
        "enabled": True,
    }
    defaults.update(kwargs)
    return SkillRecord(**defaults)


class TestSkillRegistry:
    def test_registry_starts_empty_when_no_file(self, tmp_path):
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        assert reg.load() == {}

    def test_register_and_retrieve(self, tmp_path):
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        rec = _make_record("my-skill")
        reg.register(rec)
        got = reg.get("my-skill")
        assert got is not None
        assert got.name == "my-skill"
        assert got.version == "1.0.0"

    def test_save_and_load_roundtrip(self, tmp_path):
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        records = {
            "a": _make_record("a"),
            "b": _make_record("b", version="2.0"),
        }
        reg.save(records)
        loaded = reg.load()
        assert set(loaded.keys()) == {"a", "b"}
        assert loaded["b"].version == "2.0"

    def test_unregister_removes_entry(self, tmp_path):
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        reg.register(_make_record("x"))
        reg.register(_make_record("y"))
        reg.unregister("x")
        assert reg.get("x") is None
        assert reg.get("y") is not None

    def test_list_all_returns_all_records(self, tmp_path):
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        reg.register(_make_record("a"))
        reg.register(_make_record("b"))
        reg.register(_make_record("c"))
        assert len(reg.list_all()) == 3

    def test_sync_adds_skills_found_on_disk(self, tmp_path):
        skills_dir = tmp_path / "skills"
        (skills_dir / "alpha").mkdir(parents=True)
        (skills_dir / "alpha" / "SKILL.md").write_text("name: alpha\n")

        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        reg.sync([skills_dir])

        assert reg.get("alpha") is not None
        assert reg.get("alpha").enabled is True

    def test_sync_removes_skills_missing_from_disk(self, tmp_path):
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        reg.register(_make_record("gone", path=str(tmp_path / "skills" / "gone")))

        reg.sync([tmp_path / "skills"])
        assert reg.get("gone") is None

    def test_atomic_write_no_tmp_file_left(self, tmp_path):
        reg_path = tmp_path / "registry.json"
        reg = SkillRegistry(registry_path=reg_path)
        reg.register(_make_record("x"))

        # After save, no .tmp file should exist
        tmp_file = reg_path.with_suffix(".tmp")
        assert not tmp_file.exists()
        assert reg_path.exists()

    def test_get_returns_none_for_missing(self, tmp_path):
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        assert reg.get("nonexistent") is None

    def test_system_skill_gets_system_source(self, tmp_path):
        """Skills under protected homebrew path should get source='system'."""
        skills_dir = tmp_path / "opt" / "homebrew" / "lib" / "node_modules" / "openclaw" / "skills"
        skill_path = skills_dir / "test-skill"
        skill_path.mkdir(parents=True)
        (skill_path / "SKILL.md").write_text("name: test-skill\n")

        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        # Temporarily patch PROTECTED_PATHS to use tmp_path-based path
        import sentinel.lifecycle

        original = sentinel.lifecycle.PROTECTED_PATHS[:]
        sentinel.lifecycle.PROTECTED_PATHS[0] = skills_dir
        try:
            reg.sync([skills_dir])
            rec = reg.get("test-skill")
            assert rec is not None
            assert rec.source == "system"
        finally:
            sentinel.lifecycle.PROTECTED_PATHS[:] = original

    def test_local_skill_gets_local_source(self, tmp_path):
        """Skills under a user path should get source='local'."""
        skills_dir = tmp_path / "user" / ".openclaw" / "skills"
        skill_path = skills_dir / "my-skill"
        skill_path.mkdir(parents=True)
        (skill_path / "SKILL.md").write_text("name: my-skill\n")

        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        reg.sync([skills_dir])
        rec = reg.get("my-skill")
        assert rec is not None
        assert rec.source == "local"

    def test_usr_local_skill_gets_system_source(self, tmp_path):
        """Skills under /usr/local protected path should get source='system'."""
        skills_dir = tmp_path / "usr" / "local" / "lib" / "node_modules" / "openclaw" / "skills"
        skill_path = skills_dir / "x"
        skill_path.mkdir(parents=True)
        (skill_path / "SKILL.md").write_text("name: x\n")

        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        import sentinel.lifecycle

        original = sentinel.lifecycle.PROTECTED_PATHS[:]
        sentinel.lifecycle.PROTECTED_PATHS[1] = skills_dir
        try:
            reg.sync([skills_dir])
            rec = reg.get("x")
            assert rec is not None
            assert rec.source == "system"
        finally:
            sentinel.lifecycle.PROTECTED_PATHS[:] = original
