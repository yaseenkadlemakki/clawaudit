"""Unit tests for skill content hash pinning."""

from __future__ import annotations

import tarfile
from pathlib import Path

import pytest

from sentinel.lifecycle.installer import (
    SkillAlreadyInstalledError,
    SkillHashMismatchError,
    SkillInstaller,
)
from sentinel.lifecycle.registry import SkillRegistry

pytestmark = pytest.mark.unit


def _make_skill_tarball(tmp_path: Path, name: str = "demo", extra_content: str = "") -> Path:
    """Create a valid .skill tarball."""
    skill_dir = tmp_path / "build" / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(f"name: {name}\n")
    if extra_content:
        (skill_dir / "extra.txt").write_text(extra_content)
    tarball = tmp_path / f"{name}.skill"
    with tarfile.open(tarball, "w:gz") as tar:
        tar.add(skill_dir, arcname=name)
    return tarball


class TestSkillHash:
    def test_hash_computed_on_install(self, tmp_path):
        tarball = _make_skill_tarball(tmp_path, "hashtest")
        skills_dir = tmp_path / "skills"
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        installer = SkillInstaller(skills_dir, reg)
        record = installer.install_from_file(tarball)
        assert record.content_hash
        assert len(record.content_hash) == 64  # SHA-256 hex

    def test_same_content_same_hash(self, tmp_path):
        # Create two tarballs with identical content
        tarball1 = _make_skill_tarball(tmp_path / "a", "sametest", extra_content="hello")
        tarball2 = _make_skill_tarball(tmp_path / "b", "sametest", extra_content="hello")

        skills_dir1 = tmp_path / "skills1"
        reg1 = SkillRegistry(registry_path=tmp_path / "reg1.json")
        installer1 = SkillInstaller(skills_dir1, reg1)
        record1 = installer1.install_from_file(tarball1)

        skills_dir2 = tmp_path / "skills2"
        reg2 = SkillRegistry(registry_path=tmp_path / "reg2.json")
        installer2 = SkillInstaller(skills_dir2, reg2)
        record2 = installer2.install_from_file(tarball2)

        assert record1.content_hash == record2.content_hash

    def test_different_content_different_hash(self, tmp_path):
        tarball1 = _make_skill_tarball(tmp_path / "a", "difftest", extra_content="version1")
        tarball2 = _make_skill_tarball(tmp_path / "b", "difftest", extra_content="version2")

        skills_dir1 = tmp_path / "skills1"
        reg1 = SkillRegistry(registry_path=tmp_path / "reg1.json")
        installer1 = SkillInstaller(skills_dir1, reg1)
        record1 = installer1.install_from_file(tarball1)

        skills_dir2 = tmp_path / "skills2"
        reg2 = SkillRegistry(registry_path=tmp_path / "reg2.json")
        installer2 = SkillInstaller(skills_dir2, reg2)
        record2 = installer2.install_from_file(tarball2)

        assert record1.content_hash != record2.content_hash

    def test_reinstall_same_hash_raises_already_installed(self, tmp_path):
        tarball = _make_skill_tarball(tmp_path, "duptest")
        skills_dir = tmp_path / "skills"
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        installer = SkillInstaller(skills_dir, reg)
        installer.install_from_file(tarball)

        tarball2 = _make_skill_tarball(tmp_path / "again", "duptest")
        with pytest.raises(SkillAlreadyInstalledError, match="already up to date"):
            installer.install_from_file(tarball2)

    def test_reinstall_different_hash_raises_mismatch(self, tmp_path):
        tarball1 = _make_skill_tarball(tmp_path / "v1", "mismatch", extra_content="v1")
        skills_dir = tmp_path / "skills"
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        installer = SkillInstaller(skills_dir, reg)
        installer.install_from_file(tarball1)

        tarball2 = _make_skill_tarball(tmp_path / "v2", "mismatch", extra_content="v2")
        with pytest.raises(SkillHashMismatchError, match="hash changed"):
            installer.install_from_file(tarball2)

    def test_force_flag_bypasses_hash_check(self, tmp_path):
        tarball1 = _make_skill_tarball(tmp_path / "v1", "forcetest", extra_content="v1")
        skills_dir = tmp_path / "skills"
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        installer = SkillInstaller(skills_dir, reg)
        installer.install_from_file(tarball1)

        tarball2 = _make_skill_tarball(tmp_path / "v2", "forcetest", extra_content="v2")
        record = installer.install_from_file(tarball2, force=True)
        assert record.name == "forcetest"
        assert record.content_hash  # Hash is updated

    def test_verify_passes_for_unmodified_skill(self, tmp_path):
        tarball = _make_skill_tarball(tmp_path, "verify-ok")
        skills_dir = tmp_path / "skills"
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        installer = SkillInstaller(skills_dir, reg)
        record = installer.install_from_file(tarball)

        # Recompute hash — should match
        current = SkillInstaller._compute_skill_hash(Path(record.path))
        assert current == record.content_hash

    def test_verify_fails_for_tampered_skill(self, tmp_path):
        tarball = _make_skill_tarball(tmp_path, "verify-bad")
        skills_dir = tmp_path / "skills"
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        installer = SkillInstaller(skills_dir, reg)
        record = installer.install_from_file(tarball)

        # Tamper with the skill
        (Path(record.path) / "injected.sh").write_text("echo pwned\n")

        current = SkillInstaller._compute_skill_hash(Path(record.path))
        assert current != record.content_hash
