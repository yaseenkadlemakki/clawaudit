"""Functional tests for sentinel skills verify CLI command."""

from __future__ import annotations

import sys
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

if sys.version_info < (3, 10):  # noqa: UP036
    pytest.skip("requires Python 3.10+ (str | None type union syntax)", allow_module_level=True)

from typer.testing import CliRunner

from sentinel.lifecycle.installer import SkillInstaller
from sentinel.lifecycle.registry import SkillRegistry
from sentinel.main import app

pytestmark = pytest.mark.functional

runner = CliRunner()


def _make_skill_tarball(tmp_path: Path, name: str) -> Path:
    skill_dir = tmp_path / "build" / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(f"name: {name}\n")
    tarball = tmp_path / f"{name}.skill"
    with tarfile.open(tarball, "w:gz") as tar:
        tar.add(skill_dir, arcname=name)
    return tarball


class TestSkillsVerifyCli:
    def test_skills_verify_passes_unmodified(self, tmp_path):
        tarball = _make_skill_tarball(tmp_path, "verify-ok")
        skills_dir = tmp_path / "skills"
        reg_path = tmp_path / "registry.json"
        reg = SkillRegistry(registry_path=reg_path)
        installer = SkillInstaller(skills_dir, reg)
        installer.install_from_file(tarball)

        with patch.object(SkillRegistry, "REGISTRY_PATH", reg_path):
            result = runner.invoke(app, ["skills", "verify", "verify-ok"])
        assert result.exit_code == 0
        assert "OK" in result.output

    def test_skills_verify_fails_tampered(self, tmp_path):
        tarball = _make_skill_tarball(tmp_path, "verify-bad")
        skills_dir = tmp_path / "skills"
        reg_path = tmp_path / "registry.json"
        reg = SkillRegistry(registry_path=reg_path)
        installer = SkillInstaller(skills_dir, reg)
        record = installer.install_from_file(tarball)

        # Tamper
        (Path(record.path) / "evil.sh").write_text("echo pwned\n")

        with patch.object(SkillRegistry, "REGISTRY_PATH", reg_path):
            result = runner.invoke(app, ["skills", "verify", "verify-bad"])
        assert result.exit_code == 1
        assert "TAMPERED" in result.output

    def test_skills_verify_not_registered(self, tmp_path):
        reg_path = tmp_path / "registry.json"
        with patch.object(SkillRegistry, "REGISTRY_PATH", reg_path):
            result = runner.invoke(app, ["skills", "verify", "nonexistent"])
        assert result.exit_code == 1
        assert "not found" in result.output
