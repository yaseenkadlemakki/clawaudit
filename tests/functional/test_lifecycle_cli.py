"""Functional tests for the sentinel skills CLI subcommand."""

from __future__ import annotations

import sys
import tarfile
from pathlib import Path

import pytest

if sys.version_info < (3, 10):  # noqa: UP036
    pytest.skip("requires Python 3.10+ (str | None type union syntax)", allow_module_level=True)

from typer.testing import CliRunner

from sentinel.main import app

pytestmark = pytest.mark.functional

runner = CliRunner()


def _make_skill_tarball(tmp_path: Path, name: str = "cli-test") -> Path:
    skill_dir = tmp_path / "build" / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(f"name: {name}\nversion: 2.0\nauthor: tester\n")
    tarball = tmp_path / f"{name}.skill"
    with tarfile.open(tarball, "w:gz") as tar:
        tar.add(skill_dir, arcname=name)
    return tarball


def _make_config(tmp_path: Path, skills_dir: Path) -> Path:
    """Write a minimal sentinel config YAML pointing at tmp dirs."""
    import yaml

    config_path = tmp_path / "sentinel.yaml"
    config_path.write_text(
        yaml.dump(
            {
                "openclaw": {
                    "skills_dir": str(tmp_path / "system-skills"),
                    "workspace_skills_dir": str(skills_dir),
                },
            }
        )
    )
    return config_path


class TestSkillsCli:
    def test_skills_list_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "sentinel.lifecycle.registry.SkillRegistry.REGISTRY_PATH",
            tmp_path / "registry.json",
        )
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        config = _make_config(tmp_path, skills_dir)
        result = runner.invoke(app, ["skills", "list", "--config", str(config)])
        assert result.exit_code == 0
        assert "No skills registered" in result.output or "Registered Skills" in result.output

    def test_skills_install_valid(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "sentinel.lifecycle.registry.SkillRegistry.REGISTRY_PATH",
            tmp_path / "registry.json",
        )
        skills_dir = tmp_path / "skills"
        config = _make_config(tmp_path, skills_dir)
        tarball = _make_skill_tarball(tmp_path, "installable")

        result = runner.invoke(app, ["skills", "install", str(tarball), "--config", str(config)])
        assert result.exit_code == 0
        assert "Installed" in result.output
        assert (skills_dir / "installable" / "SKILL.md").exists()

    def test_skills_install_invalid_raises(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "sentinel.lifecycle.registry.SkillRegistry.REGISTRY_PATH",
            tmp_path / "registry.json",
        )
        result = runner.invoke(
            app,
            [
                "skills",
                "install",
                "/nonexistent.skill",
                "--config",
                str(tmp_path / "sentinel.yaml"),
            ],
        )
        assert result.exit_code != 0

    def test_skills_enable_disable_cycle(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "sentinel.lifecycle.registry.SkillRegistry.REGISTRY_PATH",
            tmp_path / "registry.json",
        )
        skills_dir = tmp_path / "skills"
        config = _make_config(tmp_path, skills_dir)
        tarball = _make_skill_tarball(tmp_path, "togglable")

        # Install
        runner.invoke(app, ["skills", "install", str(tarball), "--config", str(config)])

        # Disable
        result = runner.invoke(app, ["skills", "disable", "togglable", "--config", str(config)])
        assert result.exit_code == 0
        assert "Disabled" in result.output

        # Enable
        result = runner.invoke(app, ["skills", "enable", "togglable", "--config", str(config)])
        assert result.exit_code == 0
        assert "Enabled" in result.output

    def test_skills_uninstall(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "sentinel.lifecycle.registry.SkillRegistry.REGISTRY_PATH",
            tmp_path / "registry.json",
        )
        trash_dir = tmp_path / "trash"
        monkeypatch.setattr("sentinel.lifecycle.uninstaller.TRASH_DIR", trash_dir)

        skills_dir = tmp_path / "skills"
        config = _make_config(tmp_path, skills_dir)
        tarball = _make_skill_tarball(tmp_path, "removable")

        runner.invoke(app, ["skills", "install", str(tarball), "--config", str(config)])
        result = runner.invoke(app, ["skills", "uninstall", "removable", "--config", str(config)])
        assert result.exit_code == 0
        assert "Uninstalled" in result.output

    def test_skills_health(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "sentinel.lifecycle.registry.SkillRegistry.REGISTRY_PATH",
            tmp_path / "registry.json",
        )
        skills_dir = tmp_path / "skills"
        config = _make_config(tmp_path, skills_dir)
        tarball = _make_skill_tarball(tmp_path, "healthable")

        runner.invoke(app, ["skills", "install", str(tarball), "--config", str(config)])
        result = runner.invoke(app, ["skills", "health", "healthable", "--config", str(config)])
        assert result.exit_code == 0
        assert "healthable" in result.output
