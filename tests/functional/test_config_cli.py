"""Functional tests for sentinel config CLI commands."""

from __future__ import annotations

import sys

import pytest

if sys.version_info < (3, 10):  # noqa: UP036
    pytest.skip("requires Python 3.10+ (str | None type union syntax)", allow_module_level=True)

from typer.testing import CliRunner

from sentinel.config import SecurityConfig
from sentinel.main import app

pytestmark = pytest.mark.functional

runner = CliRunner()


class TestConfigCli:
    def test_config_init_creates_file(self, tmp_path):
        target = tmp_path / "config.yaml"
        SecurityConfig.write_defaults(path=target)
        assert target.exists()
        content = target.read_text()
        assert "safe_domains:" in content

    def test_config_init_with_force_overwrites(self, tmp_path):
        target = tmp_path / "config.yaml"
        target.write_text("old content")
        SecurityConfig.write_defaults(path=target)
        content = target.read_text()
        assert "safe_domains:" in content
        assert "old content" not in content

    def test_config_show_prints_domains(self):
        result = runner.invoke(app, ["config", "show"])
        assert result.exit_code == 0
        assert "Safe domains" in result.output or "safe_domains" in result.output.lower()
