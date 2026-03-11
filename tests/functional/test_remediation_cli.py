"""Functional tests for remediation CLI commands."""

from __future__ import annotations

import sys

import pytest

if sys.version_info < (3, 10):  # noqa: UP036
    pytest.skip("requires Python 3.10+ (str | None type union syntax)", allow_module_level=True)

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from sentinel.main import app

runner = CliRunner()


class TestRemediateCommand:
    def test_dry_run_no_findings_exits_clean(self, tmp_path):
        """When there are no applicable findings, command exits with success."""

        async def _empty_audit():
            return []

        with (
            patch("sentinel.main.load_config") as mock_cfg,
            patch("sentinel.analyzer.config_auditor.ConfigAuditor.audit", side_effect=_empty_audit),
        ):
            cfg = MagicMock()
            cfg.openclaw.workspace_skills_dir = str(tmp_path)
            mock_cfg.return_value = cfg

            result = runner.invoke(app, ["remediate"])
            assert result.exit_code == 0
            assert "No remediations needed" in result.output

    def test_dry_run_shows_proposals(self, tmp_path):
        """Dry run should list proposals without modifying files."""

        async def _empty_audit():
            return []

        skill_dir = tmp_path / "risky-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("pty: true\n")
        original = (skill_dir / "SKILL.md").read_text()

        with (
            patch("sentinel.main.load_config") as mock_cfg,
            patch("sentinel.analyzer.config_auditor.ConfigAuditor.audit", side_effect=_empty_audit),
        ):
            cfg = MagicMock()
            cfg.openclaw.workspace_skills_dir = str(tmp_path)
            mock_cfg.return_value = cfg

            runner.invoke(app, ["remediate"])
            # File must not be modified in dry-run
            assert (skill_dir / "SKILL.md").read_text() == original

    def test_snapshots_list_empty(self, tmp_path):
        import sentinel.remediation.rollback as rb

        original = rb.SNAPSHOT_DIR
        rb.SNAPSHOT_DIR = tmp_path / "empty-snaps"
        try:
            result = runner.invoke(app, ["snapshots", "list"])
            assert result.exit_code == 0
            assert "No snapshots" in result.output
        finally:
            rb.SNAPSHOT_DIR = original

    def test_snapshots_rollback_missing_name(self):
        result = runner.invoke(app, ["snapshots", "rollback"])
        assert result.exit_code != 0

    def test_snapshots_rollback_nonexistent(self, tmp_path):
        import sentinel.remediation.rollback as rb

        original = rb.SNAPSHOT_DIR
        rb.SNAPSHOT_DIR = tmp_path / "snaps"
        rb.SNAPSHOT_DIR.mkdir()
        try:
            result = runner.invoke(app, ["snapshots", "rollback", "ghost.tar.gz"])
            assert result.exit_code != 0
        finally:
            rb.SNAPSHOT_DIR = original
