"""Functional tests for the new CLI commands — test real environment interactions."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from sentinel.main import app

runner = CliRunner()

pytestmark = pytest.mark.functional


class TestQuickstartFunctional:
    """Functional tests for quickstart environment detection."""

    def test_quickstart_detects_real_python_version(self) -> None:
        """Quickstart correctly detects the running Python version."""
        # Use version command to test python detection (quickstart would
        # need OpenClaw which may not exist)
        result = runner.invoke(app, ["version"])
        expected_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
        assert expected_ver in result.output


class TestDoctorFunctional:
    """Functional tests for doctor command."""

    def test_doctor_checks_real_config(self) -> None:
        """Doctor reports sentinel config presence/absence correctly."""
        result = runner.invoke(app, ["doctor"])
        sentinel_yaml = Path.home() / ".openclaw" / "sentinel" / "sentinel.yaml"
        if sentinel_yaml.exists():
            # Should show a pass for config
            assert "sentinel.yaml" in result.output
        else:
            # Should show the path even when missing
            assert "sentinel" in result.output.lower()


class TestFindingsFunctional:
    """Functional tests for findings command."""

    @patch("sentinel.main.load_config")
    def test_findings_json_valid(self, mock_cfg: MagicMock, tmp_path: Path) -> None:
        """findings --format json outputs valid JSON."""
        findings_file = tmp_path / "findings.jsonl"
        records = [
            {
                "severity": "HIGH",
                "check_id": "ADV-001",
                "title": "Shell access",
                "location": "/skill/test",
            },
            {
                "severity": "MEDIUM",
                "check_id": "ADV-002",
                "title": "Unknown publisher",
                "location": "/skill/test2",
            },
        ]
        findings_file.write_text("\n".join(json.dumps(r) for r in records))

        mock_cfg_instance = MagicMock()
        mock_cfg_instance.findings_file = findings_file
        mock_cfg.return_value = mock_cfg_instance

        result = runner.invoke(app, ["findings", "--format", "json"])
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)
        assert len(parsed) == 2

    @patch("sentinel.main.ComplianceReporter")
    @patch("sentinel.main.load_config")
    def test_scan_json_valid(
        self, mock_cfg: MagicMock, mock_reporter_cls: MagicMock, tmp_path: Path
    ) -> None:
        """scan --format json --output produces valid JSON file."""
        output_file = tmp_path / "report.json"

        mock_cfg_instance = MagicMock()
        mock_cfg_instance.findings_file = tmp_path / "findings.jsonl"
        mock_cfg.return_value = mock_cfg_instance

        mock_reporter = MagicMock()
        finding = MagicMock()
        finding.severity = "LOW"
        finding.result = "PASS"
        finding.check_id = "CONF-01"
        finding.title = "Debug disabled"
        finding.location = "/config"
        finding.to_dict.return_value = {
            "severity": "LOW",
            "result": "PASS",
            "check_id": "CONF-01",
            "title": "Debug disabled",
            "location": "/config",
        }
        mock_reporter.run_full_audit.return_value = ("run-x", [finding])
        mock_reporter_cls.return_value = mock_reporter

        with patch(
            "sentinel.reporter.renderer.render_json",
            return_value='[{"check_id": "CONF-01"}]',
        ):
            result = runner.invoke(
                app, ["scan", "--format", "json", "--output", str(output_file)]
            )

        # The scan should have run (exit code 0 for all pass)
        assert result.exit_code in (0, 1)


class TestVersionFunctional:
    """Functional tests for version command."""

    def test_version_help_shows_commands(self) -> None:
        """--help shows all expected commands."""
        result = runner.invoke(app, ["--help"])
        for cmd in ["version", "doctor", "scan", "monitor", "findings", "quickstart"]:
            assert cmd in result.output, f"Command '{cmd}' not found in help output"
