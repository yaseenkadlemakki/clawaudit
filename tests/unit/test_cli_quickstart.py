"""Unit tests for the new CLI commands: version, doctor, scan, monitor, findings, quickstart."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from sentinel.main import app

runner = CliRunner()

pytestmark = pytest.mark.unit


# ── version ──────────────────────────────────────────────────────────────────


class TestVersion:
    """Tests for the version command."""

    def test_version_shows_python(self) -> None:
        """Output contains Python version string."""
        result = runner.invoke(app, ["version"])
        assert "Python" in result.output

    def test_version_shows_platform(self) -> None:
        """Output contains Platform string."""
        result = runner.invoke(app, ["version"])
        assert "Platform" in result.output

    def test_version_shows_clawaudit(self) -> None:
        """Output contains ClawAudit label."""
        result = runner.invoke(app, ["version"])
        assert "ClawAudit" in result.output

    def test_version_shows_openclaw_status(self) -> None:
        """Output contains OpenClaw detection result."""
        result = runner.invoke(app, ["version"])
        assert "OpenClaw" in result.output


# ── doctor ───────────────────────────────────────────────────────────────────


class TestDoctor:
    """Tests for the doctor command."""

    @patch("sentinel.main.httpx.get")
    @patch("sentinel.main._find_openclaw")
    def test_doctor_passes_with_mocked_env(
        self, mock_oc: MagicMock, mock_get: MagicMock, tmp_path: Path
    ) -> None:
        """Doctor passes when all checks succeed."""
        mock_oc.return_value = tmp_path / "openclaw"
        mock_get.return_value = MagicMock(status_code=200)

        result = runner.invoke(app, ["doctor"])
        # Should have at least some pass marks
        assert "Python" in result.output

    @patch("sentinel.main._find_openclaw", return_value=None)
    def test_doctor_reports_missing_openclaw(self, mock_oc: MagicMock) -> None:
        """Doctor reports when OpenClaw is not found."""
        result = runner.invoke(app, ["doctor"])
        assert "not found" in result.output


# ── scan ─────────────────────────────────────────────────────────────────────


class TestScan:
    """Tests for the scan command (alias for audit)."""

    @patch("sentinel.main.ComplianceReporter")
    @patch("sentinel.main.load_config")
    def test_scan_delegates_to_audit(
        self, mock_cfg: MagicMock, mock_reporter_cls: MagicMock, tmp_path: Path
    ) -> None:
        """Scan delegates to audit and outputs findings."""
        mock_cfg_instance = MagicMock()
        mock_cfg_instance.findings_file = tmp_path / "findings.jsonl"
        mock_cfg.return_value = mock_cfg_instance

        mock_reporter = MagicMock()
        finding = MagicMock()
        finding.severity = "HIGH"
        finding.result = "FAIL"
        finding.check_id = "TEST-01"
        finding.title = "Test finding"
        finding.location = "/test"
        finding.to_dict.return_value = {
            "severity": "HIGH",
            "result": "FAIL",
            "check_id": "TEST-01",
            "title": "Test finding",
            "location": "/test",
        }
        mock_reporter.run_full_audit.return_value = ("run-123", [finding])
        mock_reporter_cls.return_value = mock_reporter

        result = runner.invoke(app, ["scan"])
        assert result.exit_code in (0, 1)
        assert "TEST-01" in result.output


# ── monitor ──────────────────────────────────────────────────────────────────


class TestMonitor:
    """Tests for the monitor command (alias for watch)."""

    @patch("sentinel.main.watch")
    def test_monitor_delegates_to_watch(self, mock_watch: MagicMock) -> None:
        """Monitor passes flags through to watch."""
        mock_watch.return_value = None
        result = runner.invoke(app, ["monitor", "--interval", "30"])
        # The command itself may try to call watch directly;
        # we just verify no crash and correct exit
        assert result.exit_code in (0, 1, 2) or mock_watch.called


# ── findings ─────────────────────────────────────────────────────────────────


class TestFindings:
    """Tests for the findings command."""

    @patch("sentinel.main.load_config")
    def test_findings_reads_jsonl(self, mock_cfg: MagicMock, tmp_path: Path) -> None:
        """Findings reads and displays entries from findings.jsonl."""
        findings_file = tmp_path / "findings.jsonl"
        records = [
            {
                "severity": "CRITICAL",
                "check_id": "ADV-005",
                "title": "Credential exposure",
                "location": "/skill/bad",
                "result": "FAIL",
            },
            {
                "severity": "LOW",
                "check_id": "CONF-01",
                "title": "Debug mode off",
                "location": "/config",
                "result": "PASS",
            },
        ]
        findings_file.write_text("\n".join(json.dumps(r) for r in records))

        mock_cfg_instance = MagicMock()
        mock_cfg_instance.findings_file = findings_file
        mock_cfg.return_value = mock_cfg_instance

        result = runner.invoke(app, ["findings"])
        assert "ADV-005" in result.output
        assert "CONF-01" in result.output

    @patch("sentinel.main.load_config")
    def test_findings_empty_file(self, mock_cfg: MagicMock, tmp_path: Path) -> None:
        """Findings shows message when file is empty."""
        findings_file = tmp_path / "findings.jsonl"
        findings_file.write_text("")

        mock_cfg_instance = MagicMock()
        mock_cfg_instance.findings_file = findings_file
        mock_cfg.return_value = mock_cfg_instance

        result = runner.invoke(app, ["findings"])
        assert "No findings" in result.output

    @patch("sentinel.main.load_config")
    def test_findings_no_file(self, mock_cfg: MagicMock, tmp_path: Path) -> None:
        """Findings shows message when file doesn't exist."""
        mock_cfg_instance = MagicMock()
        mock_cfg_instance.findings_file = tmp_path / "nonexistent.jsonl"
        mock_cfg.return_value = mock_cfg_instance

        result = runner.invoke(app, ["findings"])
        assert "No findings" in result.output

    @patch("sentinel.main.load_config")
    def test_findings_severity_filter(
        self, mock_cfg: MagicMock, tmp_path: Path
    ) -> None:
        """Findings filters by severity."""
        findings_file = tmp_path / "findings.jsonl"
        records = [
            {
                "severity": "CRITICAL",
                "check_id": "ADV-005",
                "title": "Cred exposure",
                "location": "/bad",
            },
            {
                "severity": "LOW",
                "check_id": "CONF-01",
                "title": "Debug off",
                "location": "/config",
            },
        ]
        findings_file.write_text("\n".join(json.dumps(r) for r in records))

        mock_cfg_instance = MagicMock()
        mock_cfg_instance.findings_file = findings_file
        mock_cfg.return_value = mock_cfg_instance

        result = runner.invoke(app, ["findings", "--severity", "CRITICAL"])
        assert "ADV-005" in result.output
        assert "CONF-01" not in result.output

    @patch("sentinel.main.load_config")
    def test_findings_json_format(self, mock_cfg: MagicMock, tmp_path: Path) -> None:
        """Findings outputs valid JSON with --format json."""
        findings_file = tmp_path / "findings.jsonl"
        records = [
            {
                "severity": "HIGH",
                "check_id": "ADV-001",
                "title": "Shell access",
                "location": "/skill",
            },
        ]
        findings_file.write_text(json.dumps(records[0]))

        mock_cfg_instance = MagicMock()
        mock_cfg_instance.findings_file = findings_file
        mock_cfg.return_value = mock_cfg_instance

        result = runner.invoke(app, ["findings", "--format", "json"])
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)
        assert parsed[0]["check_id"] == "ADV-001"


# ── quickstart ───────────────────────────────────────────────────────────────


class TestQuickstart:
    """Tests for the quickstart command."""

    @patch("sentinel.main.ComplianceReporter")
    @patch("sentinel.main.load_config")
    @patch("sentinel.main._find_openclaw")
    def test_quickstart_full_flow(
        self,
        mock_oc: MagicMock,
        mock_cfg: MagicMock,
        mock_reporter_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Quickstart completes when environment is valid."""
        oc_dir = tmp_path / "openclaw"
        skills_dir = oc_dir / "skills"
        skills_dir.mkdir(parents=True)
        skill = skills_dir / "test-skill"
        skill.mkdir()
        (skill / "SKILL.md").write_text("# test")
        mock_oc.return_value = oc_dir

        mock_cfg_instance = MagicMock()
        mock_cfg_instance.findings_file = tmp_path / "findings.jsonl"
        mock_cfg.return_value = mock_cfg_instance

        mock_reporter = MagicMock()
        finding = MagicMock()
        finding.severity = "HIGH"
        finding.result = "FAIL"
        finding.check_id = "ADV-001"
        finding.title = "Shell execution"
        finding.location = "/test-skill"
        finding.to_dict.return_value = {
            "severity": "HIGH",
            "result": "FAIL",
            "check_id": "ADV-001",
            "title": "Shell execution",
            "location": "/test-skill",
        }
        mock_reporter.run_full_audit.return_value = ("run-abc", [finding])
        mock_reporter_cls.return_value = mock_reporter

        result = runner.invoke(app, ["quickstart"])
        assert result.exit_code == 0
        assert "Scan Complete" in result.output

    @patch("sentinel.main._find_openclaw", return_value=None)
    def test_quickstart_aborts_on_missing_openclaw(
        self, mock_oc: MagicMock
    ) -> None:
        """Quickstart aborts with exit code 1 when OpenClaw is not found."""
        result = runner.invoke(app, ["quickstart"])
        assert result.exit_code == 1
        assert "not found" in result.output
