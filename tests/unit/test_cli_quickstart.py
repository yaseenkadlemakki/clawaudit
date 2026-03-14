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
        assert mock_watch.called, "monitor command must delegate to watch()"
        assert result.exit_code in (0, 1), f"unexpected exit code: {result.exit_code}"


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


# ── additional coverage ─────────────────────────────────────────────────────


def test_findings_handles_corrupt_jsonl(tmp_path: Path) -> None:
    """Corrupt JSONL lines are skipped gracefully."""
    findings_file = tmp_path / "findings.jsonl"
    findings_file.write_text(
        '{"check_id":"X","severity":"HIGH","title":"t","location":"l","run_id":"abc"}\n'
        "not valid json at all\n"
        '{"check_id":"Y","severity":"LOW","title":"t2","location":"l2","run_id":"abc"}\n'
    )

    with patch("sentinel.main.load_config") as mock_cfg:
        mock_cfg_instance = MagicMock()
        mock_cfg_instance.findings_file = findings_file
        mock_cfg.return_value = mock_cfg_instance

        result = runner.invoke(app, ["findings"])
        assert result.exit_code == 0
        assert "X" in result.output
        assert "Y" in result.output


@patch("sentinel.main.Path.home")
def test_find_openclaw_walks_up_to_install_root(
    mock_home: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_find_openclaw() finds root dir named 'openclaw' with package.json, not bin dir."""
    # Point home to tmp_path so NVM check doesn't find real dirs
    mock_home.return_value = tmp_path / "fakehome"

    # simulate /fake/openclaw/bin/openclaw binary
    openclaw_root = tmp_path / "openclaw"
    openclaw_root.mkdir()
    (openclaw_root / "package.json").write_text('{"name":"openclaw"}')
    bin_dir = openclaw_root / "bin"
    bin_dir.mkdir()
    fake_bin = bin_dir / "openclaw"
    fake_bin.touch()

    monkeypatch.setattr("shutil.which", lambda _: str(fake_bin))
    # Clear OPENCLAW_PATH so it doesn't short-circuit
    monkeypatch.delenv("OPENCLAW_PATH", raising=False)

    import sentinel.main as main_mod

    # Temporarily replace the well-known paths with non-existent ones
    original_fn = main_mod._find_openclaw.__wrapped__ if hasattr(main_mod._find_openclaw, '__wrapped__') else None
    # Patch well-known paths to empty list by redefining the function scope isn't feasible,
    # so instead we use a different approach: patch Path.exists for well-known paths
    _original_exists = Path.exists

    well_known_strs = {
        "/opt/homebrew/lib/node_modules/openclaw",
        "/usr/local/lib/node_modules/openclaw",
        "/usr/lib/node_modules/openclaw",
    }

    def _patched_exists(self: Path) -> bool:
        if str(self) in well_known_strs:
            return False
        return _original_exists(self)

    monkeypatch.setattr(Path, "exists", _patched_exists)

    from sentinel.main import _find_openclaw

    result = _find_openclaw()
    assert result == openclaw_root


def test_version_shows_unknown_when_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    """version command shows 'unknown' when package metadata is missing."""
    from importlib.metadata import PackageNotFoundError

    def _raise(_name: str) -> None:
        raise PackageNotFoundError(_name)

    monkeypatch.setattr("sentinel.main.pkg_version", _raise)
    result = runner.invoke(app, ["version"])
    assert "unknown" in result.output


@patch("sentinel.main.httpx.get")
@patch("sentinel.main._find_openclaw")
def test_doctor_skip_services(mock_oc: MagicMock, mock_get: MagicMock, tmp_path: Path) -> None:
    """With --skip-services, no HTTP calls are made."""
    mock_oc.return_value = tmp_path / "openclaw"
    result = runner.invoke(app, ["doctor", "--skip-services"])
    mock_get.assert_not_called()
    assert "Python" in result.output
