"""Integration tests for new CLI commands against a real filesystem."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
from typer.testing import CliRunner

from sentinel.main import app

runner = CliRunner()

pytestmark = pytest.mark.integration


class TestQuickstartIntegration:
    """Full quickstart flow against real filesystem."""

    @patch("sentinel.main.ComplianceReporter")
    @patch("sentinel.main.load_config")
    @patch("sentinel.main._find_openclaw")
    def test_quickstart_full_flow_real_fs(
        self,
        mock_oc: MagicMock,
        mock_cfg: MagicMock,
        mock_reporter_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Quickstart runs end-to-end writing findings to a real tmp_path."""
        # Set up a fake OpenClaw directory
        oc_dir = tmp_path / "openclaw"
        skills_dir = oc_dir / "skills"
        skills_dir.mkdir(parents=True)

        # Create some fake skills
        for name in ["skill-a", "skill-b"]:
            sd = skills_dir / name
            sd.mkdir()
            (sd / "SKILL.md").write_text(f"# {name}\nA test skill.")

        mock_oc.return_value = oc_dir

        findings_file = tmp_path / "findings.jsonl"
        mock_cfg_instance = MagicMock()
        mock_cfg_instance.findings_file = findings_file
        mock_cfg.return_value = mock_cfg_instance

        mock_reporter = MagicMock()
        findings_data = []
        for sev, cid, title in [
            ("CRITICAL", "ADV-005", "Credential exposure"),
            ("HIGH", "ADV-001", "Shell execution"),
            ("MEDIUM", "ADV-002", "Unknown publisher"),
            ("LOW", "CONF-01", "Debug mode"),
        ]:
            f = MagicMock()
            f.severity = sev
            f.result = "FAIL" if sev != "LOW" else "PASS"
            f.check_id = cid
            f.title = title
            f.location = f"/skills/{cid.lower()}"
            f.to_dict.return_value = {
                "severity": sev,
                "result": f.result,
                "check_id": cid,
                "title": title,
                "location": f.location,
            }
            findings_data.append(f)

        mock_reporter.run_full_audit.return_value = ("run-integ", findings_data)
        mock_reporter_cls.return_value = mock_reporter

        result = runner.invoke(app, ["quickstart"])
        assert result.exit_code == 0
        assert "Scan Complete" in result.output

        # Verify findings were written to disk
        assert findings_file.exists()
        lines = findings_file.read_text().strip().splitlines()
        assert len(lines) == 4
        for line in lines:
            parsed = json.loads(line)
            assert "check_id" in parsed


class TestFindingsIntegration:
    """Findings reads a real findings.jsonl fixture."""

    @patch("sentinel.main.load_config")
    def test_findings_reads_real_fixture(
        self, mock_cfg: MagicMock, tmp_path: Path
    ) -> None:
        """Findings command correctly reads and displays a fixture file."""
        findings_file = tmp_path / "findings.jsonl"
        records = [
            {
                "severity": "CRITICAL",
                "check_id": "ADV-005",
                "title": "Credential exposure in SKILL.md",
                "location": "/skills/bad-skill",
                "result": "FAIL",
            },
            {
                "severity": "HIGH",
                "check_id": "ADV-001",
                "title": "Unrestricted shell execution",
                "location": "/skills/shell-skill",
                "result": "FAIL",
            },
            {
                "severity": "LOW",
                "check_id": "CONF-01",
                "title": "Debug mode disabled",
                "location": "/config",
                "result": "PASS",
            },
        ]
        findings_file.write_text("\n".join(json.dumps(r) for r in records) + "\n")

        mock_cfg_instance = MagicMock()
        mock_cfg_instance.findings_file = findings_file
        mock_cfg.return_value = mock_cfg_instance

        result = runner.invoke(app, ["findings"])
        assert result.exit_code == 0
        assert "ADV-005" in result.output
        assert "ADV-001" in result.output
        assert "CONF-01" in result.output

    @patch("sentinel.main.load_config")
    def test_findings_limit(self, mock_cfg: MagicMock, tmp_path: Path) -> None:
        """Findings --limit restricts number of results."""
        findings_file = tmp_path / "findings.jsonl"
        records = [
            {
                "severity": "HIGH",
                "check_id": f"CHECK-{i:03d}",
                "title": f"Finding {i}",
                "location": f"/loc/{i}",
            }
            for i in range(10)
        ]
        findings_file.write_text("\n".join(json.dumps(r) for r in records))

        mock_cfg_instance = MagicMock()
        mock_cfg_instance.findings_file = findings_file
        mock_cfg.return_value = mock_cfg_instance

        result = runner.invoke(app, ["findings", "--limit", "3", "--format", "json"])
        parsed = json.loads(result.output)
        assert len(parsed) == 3


class TestDoctorIntegration:
    """Doctor checks real backend connectivity."""

    def test_doctor_checks_backend_connectivity(self) -> None:
        """Doctor reports backend status (skip if not running)."""
        backend_up = False
        try:
            httpx.get("http://localhost:18790/health", timeout=2)
            backend_up = True
        except Exception:
            pass

        result = runner.invoke(app, ["doctor"])
        if backend_up:
            # Should not show error for backend
            assert "18790" in result.output
        else:
            pytest.skip("Backend not running on :18790")
