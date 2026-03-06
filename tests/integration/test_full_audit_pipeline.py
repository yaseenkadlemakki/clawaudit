from __future__ import annotations
"""Integration tests — full audit pipeline: config + skills → reporter → renderer."""
from __future__ import annotations
import json
import pytest
import tempfile
from pathlib import Path

from sentinel.config import SentinelConfig
from sentinel.analyzer.config_auditor import ConfigAuditor
from sentinel.reporter.compliance import ComplianceReporter
from sentinel.reporter.renderer import render_markdown, render_json
from sentinel.reporter.delta import load_findings_from_jsonl, compute_delta


def _make_config(tmp_path: Path, config_data: dict | None = None) -> SentinelConfig:
    config_file = tmp_path / "openclaw.json"
    if config_data is not None:
        config_file.write_text(json.dumps(config_data))
    return SentinelConfig({
        "openclaw": {
            "gateway_url": "http://localhost:18789", "gateway_token": "",
            "skills_dir": str(tmp_path / "skills"),
            "workspace_skills_dir": str(tmp_path / "workspace"),
            "config_file": str(config_file),
        },
        "sentinel": {
            "scan_interval_seconds": 60, "log_dir": str(tmp_path / "logs"),
            "findings_file": str(tmp_path / "findings.jsonl"),
            "baseline_file": str(tmp_path / "baseline.json"),
            "policies_dir": str(tmp_path / "policies"),
        },
        "alerts": {"enabled": False, "dedup_window_seconds": 300, "channels": {}},
        "api": {"enabled": False, "port": 18790, "bind": "loopback"},
    })


@pytest.mark.integration
class TestConfigAuditorPipeline:
    def test_clean_config_produces_no_fail_findings(self):
        auditor = ConfigAuditor()
        config = {
            "channels": {"discord": {"groupPolicy": "allowlist"}},
            "gateway": {"bind": "loopback", "auth": {"mode": "token"}},
        }
        findings = auditor.audit(config, "r1")
        fails = [f for f in findings if f.result == "FAIL"]
        assert fails == []

    def test_yolo_enabled_produces_critical_finding(self):
        auditor = ConfigAuditor()
        findings = auditor.audit({"yolo": True}, "r1")
        fails = [f for f in findings if f.result == "FAIL" and f.check_id == "CONF-06"]
        assert len(fails) == 1
        assert fails[0].severity == "CRITICAL"

    def test_open_gateway_produces_high_finding(self):
        auditor = ConfigAuditor()
        findings = auditor.audit({"gateway": {"bind": "0.0.0.0"}}, "r1")
        fails = [f for f in findings if f.result == "FAIL" and f.check_id == "CONF-03"]
        assert len(fails) == 1
        assert fails[0].severity == "HIGH"

    def test_secret_in_config_produces_critical_finding(self):
        auditor = ConfigAuditor()
        config = {"token": "AKIA1234567890ABCDEF"}
        findings = auditor.audit(config, "r1")
        secret_fails = [f for f in findings if f.check_id == "CONF-05" and f.result == "FAIL"]
        assert len(secret_fails) >= 1

    def test_audit_file_parses_json_config(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"yolo": True}))
        auditor = ConfigAuditor()
        findings = auditor.audit_file(config_file, "r1")
        fails = [f for f in findings if f.result == "FAIL"]
        assert any(f.check_id == "CONF-06" for f in fails)

    def test_audit_file_missing_returns_error_finding(self, tmp_path):
        findings = ConfigAuditor().audit_file(tmp_path / "missing.json", "r1")
        assert any(f.check_id == "CONF-00" for f in findings)

    def test_all_check_ids_present_in_findings(self):
        """CONF-01 always emits a finding; CONF-03/04 only emit on FAIL (non-default config)."""
        auditor = ConfigAuditor()
        # Empty config: CONF-01 always emits PASS, most others are silent (safe defaults)
        findings = auditor.audit({}, "r1")
        check_ids = {f.check_id for f in findings}
        assert "CONF-01" in check_ids

        # Unsafe config triggers CONF-03 and CONF-04
        unsafe = {"gateway": {"bind": "0.0.0.0", "auth": {"mode": "none"}}}
        unsafe_ids = {f.check_id for f in auditor.audit(unsafe, "r2")}
        assert "CONF-03" in unsafe_ids
        assert "CONF-04" in unsafe_ids


@pytest.mark.integration
class TestComplianceReporterPipeline:
    def test_reporter_with_no_config_file_returns_findings_list(self, tmp_path):
        cfg = _make_config(tmp_path)  # no config_file written
        reporter = ComplianceReporter(cfg)
        run_id, findings = reporter.run_full_audit()
        assert isinstance(run_id, str)
        assert isinstance(findings, list)

    def test_reporter_with_yolo_config_returns_fail_finding(self, tmp_path):
        cfg = _make_config(tmp_path, config_data={"yolo": True})
        reporter = ComplianceReporter(cfg)
        _, findings = reporter.run_full_audit()
        assert any(f.result == "FAIL" and f.check_id == "CONF-06" for f in findings)

    def test_generate_markdown_returns_string(self, tmp_path):
        cfg = _make_config(tmp_path, config_data={})
        reporter = ComplianceReporter(cfg)
        content = reporter.generate(format="markdown")
        assert "ClawAudit Sentinel" in content

    def test_generate_json_returns_valid_json(self, tmp_path):
        cfg = _make_config(tmp_path, config_data={})
        reporter = ComplianceReporter(cfg)
        content = reporter.generate(format="json")
        data = json.loads(content)
        assert "findings" in data

    def test_generate_saves_to_file(self, tmp_path):
        cfg = _make_config(tmp_path, config_data={})
        reporter = ComplianceReporter(cfg)
        out = tmp_path / "report.md"
        reporter.generate(format="markdown", output=out)
        assert out.exists()
        assert "ClawAudit Sentinel" in out.read_text()

    def test_skills_dir_scanned_when_exists(self, tmp_path):
        """Skills in workspace dir are included in audit."""
        skills_dir = tmp_path / "workspace"
        skills_dir.mkdir()
        skill_dir = skills_dir / "evil-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(
            "# evil\n\nexec bash -c $USER_INPUT\n--yolo mode\nAKIA1234567890ABCDEF"
        )
        cfg = _make_config(tmp_path, config_data={})
        reporter = ComplianceReporter(cfg)
        _, findings = reporter.run_full_audit()
        # Should have skill findings
        skill_findings = [f for f in findings if f.domain in ("skills", "secrets")]
        assert len(skill_findings) > 0


@pytest.mark.integration
class TestRenderAndDeltaPipeline:
    def test_render_then_load_roundtrip(self, tmp_path):
        """render_json → write JSONL → load_findings_from_jsonl preserves findings."""
        from sentinel.models.finding import Finding
        import uuid

        findings = [
            Finding(check_id=f"C-{i}", domain="config", title=f"Finding {i}",
                    description="d", severity="HIGH", result="FAIL",
                    evidence="e", location="loc", remediation="r", run_id="run1")
            for i in range(5)
        ]
        jsonl_path = tmp_path / "findings.jsonl"
        jsonl_path.write_text("\n".join(json.dumps(f.to_dict()) for f in findings))

        loaded = load_findings_from_jsonl(jsonl_path)
        assert len(loaded) == 5
        assert {f.check_id for f in loaded} == {f"C-{i}" for i in range(5)}

    def test_delta_detects_new_finding_after_rerun(self, tmp_path):
        from sentinel.models.finding import Finding

        def make_f(check_id, location="loc"):
            return Finding(check_id=check_id, domain="config", title="t",
                           description="", severity="HIGH", result="FAIL",
                           evidence="", location=location, remediation="", run_id="r")

        prev = [make_f("A"), make_f("B")]
        curr = [make_f("A"), make_f("B"), make_f("C")]
        new, resolved = compute_delta(prev, curr)
        assert len(new) == 1
        assert new[0].check_id == "C"
        assert resolved == []

    def test_delta_detects_resolved_finding(self, tmp_path):
        from sentinel.models.finding import Finding

        def make_f(check_id):
            return Finding(check_id=check_id, domain="config", title="t",
                           description="", severity="HIGH", result="FAIL",
                           evidence="", location="loc", remediation="", run_id="r")

        prev = [make_f("A"), make_f("B")]
        curr = [make_f("A")]
        new, resolved = compute_delta(prev, curr)
        assert new == []
        assert len(resolved) == 1
        assert resolved[0].check_id == "B"
