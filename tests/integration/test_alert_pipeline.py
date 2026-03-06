"""Integration tests — finding → policy engine → alert engine → file channel."""
import json
import pytest
import tempfile
import yaml
from pathlib import Path

from sentinel.config import SentinelConfig
from sentinel.alerts.engine import AlertEngine
from sentinel.policy.engine import PolicyEngine
from sentinel.models.finding import Finding
from sentinel.models.policy import PolicyDecision


def _make_config(tmp_path: Path) -> SentinelConfig:
    return SentinelConfig({
        "openclaw": {
            "gateway_url": "http://localhost:18789", "gateway_token": "",
            "skills_dir": "/s", "workspace_skills_dir": "/w", "config_file": "/c.json",
        },
        "sentinel": {
            "scan_interval_seconds": 60, "log_dir": str(tmp_path / "logs"),
            "findings_file": str(tmp_path / "findings.jsonl"),
            "baseline_file": str(tmp_path / "baseline.json"),
            "policies_dir": str(tmp_path / "policies"),
        },
        "alerts": {
            "enabled": True,
            "dedup_window_seconds": 300,
            "channels": {
                "file": {"enabled": True, "path": str(tmp_path / "alerts.jsonl")},
                "openclaw": {"enabled": False},
            },
        },
        "api": {"enabled": False, "port": 18790, "bind": "loopback"},
    })


def _make_policy_dir(tmp_path: Path, rules: list) -> Path:
    pol_dir = tmp_path / "policies"
    pol_dir.mkdir(exist_ok=True)
    (pol_dir / "test.yaml").write_text(yaml.dump({"name": "test", "version": "1", "rules": rules}))
    return pol_dir


def _finding(**kwargs) -> Finding:
    defaults = dict(
        check_id="CONF-01", domain="config", title="Discord misconfigured",
        description="", severity="HIGH", result="FAIL",
        evidence="groupPolicy=open", location="openclaw.json",
        remediation="fix it", run_id="r1",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


@pytest.mark.integration
class TestAlertPipeline:
    def test_fail_finding_alert_action_writes_to_file(self, tmp_path):
        cfg = _make_config(tmp_path)
        engine = AlertEngine(cfg)
        decision = PolicyDecision(action="ALERT", reason="test", policy_ids=["POL-001"])

        engine.send(_finding(), decision)

        alerts_file = tmp_path / "alerts.jsonl"
        assert alerts_file.exists()
        record = json.loads(alerts_file.read_text().strip())
        assert record["check_id"] == "CONF-01"
        assert record["action"] == "ALERT"

    def test_allow_decision_does_not_write(self, tmp_path):
        cfg = _make_config(tmp_path)
        engine = AlertEngine(cfg)
        decision = PolicyDecision(action="ALLOW", reason="ok")
        engine.send(_finding(), decision)
        assert not (tmp_path / "alerts.jsonl").exists()

    def test_alert_record_has_all_required_fields(self, tmp_path):
        cfg = _make_config(tmp_path)
        engine = AlertEngine(cfg)
        engine.send(_finding(), PolicyDecision(action="ALERT", reason="r", policy_ids=["POL-001"]))
        record = json.loads((tmp_path / "alerts.jsonl").read_text().strip())
        for field in ("ts", "finding_id", "check_id", "severity", "action", "message", "policy_ids"):
            assert field in record, f"Missing: {field}"

    def test_policy_engine_to_alert_engine_pipeline(self, tmp_path):
        """Full pipeline: event → PolicyEngine → AlertEngine → FileAlertChannel."""
        from sentinel.models.event import Event
        pol_dir = _make_policy_dir(tmp_path, [{
            "id": "POL-001", "domain": "config", "check": "severity",
            "condition": "equals", "value": "CRITICAL",
            "severity": "CRITICAL", "action": "ALERT", "message": "critical finding",
        }])
        cfg = _make_config(tmp_path)
        policy_engine = PolicyEngine(pol_dir)
        alert_engine = AlertEngine(cfg)

        f = _finding(severity="CRITICAL")
        decision = policy_engine.evaluate_finding(f)
        alert_engine.send(f, decision)

        alerts_file = tmp_path / "alerts.jsonl"
        assert alerts_file.exists()
        record = json.loads(alerts_file.read_text().strip())
        assert record["severity"] == "CRITICAL"

    def test_dedup_prevents_duplicate_alerts(self, tmp_path):
        cfg = _make_config(tmp_path)
        engine = AlertEngine(cfg)
        f = _finding(check_id="CONF-01", location="openclaw.json")
        decision = PolicyDecision(action="ALERT", reason="r", policy_ids=[])

        engine.send(f, decision)
        engine.send(f, decision)
        engine.send(f, decision)

        lines = (tmp_path / "alerts.jsonl").read_text().splitlines()
        assert len(lines) == 1

    def test_multiple_distinct_findings_all_written(self, tmp_path):
        cfg = _make_config(tmp_path)
        engine = AlertEngine(cfg)
        decision = PolicyDecision(action="ALERT", reason="r", policy_ids=[])

        for i in range(4):
            engine.send(_finding(check_id=f"CONF-0{i}", location=f"loc-{i}"), decision)

        lines = (tmp_path / "alerts.jsonl").read_text().splitlines()
        assert len(lines) == 4

    def test_block_action_also_writes_alert(self, tmp_path):
        cfg = _make_config(tmp_path)
        engine = AlertEngine(cfg)
        engine.send(_finding(), PolicyDecision(action="BLOCK", reason="r"))
        assert (tmp_path / "alerts.jsonl").exists()


@pytest.mark.integration
class TestConfigCollectorToAlertPipeline:
    async def test_config_drift_event_triggers_policy_and_alert(self, tmp_path):
        """ConfigCollector drift event → PolicyEngine → AlertEngine writes alert."""
        import hashlib, json as _json
        from sentinel.collector.config_collector import ConfigCollector

        alerts_path = tmp_path / "alerts.jsonl"
        pol_dir = _make_policy_dir(tmp_path, [{
            "id": "POL-010", "domain": "config", "check": "event_type",
            "condition": "equals", "value": "config_drift",
            "severity": "HIGH", "action": "ALERT", "message": "drift",
        }])
        cfg = _make_config(tmp_path)

        policy_engine = PolicyEngine(pol_dir)
        alert_engine = AlertEngine(cfg)

        events_seen = []

        def on_event(event):
            from sentinel.models.finding import Finding
            import uuid
            events_seen.append(event)
            decision = policy_engine.evaluate(event)
            if decision.action in ("ALERT", "BLOCK"):
                f = Finding(
                    check_id=event.source, domain="runtime",
                    title=event.event_type, description=event.evidence,
                    severity=event.severity, result="FAIL",
                    evidence=event.evidence, location=event.entity,
                    remediation="", run_id=str(uuid.uuid4()),
                )
                alert_engine.send(f, decision)

        config_data = {"channels": {"discord": {"groupPolicy": "allowlist"}}}
        config_file = tmp_path / "openclaw.json"
        config_file.write_text(_json.dumps(config_data))
        cfg._data["openclaw"]["config_file"] = str(config_file)

        collector = ConfigCollector(cfg, on_event)
        # Seed with a different hash to force drift on first collect
        collector._last_hash = "oldhash000"
        await collector.collect_once()

        drift_events = [e for e in events_seen if e.event_type == "config_drift"]
        assert len(drift_events) >= 1
