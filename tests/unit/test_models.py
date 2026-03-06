"""Unit tests for sentinel data models (Finding, Event, SkillProfile)."""
import pytest
import uuid
from datetime import datetime

from sentinel.models.finding import Finding
from sentinel.models.event import Event
from sentinel.models.skill import SkillProfile


# ── helpers ─────────────────────────────────────────────────────────────────

def _make_finding(**kwargs) -> Finding:
    defaults = dict(
        check_id="CONF-01",
        domain="config",
        title="Test finding",
        description="desc",
        severity="HIGH",
        result="FAIL",
        evidence="key=value",
        location="openclaw.json",
        remediation="fix it",
        run_id="run-001",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _make_event(**kwargs) -> Event:
    defaults = dict(
        source="test_source",
        event_type="test_event",
        severity="MEDIUM",
        entity="entity-1",
        evidence="evidence text",
        action_taken="ALERT",
    )
    defaults.update(kwargs)
    return Event(**defaults)


# ── Finding ──────────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestFinding:
    def test_auto_generates_uuid_id(self):
        f = _make_finding()
        assert f.id
        uuid.UUID(f.id)  # raises if not valid UUID

    def test_default_detected_at_is_recent(self):
        before = datetime.utcnow()
        f = _make_finding()
        after = datetime.utcnow()
        assert before <= f.detected_at <= after

    def test_resolved_at_defaults_to_none(self):
        assert _make_finding().resolved_at is None

    def test_to_dict_contains_all_required_keys(self):
        d = _make_finding().to_dict()
        for key in ("id", "check_id", "domain", "title", "description",
                    "severity", "result", "evidence", "location",
                    "remediation", "run_id", "detected_at", "resolved_at"):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_resolved_at_none_when_not_set(self):
        assert _make_finding().to_dict()["resolved_at"] is None

    def test_to_dict_resolved_at_isoformat_when_set(self):
        ts = datetime(2025, 1, 15, 12, 0, 0)
        f = _make_finding()
        f.resolved_at = ts
        assert f.to_dict()["resolved_at"] == ts.isoformat()

    def test_to_dict_detected_at_is_isoformat_string(self):
        f = _make_finding()
        d = f.to_dict()
        # Should parse back without error
        datetime.fromisoformat(d["detected_at"])

    def test_custom_id_preserved(self):
        f = _make_finding(id="custom-id-123")
        assert f.id == "custom-id-123"

    def test_each_instance_gets_unique_id(self):
        ids = {_make_finding().id for _ in range(20)}
        assert len(ids) == 20

    def test_severity_values_preserved(self):
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert _make_finding(severity=sev).severity == sev


# ── Event ─────────────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestEvent:
    def test_auto_generates_uuid_id(self):
        e = _make_event()
        uuid.UUID(e.id)

    def test_default_policy_refs_empty(self):
        assert _make_event().policy_refs == []

    def test_to_dict_contains_required_keys(self):
        d = _make_event().to_dict()
        for key in ("id", "ts", "source", "event_type", "severity",
                    "entity", "evidence", "policy_refs", "action_taken"):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_ts_is_isoformat(self):
        d = _make_event().to_dict()
        datetime.fromisoformat(d["ts"])

    def test_policy_refs_preserved(self):
        e = _make_event(policy_refs=["POL-001", "POL-007"])
        assert e.to_dict()["policy_refs"] == ["POL-001", "POL-007"]

    def test_each_instance_unique_id(self):
        ids = {_make_event().id for _ in range(20)}
        assert len(ids) == 20


# ── SkillProfile ──────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestSkillProfile:
    def test_defaults(self):
        p = SkillProfile(name="my-skill", path="/skills/my-skill/SKILL.md")
        assert p.trust_score == "TRUSTED"
        assert p.trust_score_value == 100
        assert p.shell_access is False
        assert p.credential_exposure is False
        assert p.injection_risk == "LOW"
        assert p.has_allowed_tools is False
        assert p.is_signed is False
        assert p.findings == []
        assert p.outbound_domains == []

    def test_to_dict_contains_required_keys(self):
        p = SkillProfile(name="s", path="/p")
        d = p.to_dict()
        for key in ("name", "path", "trust_score", "trust_score_value",
                    "shell_access", "injection_risk", "credential_exposure",
                    "has_allowed_tools", "is_signed", "findings",
                    "outbound_domains", "shell_evidence", "injection_evidence"):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_findings_serialized(self):
        p = SkillProfile(name="s", path="/p")
        p.findings = [_make_finding()]
        d = p.to_dict()
        assert len(d["findings"]) == 1
        assert "check_id" in d["findings"][0]
