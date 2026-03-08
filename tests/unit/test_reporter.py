"""Unit tests for compliance reporter — renderer and delta."""

import json

import pytest

from sentinel.models.finding import Finding
from sentinel.reporter.delta import compute_delta, load_findings_from_jsonl
from sentinel.reporter.renderer import render_json, render_markdown


def _finding(**kwargs) -> Finding:
    defaults = dict(
        check_id="CONF-01",
        domain="config",
        title="Test Finding",
        description="desc",
        severity="HIGH",
        result="FAIL",
        evidence="key=val",
        location="openclaw.json",
        remediation="fix it",
        run_id="run-abc",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ── render_markdown ──────────────────────────────────────────────────────────


@pytest.mark.unit
class TestRenderMarkdown:
    def test_contains_header(self):
        md = render_markdown([], "run-001")
        assert "ClawAudit Sentinel" in md

    def test_contains_run_id(self):
        md = render_markdown([], "run-xyz-123")
        assert "run-xyz-123" in md

    def test_contains_finding_check_id(self):
        md = render_markdown([_finding(check_id="CONF-03")], "r")
        assert "CONF-03" in md

    def test_contains_finding_title(self):
        md = render_markdown([_finding(title="Gateway exposed")], "r")
        assert "Gateway exposed" in md

    def test_contains_finding_severity(self):
        md = render_markdown([_finding(severity="CRITICAL")], "r")
        assert "CRITICAL" in md

    def test_severity_sort_critical_before_low(self):
        findings = [
            _finding(severity="LOW", check_id="CONF-04"),
            _finding(severity="CRITICAL", check_id="CONF-01"),
        ]
        md = render_markdown(findings, "r")
        assert md.index("CONF-01") < md.index("CONF-04")

    def test_empty_findings_does_not_raise(self):
        md = render_markdown([], "r")
        assert isinstance(md, str)

    def test_summary_table_included(self):
        md = render_markdown([_finding(result="FAIL")], "r")
        assert "FAIL" in md

    def test_remediation_included(self):
        md = render_markdown([_finding(remediation="Run fix-it")], "r")
        assert "Run fix-it" in md

    def test_multiple_findings_all_appear(self):
        findings = [_finding(check_id=f"C-{i}") for i in range(5)]
        md = render_markdown(findings, "r")
        for i in range(5):
            assert f"C-{i}" in md


# ── render_json ──────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestRenderJson:
    def test_returns_valid_json(self):
        result = render_json([], "run-001")
        data = json.loads(result)  # raises on invalid JSON
        assert isinstance(data, dict)

    def test_contains_run_id(self):
        data = json.loads(render_json([], "run-abc"))
        assert data["run_id"] == "run-abc"

    def test_contains_total_count(self):
        data = json.loads(render_json([_finding(), _finding()], "r"))
        assert data["total"] == 2

    def test_findings_array_present(self):
        data = json.loads(render_json([_finding(check_id="C1")], "r"))
        assert len(data["findings"]) == 1
        assert data["findings"][0]["check_id"] == "C1"

    def test_generated_at_present(self):
        data = json.loads(render_json([], "r"))
        assert "generated_at" in data

    def test_finding_has_required_fields(self):
        data = json.loads(render_json([_finding()], "r"))
        f = data["findings"][0]
        for key in ("id", "check_id", "domain", "severity", "result", "evidence"):
            assert key in f

    def test_empty_findings(self):
        data = json.loads(render_json([], "r"))
        assert data["findings"] == []
        assert data["total"] == 0


# ── compute_delta ─────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestComputeDelta:
    def test_all_new_when_no_previous(self):
        current = [
            _finding(result="FAIL", check_id="A", location="l"),
            _finding(result="FAIL", check_id="B", location="l"),
        ]
        new, resolved = compute_delta([], current)
        assert len(new) == 2
        assert resolved == []

    def test_same_findings_no_delta(self):
        f = _finding(result="FAIL", check_id="A", location="l")
        new, resolved = compute_delta([f], [f])
        assert new == []
        assert len(resolved) == 0

    def test_resolved_when_removed(self):
        prev = [_finding(result="FAIL", check_id="A", location="l")]
        new, resolved = compute_delta(prev, [])
        assert new == []
        assert len(resolved) == 1
        assert resolved[0].check_id == "A"

    def test_new_finding_detected(self):
        prev = [_finding(result="FAIL", check_id="A", location="l")]
        curr = [
            _finding(result="FAIL", check_id="A", location="l"),
            _finding(result="FAIL", check_id="B", location="l"),
        ]
        new, resolved = compute_delta(prev, curr)
        assert len(new) == 1
        assert new[0].check_id == "B"

    def test_pass_findings_ignored_in_delta(self):
        prev = [_finding(result="PASS", check_id="A", location="l")]
        curr = [_finding(result="PASS", check_id="A", location="l")]
        new, resolved = compute_delta(prev, curr)
        assert new == []
        assert resolved == []

    def test_key_includes_location(self):
        # Same check_id but different location = different finding
        prev = [_finding(result="FAIL", check_id="A", location="loc1")]
        curr = [_finding(result="FAIL", check_id="A", location="loc2")]
        new, resolved = compute_delta(prev, curr)
        assert len(new) == 1
        assert len(resolved) == 1


# ── load_findings_from_jsonl ──────────────────────────────────────────────────


@pytest.mark.unit
class TestLoadFindingsFromJsonl:
    def test_nonexistent_path_returns_empty(self, tmp_path):
        result = load_findings_from_jsonl(tmp_path / "missing.jsonl")
        assert result == []

    def test_loads_single_finding(self, tmp_path):
        p = tmp_path / "findings.jsonl"
        f = _finding()
        p.write_text(json.dumps(f.to_dict()) + "\n")
        loaded = load_findings_from_jsonl(p)
        assert len(loaded) == 1
        assert loaded[0].check_id == f.check_id

    def test_loads_multiple_findings(self, tmp_path):
        p = tmp_path / "findings.jsonl"
        lines = [json.dumps(_finding(check_id=f"C-{i}").to_dict()) for i in range(5)]
        p.write_text("\n".join(lines) + "\n")
        loaded = load_findings_from_jsonl(p)
        assert len(loaded) == 5

    def test_skips_blank_lines(self, tmp_path):
        p = tmp_path / "findings.jsonl"
        p.write_text(json.dumps(_finding().to_dict()) + "\n\n\n")
        assert len(load_findings_from_jsonl(p)) == 1

    def test_skips_malformed_json_lines(self, tmp_path):
        p = tmp_path / "findings.jsonl"
        good = json.dumps(_finding(check_id="GOOD").to_dict())
        p.write_text("NOT_JSON\n" + good + "\n{broken:\n")
        loaded = load_findings_from_jsonl(p)
        assert len(loaded) == 1
        assert loaded[0].check_id == "GOOD"

    def test_preserves_severity(self, tmp_path):
        p = tmp_path / "findings.jsonl"
        p.write_text(json.dumps(_finding(severity="CRITICAL").to_dict()) + "\n")
        assert load_findings_from_jsonl(p)[0].severity == "CRITICAL"

    def test_roundtrip_via_render_json(self, tmp_path):
        findings = [_finding(check_id=f"C-{i}", severity="HIGH") for i in range(3)]
        p = tmp_path / "findings.jsonl"
        p.write_text("\n".join(json.dumps(f.to_dict()) for f in findings))
        loaded = load_findings_from_jsonl(p)
        assert len(loaded) == 3
        assert {f.check_id for f in loaded} == {"C-0", "C-1", "C-2"}
