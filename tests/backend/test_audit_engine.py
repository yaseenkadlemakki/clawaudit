"""Tests for backend.engine.audit_engine — covers previously uncovered lines."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.engine.audit_engine import AuditEngine
from sentinel.models.finding import Finding
from sentinel.models.skill import SkillProfile


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _finding(severity: str = "HIGH") -> Finding:
    return Finding(
        check_id="TEST-01",
        domain="config",
        title="Test Finding",
        description="desc",
        severity=severity,
        result="FAIL",
        location="test",
        evidence="evidence",
        remediation="fix it",
        run_id="run-1",
    )



def _profile(name: str = "test-skill") -> SkillProfile:
    return SkillProfile(name=name, path="/tmp/test-skill/SKILL.md")



# ── load_openclaw_config ───────────────────────────────────────────────────────

class TestLoadOpenclawConfig:
    def test_returns_dict_when_file_exists(self, tmp_path):
        cfg_data = {"gateway": {"port": 18789}}
        cfg_file = tmp_path / "openclaw.json"
        cfg_file.write_text(json.dumps(cfg_data))

        engine = AuditEngine()
        mock_cfg = MagicMock()
        mock_cfg.config_file = cfg_file

        with patch("backend.engine.audit_engine.load_config", return_value=mock_cfg):
            result = engine.load_openclaw_config()

        assert result == cfg_data

    def test_returns_empty_dict_when_file_missing(self, tmp_path):
        engine = AuditEngine()
        mock_cfg = MagicMock()
        mock_cfg.config_file = tmp_path / "nonexistent.json"

        with patch("backend.engine.audit_engine.load_config", return_value=mock_cfg):
            result = engine.load_openclaw_config()

        assert result == {}

    def test_returns_empty_dict_on_parse_error(self, tmp_path):
        bad_file = tmp_path / "openclaw.json"
        bad_file.write_text("not valid json {{{")

        engine = AuditEngine()
        mock_cfg = MagicMock()
        mock_cfg.config_file = bad_file

        with patch("backend.engine.audit_engine.load_config", return_value=mock_cfg):
            result = engine.load_openclaw_config()

        assert result == {}


# ── run_config_audit ──────────────────────────────────────────────────────────

class TestRunConfigAudit:
    def test_returns_findings_from_auditor(self):
        engine = AuditEngine()
        findings = [_finding(), _finding("CRITICAL")]

        with patch.object(engine, "load_openclaw_config", return_value={}):
            with patch.object(engine._config_auditor, "audit", return_value=findings):
                result = engine.run_config_audit("run-1")

        assert result == findings

    def test_empty_findings(self):
        engine = AuditEngine()
        with patch.object(engine, "load_openclaw_config", return_value={}):
            with patch.object(engine._config_auditor, "audit", return_value=[]):
                result = engine.run_config_audit("run-1")
        assert result == []


# ── discover_skills ───────────────────────────────────────────────────────────

class TestDiscoverSkills:
    def test_finds_skill_md_files(self, tmp_path):
        skills_dir = tmp_path / "skills"
        skill_a = skills_dir / "skill-a"
        skill_a.mkdir(parents=True)
        (skill_a / "SKILL.md").write_text("# Skill A")

        engine = AuditEngine()
        mock_cfg = MagicMock()
        mock_cfg.skills_dir = skills_dir
        mock_cfg.workspace_skills_dir = tmp_path / "nonexistent"

        with patch("backend.engine.audit_engine.load_config", return_value=mock_cfg):
            result = engine.discover_skills()

        assert len(result) == 1
        assert result[0].name == "SKILL.md"

    def test_returns_empty_when_no_dirs_exist(self, tmp_path):
        engine = AuditEngine()
        mock_cfg = MagicMock()
        mock_cfg.skills_dir = tmp_path / "nonexistent-a"
        mock_cfg.workspace_skills_dir = tmp_path / "nonexistent-b"

        with patch("backend.engine.audit_engine.load_config", return_value=mock_cfg):
            result = engine.discover_skills()

        assert result == []

    def test_searches_both_dirs(self, tmp_path):
        dir_a = tmp_path / "skills_a"
        dir_b = tmp_path / "skills_b"
        (dir_a / "skill-1").mkdir(parents=True)
        (dir_b / "skill-2").mkdir(parents=True)
        (dir_a / "skill-1" / "SKILL.md").write_text("# S1")
        (dir_b / "skill-2" / "SKILL.md").write_text("# S2")

        engine = AuditEngine()
        mock_cfg = MagicMock()
        mock_cfg.skills_dir = dir_a
        mock_cfg.workspace_skills_dir = dir_b

        with patch("backend.engine.audit_engine.load_config", return_value=mock_cfg):
            result = engine.discover_skills()

        assert len(result) == 2


# ── analyze_skill ─────────────────────────────────────────────────────────────

class TestAnalyzeSkill:
    def test_returns_profile_and_score(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text("# Test Skill")

        profile = _profile()
        engine = AuditEngine()

        with patch.object(engine._skill_analyzer, "analyze", return_value=profile):
            with patch("backend.engine.audit_engine.score_skill", return_value=(35, "MEDIUM")):
                result_profile, score, level = engine.analyze_skill(skill_file, "run-1")

        assert result_profile is profile
        assert score == 35
        assert level == "MEDIUM"


# ── run_full_audit ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestRunFullAudit:
    async def test_runs_config_and_skill_audit(self, tmp_path):
        engine = AuditEngine()
        finding = _finding()
        profile = _profile()
        profile.findings = []

        with patch.object(engine._advanced_detector, "run_all", return_value=[]):
            with patch.object(engine, "run_config_audit", return_value=[finding]):
                with patch.object(engine, "discover_skills", return_value=[tmp_path / "SKILL.md"]):
                    with patch.object(engine, "analyze_skill", return_value=(profile, 40, "HIGH")):
                        findings, skills = await engine.run_full_audit("run-1")

        assert len(findings) == 1
        assert findings[0] is finding
        assert len(skills) == 1

    async def test_callbacks_are_invoked(self, tmp_path):
        engine = AuditEngine()
        finding = _finding()
        profile = _profile()
        profile.findings = []

        on_finding = MagicMock()
        on_skill = MagicMock()
        on_progress = MagicMock()

        skill_path = tmp_path / "SKILL.md"

        with patch.object(engine._advanced_detector, "run_all", return_value=[]):
            with patch.object(engine, "run_config_audit", return_value=[finding]):
                with patch.object(engine, "discover_skills", return_value=[skill_path]):
                    with patch.object(engine, "analyze_skill", return_value=(profile, 20, "LOW")):
                        await engine.run_full_audit(
                            "run-1",
                            on_finding=on_finding,
                            on_skill=on_skill,
                            on_progress=on_progress,
                        )

        on_finding.assert_called_once_with(finding, None)
        on_skill.assert_called_once_with(profile, 20, "LOW")
        on_progress.assert_called_once_with(1, 1, skill_path.parent.name)

    async def test_stop_flag_halts_skill_loop(self, tmp_path):
        engine = AuditEngine()
        profile = _profile()
        profile.findings = []
        skill_paths = [tmp_path / f"skill-{i}" / "SKILL.md" for i in range(5)]

        call_count = 0

        def fake_analyze(p, run_id):
            nonlocal call_count
            call_count += 1
            return profile, 10, "LOW"

        stop_after = 2
        calls = 0

        def stop_flag():
            nonlocal calls
            calls += 1
            return calls > stop_after

        with patch.object(engine, "run_config_audit", return_value=[]):
            with patch.object(engine, "discover_skills", return_value=skill_paths):
                with patch.object(engine, "analyze_skill", side_effect=fake_analyze):
                    await engine.run_full_audit("run-1", stop_flag=stop_flag)

        assert call_count <= stop_after + 1

    async def test_skill_analysis_exception_is_swallowed(self, tmp_path):
        engine = AuditEngine()
        skill_path = tmp_path / "SKILL.md"

        with patch.object(engine, "run_config_audit", return_value=[]):
            with patch.object(engine, "discover_skills", return_value=[skill_path]):
                with patch.object(engine, "analyze_skill", side_effect=RuntimeError("boom")):
                    findings, skills = await engine.run_full_audit("run-1")

        assert findings == []
        assert skills == []

    async def test_skill_findings_are_included_in_results(self, tmp_path):
        engine = AuditEngine()
        profile = _profile()
        skill_finding = _finding("CRITICAL")
        profile.findings = [skill_finding]
        skill_path = tmp_path / "SKILL.md"

        on_finding = MagicMock()

        with patch.object(engine._advanced_detector, "run_all", return_value=[]):
            with patch.object(engine, "run_config_audit", return_value=[]):
                with patch.object(engine, "discover_skills", return_value=[skill_path]):
                    with patch.object(engine, "analyze_skill", return_value=(profile, 80, "CRITICAL")):
                        findings, _ = await engine.run_full_audit("run-1", on_finding=on_finding)

        assert skill_finding in findings
        on_finding.assert_called_once_with(skill_finding, profile.name)
