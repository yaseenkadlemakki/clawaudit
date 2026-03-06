"""Tests for the skill analyzer."""
import pytest
from pathlib import Path
import tempfile
import os

from sentinel.analyzer.skill_analyzer import SkillAnalyzer


@pytest.fixture
def analyzer():
    return SkillAnalyzer()


def _write_skill(content: str) -> Path:
    """Write a temp SKILL.md file and return path."""
    d = tempfile.mkdtemp()
    skill_dir = Path(d) / "test-skill"
    skill_dir.mkdir()
    p = skill_dir / "SKILL.md"
    p.write_text(content)
    return p


def test_basic_safe_skill(analyzer):
    p = _write_skill("# My Skill\nThis skill searches the web.")
    profile = analyzer.analyze(p)
    assert profile.name == "test-skill"
    assert not profile.shell_access
    assert profile.injection_risk == "LOW"


def test_shell_access_detected(analyzer):
    p = _write_skill("# Shell Skill\nRun: bash -c 'echo hello'\nUse exec to run commands.")
    profile = analyzer.analyze(p)
    assert profile.shell_access is True
    assert len(profile.shell_evidence) > 0


def test_injection_risk_detected(analyzer):
    p = _write_skill("# Risky\nRun: eval $(user_input)\nUse --yolo to override.")
    profile = analyzer.analyze(p)
    assert profile.injection_risk in ("HIGH", "CRITICAL")


def test_trust_score_quarantine_for_dangerous_skill(analyzer):
    p = _write_skill("# Dangerous\neval {user_input}\nbash -c $@\n--yolo everywhere")
    profile = analyzer.analyze(p)
    assert profile.trust_score in ("QUARANTINE", "UNTRUSTED")
    assert profile.trust_score_value < 60


def test_trust_score_high_for_safe_skill(analyzer):
    # Skill with author, allowed-tools, no shell, signed
    p = _write_skill(
        "# Safe Skill\nAuthor: security-team\n"
        "allowed-tools: browser\n"
        "signature: sha256-abc123\n"
        "Searches the web safely.\n"
        "Uses https://api.example.com"
    )
    profile = analyzer.analyze(p)
    assert profile.trust_score in ("TRUSTED", "CAUTION")


def test_credential_exposure_detected(analyzer):
    p = _write_skill("# Exposed\ntoken = sk-ant-api03-" + "X" * 30)
    profile = analyzer.analyze(p)
    assert profile.credential_exposure is True


def test_outbound_domains_extracted(analyzer):
    p = _write_skill("# Domains\nCalls https://api.github.com and https://openai.com/v1")
    profile = analyzer.analyze(p)
    assert len(profile.outbound_domains) >= 1
