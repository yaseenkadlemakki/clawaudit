"""Tests for the risk scoring engine."""

from __future__ import annotations

from unittest.mock import MagicMock

from backend.engine.risk_scoring import RISK_FACTORS, score_skill


def make_profile(**kwargs):
    """Create a minimal mock SkillProfile."""
    p = MagicMock()
    p.shell_access = kwargs.get("shell_access", False)
    p.shell_evidence = kwargs.get("shell_evidence", [])
    p.outbound_domains = kwargs.get("outbound_domains", [])
    p.author = kwargs.get("author", "test-author")
    p.is_signed = kwargs.get("is_signed", True)
    p.injection_risk = kwargs.get("injection_risk", "LOW")
    p.injection_evidence = kwargs.get("injection_evidence", [])
    p.credential_exposure = kwargs.get("credential_exposure", False)
    p.has_allowed_tools = kwargs.get("has_allowed_tools", True)
    return p


def test_clean_skill_scores_zero():
    p = make_profile()
    score, level = score_skill(p)
    assert score == 0
    assert level == "Low"


def test_shell_access_adds_points():
    p = make_profile(shell_access=True)
    score, _ = score_skill(p)
    assert score >= RISK_FACTORS["shell_execution"]


def test_network_outbound_adds_points():
    p = make_profile(outbound_domains=["api.example.com"])
    score, _ = score_skill(p)
    assert score >= RISK_FACTORS["network_outbound"]


def test_no_author_adds_points():
    p = make_profile(author="")
    score, _ = score_skill(p)
    assert score >= RISK_FACTORS["unknown_publisher"] + RISK_FACTORS["no_author"]


def test_unsigned_skill_adds_points():
    p = make_profile(is_signed=False)
    score, _ = score_skill(p)
    assert score >= RISK_FACTORS["unsigned_skill"]


def test_injection_high_adds_points():
    p = make_profile(injection_risk="HIGH")
    score, _ = score_skill(p)
    assert score >= RISK_FACTORS["injection_risk_high"]


def test_injection_medium_adds_points():
    p = make_profile(injection_risk="MEDIUM")
    score, _ = score_skill(p)
    assert score >= RISK_FACTORS["injection_risk_medium"]


def test_credential_exposure_adds_points():
    p = make_profile(credential_exposure=True)
    score, _ = score_skill(p)
    assert score >= RISK_FACTORS["credential_access"]


def test_dangerous_commands_adds_points():
    p = make_profile(shell_evidence=["rm -rf /tmp"], injection_evidence=[])
    score, _ = score_skill(p)
    assert score >= RISK_FACTORS["dangerous_commands"]


def test_no_allowed_tools_adds_points():
    p = make_profile(has_allowed_tools=False)
    score, _ = score_skill(p)
    assert score >= RISK_FACTORS["no_allowed_tools"]


def test_score_capped_at_100():
    p = make_profile(
        shell_access=True,
        shell_evidence=["eval code", "rm -rf /"],
        outbound_domains=["a.com", "b.com"],
        author="",
        is_signed=False,
        injection_risk="HIGH",
        injection_evidence=["user input in shell"],
        credential_exposure=True,
        has_allowed_tools=False,
    )
    score, level = score_skill(p)
    assert score == 100
    assert level == "Critical"


def test_risk_levels():
    assert score_skill(make_profile())[1] == "Low"  # 0
    p_medium = make_profile(is_signed=False, has_allowed_tools=False)
    _, level = score_skill(p_medium)
    # 10 + 10 = 20 → still Low boundary; add network
    p_medium2 = make_profile(is_signed=False, has_allowed_tools=False, outbound_domains=["x.com"])
    score2, level2 = score_skill(p_medium2)
    assert score2 > 20  # should be Medium+
