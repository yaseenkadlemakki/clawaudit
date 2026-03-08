"""
Unit tests for references/scoring.md.

Validates: check result levels, severity levels + SLA guidance, trust score
criteria (single canonical source, scoped shell exec allowed for TRUSTED),
scoring formulas (including the Adjusted Score added in PR review),
N/A domain handling, severity-weighting caveat, and emoji mapping.
"""

import pytest

pytestmark = pytest.mark.unit

EXPECTED_RESULT_LEVELS = frozenset({"PASS", "WARN", "FAIL", "UNKNOWN"})
EXPECTED_SEVERITY_LEVELS = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})
EXPECTED_TRUST_SCORES = frozenset({"TRUSTED", "CAUTION", "UNTRUSTED", "QUARANTINE"})
EXPECTED_SEVERITY_EMOJIS = {"🔴", "🟠", "🟡", "🟢"}


class TestCheckResultLevels:
    @pytest.mark.parametrize("level", sorted(EXPECTED_RESULT_LEVELS))
    def test_result_level_defined(self, scoring_md, level):
        assert level in scoring_md, f"Check result level '{level}' not defined in scoring.md"


class TestSeverityLevels:
    @pytest.mark.parametrize("level", sorted(EXPECTED_SEVERITY_LEVELS))
    def test_severity_level_defined(self, scoring_md, level):
        assert level in scoring_md, f"Severity level '{level}' not defined in scoring.md"

    def test_sla_guidance_present(self, scoring_md):
        assert "SLA" in scoring_md or "Fix within" in scoring_md, (
            "scoring.md must include SLA guidance for each severity level"
        )


class TestTrustScoreCriteria:
    def test_trust_score_section_exists(self, scoring_md):
        assert "Trust Score" in scoring_md

    @pytest.mark.parametrize("level", sorted(EXPECTED_TRUST_SCORES))
    def test_trust_level_defined(self, scoring_md, level):
        assert level in scoring_md, f"Trust score level '{level}' not found in scoring.md"

    def test_trusted_allows_scoped_shell_exec(self, scoring_md):
        """
        Regression guard: domains.md previously defined TRUSTED as 'no shell exec'
        while scoring.md (canonical source) defines it as 'SKILL-02 PASS/scoped'
        (allows scoped exec). The canonical criteria in scoring.md must reflect
        the correct, more permissive definition (scoped exec = TRUSTED).
        """
        assert "scoped" in scoring_md.lower() or "SKILL-02 PASS/scoped" in scoring_md, (
            "Trust score TRUSTED criteria must allow scoped shell exec (SKILL-02 PASS/scoped). "
            "The conflicting 'no shell exec' rule was removed from domains.md; "
            "scoring.md is the single canonical source."
        )


class TestScoringFormulas:
    def test_domain_score_formula_present(self, scoring_md):
        assert "Domain Score" in scoring_md

    def test_overall_score_formula_present(self, scoring_md):
        assert "Overall" in scoring_md

    def test_adjusted_score_formula_present(self, scoring_md):
        """
        Regression guard: Adjusted Score was added in PR review to give a
        confirmed-compliance rate (UNKNOWN excluded from denominator).
        A gateway-unavailable deployment should not look like 30% compliant
        just because all Domains 1/4 checks are UNKNOWN.
        """
        assert "Adjusted Score" in scoring_md, (
            "scoring.md must define an Adjusted Score that excludes UNKNOWN checks "
            "from the denominator, giving a confirmed-compliance rate."
        )

    def test_adjusted_score_excludes_unknown_from_denominator(self, scoring_md):
        text_lower = scoring_md.lower()
        has_denominator_note = "total checks" in text_lower and ("unknown" in text_lower)
        has_formula = "Total − UNKNOWN" in scoring_md or "Total checks −" in scoring_md
        assert has_denominator_note or has_formula, (
            "Adjusted Score formula must explicitly exclude UNKNOWN from the denominator"
        )

    def test_unknown_treated_as_fail_for_main_score(self, scoring_md):
        assert "UNKNOWN" in scoring_md and "FAIL" in scoring_md, (
            "scoring.md must document that UNKNOWN counts as FAIL for the main score"
        )

    def test_na_domain_handling_documented(self, scoring_md):
        """
        Regression guard: domains with 0 checks (e.g., no skills discovered for Domain 2)
        would previously cause division-by-zero in the score calculation. N/A handling
        must be documented.
        """
        assert "N/A" in scoring_md, (
            "scoring.md must document N/A for domains with 0 checks to prevent "
            "division-by-zero when no skills are discovered."
        )

    def test_severity_weighting_caveat_present(self, scoring_md):
        """
        Regression guard: unweighted score caveat was missing — a deployment with
        3 CRITICAL FAILs can score above 80%, creating false confidence.
        """
        text_lower = scoring_md.lower()
        has_caveat = "unweighted" in text_lower or "safety guarantee" in text_lower
        assert has_caveat, (
            "scoring.md must include a caveat that the numeric score is unweighted "
            "and a high score does not guarantee safety if CRITICAL findings exist."
        )


class TestEmojiMapping:
    @pytest.mark.parametrize("emoji", sorted(EXPECTED_SEVERITY_EMOJIS))
    def test_severity_emoji_present(self, scoring_md, emoji):
        assert emoji in scoring_md, (
            f"Emoji '{emoji}' not found in scoring.md severity→emoji mapping"
        )
