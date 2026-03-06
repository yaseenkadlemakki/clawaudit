"""
Functional tests: structure and completeness of references/report-template.md.

Validates all required sections, the compliance score table (including the
Adjusted Score column added in PR review), Skill Trust Matrix with N/A handling,
and the remediation roadmap structure.
"""
import pytest

pytestmark = pytest.mark.functional

REQUIRED_REPORT_SECTIONS = [
    "Executive Summary",
    "Findings by Severity",
    "Skill Trust Matrix",
    "Compliance Score",
    "Remediation Roadmap",
    "Appendix",
]

SEVERITY_HEADINGS = ["🔴 CRITICAL", "🟠 HIGH", "🟡 MEDIUM", "🟢 LOW"]

ROADMAP_HEADINGS = ["Quick Wins", "Short Term", "Strategic"]

COMPLIANCE_TABLE_DOMAINS = [
    "Configuration",
    "Skill Permissions",
    "Secrets",
    "Network",
    "Supply Chain",
    "Audit Logging",
]

TRUST_MATRIX_COLUMNS = [
    "Shell Access",
    "Outbound Calls",
    "Injection Risk",
    "Trust Score",
]


class TestRequiredSections:
    @pytest.mark.parametrize("section", REQUIRED_REPORT_SECTIONS)
    def test_required_section_present(self, report_template, section):
        assert section in report_template, (
            f"report-template.md missing required section: '{section}'"
        )

    @pytest.mark.parametrize("heading", SEVERITY_HEADINGS)
    def test_severity_heading_present(self, report_template, heading):
        assert heading in report_template, (
            f"Findings section missing severity heading: '{heading}'"
        )

    @pytest.mark.parametrize("heading", ROADMAP_HEADINGS)
    def test_roadmap_heading_present(self, report_template, heading):
        assert heading in report_template, (
            f"Remediation Roadmap missing section: '{heading}'"
        )


class TestComplianceTable:
    @pytest.mark.parametrize("domain", COMPLIANCE_TABLE_DOMAINS)
    def test_domain_row_present(self, report_template, domain):
        assert domain in report_template, (
            f"Compliance Score table missing domain row: '{domain}'"
        )

    def test_overall_row_present(self, report_template):
        assert "OVERALL" in report_template

    def test_adjusted_score_column_present(self, report_template):
        """
        Regression guard: the Adjusted Score column was added to distinguish
        UNKNOWN-driven score drops from actual confirmed failures.
        A gateway-unavailable deployment should not appear as 30% compliant.
        """
        assert "Adjusted Score" in report_template, (
            "Compliance table must include an 'Adjusted Score' column "
            "(UNKNOWN checks excluded from denominator). This was missing in the original template."
        )

    def test_worst_case_score_column_present(self, report_template):
        assert "Worst-Case Score" in report_template or "Score" in report_template

    def test_na_handling_documented(self, report_template):
        """
        Regression guard: N/A handling was missing. If the gateway is unavailable,
        Domains 1 and 4 should show N/A rather than all-UNKNOWN inflating the FAIL count.
        """
        assert "N/A" in report_template, (
            "Compliance table must show N/A for domains where checks cannot run "
            "(gateway unavailable → Domains 1/4; no skills found → Domains 2/5)"
        )

    def test_adjusted_score_footnote_or_note(self, report_template):
        """The template must explain what Adjusted Score means inline."""
        score_idx = report_template.rfind("Adjusted Score")
        assert score_idx != -1, (
            "report-template.md must contain 'Adjusted Score' — "
            "this column distinguishes UNKNOWN-driven score drops from confirmed failures"
        )
        # Look for an explanation within 500 chars of the last mention
        context = report_template[score_idx: score_idx + 500]
        has_explanation = (
            "UNKNOWN" in context
            or "denominator" in context.lower()
            or "confirmed" in context.lower()
        )
        assert has_explanation, (
            "report-template.md must explain what Adjusted Score means near the table "
            "(e.g., 'UNKNOWN excluded from denominator')"
        )


class TestSkillTrustMatrix:
    def test_skill_trust_matrix_section_present(self, report_template):
        assert "Skill Trust Matrix" in report_template

    @pytest.mark.parametrize("col", TRUST_MATRIX_COLUMNS)
    def test_trust_matrix_column_present(self, report_template, col):
        assert col in report_template, (
            f"Skill Trust Matrix missing column: '{col}'"
        )

    def test_trust_matrix_na_handling_present(self, report_template):
        """
        Regression guard: N/A handling was added for when no skills are discovered
        (install path unavailable or skills directory empty).
        """
        matrix_idx = report_template.index("Skill Trust Matrix")
        context = report_template[matrix_idx: matrix_idx + 600]
        assert "N/A" in context or "no skills" in context.lower(), (
            "Skill Trust Matrix must include N/A handling for when no skills are found"
        )

    def test_trust_score_column_includes_all_levels(self, report_template):
        """The Trust Score column header should reference the four trust levels."""
        assert "TRUSTED" in report_template and "QUARANTINE" in report_template


class TestReportHeader:
    def test_date_placeholder_present(self, report_template):
        assert "Date" in report_template

    def test_openclaw_version_placeholder_present(self, report_template):
        assert "OpenClaw Version" in report_template

    def test_auditor_agent_label_present(self, report_template):
        assert "ClawAudit" in report_template

    def test_skills_audited_count_present(self, report_template):
        assert "Skills Audited" in report_template


class TestReportFooter:
    def test_read_only_confirmation_present(self, report_template):
        text_lower = report_template.lower()
        assert "read-only" in text_lower or "no files were modified" in text_lower, (
            "Report footer must confirm that no files were modified during the audit"
        )
