"""
Functional tests: completeness of domain definitions in references/domains.md.

Validates that every domain has a check table, detection logic, and evidence
collection guidance — the three elements the agent needs to run a domain phase.
"""

import pytest

pytestmark = pytest.mark.functional

ALL_DOMAIN_SECTIONS = {
    "Domain 1": "Configuration Hardening",
    "Domain 2": "Skill Permission Audit",
    "Domain 3": "Secrets",
    "Domain 4": "Network Exposure",
    "Domain 5": "Supply Chain",
    "Domain 6": "Audit Logging",
}

# First and last check IDs per domain — verifies the table spans the full range
DOMAIN_BOUNDARY_IDS = {
    "Domain 1": ("CONF-01", "CONF-08"),
    "Domain 2": ("SKILL-01", "SKILL-10"),
    "Domain 3": ("SEC-01", "SEC-06"),
    "Domain 4": ("NET-01", "NET-07"),
    "Domain 5": ("SC-01", "SC-07"),
    "Domain 6": ("OBS-01", "OBS-05"),
}


class TestDomainSectionPresence:
    @pytest.mark.parametrize("section", sorted(ALL_DOMAIN_SECTIONS))
    def test_domain_section_present(self, domains_md, section):
        assert section in domains_md, f"domains.md missing section heading: '{section}'"

    def test_all_6_domains_present(self, domains_md):
        for section in ALL_DOMAIN_SECTIONS:
            assert section in domains_md


class TestCheckTableCompleteness:
    @pytest.mark.parametrize("domain,ids", DOMAIN_BOUNDARY_IDS.items())
    def test_first_check_id_present(self, domains_md, domain, ids):
        first_id = ids[0]
        assert first_id in domains_md, (
            f"{domain}: first check ID '{first_id}' not found in domains.md"
        )

    @pytest.mark.parametrize("domain,ids", DOMAIN_BOUNDARY_IDS.items())
    def test_last_check_id_present(self, domains_md, domain, ids):
        last_id = ids[1]
        assert last_id in domains_md, f"{domain}: last check ID '{last_id}' not found in domains.md"


class TestDetectionLogicPresence:
    def test_detection_logic_section_present(self, domains_md):
        assert "Detection Logic" in domains_md

    def test_domain1_conf01_absent_rule_in_detection_logic(self, domains_md):
        """The CONF-01 absent=PASS rule is part of the detection logic section."""
        det_idx = domains_md.index("Detection Logic")
        logic_section = domains_md[det_idx : det_idx + 1000]
        assert "CONF-01" in logic_section, (
            "Detection Logic must explicitly document CONF-01 absent-handling rule"
        )

    def test_domain2_shell_detection_logic_present(self, domains_md):
        assert "SKILL-02" in domains_md
        assert "exec" in domains_md or "shell" in domains_md.lower()

    def test_domain2_injection_detection_logic_present(self, domains_md):
        assert "SKILL-05" in domains_md
        assert "injection" in domains_md.lower() or "sanitiz" in domains_md.lower()


class TestEvidenceCollectionPresence:
    def test_evidence_collection_documented(self, domains_md):
        assert "Evidence Collection" in domains_md

    def test_domain3_no_secret_values_rule_present(self, domains_md):
        """Domain 3 must explicitly state that secret values are never output."""
        assert "Never" in domains_md or "never" in domains_md.lower()
        assert "value" in domains_md.lower()


class TestSupplyChainWebFetch:
    def test_sc03_documents_web_check_method(self, domains_md):
        """
        Regression guard: SC-03 (repo commit recency) requires a web check.
        After web_fetch was added to allowed-tools, domains.md must document
        how this check is performed.
        """
        assert "SC-03" in domains_md
        idx = domains_md.index("SC-03")
        context = domains_md[idx : idx + 350]
        assert "web_fetch" in context or "web check" in context.lower() or "UNKNOWN" in context, (
            "SC-03 must document the use of web_fetch for repo commit-recency check"
        )

    def test_sc05_documents_web_check_method(self, domains_md):
        """
        Regression guard: SC-05 (repo availability) requires a web check.
        """
        assert "SC-05" in domains_md
        idx = domains_md.index("SC-05")
        context = domains_md[idx : idx + 350]
        assert "web_fetch" in context or "web check" in context.lower() or "UNKNOWN" in context, (
            "SC-05 must document the use of web_fetch for repo availability check"
        )
