"""
Functional tests: cross-file consistency.

Validates that check IDs, domain names, and concepts defined in one file
are correctly reflected in all other files that reference them. Catches
drift when a check is added to the registry but not documented in domains.md,
or when a rule is defined in two places with conflicting content.
"""

import re

import pytest

pytestmark = pytest.mark.functional

# Domain sections in domains.md corresponding to YAML domain values
DOMAIN_TO_SECTION = {
    "config": "Domain 1",
    "skills": "Domain 2",
    "secrets": "Domain 3",
    "network": "Domain 4",
    "supply_chain": "Domain 5",
    "observability": "Domain 6",
}


class TestCheckIDsInDomainsMd:
    def test_all_yaml_check_ids_referenced_in_domains_md(self, checks, domains_md):
        """Every check ID in the registry must appear in domains.md so the agent
        has detection guidance for each check it runs."""
        missing = [c["id"] for c in checks if c.get("id") not in domains_md]
        assert not missing, (
            f"Check IDs defined in hardening-rules.yaml but not referenced in domains.md: {missing}"
        )

    def test_domain_sections_exist_for_all_yaml_domains(self, checks, domains_md):
        """Every domain value used in the YAML registry must have a corresponding
        section heading in domains.md."""
        yaml_domains = {c.get("domain") for c in checks if c.get("domain")}
        missing = [
            f"{domain} (section '{DOMAIN_TO_SECTION.get(domain)}')"
            for domain in yaml_domains
            if DOMAIN_TO_SECTION.get(domain) not in domains_md
        ]
        assert not missing, (
            f"Domains in YAML registry with no corresponding section in domains.md: {missing}"
        )


class TestAbsentHandlingSourceOfTruth:
    def test_conf01_absent_equals_pass_in_domains_md(self, domains_md):
        """
        Regression guard: the CONF-01 absent=PASS rule must exist in domains.md.
        domains.md is the single canonical source for absent-handling behavior
        (the pass_when_absent YAML field was removed to avoid split source of truth).
        The rule lives in the Detection Logic section, not the check table itself.
        """
        import re

        # The rule is in the Detection Logic section — search there, not from the
        # first table occurrence of "CONF-01" (which is too far from the PASS text).
        assert "Detection Logic" in domains_md
        det_idx = domains_md.index("Detection Logic")
        detection_section = domains_md[det_idx : det_idx + 1200]
        # Use regex to confirm the rule co-locates CONF-01 with absent and PASS,
        # preventing a false pass when the three words appear for unrelated reasons.
        assert re.search(r"CONF-01.{0,120}absent.{0,120}PASS", detection_section, re.DOTALL), (
            "The Detection Logic section of domains.md must document that "
            "CONF-01 absent key = PASS (debug defaults to false when omitted)"
        )

    def test_domains_md_declares_itself_canonical_source(self, domains_md):
        """
        Regression guard: domains.md must explicitly state it is the canonical
        source for absent-handling, so maintainers know where to update the rule.
        """
        text_lower = domains_md.lower()
        assert "canonical" in text_lower or "single" in text_lower, (
            "domains.md must declare itself the canonical source for absent-handling behavior"
        )


class TestTrustScoringSourceOfTruth:
    def test_conflicting_trust_table_removed_from_domains_md(self, domains_md):
        """
        Regression guard: domains.md previously had a trust scoring table whose
        TRUSTED criteria ('no shell exec') conflicted with scoring.md's criteria
        ('SKILL-02 PASS/scoped', which allows scoped exec). The conflicting table
        was removed; scoring.md is now the single canonical source.
        """
        # The old conflicting criteria text must not be present
        old_criteria = "allowed-tools declared; no shell exec; no injection risk; author declared"
        assert old_criteria not in domains_md, (
            "The conflicting trust scoring criteria table must not be in domains.md. "
            "Trust criteria are defined only in scoring.md (single source of truth)."
        )

    def test_domains_md_references_scoring_md_for_trust(self, domains_md):
        """
        Regression guard: domains.md must reference scoring.md instead of
        re-defining trust criteria, to prevent future conflicts.
        """
        assert "scoring.md" in domains_md, (
            "domains.md must reference scoring.md as the canonical source for Trust Score "
            "criteria instead of re-defining them locally."
        )


class TestWebFetchCrossReferences:
    def test_sc03_references_web_fetch_in_domains_md(self, domains_md):
        """
        Regression guard: SC-03 requires a web check for repo commit recency.
        After web_fetch was added to allowed-tools, domains.md must document its use.
        """
        assert "SC-03" in domains_md
        idx = domains_md.index("SC-03")
        context = domains_md[idx : idx + 300]
        assert "web_fetch" in context or "UNKNOWN" in context, (
            "SC-03 row in domains.md must document web_fetch usage or UNKNOWN fallback"
        )

    def test_sc05_references_web_fetch_in_domains_md(self, domains_md):
        """
        Regression guard: SC-05 requires a web check for repo availability.
        """
        assert "SC-05" in domains_md
        idx = domains_md.index("SC-05")
        context = domains_md[idx : idx + 300]
        assert "web_fetch" in context or "UNKNOWN" in context, (
            "SC-05 row in domains.md must document web_fetch usage or UNKNOWN fallback"
        )

    def test_web_fetch_in_skill_md_allowed_tools(self, skill_frontmatter):
        """
        Cross-reference: domains.md says SC-03/SC-05 use web_fetch, so SKILL.md
        allowed-tools must include web_fetch.
        """
        tools = skill_frontmatter.get("allowed-tools", [])
        assert "web_fetch" in tools, (
            "SKILL.md allowed-tools must include web_fetch (required for SC-03/SC-05 "
            "as documented in domains.md)"
        )


class TestSafetyRuleConsistency:
    def test_safety_rules_section_present(self, skill_body):
        assert "Safety Rules" in skill_body

    def test_at_least_8_safety_rules(self, skill_body):
        safety_idx = skill_body.index("Safety Rules")
        safety_section = skill_body[safety_idx:]
        numbered = re.findall(r"^\d+\.", safety_section, re.MULTILINE)
        assert len(numbered) >= 8, (
            f"Safety Rules must have at least 8 rules (Rules 1-8), found {len(numbered)}"
        )

    def test_self_audit_rule_uses_scoped_suppression(self, skill_body):
        """
        Regression guard: Safety Rule 7 was a blanket exclusion of clawaudit from
        Domain 2/5 checks — a blind spot if future versions gain broader tools.
        It was replaced with scoped suppression (WARN for documentation-context matches).
        """
        safety_idx = skill_body.index("Safety Rules")
        safety_section = skill_body[safety_idx : safety_idx + 2500]
        has_scoped = (
            "scoped" in safety_section.lower()
            or "documentation context" in safety_section.lower()
            or "WARN" in safety_section
        )
        old_blanket = "Exclude `clawaudit`'s own `SKILL.md` from Domain 2 and Domain 5"
        assert has_scoped, "Safety Rule 7 must use scoped suppression, not blanket exclusion"
        assert old_blanket not in safety_section, (
            "Old blanket exclusion text must not be in Safety Rules"
        )

    def test_never_block_rule_present(self, skill_body):
        safety_idx = skill_body.index("Safety Rules")
        safety_section = skill_body[safety_idx:]
        assert (
            "never block" in safety_section.lower()
            or "always be produced" in safety_section.lower()
        ), "Safety Rules must include a rule ensuring the report is always produced"


class TestVersionConsistency:
    def test_skill_version_matches_changelog(self, skill_frontmatter, changelog_md):
        version = skill_frontmatter.get("metadata", {}).get("openclaw", {}).get("version", "")
        assert version, "SKILL.md metadata.openclaw.version must be set"
        assert version in changelog_md, (
            f"Version '{version}' from SKILL.md not found in CHANGELOG.md — keep them in sync"
        )
