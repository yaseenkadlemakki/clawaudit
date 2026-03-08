"""
Unit tests for data/hardening-rules.yaml.

Validates: schema correctness, required fields, check ID format,
severity and domain enum values, check counts per domain, and absence
of disallowed fields (e.g. pass_when_absent which splits source of truth).
"""

import re

import pytest

pytestmark = pytest.mark.unit

REQUIRED_FIELDS = frozenset(
    {"id", "domain", "description", "evidence_key", "expected", "severity", "remediation"}
)

VALID_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})

VALID_DOMAINS = frozenset(
    {"config", "skills", "secrets", "network", "supply_chain", "observability"}
)

# Minimum check counts per domain — guards against accidental deletions.
# Use >= so that adding new checks doesn't require updating this file.
# The exact total (43) is enforced separately by the integration test suite.
MIN_DOMAIN_COUNTS = {
    "config": 8,
    "skills": 10,
    "secrets": 6,
    "network": 7,
    "supply_chain": 7,
    "observability": 5,
}
EXPECTED_TOTAL_CHECKS = sum(MIN_DOMAIN_COUNTS.values())  # 43 (used as lower bound in integration)

# ID prefix → domain mapping
DOMAIN_ID_PREFIX = {
    "config": "CONF",
    "skills": "SKILL",
    "secrets": "SEC",
    "network": "NET",
    "supply_chain": "SC",
    "observability": "OBS",
}

ID_PATTERN = re.compile(r"^[A-Z]+-\d{2}$")


# ── File-level schema ──────────────────────────────────────────────────────────


class TestYAMLSchema:
    def test_version_key_present(self, hardening_rules):
        assert "version" in hardening_rules

    def test_version_is_non_empty_string(self, hardening_rules):
        assert isinstance(hardening_rules.get("version"), str)
        assert hardening_rules["version"].strip()

    def test_checks_key_present(self, hardening_rules):
        assert "checks" in hardening_rules

    def test_checks_is_list(self, checks):
        assert isinstance(checks, list)

    def test_checks_list_is_non_empty(self, checks):
        assert len(checks) > 0


# ── Per-check field validation ─────────────────────────────────────────────────


class TestRequiredFields:
    @pytest.mark.parametrize("field", sorted(REQUIRED_FIELDS))
    def test_all_checks_have_field(self, checks, field):
        missing = [c.get("id", f"(index {i})") for i, c in enumerate(checks) if field not in c]
        assert not missing, f"Checks missing required field '{field}': {missing}"

    def test_no_blank_descriptions(self, checks):
        blank = [c["id"] for c in checks if not str(c.get("description", "")).strip()]
        assert not blank, f"Checks with empty description: {blank}"

    def test_no_blank_remediations(self, checks):
        blank = [c["id"] for c in checks if not str(c.get("remediation", "")).strip()]
        assert not blank, f"Checks with empty remediation: {blank}"

    def test_no_blank_evidence_keys(self, checks):
        blank = [c["id"] for c in checks if not str(c.get("evidence_key", "")).strip()]
        assert not blank, f"Checks with empty evidence_key: {blank}"

    def test_no_blank_expected_values(self, checks):
        blank = [c["id"] for c in checks if not str(c.get("expected", "")).strip()]
        assert not blank, f"Checks with empty expected value: {blank}"


class TestDisallowedFields:
    def test_pass_when_absent_not_present(self, checks):
        """
        Regression guard: pass_when_absent was removed because it split the
        source of truth for absent-handling between YAML and domains.md prose.
        domains.md is now the single canonical source.
        """
        offenders = [c.get("id", "?") for c in checks if "pass_when_absent" in c]
        assert not offenders, (
            f"pass_when_absent must not appear in hardening-rules.yaml — "
            f"absent-handling is defined only in references/domains.md. Found in: {offenders}"
        )


# ── Check ID format ────────────────────────────────────────────────────────────


class TestCheckIDFormat:
    def test_no_duplicate_ids(self, checks):
        ids = [c["id"] for c in checks if "id" in c]
        seen: set = set()
        duplicates = [i for i in ids if i in seen or seen.add(i)]  # type: ignore[func-returns-value]
        assert not duplicates, f"Duplicate check IDs: {duplicates}"

    def test_all_ids_match_pattern(self, checks):
        bad = [c["id"] for c in checks if not ID_PATTERN.match(c.get("id", ""))]
        assert not bad, f"Check IDs not matching format DOMAIN-NN: {bad}"

    def test_id_prefix_matches_domain(self, checks):
        mismatches = []
        for c in checks:
            cid = c.get("id", "")
            domain = c.get("domain", "")
            expected_prefix = DOMAIN_ID_PREFIX.get(domain)
            if expected_prefix and not cid.startswith(expected_prefix + "-"):
                mismatches.append(f"{cid} (domain={domain}, expected prefix={expected_prefix}-)")
        assert not mismatches, f"Check ID prefix/domain mismatch: {mismatches}"


# ── Enum constraints ───────────────────────────────────────────────────────────


class TestEnumValues:
    def test_all_severities_are_valid(self, checks):
        bad = [
            (c.get("id"), c.get("severity"))
            for c in checks
            if c.get("severity") not in VALID_SEVERITIES
        ]
        assert not bad, f"Invalid severity values (allowed: {VALID_SEVERITIES}): {bad}"

    def test_all_domains_are_valid(self, checks):
        bad = [
            (c.get("id"), c.get("domain")) for c in checks if c.get("domain") not in VALID_DOMAINS
        ]
        assert not bad, f"Invalid domain values (allowed: {VALID_DOMAINS}): {bad}"


# ── Check counts ───────────────────────────────────────────────────────────────


class TestCheckCounts:
    def test_total_check_count_at_least_minimum(self, checks):
        assert len(checks) >= EXPECTED_TOTAL_CHECKS, (
            f"Expected at least {EXPECTED_TOTAL_CHECKS} total checks, got {len(checks)}"
        )

    @pytest.mark.parametrize("domain,minimum", MIN_DOMAIN_COUNTS.items())
    def test_per_domain_check_count_at_least_minimum(self, checks, domain, minimum):
        actual = sum(1 for c in checks if c.get("domain") == domain)
        assert actual >= minimum, (
            f"Domain '{domain}': expected at least {minimum} checks, got {actual}"
        )
