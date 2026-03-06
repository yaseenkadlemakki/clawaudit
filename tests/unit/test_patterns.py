"""
Unit tests for detectors/secret-patterns.md and detectors/injection-patterns.md.

Validates: scan order (Anthropic-before-OpenAI), credential type completeness,
false-positive reduction constraints, injection vector coverage (including
the two vectors added in the PR review), and OWASP references.
"""
import pytest

pytestmark = pytest.mark.unit

EXPECTED_CREDENTIAL_TYPES = [
    "Anthropic API Key",
    "OpenAI API Key",
    "AWS Access Key ID",
    "AWS Secret Access Key",
    "GitHub Personal Access Token",
    "GitHub Fine-grained PAT",
    "Google API Key",
    "Google OAuth Client Secret",
    "Telegram Bot Token",
    "Discord Bot Token",
    "Generic Bearer Token",
    "JWT Token",
    "Generic API Key",
    "Private Key PEM",
    "SSH Private Key",
]


# ── Secret patterns ────────────────────────────────────────────────────────────

class TestScanOrder:
    def test_scan_order_section_exists(self, secret_patterns_md):
        text_lower = secret_patterns_md.lower()
        assert "scan order" in text_lower or "scan-order" in text_lower, (
            "secret-patterns.md must have a 'Scan Order' section"
        )

    def test_anthropic_pattern_before_openai(self, secret_patterns_md):
        """
        Regression guard: OpenAI sk- is a superset of Anthropic sk-ant-.
        A scanner that checks sk- first will misclassify Anthropic keys.
        The Anthropic pattern must appear first in the registry.
        """
        assert "Anthropic API Key" in secret_patterns_md
        assert "OpenAI API Key" in secret_patterns_md
        anthr_pos = secret_patterns_md.index("Anthropic API Key")
        openai_pos = secret_patterns_md.index("OpenAI API Key")
        assert anthr_pos < openai_pos, (
            "Anthropic API Key must be listed before OpenAI API Key. "
            "The sk- prefix (OpenAI) is a superset of sk-ant- (Anthropic); "
            "checking sk- first misclassifies Anthropic keys."
        )

    def test_negative_lookahead_documented_for_openai(self, secret_patterns_md):
        """
        Regression guard: the OpenAI pattern needs a negative lookahead to exclude
        sk-ant- (Anthropic) matches. This must be documented so implementors apply it.
        """
        has_lookahead = "(?!ant-)" in secret_patterns_md
        has_prose = "negative lookahead" in secret_patterns_md.lower()
        assert has_lookahead or has_prose, (
            "OpenAI pattern must document negative lookahead (sk-(?!ant-)) to avoid "
            "misclassifying Anthropic API keys. Found neither the regex nor prose explanation."
        )


class TestCredentialTypeRegistry:
    @pytest.mark.parametrize("cred_type", EXPECTED_CREDENTIAL_TYPES)
    def test_credential_type_present(self, secret_patterns_md, cred_type):
        assert cred_type in secret_patterns_md, (
            f"Credential type '{cred_type}' not found in secret-patterns.md pattern registry"
        )

    def test_at_least_15_credential_types(self, secret_patterns_md):
        import re
        # Match table rows that are NOT separator lines (|---|---| style).
        # Separator lines have cells containing only dashes, colons, and spaces.
        # NOTE: we cannot use "---" not in line because credential rows like
        # "-----BEGIN RSA PRIVATE KEY-----" legitimately contain "---".
        separator_re = re.compile(r"^\|[\s\-|:]+\|?\s*$")
        table_rows = [
            line for line in secret_patterns_md.splitlines()
            if line.strip().startswith("|")
            and not separator_re.match(line.strip())
            and "Credential Type" not in line
        ]
        assert len(table_rows) >= 15, (
            f"Expected at least 15 credential-type rows, found {len(table_rows)}"
        )

    def test_version_header_present(self, secret_patterns_md):
        assert "version" in secret_patterns_md.lower(), (
            "secret-patterns.md must have a version/last-reviewed header"
        )


class TestGenericApiKeyConstraints:
    def test_length_constraint_documented(self, secret_patterns_md):
        """
        Regression guard: Generic API Key matched config fields like max_token_length
        (value = small integer) before the length constraint was added.
        """
        has_constraint = (
            "≥ 20" in secret_patterns_md
            or ">= 20" in secret_patterns_md
            or "20 char" in secret_patterns_md
            or "20-char" in secret_patterns_md
        )
        assert has_constraint, (
            "Generic API Key pattern must require value length ≥ 20 chars to prevent "
            "false positives on short config values like max_token_length."
        )

    def test_purely_numeric_exclusion_documented(self, secret_patterns_md):
        """
        Regression guard: fields like session_timeout: 3600 matched Generic API Key.
        Purely numeric values must be excluded.
        """
        assert "purely numeric" in secret_patterns_md.lower(), (
            "Generic API Key false-positive list must explicitly exclude purely numeric values "
            "(e.g., port numbers, counts, expiry timestamps)."
        )

    def test_known_non_credential_key_names_listed(self, secret_patterns_md):
        """
        Regression guard: key names like max_tokens, session_token_expiry were
        matched by the 'token' substring in the Generic API Key check.
        """
        has_exclusion = (
            "max_token" in secret_patterns_md
            or "token_limit" in secret_patterns_md
            or "token_count" in secret_patterns_md
            or "token_expiry" in secret_patterns_md
        )
        assert has_exclusion, (
            "False positive reduction must list known non-credential key names "
            "(e.g., max_tokens, max_token_length, session_token_expiry)."
        )


class TestFalsePositiveReduction:
    def test_false_positive_section_exists(self, secret_patterns_md):
        assert "False Positive" in secret_patterns_md

    def test_redacted_placeholder_values_listed(self, secret_patterns_md):
        assert "__OPENCLAW_REDACTED__" in secret_patterns_md or "REDACTED" in secret_patterns_md

    def test_comment_line_exclusion_documented(self, secret_patterns_md):
        has_exclusion = "#" in secret_patterns_md and "comment" in secret_patterns_md.lower()
        assert has_exclusion, (
            "False positive section must document excluding pattern matches on comment lines"
        )


# ── Injection patterns ─────────────────────────────────────────────────────────

class TestInjectionPatternSections:
    def test_shell_injection_section_exists(self, injection_patterns_md):
        assert "Shell Injection" in injection_patterns_md

    def test_prompt_injection_section_exists(self, injection_patterns_md):
        assert "Prompt Injection" in injection_patterns_md

    def test_injection_risk_scoring_section_exists(self, injection_patterns_md):
        assert "Injection Risk Scoring" in injection_patterns_md

    def test_version_header_present(self, injection_patterns_md):
        assert "version" in injection_patterns_md.lower()


class TestShellInjectionPatterns:
    def test_eval_listed_as_critical(self, injection_patterns_md):
        # Search for the backtick-quoted `eval` that appears in the table, not
        # the word "evaluate" that appears in the Rules prose section.
        import re
        match = re.search(r"`eval`", injection_patterns_md)
        assert match, "injection-patterns.md must list `eval` as a shell injection pattern"
        surrounding = injection_patterns_md[match.start(): match.start() + 200]
        assert "CRITICAL" in surrounding, "The `eval` pattern must be classified as CRITICAL risk"

    def test_dollar_star_expansion_listed(self, injection_patterns_md):
        assert "$@" in injection_patterns_md or "$*" in injection_patterns_md, (
            "Shell injection patterns must include $@ / $* argument expansion (passes all args verbatim)"
        )

    def test_yolo_flag_listed(self, injection_patterns_md):
        assert "--yolo" in injection_patterns_md, (
            "Shell injection patterns must flag --yolo (disables sandbox and approval guards)"
        )

    def test_high_risk_patterns_section_exists(self, injection_patterns_md):
        text_lower = injection_patterns_md.lower()
        assert "high-risk" in text_lower or "high risk" in text_lower


class TestPromptInjectionVectors:
    def test_issue_body_vector_listed(self, injection_patterns_md):
        assert "issue body" in injection_patterns_md.lower() or "issue" in injection_patterns_md

    def test_webhook_vector_listed(self, injection_patterns_md):
        assert "webhook" in injection_patterns_md.lower() or "Webhook" in injection_patterns_md

    def test_tool_output_recycling_vector_present(self, injection_patterns_md):
        """
        Regression guard: tool output recycling was missing from the original
        injection-patterns.md. It is the most common real-world prompt injection
        vector (a skill reads an external file/API and passes raw content to the LLM).
        Added in PR review.
        """
        has_vector = (
            "recycling" in injection_patterns_md.lower()
            or "tool output" in injection_patterns_md.lower()
        )
        assert has_vector, (
            "injection-patterns.md must include 'tool output recycling' as a prompt injection "
            "vector: a skill reads file/API response and passes raw content to the LLM. "
            "This is OWASP LLM01 and the most common real-world PI vector."
        )

    def test_ssrf_via_url_fetch_vector_present(self, injection_patterns_md):
        """
        Regression guard: SSRF via URL-derived fetch was missing from the original
        injection-patterns.md. Added in PR review.
        """
        has_ssrf = (
            "SSRF" in injection_patterns_md
            or "ssrf" in injection_patterns_md.lower()
            or "URL-derived" in injection_patterns_md
        )
        assert has_ssrf, (
            "injection-patterns.md must include SSRF-via-URL-derived-fetch as a prompt "
            "injection vector: user-controlled URL → web_fetch → LLM receives attacker content."
        )

    def test_owasp_lm01_referenced(self, injection_patterns_md):
        """
        Regression guard: OWASP LLM01 references were added for the new vectors.
        """
        assert "OWASP" in injection_patterns_md or "LLM01" in injection_patterns_md, (
            "injection-patterns.md must reference OWASP LLM Top 10 (LLM01: Prompt Injection)"
        )


class TestInjectionRiskScoring:
    def test_all_four_risk_levels_defined(self, injection_patterns_md):
        for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            assert level in injection_patterns_md, (
                f"Injection Risk Scoring must define the '{level}' risk level"
            )
