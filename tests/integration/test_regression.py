"""
Regression tests: one test per confirmed bug from previous PRs.

These are the highest-priority tests in the suite. Each test:
  1. Documents the original bug and its symptoms
  2. States which PR fixed it
  3. Asserts exactly the condition that the fix established

If any of these tests fail, a previously fixed bug has been reintroduced.
Failing a regression test is a hard blocker — do not merge.
"""
import pytest

pytestmark = pytest.mark.integration


# ── PR #1 regressions ─────────────────────────────────────────────────────────

class TestPR1Regressions:

    def test_no_duplicate_inner_clawaudit_directory(self, repo_root):
        """
        BUG (PR #1): The entire skill directory was duplicated inside a
        clawaudit/ subdirectory. Fixes applied to root files did not propagate
        to the copy, causing stale audits.

        FIX: Inner directory removed. All files live at the repository root.
        """
        inner = repo_root / "clawaudit"
        assert not inner.is_dir(), (
            "REGRESSION: clawaudit/ inner directory has reappeared. "
            "Remove it — all skill files must be at the repository root only."
        )

    def test_conf01_absent_key_is_pass_not_fail(self, domains_md):
        """
        BUG (PR #1): CONF-01 had expected='absent or false' (PASS) but the
        detection algorithm said 'absent → FAIL'. Deployments that omit the
        debug key (which defaults to false — the safe state) were incorrectly
        flagged as failing.

        FIX: Detection Logic in domains.md updated: CONF-01 absent = PASS.
        """
        assert "Detection Logic" in domains_md
        det_idx = domains_md.index("Detection Logic")
        # The CONF-01 absent=PASS rule is in the Detection Logic section,
        # not in the check-table row (which is hundreds of chars earlier).
        detection_section = domains_md[det_idx: det_idx + 1200]
        assert "CONF-01" in detection_section and "PASS" in detection_section, (
            "REGRESSION: CONF-01 absent=PASS rule missing from Detection Logic in domains.md. "
            "Absent debug key must be PASS (it defaults to false — the safe state)."
        )

    def test_author_is_not_skill_name(self, skill_frontmatter):
        """
        BUG (PR #1): metadata.openclaw.author was 'clawaudit' — the skill's own
        name instead of a real author identity. SKILL-09 (author declared) would
        technically pass but the field carried no useful information.

        FIX: author changed to 'OpenClaw Security'.
        """
        author = (
            skill_frontmatter.get("metadata", {})
            .get("openclaw", {})
            .get("author", "")
        )
        assert author.lower() != "clawaudit", (
            f"REGRESSION: author is '{author}' — must not be the skill name 'clawaudit'."
        )

    def test_gitignore_exists(self, repo_root):
        """
        BUG (PR #1): No .gitignore. OS artifacts (.DS_Store), generated reports,
        and .env files would pollute git history.

        FIX: .gitignore added with appropriate entries.
        """
        assert (repo_root / ".gitignore").exists(), (
            "REGRESSION: .gitignore removed. Re-add it to prevent artifact pollution."
        )

    def test_readme_exists(self, repo_root):
        """
        BUG (PR #1): No README.md. New contributors had no entry point to
        understand the project, its architecture, or how to run it.

        FIX: README.md added.
        """
        assert (repo_root / "README.md").exists(), (
            "REGRESSION: README.md removed. Re-add it."
        )

    def test_changelog_exists(self, repo_root):
        """
        BUG (PR #1): No CHANGELOG.md. No version history, no record of what
        changed between releases.

        FIX: CHANGELOG.md added following Keep a Changelog format.
        """
        assert (repo_root / "CHANGELOG.md").exists(), (
            "REGRESSION: CHANGELOG.md removed. Re-add it."
        )

    def test_phase0_has_gateway_error_handling(self, skill_body):
        """
        BUG (PR #1): Phase 0 had no error-handling. If gateway config.get failed,
        the entire audit would halt mid-run with no report produced.

        FIX: Phase 0 now marks Domains 1/4 as UNKNOWN and continues.
        """
        phase0_start = skill_body.index("Phase 0")
        phase1_start = skill_body.index("Phase 1")
        phase0_text = skill_body[phase0_start:phase1_start]
        assert "UNKNOWN" in phase0_text, (
            "REGRESSION: Phase 0 error-handling removed. "
            "Gateway unavailability must mark Domains 1/4 UNKNOWN, not halt the audit."
        )

    def test_phase0_has_linux_install_path(self, skill_body):
        """
        BUG (PR #1): Phase 0 only referenced /opt/homebrew/... (macOS Homebrew).
        Linux deployments would fail skill discovery without a fallback path.

        FIX: /usr/local/lib/node_modules/openclaw/ added as Linux fallback.
        """
        phase0_start = skill_body.index("Phase 0")
        phase1_start = skill_body.index("Phase 1")
        phase0_text = skill_body[phase0_start:phase1_start]
        assert "/usr/local/" in phase0_text or "Linux" in phase0_text, (
            "REGRESSION: Linux install path fallback removed from Phase 0. "
            "Add /usr/local/lib/node_modules/openclaw/ as Linux npm global fallback."
        )

    def test_trust_criteria_not_duplicated_in_domains_md(self, domains_md):
        """
        BUG (PR #1): Trust scoring was defined in both domains.md ('no shell exec'
        for TRUSTED) and scoring.md ('SKILL-02 PASS/scoped', which allows scoped
        exec). The agent received conflicting instructions and produced inconsistent
        Trust Matrix results across runs.

        FIX: Duplicate trust table removed from domains.md; scoring.md is canonical.
        """
        conflicting_text = (
            "allowed-tools declared; no shell exec; no injection risk; author declared"
        )
        assert conflicting_text not in domains_md, (
            "REGRESSION: Conflicting trust criteria table reappeared in domains.md. "
            "Trust criteria must only be defined in scoring.md (single canonical source)."
        )


# ── PR #1 review comment regressions ─────────────────────────────────────────

class TestPRReviewRegressions:

    def test_web_fetch_in_allowed_tools(self, skill_frontmatter):
        """
        BUG (PR #1 review, comment #2893212543): SC-03 (repo commit recency) and
        SC-05 (repo availability) require web checks, but web_fetch was absent from
        allowed-tools. Both checks permanently returned UNKNOWN, structurally
        degrading the Supply Chain domain score regardless of actual skill quality.

        FIX: web_fetch added to allowed-tools with read-only justification.
        """
        tools = skill_frontmatter.get("allowed-tools", [])
        assert "web_fetch" in tools, (
            "REGRESSION: web_fetch removed from allowed-tools. "
            "SC-03 and SC-05 require web_fetch for repo availability and commit-recency checks. "
            "Without it, both checks permanently return UNKNOWN/FAIL."
        )

    def test_self_audit_exclusion_is_scoped_not_blanket(self, skill_body):
        """
        BUG (PR #1 review, comment #2893213228): Safety Rule 7 was a blanket
        exclusion of clawaudit from Domain 2/5 — a blind spot. If future versions
        gained exec or network tools, this file would never be audited.

        FIX: Replaced with scoped suppression (WARN for documentation-context matches).
        """
        safety_idx = skill_body.index("Safety Rules")
        safety_section = skill_body[safety_idx: safety_idx + 2500]
        old_blanket = "Exclude `clawaudit`'s own `SKILL.md` from Domain 2 and Domain 5"
        assert old_blanket not in safety_section, (
            "REGRESSION: Blanket self-exclusion text reappeared in Safety Rule 7. "
            "Use scoped suppression: audit normally, downgrade to WARN for documentation-context matches."
        )

    def test_pass_when_absent_not_in_yaml(self, checks):
        """
        BUG (PR #1 review, comment #2893214066): pass_when_absent was added to
        hardening-rules.yaml, splitting the source of truth for absent-handling
        between the YAML file and domains.md prose. Maintainers needed to update
        two files when changing a rule.

        FIX: Field removed. domains.md is the single canonical source.
        """
        offenders = [c.get("id", "?") for c in checks if "pass_when_absent" in c]
        assert not offenders, (
            f"REGRESSION: pass_when_absent field reappeared in hardening-rules.yaml "
            f"for checks: {offenders}. "
            "Absent-handling is defined only in references/domains.md."
        )

    def test_adjusted_score_in_report_template(self, report_template):
        """
        BUG (PR #1 review, comment #2893214688): The compliance table had only a
        single score column (worst-case, UNKNOWN=FAIL). A gateway-unavailable
        deployment would show ~30% compliance even if nothing was misconfigured,
        because all Domain 1/4 checks became UNKNOWN.

        FIX: Adjusted Score column added (UNKNOWN excluded from denominator).
        """
        assert "Adjusted Score" in report_template, (
            "REGRESSION: Adjusted Score column removed from compliance table. "
            "Operators need two signals: worst-case (UNKNOWN=FAIL) and confirmed rate "
            "(UNKNOWN excluded). Re-add the Adjusted Score column."
        )

    def test_anthropic_pattern_appears_before_openai(self, secret_patterns_md):
        """
        BUG (PR #1 review, comment #2893215488 — issue 1): OpenAI sk- is a superset
        of Anthropic sk-ant-. A scanner applying sk- first misclassifies Anthropic
        keys as OpenAI keys, potentially routing alert severity to the wrong owner.

        FIX: Scan-order rule added; Anthropic pattern listed before OpenAI.
        """
        assert "Anthropic API Key" in secret_patterns_md
        assert "OpenAI API Key" in secret_patterns_md
        anthr_pos = secret_patterns_md.index("Anthropic API Key")
        openai_pos = secret_patterns_md.index("OpenAI API Key")
        assert anthr_pos < openai_pos, (
            "REGRESSION: OpenAI API Key pattern appears before Anthropic API Key. "
            "The sk- prefix (OpenAI) is a superset of sk-ant- (Anthropic). "
            "Anthropic must be checked first to prevent misclassification."
        )

    def test_generic_api_key_has_length_constraint(self, secret_patterns_md):
        """
        BUG (PR #1 review, comment #2893215488 — issue 2): Generic API Key matched
        key *names* containing 'token' regardless of value length, producing false
        positives on fields like max_token_length: 4096 and session_timeout: 3600.

        FIX: Minimum value-length constraint (≥ 20 chars) added.
        """
        has_constraint = (
            "≥ 20" in secret_patterns_md
            or ">= 20" in secret_patterns_md
            or "20 char" in secret_patterns_md
        )
        assert has_constraint, (
            "REGRESSION: Generic API Key length constraint (≥ 20 chars) removed. "
            "Fields like max_token_length will generate false positive findings."
        )

    def test_tool_output_recycling_in_injection_patterns(self, injection_patterns_md):
        """
        BUG (PR #1 review, comment #2893216111 — vector 1): Tool output recycling
        was missing from injection-patterns.md. This is the most common real-world
        prompt injection vector (OWASP LLM01): a skill reads a file or API response
        containing injected instructions and the content flows to the LLM.

        FIX: Added to Prompt Injection Indicators table.
        """
        has_vector = (
            "recycling" in injection_patterns_md.lower()
            or "tool output" in injection_patterns_md.lower()
        )
        assert has_vector, (
            "REGRESSION: Tool output recycling vector removed from injection-patterns.md. "
            "This is OWASP LLM01 and the most common real-world PI surface. Re-add it."
        )

    def test_ssrf_via_url_fetch_in_injection_patterns(self, injection_patterns_md):
        """
        BUG (PR #1 review, comment #2893216111 — vector 2): SSRF via URL-derived
        fetch was missing. A skill that accepts user-supplied input to construct a
        URL, then fetches it with web_fetch and passes the response to the LLM,
        gives the remote server control over injected LLM content.

        FIX: Added to Prompt Injection Indicators table with SSRF label.
        """
        has_ssrf = (
            "SSRF" in injection_patterns_md
            or "ssrf" in injection_patterns_md.lower()
            or "URL-derived" in injection_patterns_md
        )
        assert has_ssrf, (
            "REGRESSION: SSRF-via-URL-derived-fetch vector removed from injection-patterns.md. "
            "Re-add: user-controlled URL → web_fetch → LLM receives attacker content."
        )

    def test_trust_scoring_has_single_canonical_source(self, domains_md, scoring_md):
        """
        BUG (PR #1 review, comment #2893216917): Trust score criteria were defined
        in both domains.md and scoring.md with conflicting TRUSTED requirements.
        The LLM agent received contradictory instructions and produced inconsistent
        Trust Matrix results.

        FIX: domains.md defers to scoring.md; trust criteria only in scoring.md.
        """
        # scoring.md: TRUSTED must allow scoped shell (SKILL-02 PASS/scoped)
        assert "TRUSTED" in scoring_md, "Trust criteria must be defined in scoring.md"
        # domains.md: must NOT re-define TRUSTED criteria (old conflicting text)
        old_text = "allowed-tools declared; no shell exec; no injection risk; author declared"
        assert old_text not in domains_md, (
            "REGRESSION: Conflicting TRUSTED criteria ('no shell exec') reappeared in "
            "domains.md. Trust criteria must only be in scoring.md."
        )
        # domains.md: must reference scoring.md
        assert "scoring.md" in domains_md, (
            "domains.md must reference scoring.md for trust criteria "
            "(single canonical source)"
        )
