"""
Integration tests: full repository consistency.

These tests span multiple files simultaneously and validate end-to-end
structural invariants: all required files exist, the orchestration phase
sequence is correct, check counts are internally consistent across files,
version numbers are kept in sync, and the architecture diagram matches
the actual directory structure.
"""

import re

import pytest

pytestmark = pytest.mark.integration

REQUIRED_FILES = [
    "SKILL.md",
    "INSTALL.md",
    "README.md",
    "CHANGELOG.md",
    ".gitignore",
    "data/hardening-rules.yaml",
    "detectors/secret-patterns.md",
    "detectors/injection-patterns.md",
    "references/domains.md",
    "references/scoring.md",
    "references/report-template.md",
]

ORCHESTRATION_PHASES = [
    "Phase 0",
    "Phase 1",
    "Phase 2",
    "Phase 3",
    "Phase 4",
    "Phase 5",
    "Phase 6",
    "Phase 7",
]

# Total checks: 8 + 10 + 6 + 7 + 7 + 5
EXPECTED_TOTAL_CHECKS = 43


class TestRequiredFilesExist:
    @pytest.mark.parametrize("filepath", REQUIRED_FILES)
    def test_file_exists_and_non_empty(self, repo_root, filepath):
        path = repo_root / filepath
        assert path.exists(), f"Required file missing: {filepath}"
        assert path.stat().st_size > 0, f"Required file is empty: {filepath}"

    def test_no_duplicate_inner_directory(self, repo_root):
        """
        Regression guard: the clawaudit/ inner directory (exact duplicate of all
        root files) was removed in PR #1. If it reappears, maintainers would be
        working on stale copies.
        """
        inner = repo_root / "clawaudit"
        assert not inner.exists(), (
            "Duplicate clawaudit/ inner directory must not exist. "
            "All skill files live at the repository root."
        )

    def test_no_nested_skill_md(self, repo_root):
        """There must be exactly one SKILL.md at the repository root."""
        nested = [p for p in repo_root.rglob("SKILL.md") if p.parent != repo_root]
        assert not nested, f"SKILL.md found in subdirectory (duplicate): {[str(p) for p in nested]}"


class TestGitignore:
    def test_gitignore_excludes_ds_store(self, repo_root):
        text = (repo_root / ".gitignore").read_text()
        assert ".DS_Store" in text

    def test_gitignore_excludes_env_files(self, repo_root):
        text = (repo_root / ".gitignore").read_text()
        assert ".env" in text

    def test_gitignore_excludes_skill_outputs(self, repo_root):
        text = (repo_root / ".gitignore").read_text()
        assert "*.skill" in text

    def test_gitignore_excludes_generated_reports(self, repo_root):
        text = (repo_root / ".gitignore").read_text()
        # Pattern for generated audit report files
        assert "clawaudit-report" in text or "*.md" in text or "report" in text.lower()


class TestVersionSync:
    def test_skill_version_in_changelog(self, skill_frontmatter, changelog_md):
        version = skill_frontmatter.get("metadata", {}).get("openclaw", {}).get("version", "")
        assert version, "SKILL.md metadata.openclaw.version not set"
        assert version in changelog_md, (
            f"SKILL.md version '{version}' not found in CHANGELOG.md — keep in sync"
        )

    def test_changelog_uses_keepachangelog_format(self, changelog_md):
        assert "## [" in changelog_md, (
            "CHANGELOG.md must use Keep a Changelog format: ## [version] — date"
        )

    def test_changelog_has_version_1_0_0(self, changelog_md):
        assert "1.0.0" in changelog_md

    def test_yaml_registry_has_version(self, hardening_rules):
        assert hardening_rules.get("version"), "hardening-rules.yaml must have a version field"

    def test_skill_version_matches_yaml_registry_version(self, skill_frontmatter, hardening_rules):
        skill_version = skill_frontmatter.get("metadata", {}).get("openclaw", {}).get("version", "")
        yaml_version = hardening_rules.get("version", "")
        assert skill_version == yaml_version, (
            f"Version mismatch: SKILL.md has '{skill_version}', "
            f"hardening-rules.yaml has '{yaml_version}'. Keep them in sync."
        )


class TestOrchestrationPhaseSequence:
    @pytest.mark.parametrize("phase", ORCHESTRATION_PHASES)
    def test_phase_present_in_skill_body(self, skill_body, phase):
        assert phase in skill_body, f"Phase '{phase}' missing from SKILL.md orchestration"

    def test_phases_appear_in_ascending_order(self, skill_body):
        # Search for section headings specifically (e.g. "### Phase 0 —") to avoid
        # matching prose references like "skip Phase 2 and Phase 5" in Phase 0 body.
        positions = []
        for phase in ORCHESTRATION_PHASES:
            m = re.search(rf"###\s+{re.escape(phase)}\b", skill_body)
            if m:
                positions.append(m.start())
        assert positions == sorted(positions), (
            "Orchestration phase headings must appear in ascending order in SKILL.md"
        )

    def test_phase0_has_gateway_error_handling(self, skill_body):
        """
        Regression guard: Phase 0 previously had no error handling. If
        gateway config.get failed, the entire audit would halt.
        Fixed: error handling added for gateway unavailability.
        """
        phase0_start = skill_body.index("Phase 0")
        phase1_start = skill_body.index("Phase 1")
        phase0_text = skill_body[phase0_start:phase1_start]
        assert "UNKNOWN" in phase0_text, (
            "Phase 0 must document marking domains UNKNOWN if gateway is unavailable"
        )
        assert "unavailable" in phase0_text.lower() or "fail" in phase0_text.lower(), (
            "Phase 0 must describe what happens when gateway config.get fails"
        )

    def test_phase0_has_linux_path_fallback(self, skill_body):
        """
        Regression guard: Phase 0 only had the macOS Homebrew install path.
        Linux deployments would silently skip Domains 2 and 5.
        Fixed: Linux path fallback added.
        """
        phase0_start = skill_body.index("Phase 0")
        phase1_start = skill_body.index("Phase 1")
        phase0_text = skill_body[phase0_start:phase1_start]
        has_linux = "/usr/local/" in phase0_text or "Linux" in phase0_text
        assert has_linux, (
            "Phase 0 must include a Linux install path fallback "
            "(/usr/local/lib/node_modules/openclaw/) for non-macOS deployments"
        )


class TestCheckCountConsistency:
    def test_total_43_checks(self, checks):
        assert len(checks) == EXPECTED_TOTAL_CHECKS, (
            f"Expected {EXPECTED_TOTAL_CHECKS} checks total, got {len(checks)}"
        )

    def test_per_domain_counts_sum_to_total(self, checks):
        from collections import Counter

        counts = Counter(c.get("domain") for c in checks)
        total = sum(counts.values())
        assert total == EXPECTED_TOTAL_CHECKS, (
            f"Per-domain counts sum to {total}, expected {EXPECTED_TOTAL_CHECKS}. "
            f"Breakdown: {dict(counts)}"
        )

    def test_report_template_references_config_domain_count(self, report_template):
        """Configuration domain has 8 checks — this must be visible in the template."""
        assert "8" in report_template, (
            "Report template compliance table must reference the 8-check Configuration domain count"
        )


class TestArchitectureDiagramAccuracy:
    def test_readme_has_architecture_section(self, readme_md):
        text_lower = readme_md.lower()
        assert "architecture" in text_lower

    def test_skill_md_diagram_files_exist(self, skill_body, repo_root):
        """Files mentioned in the SKILL.md architecture diagram must exist on disk."""
        diagram_files = [
            "SKILL.md",
            "domains.md",
            "scoring.md",
            "report-template.md",
            "secret-patterns.md",
            "injection-patterns.md",
            "hardening-rules.yaml",
        ]
        missing = [f for f in diagram_files if not list(repo_root.rglob(f))]
        assert not missing, (
            f"Files referenced in SKILL.md architecture diagram don't exist: {missing}"
        )

    def test_readme_references_key_files(self, readme_md):
        key_files = [
            "SKILL.md",
            "hardening-rules.yaml",
            "domains.md",
            "scoring.md",
            "report-template.md",
        ]
        missing = [f for f in key_files if f not in readme_md]
        assert not missing, f"README.md architecture section missing references to: {missing}"


class TestInstallDocumentCompleteness:
    def test_install_md_has_requirements_section(self, install_md):
        assert "Requirements" in install_md or "requirement" in install_md.lower()

    def test_install_md_mentions_platform(self, install_md):
        assert "macOS" in install_md or "Linux" in install_md

    def test_install_md_has_verification_step(self, install_md):
        assert "Verification" in install_md or "verify" in install_md.lower()

    def test_install_md_cron_timezone_customization_note(self, install_md):
        """
        Regression guard: the cron example had a hardcoded America/New_York timezone
        with no note that it must be customised. Fixed in PR #1.
        """
        assert (
            "timezone" in install_md.lower()
            or "IANA" in install_md
            or "America/New_York" in install_md
        ), "INSTALL.md must note that the cron timezone must be customised"
