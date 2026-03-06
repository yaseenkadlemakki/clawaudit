"""
Shared test fixtures for the ClawAudit test suite.

All fixtures are session-scoped: each file is read once per test run and
shared across all tests, keeping the suite fast even as it grows.
"""
import re
from pathlib import Path

import pytest
import yaml

# Repository root is two levels up from this file (tests/conftest.py → repo root)
REPO_ROOT = Path(__file__).parent.parent


# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse_frontmatter(path: Path) -> dict:
    """Parse YAML frontmatter delimited by --- lines from a markdown file."""
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return {}
    lines = text.split("\n")
    closing = None
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            closing = i
            break
    if closing is None:
        return {}
    fm_text = "\n".join(lines[1:closing])
    return yaml.safe_load(fm_text) or {}


def _get_body(path: Path) -> str:
    """Return the body of a markdown file (everything after the frontmatter)."""
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return text
    lines = text.split("\n")
    closing = None
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            closing = i
            break
    if closing is None:
        return text
    return "\n".join(lines[closing + 1:]).strip()


def _read(relpath: str) -> str:
    return (REPO_ROOT / relpath).read_text(encoding="utf-8")


# ── Session fixtures ────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def hardening_rules() -> dict:
    """Parsed data/hardening-rules.yaml as a Python dict."""
    path = REPO_ROOT / "data" / "hardening-rules.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def checks(hardening_rules) -> list:
    """Flat list of check entry dicts from the YAML registry."""
    return hardening_rules.get("checks", [])


@pytest.fixture(scope="session")
def skill_frontmatter() -> dict:
    """Parsed YAML frontmatter from SKILL.md."""
    return _parse_frontmatter(REPO_ROOT / "SKILL.md")


@pytest.fixture(scope="session")
def skill_body() -> str:
    """Markdown body of SKILL.md (after frontmatter)."""
    return _get_body(REPO_ROOT / "SKILL.md")


@pytest.fixture(scope="session")
def domains_md() -> str:
    return _read("references/domains.md")


@pytest.fixture(scope="session")
def scoring_md() -> str:
    return _read("references/scoring.md")


@pytest.fixture(scope="session")
def report_template() -> str:
    return _read("references/report-template.md")


@pytest.fixture(scope="session")
def secret_patterns_md() -> str:
    return _read("detectors/secret-patterns.md")


@pytest.fixture(scope="session")
def injection_patterns_md() -> str:
    return _read("detectors/injection-patterns.md")


@pytest.fixture(scope="session")
def install_md() -> str:
    return _read("INSTALL.md")


@pytest.fixture(scope="session")
def changelog_md() -> str:
    return _read("CHANGELOG.md")


@pytest.fixture(scope="session")
def readme_md() -> str:
    return _read("README.md")
