"""
Unit tests for SKILL.md frontmatter.

Validates: required keys, allowed-tools list (including web_fetch regression),
metadata field completeness, and author identity correctness.
"""
import pytest

pytestmark = pytest.mark.unit

REQUIRED_KEYS = frozenset({"name", "description", "user-invocable", "allowed-tools", "metadata"})
REQUIRED_TOOLS = frozenset({"Read", "web_fetch", "gateway", "session_status"})


class TestFrontmatterStructure:
    def test_frontmatter_is_non_empty(self, skill_frontmatter):
        assert skill_frontmatter, "SKILL.md frontmatter could not be parsed or is empty"

    @pytest.mark.parametrize("key", sorted(REQUIRED_KEYS))
    def test_required_key_present(self, skill_frontmatter, key):
        assert key in skill_frontmatter, f"SKILL.md frontmatter missing required key: '{key}'"

    def test_name_equals_clawaudit(self, skill_frontmatter):
        assert skill_frontmatter.get("name") == "clawaudit"

    def test_user_invocable_is_true(self, skill_frontmatter):
        assert skill_frontmatter.get("user-invocable") is True

    def test_description_is_non_empty(self, skill_frontmatter):
        assert skill_frontmatter.get("description", "").strip(), "description must not be blank"


class TestAllowedTools:
    def test_allowed_tools_is_list(self, skill_frontmatter):
        tools = skill_frontmatter.get("allowed-tools")
        assert isinstance(tools, list), f"allowed-tools must be a list, got {type(tools)}"

    def test_allowed_tools_is_non_empty(self, skill_frontmatter):
        assert skill_frontmatter.get("allowed-tools"), "allowed-tools must not be empty"

    @pytest.mark.parametrize("tool", sorted(REQUIRED_TOOLS))
    def test_required_tool_present(self, skill_frontmatter, tool):
        tools = skill_frontmatter.get("allowed-tools", [])
        assert tool in tools, (
            f"Required tool '{tool}' not in allowed-tools. Current list: {tools}"
        )

    def test_web_fetch_present(self, skill_frontmatter):
        """
        Regression guard: web_fetch was missing, causing SC-03/SC-05 supply-chain
        checks to permanently return UNKNOWN because no web tool was available.
        """
        tools = skill_frontmatter.get("allowed-tools", [])
        assert "web_fetch" in tools, (
            "web_fetch must be in allowed-tools to support SC-03 (repo commit recency) "
            "and SC-05 (repo availability) supply-chain checks."
        )

    def test_no_wildcard_tool(self, skill_frontmatter):
        """Wildcard tool grants (*) would violate the least-privilege principle."""
        tools = skill_frontmatter.get("allowed-tools", [])
        assert "*" not in tools, "allowed-tools must not contain a wildcard ('*')"


class TestMetadata:
    def _openclaw(self, skill_frontmatter: dict) -> dict:
        return skill_frontmatter.get("metadata", {}).get("openclaw", {})

    def test_metadata_has_openclaw_key(self, skill_frontmatter):
        assert "openclaw" in skill_frontmatter.get("metadata", {}), (
            "metadata must contain an 'openclaw' sub-key"
        )

    def test_emoji_present_and_non_empty(self, skill_frontmatter):
        assert self._openclaw(skill_frontmatter).get("emoji"), "metadata.openclaw.emoji must be set"

    def test_version_present_and_non_empty(self, skill_frontmatter):
        assert self._openclaw(skill_frontmatter).get("version"), "metadata.openclaw.version must be set"

    def test_author_present_and_non_empty(self, skill_frontmatter):
        assert self._openclaw(skill_frontmatter).get("author"), "metadata.openclaw.author must be set"

    def test_author_is_not_skill_name(self, skill_frontmatter):
        """
        Regression guard: author was set to 'clawaudit' (the skill's own name)
        instead of a real identity. Fixed in PR #1.
        """
        author = self._openclaw(skill_frontmatter).get("author", "")
        assert author.lower() != "clawaudit", (
            f"author field is '{author}' — must be a real identity, not the skill name. "
            "e.g. 'OpenClaw Security'"
        )

    def test_author_is_string_with_minimum_length(self, skill_frontmatter):
        author = self._openclaw(skill_frontmatter).get("author", "")
        assert isinstance(author, str) and len(author) >= 4, (
            f"author must be a meaningful string, got: '{author}'"
        )

    def test_version_is_semver(self, skill_frontmatter):
        import re
        version = self._openclaw(skill_frontmatter).get("version", "")
        assert re.match(r"^\d+\.\d+\.\d+$", str(version)), (
            f"metadata.openclaw.version must be a semver string (e.g. '1.0.0'), got: '{version}'"
        )
