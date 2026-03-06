"""Unit tests for policy action resolution."""
import pytest

from sentinel.policy.actions import resolve_action, handle_allow, handle_warn, handle_alert, handle_block
from sentinel.models.policy import PolicyDecision


@pytest.mark.unit
class TestResolveAction:
    def test_empty_list_returns_allow(self):
        assert resolve_action([]) == "ALLOW"

    def test_single_allow(self):
        assert resolve_action(["ALLOW"]) == "ALLOW"

    def test_single_warn(self):
        assert resolve_action(["WARN"]) == "WARN"

    def test_single_alert(self):
        assert resolve_action(["ALERT"]) == "ALERT"

    def test_single_block(self):
        assert resolve_action(["BLOCK"]) == "BLOCK"

    def test_block_beats_all(self):
        assert resolve_action(["ALLOW", "WARN", "ALERT", "BLOCK"]) == "BLOCK"

    def test_alert_beats_warn_and_allow(self):
        assert resolve_action(["ALLOW", "WARN", "ALERT"]) == "ALERT"

    def test_warn_beats_allow(self):
        assert resolve_action(["ALLOW", "WARN"]) == "WARN"

    def test_case_insensitive_block(self):
        assert resolve_action(["block", "warn"]) == "block"

    def test_duplicate_actions(self):
        assert resolve_action(["ALERT", "ALERT", "ALERT"]) == "ALERT"

    def test_unknown_action_loses_to_alert(self):
        # Unknown action has priority 0, same as ALLOW
        result = resolve_action(["ALERT", "UNKNOWN_ACTION"])
        assert result == "ALERT"

    def test_priority_order_correct(self):
        # Verify strict ordering: ALLOW < WARN < ALERT < BLOCK
        from sentinel.policy.actions import ACTION_PRIORITY
        assert ACTION_PRIORITY["ALLOW"] < ACTION_PRIORITY["WARN"]
        assert ACTION_PRIORITY["WARN"] < ACTION_PRIORITY["ALERT"]
        assert ACTION_PRIORITY["ALERT"] < ACTION_PRIORITY["BLOCK"]


@pytest.mark.unit
class TestHandlerFunctions:
    """Smoke tests — handlers log and do not raise."""

    def _decision(self, action="ALLOW") -> PolicyDecision:
        return PolicyDecision(action=action, reason="test reason")

    def test_handle_allow_does_not_raise(self):
        handle_allow(self._decision("ALLOW"))

    def test_handle_warn_does_not_raise(self):
        handle_warn(self._decision("WARN"))

    def test_handle_alert_does_not_raise(self):
        handle_alert(self._decision("ALERT"))

    def test_handle_block_does_not_raise(self):
        handle_block(self._decision("BLOCK"))
