"""Unit tests for policy actions including QUARANTINE (Phase 8)."""

from __future__ import annotations

import pytest

from sentinel.models.policy import PolicyDecision, Rule
from sentinel.policy.actions import (
    ACTION_PRIORITY,
    handle_alert,
    handle_allow,
    handle_block,
    handle_quarantine,
    handle_warn,
    resolve_action,
)


class TestActionPriority:
    def test_quarantine_is_highest_priority(self):
        assert ACTION_PRIORITY["QUARANTINE"] > ACTION_PRIORITY["BLOCK"]
        assert ACTION_PRIORITY["QUARANTINE"] > ACTION_PRIORITY["ALERT"]
        assert ACTION_PRIORITY["QUARANTINE"] > ACTION_PRIORITY["WARN"]
        assert ACTION_PRIORITY["QUARANTINE"] > ACTION_PRIORITY["ALLOW"]

    def test_block_is_second_highest(self):
        assert ACTION_PRIORITY["BLOCK"] > ACTION_PRIORITY["ALERT"]
        assert ACTION_PRIORITY["BLOCK"] > ACTION_PRIORITY["WARN"]
        assert ACTION_PRIORITY["BLOCK"] > ACTION_PRIORITY["ALLOW"]

    def test_all_five_actions_present(self):
        for action in ("ALLOW", "WARN", "ALERT", "BLOCK", "QUARANTINE"):
            assert action in ACTION_PRIORITY

    def test_priority_values(self):
        assert ACTION_PRIORITY["ALLOW"] == 0
        assert ACTION_PRIORITY["WARN"] == 1
        assert ACTION_PRIORITY["ALERT"] == 2
        assert ACTION_PRIORITY["BLOCK"] == 3
        assert ACTION_PRIORITY["QUARANTINE"] == 4


class TestResolveAction:
    def test_empty_list_returns_allow(self):
        assert resolve_action([]) == "ALLOW"

    def test_single_action_returned(self):
        assert resolve_action(["BLOCK"]) == "BLOCK"

    def test_quarantine_wins_over_block(self):
        assert resolve_action(["BLOCK", "QUARANTINE"]) == "QUARANTINE"

    def test_quarantine_wins_over_all(self):
        assert resolve_action(["ALLOW", "WARN", "ALERT", "BLOCK", "QUARANTINE"]) == "QUARANTINE"

    def test_block_wins_over_alert(self):
        assert resolve_action(["ALERT", "BLOCK"]) == "BLOCK"

    def test_alert_wins_over_warn(self):
        assert resolve_action(["WARN", "ALERT"]) == "ALERT"

    def test_warn_wins_over_allow(self):
        assert resolve_action(["ALLOW", "WARN"]) == "WARN"

    def test_case_insensitive_comparison(self):
        # resolve_action uses .upper() for comparison but returns the original value
        result = resolve_action(["block", "quarantine"])
        assert result.upper() == "QUARANTINE"

    def test_duplicates(self):
        assert resolve_action(["BLOCK", "BLOCK"]) == "BLOCK"


class TestHandlers:
    def _make_decision(self, action: str) -> PolicyDecision:
        return PolicyDecision(action=action, reason="test reason")

    def test_handle_allow(self, caplog):
        import logging

        with caplog.at_level(logging.DEBUG, logger="sentinel.policy.actions"):
            handle_allow(self._make_decision("ALLOW"))
        # No error/warning emitted for ALLOW

    def test_handle_warn(self, caplog):
        import logging

        with caplog.at_level(logging.WARNING):
            handle_warn(self._make_decision("WARN"))
        assert any("WARN" in r.message for r in caplog.records)

    def test_handle_alert(self, caplog):
        import logging

        with caplog.at_level(logging.WARNING):
            handle_alert(self._make_decision("ALERT"))
        assert any("ALERT" in r.message for r in caplog.records)

    def test_handle_block(self, caplog):
        import logging

        with caplog.at_level(logging.ERROR):
            handle_block(self._make_decision("BLOCK"))
        assert any("BLOCK" in r.message for r in caplog.records)

    def test_handle_quarantine(self, caplog):
        import logging

        with caplog.at_level(logging.ERROR):
            handle_quarantine(self._make_decision("QUARANTINE"))
        assert any("QUARANTINE" in r.message for r in caplog.records)
