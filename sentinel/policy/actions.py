"""Policy action handlers."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.models.policy import PolicyDecision

logger = logging.getLogger(__name__)

ACTION_PRIORITY = {"ALLOW": 0, "WARN": 1, "ALERT": 2, "BLOCK": 3, "QUARANTINE": 4}


def resolve_action(actions: list[str]) -> str:
    """Return the highest-priority action from a list."""
    if not actions:
        return "ALLOW"
    return max(actions, key=lambda a: ACTION_PRIORITY.get(a.upper(), 0))


def handle_allow(decision: PolicyDecision) -> None:
    """Handle ALLOW decision."""
    logger.debug("Policy decision: ALLOW — %s", decision.reason)


def handle_warn(decision: PolicyDecision) -> None:
    """Handle WARN decision."""
    logger.warning("Policy decision: WARN — %s", decision.reason)


def handle_alert(decision: PolicyDecision) -> None:
    """Handle ALERT decision — alert engine will route this."""
    logger.warning("Policy decision: ALERT — %s", decision.reason)


def handle_block(decision: PolicyDecision) -> None:
    """Handle BLOCK decision."""
    logger.error("Policy decision: BLOCK — %s", decision.reason)


def handle_quarantine(decision: PolicyDecision) -> None:
    """Handle QUARANTINE decision — skill will be quarantined."""
    logger.error("Policy decision: QUARANTINE — %s", decision.reason)
