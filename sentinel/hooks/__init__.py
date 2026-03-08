"""ClawAudit runtime hook integration — plugin event system."""

from __future__ import annotations

from sentinel.hooks.bus import HookBus
from sentinel.hooks.event import ToolEvent
from sentinel.hooks.plugin import ClawAuditPlugin
from sentinel.hooks.rules import evaluate_rules
from sentinel.hooks.store import EventStore

__all__ = [
    "ClawAuditPlugin",
    "EventStore",
    "HookBus",
    "ToolEvent",
    "evaluate_rules",
]
