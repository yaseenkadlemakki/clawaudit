"""Starter (built-in) policies seeded on first startup."""

from __future__ import annotations

STARTER_POLICIES = [
    {
        "name": "block-pty-exec",
        "domain": "tool_call",
        "check": "params.pty",
        "condition": "equals",
        "value": "true",
        "severity": "HIGH",
        "action": "BLOCK",
        "description": "Block exec tool calls with PTY enabled — these open interactive shells.",
        "builtin": True,
        "priority": 100,
    },
    {
        "name": "alert-credential-file-read",
        "domain": "tool_call",
        "check": "params.path",
        "condition": "matches",
        "value": r"\.env$|credentials|\.pem$|\.key$|id_rsa|\.secret",
        "severity": "HIGH",
        "action": "ALERT",
        "description": "Alert when a skill reads credential or secret files.",
        "builtin": True,
        "priority": 90,
    },
    {
        "name": "alert-elevated-exec",
        "domain": "tool_call",
        "check": "params.elevated",
        "condition": "equals",
        "value": "true",
        "severity": "HIGH",
        "action": "ALERT",
        "description": "Alert when a skill requests elevated (host) execution.",
        "builtin": True,
        "priority": 90,
    },
    {
        "name": "alert-browser-external-navigate",
        "domain": "tool_call",
        "check": "params.url",
        "condition": "matches",
        "value": r"^https?://(?!localhost)",
        "severity": "MEDIUM",
        "action": "ALERT",
        "description": "Alert when a skill navigates the browser to an external URL.",
        "builtin": True,
        "priority": 70,
    },
    {
        "name": "alert-message-send",
        "domain": "tool_call",
        "check": "tool",
        "condition": "equals",
        "value": "message",
        "severity": "MEDIUM",
        "action": "ALERT",
        "description": "Alert when a skill sends a message via the message tool.",
        "builtin": True,
        "priority": 60,
    },
]


async def seed_starter_policies() -> None:
    """Seed built-in policies if they don't exist yet (idempotent)."""
    from backend.database import AsyncSessionLocal
    from backend.storage.repository import PolicyRepository

    async with AsyncSessionLocal() as db:
        repo = PolicyRepository(db)
        for policy_data in STARTER_POLICIES:
            existing = await repo.get_by_name(policy_data["name"])
            if not existing:
                await repo.create(policy_data)
