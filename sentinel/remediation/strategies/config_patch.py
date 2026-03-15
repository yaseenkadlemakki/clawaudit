"""Strategy for CONF-xx — OpenClaw configuration hardening patches."""

from __future__ import annotations

import copy
import difflib
import json
from pathlib import Path

from sentinel.remediation.actions import ActionType, RemediationProposal

# Mapping from CONF check_id to fix specification.
# key_path: list of JSON keys to traverse
# target: desired value to set
# title: human-readable description
# impact: list of consequences
_CONFIG_FIXES: dict[str, dict] = {
    "CONF-01": {
        "key_path": ["channels", "discord", "groupPolicy"],
        "target": "allowlist",
        "title": "Set Discord group policy to allowlist",
        "impact": [
            "Only allowlisted users can interact with the agent via Discord.",
            "Existing non-allowlisted users will lose access.",
        ],
    },
    "CONF-02": {
        "key_path": ["channels", "telegram", "groupPolicy"],
        "target": "allowlist",
        "title": "Set Telegram group policy to allowlist",
        "impact": ["Only allowlisted users can interact via Telegram."],
    },
    "CONF-03": {
        "key_path": ["gateway", "bind"],
        "target": "loopback",
        "title": "Bind gateway to loopback address",
        "impact": [
            "Gateway will only accept connections from localhost.",
            "Remote access to the gateway will be blocked.",
        ],
    },
    "CONF-04": {
        "key_path": ["gateway", "auth", "mode"],
        "target": "token",
        "title": "Enable gateway authentication",
        "impact": ["All gateway requests will require a valid auth token."],
    },
    "CONF-06": {
        "key_path": ["yolo"],
        "target": False,
        "title": "Disable yolo mode",
        "impact": [
            "Agent will require confirmation for dangerous operations.",
            "Commands previously auto-approved will now prompt.",
        ],
    },
    "CONF-07": {
        "key_path": ["rateLimit", "enabled"],
        "target": True,
        "title": "Enable rate limiting",
        "impact": ["API calls will be throttled to prevent abuse."],
    },
    "CONF-08": {
        "key_path": ["updates", "checkEnabled"],
        "target": True,
        "title": "Enable automatic update checks",
        "impact": ["OpenClaw will check for updates on startup."],
    },
}


def _get_nested(data: dict, keys: list[str]) -> object:
    """Traverse nested dict by key path. Returns None if any key is missing."""
    for k in keys:
        if not isinstance(data, dict) or k not in data:
            return None
        data = data[k]
    return data


def _set_nested(data: dict, keys: list[str], value: object) -> None:
    """Set a value in a nested dict, creating intermediate dicts as needed."""
    if not keys:
        raise ValueError("key_path must not be empty")
    for k in keys[:-1]:
        next_level = data.get(k)
        if not isinstance(next_level, dict):
            data[k] = {}
        data = data[k]
    data[keys[-1]] = value


def propose(
    skill_name: str,
    skill_path: Path,
    finding_id: str,
    check_id: str | None = None,
) -> RemediationProposal | None:
    """Generate a config patch proposal.

    For config checks, skill_path points to the openclaw.json file itself.
    check_id is required to look up the fix specification.
    """
    if check_id is None or check_id not in _CONFIG_FIXES:
        return None

    fix = _CONFIG_FIXES[check_id]
    config_file = skill_path / "openclaw.json" if skill_path.is_dir() else skill_path

    if not config_file.exists():
        return None

    try:
        original = json.loads(config_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    current_value = _get_nested(original, fix["key_path"])
    if current_value == fix["target"]:
        return None  # Already fixed

    patched = copy.deepcopy(original)
    _set_nested(patched, fix["key_path"], fix["target"])

    original_text = json.dumps(original, indent=2).splitlines(keepends=True)
    patched_text = json.dumps(patched, indent=2).splitlines(keepends=True)
    diff = "".join(difflib.unified_diff(
        original_text,
        patched_text,
        fromfile="a/openclaw.json",
        tofile="b/openclaw.json",
    ))

    key_path_str = ".".join(str(k) for k in fix["key_path"])

    return RemediationProposal.create(
        finding_id=finding_id,
        check_id=check_id,
        skill_name="openclaw-config",
        skill_path=config_file.parent,
        description=(
            f"{fix['title']}: set {key_path_str} = {json.dumps(fix['target'])}"
        ),
        action_type=ActionType.CONFIG_PATCH,
        diff_preview=diff,
        impact=fix["impact"],
        reversible=True,
    )


def apply_patch(skill_path: Path, check_id: str | None = None) -> str:
    """Apply a config patch in-place. Returns new file content.

    skill_path: directory containing openclaw.json, or the file itself.
    check_id: required to look up which fix to apply.
    """
    config_file = skill_path / "openclaw.json" if skill_path.is_dir() else skill_path

    fix = _CONFIG_FIXES.get(check_id or "")
    if not fix:
        raise ValueError(f"No config fix for check_id={check_id}")

    try:
        original = json.loads(config_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"Cannot read or parse {config_file}: {exc}") from exc
    _set_nested(original, fix["key_path"], fix["target"])

    content = json.dumps(original, indent=2) + "\n"
    tmp = config_file.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(config_file)
    return content
