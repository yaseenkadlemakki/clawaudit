"""Skill lifecycle management — install, enable/disable, uninstall, and registry."""

from pathlib import Path

PROTECTED_PATHS = [
    Path("/opt/homebrew/lib/node_modules/openclaw/skills"),
    Path("/usr/local/lib/node_modules/openclaw/skills"),
    Path("/usr/lib/node_modules/openclaw/skills"),
]
