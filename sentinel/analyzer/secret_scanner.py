"""Credential and secret pattern detection.

IMPORTANT: Matched secret values are NEVER logged or returned.
Only the secret type and its location are reported.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List


PATTERNS: dict[str, str] = {
    "anthropic_key": r"sk-ant-[a-zA-Z0-9\-_]{20,}",
    "openai_key": r"sk-(?!ant)[a-zA-Z0-9]{20,}",
    "aws_access_key": r"AKIA[A-Z0-9]{16}",
    "github_pat": r"gh[pors]_[a-zA-Z0-9]{36,}",
    "github_fine_grained": r"github_pat_[a-zA-Z0-9_]{82}",
    "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
    "telegram_bot_token": r"\d{8,10}:[a-zA-Z0-9_-]{35}",
    "pem_private_key": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "jwt_token": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    "generic_bearer": r"Bearer\s+[a-zA-Z0-9\-_\.]{20,}",
}

SKIP_VALUES: set[str] = {
    "__OPENCLAW_REDACTED__",
    "***",
    "<redacted>",
    "YOUR_TOKEN_HERE",
    "${OPENCLAW_GATEWAY_TOKEN}",
}

_COMPILED: dict[str, re.Pattern] = {
    name: re.compile(pattern)
    for name, pattern in PATTERNS.items()
}


@dataclass
class SecretMatch:
    """A detected secret occurrence — value is never stored."""

    secret_type: str
    location: str
    line_number: int
    context: str  # sanitized context (surrounding chars, no secret value)

    def to_dict(self) -> dict:
        return {
            "secret_type": self.secret_type,
            "location": self.location,
            "line_number": self.line_number,
            "context": self.context,
        }


def _is_skip_value(line: str, match: re.Match) -> bool:  # type: ignore[type-arg]
    """Return True if the matched text is a known placeholder."""
    matched_text = match.group(0)
    if matched_text in SKIP_VALUES:
        return True
    for skip in SKIP_VALUES:
        if skip in line:
            return True
    return False


def _sanitize_context(line: str, match: re.Match, window: int = 20) -> str:  # type: ignore[type-arg]
    """Return context around match without the secret value itself."""
    start = max(0, match.start() - window)
    end = min(len(line), match.end() + window)
    before = line[start:match.start()]
    after = line[match.end():end]
    return f"{before}<REDACTED>{after}".strip()


class SecretScanner:
    """Scans text content for credential patterns."""

    def scan_text(self, text: str, location: str) -> List[SecretMatch]:
        """Scan text for secret patterns, return matches without secret values."""
        matches: List[SecretMatch] = []
        for line_num, line in enumerate(text.splitlines(), start=1):
            for secret_type, pattern in _COMPILED.items():
                for m in pattern.finditer(line):
                    if _is_skip_value(line, m):
                        continue
                    matches.append(SecretMatch(
                        secret_type=secret_type,
                        location=location,
                        line_number=line_num,
                        context=_sanitize_context(line, m),
                    ))
        return matches

    def scan_file(self, path: Path) -> List[SecretMatch]:
        """Scan a file for secret patterns."""
        try:
            text = path.read_text(errors="replace")
            return self.scan_text(text, str(path))
        except (OSError, PermissionError):
            return []

    def scan_dict(self, data: dict, location: str = "") -> List[SecretMatch]:
        """Recursively scan a dict for secret values."""
        matches: List[SecretMatch] = []
        for key, value in data.items():
            loc = f"{location}.{key}" if location else key
            if isinstance(value, str):
                hits = self.scan_text(value, loc)
                matches.extend(hits)
            elif isinstance(value, dict):
                matches.extend(self.scan_dict(value, loc))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        hits = self.scan_text(item, f"{loc}[{i}]")
                        matches.extend(hits)
                    elif isinstance(item, dict):
                        matches.extend(self.scan_dict(item, f"{loc}[{i}]"))
        return matches
