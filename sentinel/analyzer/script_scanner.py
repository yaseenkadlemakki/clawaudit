"""Script file security scanner — detects malicious patterns in skill script files.

Scans all non-SKILL.md files in a skill directory (shell scripts, Python files,
any executable content) for patterns that indicate supply chain attacks,
credential harvesting, or privilege escalation.

Finding codes:
  SCR-001  Remote code execution via curl/wget piped to shell
  SCR-002  Encoded payload (base64 decoded and executed)
  SCR-003  Destructive filesystem operations (rm -rf, chmod 777)
  SCR-004  Credential file reads (~/.openclaw, ~/.ssh, ~/.aws, ~/.config)
  SCR-005  Hardcoded non-allowlisted external IP or domain in script
  SCR-006  Arbitrary code execution via eval
"""

from __future__ import annotations

import ipaddress
import logging
import re
import uuid
from pathlib import Path

from sentinel.models.finding import Finding

logger = logging.getLogger(__name__)

_MAX_FILE_SIZE = 1_048_576  # 1 MB default
_BINARY_CHECK_SIZE = 8192

_SKIP_NAMES = frozenset({"SKILL.md", "SKILL.md.disabled"})

# ── Compiled patterns ──────────────────────────────────────────────────────────

_SCR001_PATTERNS = [
    re.compile(r"(curl|wget)\s+.*\s*\|\s*(bash|sh|zsh|python|python3)", re.IGNORECASE),
    re.compile(r"(curl|wget)\s+.*-[oO]\s*-\s*\|\s*(bash|sh)", re.IGNORECASE),
]

_SCR002_PATTERNS = [
    re.compile(r"base64\s+(--decode|-d)\s*\|", re.IGNORECASE),
    re.compile(r"echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64", re.IGNORECASE),
]

_SCR003_PATTERNS = [
    re.compile(r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*r", re.IGNORECASE),
    re.compile(r"chmod\s+(777|a\+x|0777)", re.IGNORECASE),
    re.compile(r":\s*>\s*/etc/", re.IGNORECASE),
]

_SCR004_PATTERNS = [
    re.compile(r"~/\.openclaw/(openclaw\.json|workspace)", re.IGNORECASE),
    re.compile(r"~/\.ssh/", re.IGNORECASE),
    re.compile(r"~/\.aws/", re.IGNORECASE),
    re.compile(r"~/\.config/", re.IGNORECASE),
    re.compile(r"\$HOME/\.openclaw", re.IGNORECASE),
    re.compile(r"\$HOME/\.ssh", re.IGNORECASE),
]

_SCR005_IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_SCR005_URL_PATTERN = re.compile(r"https?://([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})")

_SCR006_PATTERNS = [
    re.compile(r"\beval\s*\$\(", re.IGNORECASE),
    re.compile(r"\beval\s*`", re.IGNORECASE),
    re.compile(r"\bexec\s*\(.*__import__", re.IGNORECASE),
    re.compile(r"\beval\s*\(.*compile\(", re.IGNORECASE),
]

# ── Risk / severity mapping ───────────────────────────────────────────────────

_CHECK_META: dict[str, tuple[str, str, str]] = {
    # check_id → (title_template, severity, domain)
    "SCR-001": ("Remote code execution via curl/wget pipe", "CRITICAL", "scripts"),
    "SCR-002": ("Encoded payload execution (base64)", "CRITICAL", "scripts"),
    "SCR-003": ("Destructive filesystem operation", "HIGH", "scripts"),
    "SCR-004": ("Credential file access", "HIGH", "scripts"),
    "SCR-005": ("Hardcoded external IP/domain", "MEDIUM", "scripts"),
    "SCR-006": ("Arbitrary code execution via eval", "CRITICAL", "scripts"),
}

_PRIVATE_PREFIXES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
]


def _is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_PREFIXES)


class ScriptScanner:
    """Scan non-SKILL.md files in a skill directory for malicious patterns."""

    def __init__(
        self,
        safe_domains: frozenset[str] | None = None,
        max_file_size_mb: float = 1.0,
    ) -> None:
        from sentinel.config import _DEFAULT_SAFE_DOMAINS

        self._safe_domains = safe_domains if safe_domains is not None else _DEFAULT_SAFE_DOMAINS
        self._max_file_size = int(max_file_size_mb * 1_048_576)

    def scan_skill(self, skill_name: str, skill_dir: Path) -> list[Finding]:
        """Scan every eligible file in *skill_dir* and return findings."""
        findings: list[Finding] = []
        if not skill_dir.is_dir():
            return findings
        resolved_root = skill_dir.resolve()
        for file_path in sorted(skill_dir.rglob("*")):
            if not file_path.is_file():
                continue
            if file_path.name in _SKIP_NAMES:
                continue
            # Reject symlinks that escape the skill directory (path traversal)
            resolved = file_path.resolve()
            if not resolved.is_relative_to(resolved_root):
                logger.warning("Skipping symlink escaping skill dir: %s", file_path)
                continue
            findings.extend(self._scan_file(skill_name, skill_dir, file_path))
        return findings

    def _scan_file(self, skill_name: str, skill_dir: Path, file_path: Path) -> list[Finding]:
        # Skip large files
        try:
            size = file_path.stat().st_size
        except OSError:
            return []
        if size > self._max_file_size:
            return []
        # Skip binary files
        if self._is_binary(file_path):
            return []
        try:
            content = file_path.read_text(errors="replace")
        except OSError:
            return []

        run_id = str(uuid.uuid4())
        rel = str(file_path.relative_to(skill_dir))
        location = f"{skill_name}/{rel}"

        hits: list[tuple[str, str]] = []
        hits.extend(("SCR-001", desc) for desc in self._check_scr001(content))
        hits.extend(("SCR-002", desc) for desc in self._check_scr002(content))
        hits.extend(("SCR-003", desc) for desc in self._check_scr003(content))
        hits.extend(("SCR-004", desc) for desc in self._check_scr004(content))
        hits.extend(("SCR-005", desc) for desc in self._check_scr005(content))
        hits.extend(("SCR-006", desc) for desc in self._check_scr006(content))

        findings: list[Finding] = []
        for check_id, description in hits:
            title_tpl, severity, domain = _CHECK_META[check_id]
            findings.append(
                Finding(
                    check_id=check_id,
                    domain=domain,
                    title=f"{title_tpl} in '{skill_name}'",
                    description=description,
                    severity=severity,
                    result="FAIL",
                    evidence=description,
                    location=location,
                    remediation=f"Remove or refactor the flagged pattern ({check_id}).",
                    run_id=run_id,
                )
            )
        return findings

    # ── Binary detection ───────────────────────────────────────────────────

    @staticmethod
    def _is_binary(file_path: Path) -> bool:
        try:
            chunk = file_path.read_bytes()[:_BINARY_CHECK_SIZE]
        except OSError:
            return True
        return b"\x00" in chunk

    # ── Pattern checks ─────────────────────────────────────────────────────

    @staticmethod
    def _check_scr001(content: str) -> list[str]:
        out: list[str] = []
        for pat in _SCR001_PATTERNS:
            for m in pat.finditer(content):
                out.append(f"curl/wget piped to shell: {m.group()[:120]}")
        return out

    @staticmethod
    def _check_scr002(content: str) -> list[str]:
        out: list[str] = []
        for pat in _SCR002_PATTERNS:
            for m in pat.finditer(content):
                out.append(f"base64 decode piped to execution: {m.group()[:120]}")
        return out

    @staticmethod
    def _check_scr003(content: str) -> list[str]:
        out: list[str] = []
        for pat in _SCR003_PATTERNS:
            for m in pat.finditer(content):
                out.append(f"Destructive operation: {m.group()[:120]}")
        return out

    @staticmethod
    def _check_scr004(content: str) -> list[str]:
        out: list[str] = []
        for pat in _SCR004_PATTERNS:
            for m in pat.finditer(content):
                out.append(f"Credential file access: {m.group()[:120]}")
        return out

    def _check_scr005(self, content: str) -> list[str]:
        out: list[str] = []
        # External IPs
        for m in _SCR005_IP_PATTERN.finditer(content):
            ip = m.group(1)
            if not _is_private_ip(ip):
                out.append(f"Hardcoded external IP: {ip}")
        # External domains
        for m in _SCR005_URL_PATTERN.finditer(content):
            domain = m.group(1).lower()
            if domain not in self._safe_domains:
                out.append(f"Non-allowlisted domain: {domain}")
        return out

    @staticmethod
    def _check_scr006(content: str) -> list[str]:
        out: list[str] = []
        for pat in _SCR006_PATTERNS:
            for m in pat.finditer(content):
                out.append(f"Eval/exec pattern: {m.group()[:120]}")
        return out
