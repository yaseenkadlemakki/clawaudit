"""Deep skill security analysis and trust scoring."""

from __future__ import annotations

import logging
import re
import uuid
from pathlib import Path

from sentinel.analyzer.injection_detector import RISK_ORDER, InjectionDetector
from sentinel.analyzer.secret_scanner import SecretScanner
from sentinel.models.finding import Finding
from sentinel.models.skill import SkillProfile

logger = logging.getLogger(__name__)

SHELL_ACCESS_PATTERNS: list[tuple[str, str]] = [
    (r"\bexec\b", "exec keyword"),
    (r"pty\s*:\s*true", "pty:true flag"),
    (r"\bbash\b", "bash reference"),
    (r"\bsh\s+-c\b", "sh -c invocation"),
    (r"`[^`]+`", "backtick command substitution"),
    (r"\bsubprocess\b", "subprocess module"),
    (r"\bos\.system\b", "os.system call"),
    (r"\bcurl\b", "curl invocation"),
    (r"\bwget\b", "wget invocation"),
    (r"\bnpm\b", "npm invocation"),
    (r"\bpip\b", "pip invocation"),
    (r"\bgit\b", "git invocation"),
]

URL_PATTERN = re.compile(r"https?://([a-zA-Z0-9.\-]+)")


def _extract_metadata(text: str) -> dict[str, str]:
    """Extract skill metadata from SKILL.md content."""
    meta: dict[str, str] = {}
    for line in text.splitlines()[:30]:
        lower = line.lower()
        if "author" in lower and ":" in line:
            meta["author"] = line.split(":", 1)[1].strip().strip("*_ ")
        if "version" in lower and ":" in line:
            meta["version"] = line.split(":", 1)[1].strip().strip("*_ ")
        if "source" in lower and ":" in line:
            meta["source"] = line.split(":", 1)[1].strip().strip("*_ ")
    return meta


def _check_allowed_tools(text: str) -> bool:
    """Check if skill declares allowed-tools constraint."""
    return bool(re.search(r"allowed[_-]tools", text, re.IGNORECASE))


def _check_signed(text: str) -> bool:
    """Check if skill has a cryptographic signature."""
    return bool(re.search(r"signature|signed-by|pgp|gpg", text, re.IGNORECASE))


def _extract_domains(text: str) -> list[str]:
    """Extract declared outbound domains."""
    domains: list[str] = list(set(URL_PATTERN.findall(text)))
    # Exclude common localhost / example patterns
    return [d for d in domains if d not in ("localhost", "example.com", "127.0.0.1")]


def _calculate_trust_score(profile: SkillProfile) -> tuple[int, str]:
    """Calculate numeric trust score and label."""
    score = 100

    if not profile.has_allowed_tools:
        score -= 20
    if profile.shell_access:
        # Only penalize if not scoped (no allowed-tools)
        if not profile.has_allowed_tools:
            score -= 30
        else:
            score -= 10
    if profile.injection_risk == "HIGH":
        score -= 30
    elif profile.injection_risk == "CRITICAL":
        score -= 50
    elif profile.injection_risk == "MEDIUM":
        score -= 15
    if not profile.is_signed:
        score -= 10
    if not profile.author:
        score -= 10
    if profile.outbound_domains:
        # Penalize skills that make outbound calls without declared tool scoping
        if not profile.has_allowed_tools:
            score -= 10

    score = max(0, score)
    if score >= 80:
        label = "TRUSTED"
    elif score >= 60:
        label = "CAUTION"
    elif score >= 40:
        label = "UNTRUSTED"
    else:
        label = "QUARANTINE"

    return score, label


class SkillAnalyzer:
    """Analyzes OpenClaw skills for security risks."""

    def __init__(self) -> None:
        self._secret_scanner = SecretScanner()
        self._injection_detector = InjectionDetector()

    def analyze(self, skill_path: Path, run_id: str | None = None) -> SkillProfile:
        """Perform comprehensive security analysis of a SKILL.md file."""
        run_id = run_id or str(uuid.uuid4())

        try:
            text = skill_path.read_text(errors="replace")
        except (OSError, PermissionError) as exc:
            logger.debug("Cannot read skill %s: %s", skill_path, exc)
            return SkillProfile(
                name=skill_path.parent.name,
                path=str(skill_path),
                trust_score="QUARANTINE",
                trust_score_value=0,
            )

        name = skill_path.parent.name
        meta = _extract_metadata(text)

        profile = SkillProfile(
            name=name,
            path=str(skill_path),
            source=meta.get("source", ""),
            version=meta.get("version", ""),
            author=meta.get("author", ""),
            has_allowed_tools=_check_allowed_tools(text),
            is_signed=_check_signed(text),
            outbound_domains=_extract_domains(text),
        )

        # Shell access detection
        shell_evidence: list[str] = []
        for pattern, description in SHELL_ACCESS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                shell_evidence.append(description)
        profile.shell_access = len(shell_evidence) > 0
        profile.shell_evidence = shell_evidence

        # Injection detection
        inj_report = self._injection_detector.analyze_text(text, str(skill_path))
        profile.injection_risk = inj_report.overall_risk  # type: ignore[assignment]
        profile.injection_evidence = [f.evidence for f in inj_report.findings]

        # Secret scanning
        secret_matches = self._secret_scanner.scan_text(text, str(skill_path))
        profile.credential_exposure = len(secret_matches) > 0

        # Trust scoring
        score, label = _calculate_trust_score(profile)
        profile.trust_score_value = score
        profile.trust_score = label  # type: ignore[assignment]

        # Build findings
        findings: list[Finding] = []

        if profile.shell_access:
            findings.append(
                Finding(
                    check_id="SKILL-01",
                    domain="skills",
                    title=f"Skill '{name}' has shell access",
                    description=f"Detected shell access patterns: {', '.join(shell_evidence[:3])}",
                    severity="MEDIUM" if profile.has_allowed_tools else "HIGH",
                    result="FAIL",
                    evidence=", ".join(shell_evidence[:5]),
                    location=str(skill_path),
                    remediation="Scope shell access with allowed-tools constraint.",
                    run_id=run_id,
                )
            )

        if RISK_ORDER.get(profile.injection_risk, 0) >= 2:
            findings.append(
                Finding(
                    check_id="SKILL-02",
                    domain="skills",
                    title=f"Skill '{name}' has {profile.injection_risk} injection risk",
                    description="Template variables or user input may reach shell commands.",
                    severity=profile.injection_risk,
                    result="FAIL",
                    evidence="; ".join(profile.injection_evidence[:3]),
                    location=str(skill_path),
                    remediation="Validate and sanitize user input before passing to shell commands.",
                    run_id=run_id,
                )
            )

        if profile.credential_exposure:
            findings.append(
                Finding(
                    check_id="SKILL-03",
                    domain="secrets",
                    title=f"Skill '{name}' may expose credentials",
                    description="Secret patterns detected in skill body.",
                    severity="CRITICAL",
                    result="FAIL",
                    evidence="[secret values redacted]",
                    location=str(skill_path),
                    remediation="Remove hardcoded credentials from skill files.",
                    run_id=run_id,
                )
            )

        profile.findings = findings
        return profile
