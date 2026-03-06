"""Extensible additive risk scoring engine (0-100)."""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.models.skill import SkillProfile

RISK_FACTORS: dict[str, int] = {
    "shell_execution": 30,
    "filesystem_write": 20,
    "network_outbound": 15,
    "unknown_publisher": 10,
    "unsigned_skill": 10,
    "injection_risk_high": 25,
    "injection_risk_medium": 10,
    "credential_access": 20,
    "dangerous_commands": 15,  # rm -rf, eval, curl | bash
    "no_allowed_tools": 10,
    "no_author": 5,
}

_DANGEROUS_PATTERNS = [
    r"rm\s+-rf",
    r"\beval\b",
    r"curl\s+.*\|\s*bash",
    r"curl\s+.*\|\s*sh",
    r"wget\s+.*\|\s*bash",
    r":(){ :|:& };:",  # fork bomb
]


def _has_dangerous_commands(profile: "SkillProfile") -> bool:
    """Check if any shell evidence includes dangerous patterns."""
    text = " ".join(profile.shell_evidence + profile.injection_evidence)
    return any(re.search(p, text, re.IGNORECASE) for p in _DANGEROUS_PATTERNS)


def score_skill(profile: "SkillProfile") -> tuple[int, str]:
    """
    Compute additive risk score (0–100) and level for a SkillProfile.

    Returns:
        (score, risk_level) where risk_level is Low/Medium/High/Critical
    """
    score = 0
    factors: list[str] = []

    if profile.shell_access:
        score += RISK_FACTORS["shell_execution"]
        factors.append("shell_execution")

    # filesystem write: look for write-related shell evidence
    write_patterns = ["filesystem_write", "write", "echo >", "tee ", ">>"]
    if any(p in " ".join(profile.shell_evidence).lower() for p in write_patterns):
        score += RISK_FACTORS["filesystem_write"]
        factors.append("filesystem_write")

    if profile.outbound_domains:
        score += RISK_FACTORS["network_outbound"]
        factors.append("network_outbound")

    if not profile.author:
        score += RISK_FACTORS["unknown_publisher"]
        factors.append("unknown_publisher")
        score += RISK_FACTORS["no_author"]
        factors.append("no_author")

    if not profile.is_signed:
        score += RISK_FACTORS["unsigned_skill"]
        factors.append("unsigned_skill")

    if profile.injection_risk in ("HIGH", "CRITICAL"):
        score += RISK_FACTORS["injection_risk_high"]
        factors.append("injection_risk_high")
    elif profile.injection_risk == "MEDIUM":
        score += RISK_FACTORS["injection_risk_medium"]
        factors.append("injection_risk_medium")

    if profile.credential_exposure:
        score += RISK_FACTORS["credential_access"]
        factors.append("credential_access")

    if _has_dangerous_commands(profile):
        score += RISK_FACTORS["dangerous_commands"]
        factors.append("dangerous_commands")

    if not profile.has_allowed_tools:
        score += RISK_FACTORS["no_allowed_tools"]
        factors.append("no_allowed_tools")

    score = min(score, 100)

    if score <= 20:
        level = "Low"
    elif score <= 40:
        level = "Medium"
    elif score <= 70:
        level = "High"
    else:
        level = "Critical"

    return score, level
