"""Advanced security detection rules for OpenClaw skill analysis."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from sentinel.models.finding import Finding

if TYPE_CHECKING:
    from sentinel.models.skill import SkillProfile

# Domains considered safe for outbound access
_SAFE_DOMAINS: frozenset[str] = frozenset(
    {
        "github.com",
        "api.github.com",
        "pypi.org",
        "files.pythonhosted.org",
        "npmjs.com",
        "registry.npmjs.org",
        "anthropic.com",
        "api.anthropic.com",
        "openai.com",
        "api.openai.com",
        "google.com",
        "googleapis.com",
        "ai.google.dev",
        "huggingface.co",
        "raw.githubusercontent.com",
        "cloudflare.com",
    }
)

# Regex patterns that indicate exposed secrets in skill files
_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}", re.I)),
    ("OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9]{20,}", re.I)),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "Generic token",
        re.compile(
            r'(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*["\']?[A-Za-z0-9+/=_\-]{16,}["\']?'
        ),
    ),
    ("GitHub PAT", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("Private key header", re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----")),
]


def _finding(
    check_id: str,
    domain: str,
    title: str,
    description: str,
    severity: str,
    evidence: str,
    location: str,
    remediation: str,
    run_id: str,
) -> Finding:
    return Finding(
        check_id=check_id,
        domain=domain,
        title=title,
        description=description,
        severity=severity,
        result="FAIL",
        evidence=evidence,
        location=location,
        remediation=remediation,
        run_id=run_id,
    )


class AdvancedDetector:
    """Extended audit checks beyond the standard sentinel rules."""

    def check_unrestricted_shell(self, profile: SkillProfile, run_id: str) -> list[Finding]:
        """Flag skills that enable shell execution — high-risk capability."""
        if not profile.shell_access:
            return []
        return [
            _finding(
                check_id="ADV-001",
                domain="capability",
                title=f"Unrestricted shell execution in skill '{profile.name}'",
                description=(
                    f"Skill '{profile.name}' has shell_access=True, granting it the ability "
                    "to execute arbitrary shell commands on the host system."
                ),
                severity="HIGH",
                evidence=f"shell_access=True, shell_evidence={profile.shell_evidence}",
                location=profile.path,
                remediation=(
                    "Review whether shell access is strictly necessary. If so, document the "
                    "justification in the skill's SKILL.md. Consider sandboxing or restricting "
                    "the allowed commands."
                ),
                run_id=run_id,
            )
        ]

    def check_unknown_publisher(self, profile: SkillProfile, run_id: str) -> list[Finding]:
        """Flag skills with no declared author/publisher."""
        if profile.author and profile.author.strip():
            return []
        return [
            _finding(
                check_id="ADV-002",
                domain="provenance",
                title=f"Unknown publisher for skill '{profile.name}'",
                description=(
                    f"Skill '{profile.name}' has no declared author or publisher, "
                    "making it impossible to verify its provenance."
                ),
                severity="MEDIUM",
                evidence=f"author='{profile.author}', source='{profile.source}'",
                location=profile.path,
                remediation=(
                    "Add an 'author' field to the skill's SKILL.md or claw.yaml. "
                    "Only install skills from verified, trusted publishers."
                ),
                run_id=run_id,
            )
        ]

    def check_supply_chain_risk(self, profile: SkillProfile, run_id: str) -> list[Finding]:
        """Flag skills contacting domains outside the known-safe allowlist."""
        risky = [d for d in profile.outbound_domains if d not in _SAFE_DOMAINS]
        if not risky:
            return []
        return [
            _finding(
                check_id="ADV-003",
                domain="network",
                title=f"Supply chain risk — unknown outbound domains in '{profile.name}'",
                description=(
                    f"Skill '{profile.name}' contacts {len(risky)} domain(s) not in the "
                    f"trusted allowlist: {', '.join(risky)}"
                ),
                severity="HIGH",
                evidence=f"risky_domains={risky}",
                location=profile.path,
                remediation=(
                    "Review each unlisted domain. Add legitimate ones to the organisational "
                    "allowlist. Remove or sandbox skills contacting unknown external endpoints."
                ),
                run_id=run_id,
            )
        ]

    def check_unsigned_skill(self, profile: SkillProfile, run_id: str) -> list[Finding]:
        """Flag skills that are not cryptographically signed."""
        if profile.is_signed:
            return []
        return [
            _finding(
                check_id="ADV-004",
                domain="integrity",
                title=f"Unsigned skill '{profile.name}'",
                description=(
                    f"Skill '{profile.name}' is not cryptographically signed. "
                    "Without a signature, integrity cannot be verified."
                ),
                severity="LOW",
                evidence="is_signed=False",
                location=profile.path,
                remediation=(
                    "Sign skills using the OpenClaw signing mechanism before deployment "
                    "in production environments."
                ),
                run_id=run_id,
            )
        ]

    def check_secrets_in_config(self, skill_path: Path, run_id: str) -> list[Finding]:
        """Scan SKILL.md for exposed secrets/credentials."""
        findings: list[Finding] = []
        if not skill_path.exists():
            return findings

        try:
            content = skill_path.read_text(errors="ignore")
        except OSError:
            return findings

        for label, pattern in _SECRET_PATTERNS:
            if pattern.search(content):
                findings.append(
                    _finding(
                        check_id="ADV-005",
                        domain="secrets",
                        title=f"Potential secret exposure in '{skill_path.parent.name}' SKILL.md",
                        description=(
                            f"Pattern matching '{label}' was found in {skill_path}. "
                            "Hardcoded secrets in skill files are a critical security risk."
                        ),
                        severity="CRITICAL",
                        evidence=f"pattern='{label}' matched in {skill_path.name}",
                        location=str(skill_path),
                        remediation=(
                            "Remove the secret from the skill file immediately. "
                            "Use environment variables or a secrets manager instead. "
                            "Rotate any exposed credentials."
                        ),
                        run_id=run_id,
                    )
                )
                break  # One finding per file is enough

        return findings

    def run_all(self, profile: SkillProfile, skill_path: Path, run_id: str) -> list[Finding]:
        """Run all advanced checks for a skill profile."""
        findings: list[Finding] = []
        findings.extend(self.check_unrestricted_shell(profile, run_id))
        findings.extend(self.check_unknown_publisher(profile, run_id))
        findings.extend(self.check_supply_chain_risk(profile, run_id))
        findings.extend(self.check_unsigned_skill(profile, run_id))
        findings.extend(self.check_secrets_in_config(skill_path, run_id))
        return findings
