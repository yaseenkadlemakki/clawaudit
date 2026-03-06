"""SkillProfile data model."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Literal, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .finding import Finding


@dataclass
class SkillProfile:
    """Security profile for an OpenClaw skill."""

    name: str
    path: str
    source: str = ""
    version: str = ""
    author: str = ""
    shell_access: bool = False
    shell_evidence: List[str] = field(default_factory=list)
    outbound_domains: List[str] = field(default_factory=list)
    injection_risk: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    injection_evidence: List[str] = field(default_factory=list)
    credential_exposure: bool = False
    trust_score: Literal["TRUSTED", "CAUTION", "UNTRUSTED", "QUARANTINE"] = "TRUSTED"
    trust_score_value: int = 100
    has_allowed_tools: bool = False
    is_signed: bool = False
    findings: List["Finding"] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "source": self.source,
            "version": self.version,
            "author": self.author,
            "shell_access": self.shell_access,
            "shell_evidence": self.shell_evidence,
            "outbound_domains": self.outbound_domains,
            "injection_risk": self.injection_risk,
            "injection_evidence": self.injection_evidence,
            "credential_exposure": self.credential_exposure,
            "trust_score": self.trust_score,
            "trust_score_value": self.trust_score_value,
            "has_allowed_tools": self.has_allowed_tools,
            "is_signed": self.is_signed,
            "findings": [f.to_dict() for f in self.findings],
        }
