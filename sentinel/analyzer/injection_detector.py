"""Shell and prompt injection detection."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Literal

# Patterns that indicate shell execution contexts
SHELL_EXECUTION_PATTERNS: list[tuple[str, str]] = [
    (r"exec\s*\(", "exec() call"),
    (r"pty\s*:\s*true", "pty:true flag"),
    (r"\bsh\s+-c\b", "sh -c invocation"),
    (r"\bbash\s+-c\b", "bash -c invocation"),
    (r"`[^`]+`", "backtick command substitution"),
    (r"\$\([^)]+\)", "command substitution $()"),
    (r"\bsubprocess\b", "subprocess module reference"),
    (r"\bos\.system\b", "os.system call"),
    (r"\beval\b", "eval usage"),
]

# Patterns indicating user input in shell context
INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern, description, risk_level)
    (r"\{[a-zA-Z_][a-zA-Z0-9_]*\}.*(?:exec|bash|sh|curl|wget)", "template var in shell cmd", "HIGH"),
    (r"--yolo", "--yolo flag without gate", "HIGH"),
    (r"\$[@*]", "$@ or $* shell expansion", "HIGH"),
    (r"\beval\b", "eval in any context", "HIGH"),
    (r"\{user_?input\}", "user_input template variable", "CRITICAL"),
    (r"\{query\}.*(?:curl|bash|sh|exec)", "query var in shell context", "CRITICAL"),
    (r"(?:curl|wget).*\{[^}]+\}", "URL template var in curl/wget", "HIGH"),
    (r"(?:git|npm|pip).*\{[^}]+\}", "template var in package manager", "MEDIUM"),
]

RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
RISK_LABELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class InjectionFinding:
    """A detected injection risk."""

    description: str
    risk_level: str
    line_number: int
    evidence: str


@dataclass
class InjectionReport:
    """Aggregated injection risk report for a piece of content."""

    overall_risk: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    findings: List[InjectionFinding] = field(default_factory=list)

    def _recalculate_risk(self) -> None:
        if not self.findings:
            self.overall_risk = "LOW"
            return
        max_idx = max(RISK_ORDER.get(f.risk_level, 0) for f in self.findings)
        self.overall_risk = RISK_LABELS[max_idx]  # type: ignore[assignment]

    def add(self, finding: InjectionFinding) -> None:
        self.findings.append(finding)
        self._recalculate_risk()


class InjectionDetector:
    """Detects shell and prompt injection risks in skill content."""

    def analyze_text(self, text: str, location: str = "") -> InjectionReport:
        """Analyze text for injection vulnerabilities."""
        report = InjectionReport()
        lines = text.splitlines()

        for line_num, line in enumerate(lines, start=1):
            for pattern, description, risk in INJECTION_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    # Sanitize the evidence
                    evidence = line.strip()[:120]
                    report.add(InjectionFinding(
                        description=description,
                        risk_level=risk,
                        line_number=line_num,
                        evidence=evidence,
                    ))

        return report

    def analyze_file(self, path: Path) -> InjectionReport:
        """Analyze a file for injection risks."""
        try:
            text = path.read_text(errors="replace")
            return self.analyze_text(text, str(path))
        except (OSError, PermissionError):
            return InjectionReport()
