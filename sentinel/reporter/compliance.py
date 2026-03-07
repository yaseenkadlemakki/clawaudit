"""Full compliance report generator."""

from __future__ import annotations

import uuid
from pathlib import Path

from sentinel.analyzer.config_auditor import ConfigAuditor
from sentinel.analyzer.skill_analyzer import SkillAnalyzer
from sentinel.config import SentinelConfig
from sentinel.models.finding import Finding
from sentinel.reporter.renderer import render_json, render_markdown


class ComplianceReporter:
    """Generates comprehensive compliance reports."""

    def __init__(self, config: SentinelConfig) -> None:
        self._config = config
        self._config_auditor = ConfigAuditor()
        self._skill_analyzer = SkillAnalyzer()

    def run_full_audit(self) -> tuple[str, list[Finding]]:
        """Run all checks, return (run_id, findings)."""
        run_id = str(uuid.uuid4())
        findings: list[Finding] = []

        # Config audit
        if self._config.config_file.exists():
            findings.extend(self._config_auditor.audit_file(self._config.config_file, run_id))

        # Skill analysis
        for skills_dir in [self._config.skills_dir, self._config.workspace_skills_dir]:
            if skills_dir.exists():
                for skill_md in skills_dir.rglob("SKILL.md"):
                    profile = self._skill_analyzer.analyze(skill_md, run_id)
                    findings.extend(profile.findings)

        return run_id, findings

    def generate(self, format: str = "markdown", output: Path | None = None) -> str:
        """Generate and optionally save a compliance report."""
        run_id, findings = self.run_full_audit()

        if format == "json":
            content = render_json(findings, run_id)
        else:
            content = render_markdown(findings, run_id)

        if output:
            output.write_text(content)

        return content
