"""Audit engine — wraps sentinel's ConfigAuditor and SkillAnalyzer."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable

from sentinel.analyzer.config_auditor import ConfigAuditor
from sentinel.analyzer.skill_analyzer import SkillAnalyzer
from sentinel.config import load_config
from sentinel.models.finding import Finding
from sentinel.models.skill import SkillProfile

from backend.engine.advanced_detection import AdvancedDetector
from backend.engine.risk_scoring import score_skill

logger = logging.getLogger(__name__)


class AuditEngine:
    """
    Wraps existing sentinel analyzers into a single async-friendly pipeline.

    Emits findings and skill profiles via callbacks so the ScanManager can
    stream them to WebSocket clients and persist them to the DB.
    """

    def __init__(self) -> None:
        self._config_auditor = ConfigAuditor()
        self._skill_analyzer = SkillAnalyzer()
        self._advanced_detector = AdvancedDetector()

    def load_openclaw_config(self) -> dict[str, Any]:
        """Load the openclaw.json config for auditing."""
        cfg = load_config()
        if cfg.config_file.exists():
            try:
                return json.loads(cfg.config_file.read_text())
            except Exception as exc:
                logger.warning("Failed to read openclaw.json: %s", exc)
        return {}

    def run_config_audit(self, run_id: str) -> list[Finding]:
        """Run ConfigAuditor against openclaw.json and return findings."""
        config_data = self.load_openclaw_config()
        findings = self._config_auditor.audit(config_data, run_id=run_id)
        logger.info("Config audit produced %d findings", len(findings))
        return findings

    def discover_skills(self) -> list[Path]:
        """Discover all SKILL.md files from configured skill directories."""
        cfg = load_config()
        skill_paths: list[Path] = []
        for skills_dir in [cfg.skills_dir, cfg.workspace_skills_dir]:
            if skills_dir.exists():
                skill_paths.extend(skills_dir.rglob("SKILL.md"))
        logger.info("Discovered %d skills", len(skill_paths))
        return skill_paths

    def analyze_skill(self, skill_path: Path, run_id: str) -> tuple[SkillProfile, int, str]:
        """
        Analyze a single skill file.

        Returns:
            (profile, risk_score, risk_level)
        """
        profile = self._skill_analyzer.analyze(skill_path, run_id=run_id)
        risk_score, risk_level = score_skill(profile)
        return profile, risk_score, risk_level

    async def run_full_audit(
        self,
        run_id: str,
        on_finding: Callable[[Finding, str | None], None] | None = None,
        on_skill: Callable[[SkillProfile, int, str], None] | None = None,
        on_progress: Callable[[int, int, str], None] | None = None,
        stop_flag: Callable[[], bool] | None = None,
    ) -> tuple[list[Finding], list[tuple[SkillProfile, int, str]]]:
        """
        Run the complete audit pipeline asynchronously.

        Args:
            run_id: Scan run UUID
            on_finding: Callback(finding, skill_name) for each finding
            on_skill: Callback(profile, risk_score, risk_level) for each skill
            on_progress: Callback(current, total, skill_name) for progress
            stop_flag: Callable returning True when scan should stop early

        Returns:
            (all_findings, skill_results)
        """
        all_findings: list[Finding] = []
        skill_results: list[tuple[SkillProfile, int, str]] = []

        # 1. Config audit
        config_findings = self.run_config_audit(run_id)
        for f in config_findings:
            all_findings.append(f)
            if on_finding:
                on_finding(f, None)

        # 2. Skill discovery + analysis
        skill_paths = self.discover_skills()
        total = len(skill_paths)

        for idx, skill_path in enumerate(skill_paths):
            if stop_flag and stop_flag():
                logger.info("Scan stop requested at skill %d/%d", idx, total)
                break

            if on_progress:
                on_progress(idx + 1, total, skill_path.parent.name)

            try:
                profile, risk_score, risk_level = self.analyze_skill(skill_path, run_id)
            except Exception as exc:
                logger.exception("Error analyzing skill %s: %s", skill_path, exc)
                continue

            skill_results.append((profile, risk_score, risk_level))

            if on_skill:
                on_skill(profile, risk_score, risk_level)

            for finding in profile.findings:
                all_findings.append(finding)
                if on_finding:
                    on_finding(finding, profile.name)

            # Advanced detection checks
            try:
                adv_findings = self._advanced_detector.run_all(profile, skill_path, run_id)
                for finding in adv_findings:
                    all_findings.append(finding)
                    if on_finding:
                        on_finding(finding, profile.name)
            except Exception as exc:
                logger.warning("Advanced detection error for %s: %s", skill_path, exc)

        return all_findings, skill_results
