"""Expanded unit tests for RemediationEngine — config findings and path resolution."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.remediation.engine import RemediationEngine, _STRATEGY_MAP
from sentinel.remediation.strategies import config_patch, permissions, shell_access


@pytest.mark.unit
class TestStrategyMapCoverage:
    """Verify the strategy map covers all expected check IDs."""

    def test_strategy_map_covers_conf_checks(self):
        for check_id in ["CONF-01", "CONF-02", "CONF-03", "CONF-04", "CONF-06", "CONF-07", "CONF-08"]:
            assert check_id in _STRATEGY_MAP, f"{check_id} missing from _STRATEGY_MAP"
            assert _STRATEGY_MAP[check_id] is config_patch

    def test_strategy_map_covers_skill01(self):
        assert "SKILL-01" in _STRATEGY_MAP
        assert _STRATEGY_MAP["SKILL-01"] is permissions

    def test_strategy_map_preserves_existing_adv(self):
        assert "ADV-001" in _STRATEGY_MAP
        assert "ADV-005" in _STRATEGY_MAP

    def test_strategy_map_preserves_perm001(self):
        assert "PERM-001" in _STRATEGY_MAP


@pytest.mark.unit
class TestConfigFindingHandling:
    """Verify config findings (no skill_name) are handled correctly."""

    def _write_config(self, path: Path, config: dict) -> Path:
        config_file = path / "openclaw.json"
        config_file.write_text(json.dumps(config, indent=2))
        return config_file

    def test_config_finding_without_skill_name_not_filtered(self, tmp_path):
        """CONF-xx findings with skill_name='' should produce proposals."""
        self._write_config(tmp_path, {"gateway": {"bind": "0.0.0.0"}})

        engine = RemediationEngine(skills_dir=tmp_path / "skills", config_dir=tmp_path)
        proposals = engine.scan_for_proposals([
            {
                "id": "f1",
                "check_id": "CONF-03",
                "skill_name": "",
                "location": "",
            },
        ])
        assert len(proposals) == 1
        assert proposals[0].check_id == "CONF-03"

    def test_config_finding_with_none_skill_name(self, tmp_path):
        """CONF-xx findings with skill_name=None should produce proposals."""
        self._write_config(tmp_path, {"yolo": True})

        engine = RemediationEngine(skills_dir=tmp_path / "skills", config_dir=tmp_path)
        proposals = engine.scan_for_proposals([
            {
                "id": "f1",
                "check_id": "CONF-06",
                "skill_name": None,
                "location": "",
            },
        ])
        assert len(proposals) == 1
        assert proposals[0].check_id == "CONF-06"

    def test_config_finding_no_config_file_returns_empty(self, tmp_path):
        """If openclaw.json doesn't exist, no proposals generated."""
        engine = RemediationEngine(skills_dir=tmp_path / "skills", config_dir=tmp_path)
        proposals = engine.scan_for_proposals([
            {
                "id": "f1",
                "check_id": "CONF-03",
                "skill_name": "",
                "location": "",
            },
        ])
        assert len(proposals) == 0


@pytest.mark.unit
class TestSkillPathResolution:
    """Verify file path resolution for skill/ADV findings."""

    def test_skill_finding_file_path_resolved_to_parent(self, tmp_path):
        """Location pointing to SKILL.md file should resolve to parent dir."""
        skill_dir = tmp_path / "test-skill"
        skill_dir.mkdir()
        skill_md = skill_dir / "SKILL.md"
        skill_md.write_text("pty: true\n")

        engine = RemediationEngine(skills_dir=tmp_path)
        proposals = engine.scan_for_proposals([
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "test-skill",
                "location": str(skill_md),  # File path, not directory
            },
        ])
        assert len(proposals) == 1

    def test_adv_finding_file_path_resolved(self, tmp_path):
        """ADV findings with file-path location should be resolved."""
        skill_dir = tmp_path / "risky-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("exec:\n  pty: true\n  security: full\n")

        engine = RemediationEngine(skills_dir=tmp_path)
        proposals = engine.scan_for_proposals([
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "risky-skill",
                "location": str(skill_dir / "SKILL.md"),
            },
        ])
        assert len(proposals) == 1

    def test_unknown_check_id_returns_empty(self, tmp_path):
        skill_dir = tmp_path / "test-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("safe content\n")

        engine = RemediationEngine(skills_dir=tmp_path)
        proposals = engine.scan_for_proposals([
            {
                "id": "f1",
                "check_id": "UNKNOWN-99",
                "skill_name": "test-skill",
                "location": str(skill_dir),
            },
        ])
        assert len(proposals) == 0


@pytest.mark.unit
class TestExistingStrategyRegression:
    """Ensure existing ADV strategies still work through the engine."""

    def test_adv001_shell_access_via_engine(self, tmp_path):
        skill_dir = tmp_path / "shell-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("exec:\n  pty: true\n")

        engine = RemediationEngine(skills_dir=tmp_path)
        proposals = engine.scan_for_proposals([
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "shell-skill",
                "location": str(skill_dir),
            },
        ])
        assert len(proposals) == 1
        assert proposals[0].check_id == "ADV-001"

    def test_adv005_secrets_via_engine(self, tmp_path):
        skill_dir = tmp_path / "secret-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("key: sk-ant-api123456789abcdefghij\n")

        engine = RemediationEngine(skills_dir=tmp_path)
        proposals = engine.scan_for_proposals([
            {
                "id": "f1",
                "check_id": "ADV-005",
                "skill_name": "secret-skill",
                "location": str(skill_dir),
            },
        ])
        assert len(proposals) == 1
        assert proposals[0].check_id == "ADV-005"


@pytest.mark.unit
class TestDeduplication:
    """Verify that duplicate findings produce only one proposal."""

    def _write_config(self, path: Path, config: dict) -> Path:
        config_file = path / "openclaw.json"
        config_file.write_text(json.dumps(config, indent=2))
        return config_file

    def test_duplicate_config_findings_produce_single_proposal(self, tmp_path):
        """Two identical CONF-03 findings should yield exactly one proposal."""
        self._write_config(tmp_path, {"gateway": {"bind": "0.0.0.0"}})

        engine = RemediationEngine(skills_dir=tmp_path / "skills", config_dir=tmp_path)
        proposals = engine.scan_for_proposals([
            {
                "id": "f1",
                "check_id": "CONF-03",
                "skill_name": "",
                "location": "",
            },
            {
                "id": "f2",
                "check_id": "CONF-03",
                "skill_name": "",
                "location": "",
            },
        ])
        assert len(proposals) == 1, f"Expected 1 proposal but got {len(proposals)}"

    def test_duplicate_skill_findings_produce_single_proposal(self, tmp_path):
        """Two identical ADV-001 findings for the same skill should yield one proposal."""
        skill_dir = tmp_path / "dup-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("exec:\n  pty: true\n")

        engine = RemediationEngine(skills_dir=tmp_path)
        proposals = engine.scan_for_proposals([
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "dup-skill",
                "location": str(skill_dir),
            },
            {
                "id": "f2",
                "check_id": "ADV-001",
                "skill_name": "dup-skill",
                "location": str(skill_dir),
            },
        ])
        assert len(proposals) == 1

    def test_different_check_ids_same_path_not_deduped(self, tmp_path):
        """Different check_ids for the same skill should produce separate proposals."""
        skill_dir = tmp_path / "multi-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("pty: true\npermissions: all\n")

        engine = RemediationEngine(skills_dir=tmp_path)
        proposals = engine.scan_for_proposals([
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "multi-skill",
                "location": str(skill_dir),
            },
            {
                "id": "f2",
                "check_id": "PERM-001",
                "skill_name": "multi-skill",
                "location": str(skill_dir),
            },
        ])
        assert len(proposals) == 2


@pytest.mark.unit
class TestCheckIdPassthrough:
    """Verify that SKILL-01 findings get the correct check_id on proposals."""

    def test_skill01_proposal_has_correct_check_id(self, tmp_path):
        """SKILL-01 maps to permissions strategy but must keep check_id='SKILL-01'."""
        skill_dir = tmp_path / "broad-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("allowed-tools: '*'\n")

        engine = RemediationEngine(skills_dir=tmp_path)
        proposals = engine.scan_for_proposals([
            {
                "id": "f1",
                "check_id": "SKILL-01",
                "skill_name": "broad-skill",
                "location": str(skill_dir),
            },
        ])
        assert len(proposals) == 1
        assert proposals[0].check_id == "SKILL-01", (
            f"Expected check_id='SKILL-01' but got '{proposals[0].check_id}'"
        )

    def test_perm001_proposal_still_works(self, tmp_path):
        """PERM-001 should still use the default check_id."""
        skill_dir = tmp_path / "perm-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("permissions: all\n")

        engine = RemediationEngine(skills_dir=tmp_path)
        proposals = engine.scan_for_proposals([
            {
                "id": "f1",
                "check_id": "PERM-001",
                "skill_name": "perm-skill",
                "location": str(skill_dir),
            },
        ])
        assert len(proposals) == 1
        assert proposals[0].check_id == "PERM-001"


@pytest.mark.unit
class TestSeverityPropagation:
    """Verify that severity flows through from findings to proposals."""

    def test_severity_propagated_to_skill_proposal(self, tmp_path):
        """Severity from finding dict should appear on the generated proposal."""
        skill_dir = tmp_path / "sev-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("exec:\n  pty: true\n")

        engine = RemediationEngine(skills_dir=tmp_path)
        proposals = engine.scan_for_proposals([
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "sev-skill",
                "location": str(skill_dir),
                "severity": "HIGH",
            },
        ])
        assert len(proposals) == 1
        assert proposals[0].severity == "HIGH"

    def test_severity_propagated_to_config_proposal(self, tmp_path):
        """Severity from config finding should appear on the config proposal."""
        config_file = tmp_path / "openclaw.json"
        config_file.write_text(json.dumps({"gateway": {"bind": "0.0.0.0"}}))

        engine = RemediationEngine(skills_dir=tmp_path / "skills", config_dir=tmp_path)
        proposals = engine.scan_for_proposals([
            {
                "id": "f1",
                "check_id": "CONF-03",
                "skill_name": "",
                "location": "",
                "severity": "CRITICAL",
            },
        ])
        assert len(proposals) == 1
        assert proposals[0].severity == "CRITICAL"

    def test_empty_severity_defaults_to_empty_string(self, tmp_path):
        """Missing severity should default to empty string."""
        skill_dir = tmp_path / "nosev-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("exec:\n  pty: true\n")

        engine = RemediationEngine(skills_dir=tmp_path)
        proposals = engine.scan_for_proposals([
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "nosev-skill",
                "location": str(skill_dir),
            },
        ])
        assert len(proposals) == 1
        assert proposals[0].severity == ""
