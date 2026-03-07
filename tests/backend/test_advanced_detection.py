"""Tests for backend.engine.advanced_detection."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from backend.engine.advanced_detection import AdvancedDetector
from sentinel.models.skill import SkillProfile


def _profile(**kwargs) -> SkillProfile:
    defaults = dict(
        name="test-skill",
        path="/tmp/test-skill/SKILL.md",
        author="trusted-author",
        source="https://example.com",
        shell_access=False,
        shell_evidence=[],
        outbound_domains=[],
        injection_risk="LOW",
        injection_evidence=[],
        trust_score="TRUSTED",
        is_signed=True,
    )
    defaults.update(kwargs)
    return SkillProfile(**defaults)


RUN_ID = "run-test-123"


class TestCheckUnrestrictedShell:
    def test_no_finding_when_shell_disabled(self):
        detector = AdvancedDetector()
        profile = _profile(shell_access=False)
        assert detector.check_unrestricted_shell(profile, RUN_ID) == []

    def test_finding_when_shell_enabled(self):
        detector = AdvancedDetector()
        profile = _profile(shell_access=True, shell_evidence=["exec bash"])
        findings = detector.check_unrestricted_shell(profile, RUN_ID)
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"
        assert findings[0].check_id == "ADV-001"
        assert "test-skill" in findings[0].title

    def test_finding_includes_remediation(self):
        detector = AdvancedDetector()
        profile = _profile(shell_access=True)
        findings = detector.check_unrestricted_shell(profile, RUN_ID)
        assert findings[0].remediation


class TestCheckUnknownPublisher:
    def test_no_finding_when_author_set(self):
        detector = AdvancedDetector()
        profile = _profile(author="trusted-corp")
        assert detector.check_unknown_publisher(profile, RUN_ID) == []

    def test_finding_when_author_empty(self):
        detector = AdvancedDetector()
        profile = _profile(author="")
        findings = detector.check_unknown_publisher(profile, RUN_ID)
        assert len(findings) == 1
        assert findings[0].severity == "MEDIUM"
        assert findings[0].check_id == "ADV-002"

    def test_finding_when_author_whitespace(self):
        detector = AdvancedDetector()
        profile = _profile(author="   ")
        findings = detector.check_unknown_publisher(profile, RUN_ID)
        assert len(findings) == 1


class TestCheckSupplyChainRisk:
    def test_no_finding_for_safe_domains(self):
        detector = AdvancedDetector()
        profile = _profile(outbound_domains=["github.com", "api.anthropic.com"])
        assert detector.check_supply_chain_risk(profile, RUN_ID) == []

    def test_finding_for_unknown_domain(self):
        detector = AdvancedDetector()
        profile = _profile(outbound_domains=["evil-exfil.io", "github.com"])
        findings = detector.check_supply_chain_risk(profile, RUN_ID)
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"
        assert findings[0].check_id == "ADV-003"
        assert "evil-exfil.io" in findings[0].description

    def test_no_finding_for_empty_domains(self):
        detector = AdvancedDetector()
        profile = _profile(outbound_domains=[])
        assert detector.check_supply_chain_risk(profile, RUN_ID) == []

    def test_multiple_risky_domains_single_finding(self):
        detector = AdvancedDetector()
        profile = _profile(outbound_domains=["bad1.io", "bad2.io"])
        findings = detector.check_supply_chain_risk(profile, RUN_ID)
        assert len(findings) == 1


class TestCheckUnsignedSkill:
    def test_no_finding_when_signed(self):
        detector = AdvancedDetector()
        profile = _profile(is_signed=True)
        assert detector.check_unsigned_skill(profile, RUN_ID) == []

    def test_finding_when_unsigned(self):
        detector = AdvancedDetector()
        profile = _profile(is_signed=False)
        findings = detector.check_unsigned_skill(profile, RUN_ID)
        assert len(findings) == 1
        assert findings[0].severity == "LOW"
        assert findings[0].check_id == "ADV-004"


class TestCheckSecretsInConfig:
    def test_no_finding_for_clean_file(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text("# Clean skill\n\nDoes harmless things.")
        detector = AdvancedDetector()
        assert detector.check_secrets_in_config(skill_file, RUN_ID) == []

    def test_finding_for_anthropic_key(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text("# Skill\n\napi_key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456")
        detector = AdvancedDetector()
        findings = detector.check_secrets_in_config(skill_file, RUN_ID)
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"
        assert findings[0].check_id == "ADV-005"

    def test_finding_for_openai_key(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text("secret = sk-abcdefghijklmnopqrstuvwxyz123456789012")
        detector = AdvancedDetector()
        findings = detector.check_secrets_in_config(skill_file, RUN_ID)
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"

    def test_finding_for_github_pat(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        detector = AdvancedDetector()
        findings = detector.check_secrets_in_config(skill_file, RUN_ID)
        assert len(findings) == 1

    def test_finding_for_private_key(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...")
        detector = AdvancedDetector()
        findings = detector.check_secrets_in_config(skill_file, RUN_ID)
        assert len(findings) == 1

    def test_finding_for_generic_token(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text("config:\n  password: mysupersecretpassword123456")
        detector = AdvancedDetector()
        findings = detector.check_secrets_in_config(skill_file, RUN_ID)
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"
        assert findings[0].check_id == "ADV-005"

    def test_returns_empty_for_missing_file(self, tmp_path):
        detector = AdvancedDetector()
        findings = detector.check_secrets_in_config(tmp_path / "nonexistent.md", RUN_ID)
        assert findings == []

    def test_only_one_finding_per_file(self, tmp_path):
        """Multiple secret patterns in one file should produce one finding."""
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text(
            "key1: sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456\n"
            "key2: sk-abcdefghijklmnopqrstuvwxyz1234567890"
        )
        detector = AdvancedDetector()
        findings = detector.check_secrets_in_config(skill_file, RUN_ID)
        assert len(findings) == 1


class TestRunAll:
    def test_clean_profile_returns_no_findings(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text("# Clean skill")
        profile = _profile(
            shell_access=False,
            author="trusted",
            outbound_domains=["github.com"],
            is_signed=True,
        )
        detector = AdvancedDetector()
        findings = detector.run_all(profile, skill_file, RUN_ID)
        # Signed + known domains + author + no shell → only unsigned is suppressed
        assert all(f.check_id != "ADV-001" for f in findings)

    def test_risky_profile_returns_multiple_findings(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text("api_key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456")
        profile = _profile(
            shell_access=True,
            author="",
            outbound_domains=["evil.io"],
            is_signed=False,
        )
        detector = AdvancedDetector()
        findings = detector.run_all(profile, skill_file, RUN_ID)
        check_ids = {f.check_id for f in findings}
        assert "ADV-001" in check_ids  # shell
        assert "ADV-002" in check_ids  # unknown publisher
        assert "ADV-003" in check_ids  # supply chain
        assert "ADV-004" in check_ids  # unsigned
        assert "ADV-005" in check_ids  # secrets
