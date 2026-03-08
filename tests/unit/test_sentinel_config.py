"""Unit tests for sentinel.config SecurityConfig."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.config import (
    _DEFAULT_SAFE_DOMAINS,
    ScanConfig,
    SecurityConfig,
)

pytestmark = pytest.mark.unit


class TestSecurityConfig:
    def test_load_returns_defaults_when_no_file(self):
        cfg = SecurityConfig.load(path=Path("/nonexistent/config.yaml"))
        assert cfg.safe_domains == _DEFAULT_SAFE_DOMAINS
        assert cfg.scan.scan_scripts is True

    def test_load_reads_yaml_file(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(
            "safe_domains:\n"
            "  - example.com\n"
            "  - custom.org\n"
            "scan:\n"
            "  severity_threshold: high\n"
            "  scan_scripts: false\n"
        )
        cfg = SecurityConfig.load(path=cfg_file)
        assert "example.com" in cfg.safe_domains
        assert "custom.org" in cfg.safe_domains
        assert cfg.scan.severity_threshold == "high"
        assert cfg.scan.scan_scripts is False

    def test_load_merges_custom_domains(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("safe_domains:\n  - my-cdn.com\n")
        cfg = SecurityConfig.load(path=cfg_file)
        assert "my-cdn.com" in cfg.safe_domains
        # Should NOT have defaults since we provided explicit list
        # (replace, not merge)

    def test_load_handles_corrupt_yaml_gracefully(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(": {invalid yaml[")
        cfg = SecurityConfig.load(path=cfg_file)
        # Should fall back to defaults
        assert cfg.safe_domains == _DEFAULT_SAFE_DOMAINS

    def test_write_defaults_creates_file(self, tmp_path):
        path = tmp_path / "config.yaml"
        SecurityConfig.write_defaults(path=path)
        assert path.exists()
        content = path.read_text()
        assert "safe_domains:" in content
        assert "scan_scripts:" in content

    def test_write_defaults_contains_all_default_domains(self, tmp_path):
        path = tmp_path / "config.yaml"
        SecurityConfig.write_defaults(path=path)
        content = path.read_text()
        for domain in _DEFAULT_SAFE_DOMAINS:
            assert domain in content

    def test_scan_config_defaults(self):
        sc = ScanConfig()
        assert sc.severity_threshold == "low"
        assert sc.scan_scripts is True
        assert sc.max_script_size_mb == 1.0

    def test_scan_config_loaded_from_yaml(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(
            "scan:\n"
            "  severity_threshold: critical\n"
            "  scan_scripts: true\n"
            "  max_script_size_mb: 2.5\n"
        )
        cfg = SecurityConfig.load(path=cfg_file)
        assert cfg.scan.severity_threshold == "critical"
        assert cfg.scan.max_script_size_mb == 2.5
