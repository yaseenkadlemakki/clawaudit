"""Unit tests for sentinel.lifecycle.installer."""

from __future__ import annotations

import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sentinel.lifecycle.installer import SkillAlreadyInstalledError, SkillInstaller
from sentinel.lifecycle.registry import SkillRegistry

pytestmark = pytest.mark.unit


def _make_skill_tarball(tmp_path: Path, name: str = "demo", version: str | None = None) -> Path:
    """Create a valid .skill tarball containing SKILL.md."""
    skill_dir = tmp_path / "build" / name
    skill_dir.mkdir(parents=True)
    content = f"name: {name}\n"
    if version:
        content += f"version: {version}\n"
    (skill_dir / "SKILL.md").write_text(content)
    tarball = tmp_path / f"{name}.skill"
    with tarfile.open(tarball, "w:gz") as tar:
        tar.add(skill_dir, arcname=name)
    return tarball


class TestSkillInstaller:
    def test_install_from_valid_skill_file(self, tmp_path):
        tarball = _make_skill_tarball(tmp_path, "hello")
        skills_dir = tmp_path / "skills"
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        installer = SkillInstaller(skills_dir, reg)

        record = installer.install_from_file(tarball)
        assert record.name == "hello"
        assert (skills_dir / "hello" / "SKILL.md").exists()
        assert reg.get("hello") is not None

    def test_install_rejects_missing_skill_md(self, tmp_path):
        # Create a tarball without SKILL.md
        no_skill_dir = tmp_path / "build" / "bad"
        no_skill_dir.mkdir(parents=True)
        (no_skill_dir / "README.md").write_text("no skill here")
        tarball = tmp_path / "bad.skill"
        with tarfile.open(tarball, "w:gz") as tar:
            tar.add(no_skill_dir, arcname="bad")

        skills_dir = tmp_path / "skills"
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        installer = SkillInstaller(skills_dir, reg)

        with pytest.raises(ValueError, match="SKILL.md"):
            installer.install_from_file(tarball)

    def test_install_rejects_missing_name_field(self, tmp_path):
        skill_dir = tmp_path / "build" / "noname"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("# Just a title\nNo name field here.")
        tarball = tmp_path / "noname.skill"
        with tarfile.open(tarball, "w:gz") as tar:
            tar.add(skill_dir, arcname="noname")

        skills_dir = tmp_path / "skills"
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        installer = SkillInstaller(skills_dir, reg)

        with pytest.raises(ValueError, match="name"):
            installer.install_from_file(tarball)

    def test_install_prevents_path_traversal(self, tmp_path):
        # Create a tarball with a ../ entry
        tarball = tmp_path / "evil.skill"
        skill_dir = tmp_path / "build" / "evil"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("name: evil\n")

        with tarfile.open(tarball, "w:gz") as tar:
            tar.add(skill_dir / "SKILL.md", arcname="evil/SKILL.md")
            # Add a malicious traversal member
            info = tarfile.TarInfo(name="../../../etc/passwd")
            info.size = 4
            import io

            tar.addfile(info, io.BytesIO(b"pwnd"))

        skills_dir = tmp_path / "skills"
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        installer = SkillInstaller(skills_dir, reg)

        # Should install successfully but skip the traversal member
        record = installer.install_from_file(tarball)
        assert record.name == "evil"
        # The traversal file must not exist
        assert not (tmp_path / "etc" / "passwd").exists()

    def test_install_from_url_calls_httpx(self, tmp_path):
        tarball = _make_skill_tarball(tmp_path, "remote")
        tarball_bytes = tarball.read_bytes()

        skills_dir = tmp_path / "skills"
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        installer = SkillInstaller(skills_dir, reg)

        # Mock httpx — imported lazily inside install_from_url
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.iter_bytes = MagicMock(return_value=[tarball_bytes])
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        mock_httpx = MagicMock()
        mock_httpx.stream = MagicMock(return_value=mock_response)

        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            record = installer.install_from_url("https://example.com/remote.skill")

        assert record.name == "remote"
        assert record.source == "https://example.com/remote.skill"

    def test_install_from_url_rejects_non_http(self, tmp_path):
        skills_dir = tmp_path / "skills"
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        installer = SkillInstaller(skills_dir, reg)

        with pytest.raises(ValueError, match="http"):
            installer.install_from_url("ftp://evil.com/bad.skill")

    def test_install_rejects_already_installed(self, tmp_path):
        tarball = _make_skill_tarball(tmp_path, "dup")
        skills_dir = tmp_path / "skills"
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        installer = SkillInstaller(skills_dir, reg)

        installer.install_from_file(tarball)
        # Second install with same content should raise already-installed
        tarball2 = _make_skill_tarball(tmp_path / "again", "dup")
        with pytest.raises(SkillAlreadyInstalledError):
            installer.install_from_file(tarball2)

    def test_parse_version_from_frontmatter(self, tmp_path):
        tarball = _make_skill_tarball(tmp_path, "versioned", version="3.2.1")
        skills_dir = tmp_path / "skills"
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        installer = SkillInstaller(skills_dir, reg)

        record = installer.install_from_file(tarball)
        assert record.version == "3.2.1"

    def test_parse_version_defaults_unknown(self, tmp_path):
        tarball = _make_skill_tarball(tmp_path, "noversion")
        skills_dir = tmp_path / "skills"
        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        installer = SkillInstaller(skills_dir, reg)

        record = installer.install_from_file(tarball)
        assert record.version == "unknown"


class TestSSRFValidation:
    """Tests for _validate_url_ssrf() — the most critical security function in the PR."""

    def _installer(self, tmp_path):
        from sentinel.lifecycle.installer import SkillInstaller
        from sentinel.lifecycle.registry import SkillRegistry

        reg = SkillRegistry(registry_path=tmp_path / "registry.json")
        return SkillInstaller(tmp_path / "skills", reg)

    def test_rejects_http_scheme(self, tmp_path):
        installer = self._installer(tmp_path)
        with pytest.raises(ValueError, match="https"):
            installer._validate_url_ssrf("http://example.com/skill.skill")

    def test_rejects_ftp_scheme(self, tmp_path):
        installer = self._installer(tmp_path)
        with pytest.raises(ValueError, match="https"):
            installer._validate_url_ssrf("ftp://example.com/skill.skill")

    def test_rejects_loopback_ipv4(self, tmp_path):
        installer = self._installer(tmp_path)
        with pytest.raises(ValueError, match="blocked"):
            installer._validate_url_ssrf("https://127.0.0.1/skill.skill")

    def test_rejects_loopback_ipv6(self, tmp_path):
        installer = self._installer(tmp_path)
        with pytest.raises(ValueError, match="blocked"):
            installer._validate_url_ssrf("https://[::1]/skill.skill")

    def test_rejects_private_rfc1918_10x(self, tmp_path):
        installer = self._installer(tmp_path)
        with pytest.raises(ValueError, match="blocked"):
            installer._validate_url_ssrf("https://10.0.0.1/skill.skill")

    def test_rejects_private_rfc1918_192168(self, tmp_path):
        installer = self._installer(tmp_path)
        with pytest.raises(ValueError, match="blocked"):
            installer._validate_url_ssrf("https://192.168.1.1/skill.skill")

    def test_rejects_link_local_169254(self, tmp_path):
        """AWS/GCP metadata endpoint — must be blocked."""
        installer = self._installer(tmp_path)
        with pytest.raises(ValueError, match="blocked"):
            installer._validate_url_ssrf("https://169.254.169.254/latest/meta-data")

    def test_rejects_no_hostname(self, tmp_path):
        installer = self._installer(tmp_path)
        with pytest.raises(ValueError, match="hostname"):
            installer._validate_url_ssrf("https:///path")

    def test_rejects_unresolvable_hostname(self, tmp_path):
        installer = self._installer(tmp_path)
        with pytest.raises(ValueError, match="resolve"):
            installer._validate_url_ssrf(
                "https://this.hostname.definitely.does.not.exist.invalid/x"
            )

    def test_returns_safe_ip_for_valid_url(self, tmp_path):
        """_validate_url_ssrf returns a non-empty IP string for a resolvable public host."""
        import socket

        installer = self._installer(tmp_path)
        # Only run if DNS is available in test environment
        try:
            socket.getaddrinfo("one.one.one.one", 443)
        except socket.gaierror:
            pytest.skip("DNS not available in test environment")
        result = installer._validate_url_ssrf("https://one.one.one.one/skill.skill")
        assert isinstance(result, str)
        assert len(result) > 0
