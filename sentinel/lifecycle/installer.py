"""Install skills from local .skill files (tar.gz) or HTTP URLs."""

from __future__ import annotations

import hashlib
import logging
import re
import shutil
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from sentinel.lifecycle.registry import SkillRecord, SkillRegistry

logger = logging.getLogger(__name__)


class SkillAlreadyInstalledError(Exception):
    """Raised when a skill is already installed with the same content hash."""


class SkillHashMismatchError(Exception):
    """Raised when a skill is already installed but content hash differs."""


_NAME_RE = re.compile(r"^(?:name\s*:\s*)(.+)", re.MULTILINE)
_VERSION_RE = re.compile(r"^(?:version\s*:\s*)(.+)", re.MULTILINE)


def _safe_members(tar: tarfile.TarFile, target: Path) -> list[tarfile.TarInfo]:
    """Filter tar members to prevent path traversal attacks."""
    safe: list[tarfile.TarInfo] = []
    resolved_target = target.resolve()
    for member in tar.getmembers():
        member_path = (target / member.name).resolve()
        if not (member_path == resolved_target or member_path.is_relative_to(resolved_target)):
            logger.warning("Skipping unsafe tar member: %s", member.name)
            continue
        safe.append(member)
    return safe


class SkillInstaller:
    """Install skills from .skill files or URLs into a skills directory."""

    def __init__(self, skills_dir: Path, registry: SkillRegistry) -> None:
        self._skills_dir = skills_dir
        self._registry = registry

    def install_from_file(self, skill_path: Path, force: bool = False) -> SkillRecord:
        """Install a skill from a local .skill (tar.gz) file.

        Raises:
            FileNotFoundError: If skill_path doesn't exist.
            ValueError: If the archive is invalid or missing SKILL.md/name.
            FileExistsError: If the skill is already installed (no hash tracking).
            SkillAlreadyInstalledError: If already installed with same hash.
            SkillHashMismatchError: If already installed but hash differs.
        """
        if not skill_path.exists():
            raise FileNotFoundError(f"Skill file not found: {skill_path}")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with tarfile.open(skill_path, "r:gz") as tar:
                safe = _safe_members(tar, tmp_path)
                if not safe:
                    raise ValueError("Archive contains no safe members")
                try:
                    tar.extractall(path=tmp_path, members=safe, filter="data")
                except TypeError:
                    tar.extractall(path=tmp_path, members=safe)

            # Find SKILL.md in extracted content
            skill_name = self._validate_manifest(tmp_path)

            # Locate the extracted skill root (may be nested one level)
            skill_root = self._find_skill_root(tmp_path)

            # Compute content hash of the new archive
            new_hash = self._compute_skill_hash(skill_root)

            # Check not already installed
            dest = self._skills_dir / skill_name
            existing = self._registry.get(skill_name)
            if dest.exists() and not force:
                if existing and existing.content_hash:
                    if existing.content_hash == new_hash:
                        raise SkillAlreadyInstalledError(f"Skill '{skill_name}' already up to date")
                    raise SkillHashMismatchError(
                        f"Skill '{skill_name}' hash changed, use --force to override"
                    )
                raise FileExistsError(f"Skill '{skill_name}' is already installed at {dest}")

            # If force and dest exists, remove old copy first
            if dest.exists() and force:
                shutil.rmtree(dest)

            # Move to skills dir
            self._skills_dir.mkdir(parents=True, exist_ok=True)
            shutil.copytree(skill_root, dest)

        version = self._parse_version(dest)
        source = "local"
        record = SkillRecord(
            name=skill_name,
            path=str(dest),
            source=source,
            version=version,
            installed_at=datetime.now(timezone.utc).isoformat(),  # noqa: UP017
            enabled=True,
            content_hash=new_hash,
        )
        self._registry.register(record)
        logger.info("Installed skill '%s' to %s", skill_name, dest)
        return record

    @staticmethod
    def _validate_url_ssrf(url: str) -> str:
        """Validate URL and return the safe resolved IP to pin during download.

        Blocks: http (non-TLS), loopback, RFC-1918 private, link-local (169.254.x.x).
        Returns the first resolved IP as a string so the caller can pin it in the
        HTTP transport, preventing DNS rebinding between validation and download.

        Raises:
            ValueError: If the URL or its resolved address is unsafe.
        """
        import ipaddress
        import socket
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise ValueError(f"Only https:// URLs are allowed, got: {parsed.scheme!r}")

        hostname = parsed.hostname
        if not hostname:
            raise ValueError("URL has no hostname")

        try:
            infos = socket.getaddrinfo(hostname, parsed.port or 443, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError(f"Could not resolve hostname {hostname!r}: {exc}") from exc

        safe_ip: str | None = None
        for *_, sockaddr in infos:
            addr = ipaddress.ip_address(sockaddr[0])
            if addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_reserved:
                raise ValueError(f"SSRF blocked: {hostname!r} resolves to a blocked address {addr}")
            if safe_ip is None:
                safe_ip = str(addr)

        if safe_ip is None:
            raise ValueError(f"Could not determine safe IP for {hostname!r}")

        return safe_ip

    def install_from_url(self, url: str, force: bool = False) -> SkillRecord:
        """Download a .skill file from a URL and install it.

        Raises:
            ValueError: If the URL is not https or resolves to a blocked address.
        """
        from urllib.parse import urlparse

        # Validate and get the pinned IP to prevent DNS rebinding
        safe_ip = self._validate_url_ssrf(url)
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        port = parsed.port or 443

        try:
            import httpx
        except ImportError as exc:
            raise ImportError("httpx is required for URL installs: pip install httpx") from exc

        # Pin the transport to the validated IP — prevents DNS rebinding on re-resolution
        transport = httpx.HTTPTransport(local_address=None)
        # Override Host header and connect directly to the pinned IP
        pinned_url = url.replace(f"https://{hostname}", f"https://{safe_ip}", 1)
        headers = {"Host": f"{hostname}:{port}" if port != 443 else hostname}

        with tempfile.NamedTemporaryFile(suffix=".skill", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            with httpx.stream(
                "GET",
                pinned_url,
                headers=headers,
                timeout=30.0,
                follow_redirects=False,  # don't follow redirects — could redirect to private IP
                verify=True,
                transport=transport,
            ) as resp:
                resp.raise_for_status()
                with tmp_path.open("wb") as fh:
                    for chunk in resp.iter_bytes():
                        fh.write(chunk)
            record = self.install_from_file(tmp_path, force=force)
            # Override source to the original URL (install_from_file records "local").
            # Use a single locked register call — do NOT call register() again here
            # to avoid a double-write race under concurrent requests. (#17 review #4)
            with self._registry._locked():  # noqa: SLF001
                records = self._registry.load()
                if record.name in records:
                    records[record.name].source = url
                    self._registry.save(records)
                    record.source = url
            return record
        finally:
            tmp_path.unlink(missing_ok=True)

    def _validate_manifest(self, extract_dir: Path) -> str:
        """Validate extracted archive has SKILL.md with a name field.

        Returns the skill name.
        """
        # Search for SKILL.md in the extracted tree
        skill_mds = list(extract_dir.rglob("SKILL.md"))
        if not skill_mds:
            raise ValueError("Archive does not contain a SKILL.md file")

        text = skill_mds[0].read_text(errors="replace")
        match = _NAME_RE.search(text)
        if not match:
            raise ValueError("SKILL.md does not contain a 'name:' field")

        return match.group(1).strip().strip("\"'")

    def _parse_version(self, skill_dir: Path) -> str:
        """Parse version from SKILL.md front-matter, default 'unknown'."""
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            return "unknown"
        text = skill_md.read_text(errors="replace")
        match = _VERSION_RE.search(text)
        if match:
            return match.group(1).strip().strip("\"'")
        return "unknown"

    def _find_skill_root(self, extract_dir: Path) -> Path:
        """Locate the directory containing SKILL.md."""
        # Check if SKILL.md is at top level
        if (extract_dir / "SKILL.md").exists():
            return extract_dir
        # Check one level deep
        for child in extract_dir.iterdir():
            if child.is_dir() and (child / "SKILL.md").exists():
                return child
        # Fallback: search recursively
        for skill_md in extract_dir.rglob("SKILL.md"):
            return skill_md.parent
        raise ValueError("Cannot locate SKILL.md in extracted archive")

    @staticmethod
    def _compute_skill_hash(skill_dir: Path) -> str:
        """SHA-256 hash of all files in *skill_dir*, sorted by path for determinism."""
        hasher = hashlib.sha256()
        for file_path in sorted(skill_dir.rglob("*")):
            if file_path.is_file():
                hasher.update(str(file_path.relative_to(skill_dir)).encode())
                hasher.update(file_path.read_bytes())
        return hasher.hexdigest()
