"""Configuration auditor — runs ClawAudit checks against OpenClaw config."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from sentinel.analyzer.secret_scanner import SecretScanner
from sentinel.models.finding import Finding


def _get_nested(data: dict, key_path: str, default: Any = None) -> Any:
    """Get a nested value using dot-notation key path."""
    parts = key_path.split(".")
    node = data
    for part in parts:
        if not isinstance(node, dict):
            return default
        node = node.get(part, default)
    return node


class ConfigAuditor:
    """Runs security checks against the OpenClaw configuration."""

    def __init__(self) -> None:
        self._secret_scanner = SecretScanner()

    def audit(self, config: dict[str, Any], run_id: str | None = None) -> list[Finding]:
        """Run all config checks and return findings."""
        run_id = run_id or str(uuid.uuid4())
        findings: list[Finding] = []

        checks = [
            self._check_discord_group_policy,
            self._check_telegram_group_policy,
            self._check_gateway_bind,
            self._check_gateway_auth,
            self._check_no_credentials_in_config,
            self._check_no_yolo_global,
            self._check_ratelimit_enabled,
            self._check_update_check_enabled,
        ]

        for check in checks:
            result = check(config, run_id)
            if result:
                findings.extend(result if isinstance(result, list) else [result])

        return findings

    def _check_discord_group_policy(self, config: dict, run_id: str) -> list[Finding]:
        """CONF-01: discord.groupPolicy must be allowlist."""
        findings = []
        channels = config.get("channels", {})
        discord = channels.get("discord", {})
        policy = discord.get("groupPolicy", "unknown")

        if policy not in ("allowlist", "unknown") and policy != "allowlist":
            findings.append(
                Finding(
                    check_id="CONF-01",
                    domain="config",
                    title="Discord groupPolicy is not 'allowlist'",
                    description=f"discord.groupPolicy is '{policy}'. Any server member can invoke the agent.",
                    severity="CRITICAL",
                    result="FAIL",
                    evidence=f"groupPolicy={policy}",
                    location="~/.openclaw/openclaw.json → channels.discord.groupPolicy",
                    remediation="Set channels.discord.groupPolicy to 'allowlist' in openclaw.json",
                    run_id=run_id,
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="CONF-01",
                    domain="config",
                    title="Discord groupPolicy is allowlist",
                    description="Discord group policy is correctly set.",
                    severity="INFO",
                    result="PASS",
                    evidence=f"groupPolicy={policy}",
                    location="~/.openclaw/openclaw.json → channels.discord.groupPolicy",
                    remediation="",
                    run_id=run_id,
                )
            )
        return findings

    def _check_telegram_group_policy(self, config: dict, run_id: str) -> list[Finding]:
        """CONF-02: telegram.groupPolicy must be allowlist."""
        findings = []
        channels = config.get("channels", {})
        telegram = channels.get("telegram", {})
        policy = telegram.get("groupPolicy", None)

        if policy is None:
            return []  # Telegram not configured

        if policy != "allowlist":
            findings.append(
                Finding(
                    check_id="CONF-02",
                    domain="config",
                    title="Telegram groupPolicy is not 'allowlist'",
                    description=f"telegram.groupPolicy is '{policy}'.",
                    severity="CRITICAL",
                    result="FAIL",
                    evidence=f"groupPolicy={policy}",
                    location="~/.openclaw/openclaw.json → channels.telegram.groupPolicy",
                    remediation="Set channels.telegram.groupPolicy to 'allowlist'",
                    run_id=run_id,
                )
            )
        return findings

    def _check_gateway_bind(self, config: dict, run_id: str) -> list[Finding]:
        """CONF-03: gateway.bind must be loopback."""
        gateway = config.get("gateway", {})
        bind = gateway.get("bind", "loopback")

        if bind not in ("loopback", "localhost", "127.0.0.1", "::1"):
            return [
                Finding(
                    check_id="CONF-03",
                    domain="config",
                    title="Gateway is not bound to loopback",
                    description=f"gateway.bind='{bind}' exposes the gateway to network interfaces.",
                    severity="HIGH",
                    result="FAIL",
                    evidence=f"bind={bind}",
                    location="~/.openclaw/openclaw.json → gateway.bind",
                    remediation="Set gateway.bind to 'loopback'",
                    run_id=run_id,
                )
            ]
        return []

    def _check_gateway_auth(self, config: dict, run_id: str) -> list[Finding]:
        """CONF-04: gateway.auth.mode must be token or oauth."""
        gateway = config.get("gateway", {})
        auth = gateway.get("auth", {})
        mode = auth.get("mode", "token")

        if mode not in ("token", "oauth", "bearer"):
            return [
                Finding(
                    check_id="CONF-04",
                    domain="config",
                    title=f"Gateway auth mode '{mode}' is insecure",
                    description="Gateway authentication should use token or oauth mode.",
                    severity="HIGH",
                    result="FAIL",
                    evidence=f"auth.mode={mode}",
                    location="~/.openclaw/openclaw.json → gateway.auth.mode",
                    remediation="Set gateway.auth.mode to 'token' or 'oauth'",
                    run_id=run_id,
                )
            ]
        return []

    def _check_no_credentials_in_config(self, config: dict, run_id: str) -> list[Finding]:
        """CONF-05: No credential patterns in config values."""
        matches = self._secret_scanner.scan_dict(config, "openclaw.json")
        findings = []
        for m in matches:
            findings.append(
                Finding(
                    check_id="CONF-05",
                    domain="secrets",
                    title=f"Credential pattern detected in config: {m.secret_type}",
                    description="A credential pattern was found in the OpenClaw config file.",
                    severity="CRITICAL",
                    result="FAIL",
                    evidence=f"type={m.secret_type} at {m.location} line {m.line_number}",
                    location=m.location,
                    remediation="Use environment variable references like ${ENV_VAR} instead.",
                    run_id=run_id,
                )
            )
        return findings

    def _check_no_yolo_global(self, config: dict, run_id: str) -> list[Finding]:
        """CONF-06: --yolo mode must not be enabled globally."""
        yolo = config.get("yolo", False) or config.get("security", {}).get("yolo", False)
        if yolo:
            return [
                Finding(
                    check_id="CONF-06",
                    domain="config",
                    title="Global --yolo mode is enabled",
                    description="--yolo disables safety checks globally.",
                    severity="CRITICAL",
                    result="FAIL",
                    evidence="yolo=true",
                    location="~/.openclaw/openclaw.json → yolo",
                    remediation="Disable yolo mode. Use per-command override if needed.",
                    run_id=run_id,
                )
            ]
        return []

    def _check_ratelimit_enabled(self, config: dict, run_id: str) -> list[Finding]:
        """CONF-07: Rate limiting should be enabled."""
        rl = config.get("rateLimit", config.get("rateLimiting", {}))
        if rl and rl.get("enabled") is False:
            return [
                Finding(
                    check_id="CONF-07",
                    domain="config",
                    title="Rate limiting is disabled",
                    description="Rate limiting protects against runaway agent behavior.",
                    severity="MEDIUM",
                    result="FAIL",
                    evidence="rateLimit.enabled=false",
                    location="~/.openclaw/openclaw.json → rateLimit.enabled",
                    remediation="Enable rate limiting.",
                    run_id=run_id,
                )
            ]
        return []

    def _check_update_check_enabled(self, config: dict, run_id: str) -> list[Finding]:
        """CONF-08: Auto-update check should be enabled."""
        updates = config.get("updates", {})
        if updates.get("checkEnabled") is False:
            return [
                Finding(
                    check_id="CONF-08",
                    domain="config",
                    title="Update check is disabled",
                    description="Disabling update checks prevents security patch notifications.",
                    severity="LOW",
                    result="WARN",
                    evidence="updates.checkEnabled=false",
                    location="~/.openclaw/openclaw.json → updates.checkEnabled",
                    remediation="Enable update checks.",
                    run_id=run_id,
                )
            ]
        return []

    def audit_file(self, config_path: Path, run_id: str | None = None) -> list[Finding]:
        """Load config from file and audit it."""
        run_id = run_id or str(uuid.uuid4())
        try:
            data = json.loads(config_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            return [
                Finding(
                    check_id="CONF-00",
                    domain="config",
                    title="Cannot read config file",
                    description=str(exc),
                    severity="HIGH",
                    result="UNKNOWN",
                    evidence=str(exc),
                    location=str(config_path),
                    remediation="Ensure the config file exists and is valid JSON.",
                    run_id=run_id,
                )
            ]
        return self.audit(data, run_id)
