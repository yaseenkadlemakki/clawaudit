# Changelog

All notable changes to ClawAudit are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — 2026-03-05

### Added
- Initial release of ClawAudit — read-only forensic security auditor for OpenClaw deployments.
- 43 checks across 6 domains: Configuration Hardening, Skill Permission Audit, Secrets Hygiene, Network Exposure, Supply Chain Risk, Audit Logging.
- Credential detection patterns for 14 credential types (`detectors/secret-patterns.md`).
- Shell and prompt injection heuristics (`detectors/injection-patterns.md`).
- Canonical hardening rules registry with severity, evidence keys, and remediations (`data/hardening-rules.yaml`).
- Structured compliance report template with Skill Trust Matrix and Remediation Roadmap.
- Severity scoring: CRITICAL / HIGH / MEDIUM / LOW / INFO with SLA guidance.
- Trust scoring: TRUSTED / CAUTION / UNTRUSTED / QUARANTINE per skill.
- Installation guide and periodic audit scheduling via OpenClaw cron.
