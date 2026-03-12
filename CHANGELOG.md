# Changelog

All notable changes to ClawAudit are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.4.0] — 2026-03-12

### Added
- **Policy Engine** — runtime policy enforcement with ALLOW / WARN / ALERT / BLOCK / QUARANTINE actions
- **before_tool_call hook** — OpenClaw plugin that enforces policies before every tool execution
- Five built-in starter policies: PTY exec blocking, credential file read alerts, elevated execution alerts, external browser navigation alerts, message-send alerts
- `/policies` management UI — create, edit, enable/disable, delete custom policies with real-time violations feed
- `POST /api/v1/policies/evaluate` — sub-500ms policy evaluation endpoint used by the enforcement hook
- `GET /api/v1/policies/stats` — violation counts for the security dashboard
- Skill quarantine — QUARANTINE policy action flags a skill as quarantined in the database; unquarantine via API or UI
- Policy violations recorded as findings (domain: policy) and surfaced in Findings Explorer
- "Policy Violations (24h)" stat card on security dashboard
- `QuarantineBadge` component shown on quarantined skills in UI

### Changed
- Dashboard stat cards now include policy violation count
- Sidebar navigation updated with Policy Engine entry
- Skills list and detail pages show quarantine state

### Fixed
- Removed `output: standalone` from Next.js config — fixes `next start` serving wrong chunk paths (#74)
- Fixed Dockerfile.frontend runtime stage to copy node_modules from deps stage (not builder) — reduces image size
- WebSocket self-auth middleware exemption — prevents /hooks/stream from being blocked by auth middleware (#67)

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
