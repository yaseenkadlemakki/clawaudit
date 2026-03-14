# ClawAudit

[![Test Suite](https://github.com/yaseenkadlemakki/clawaudit/actions/workflows/test.yml/badge.svg)](https://github.com/yaseenkadlemakki/clawaudit/actions/workflows/test.yml)
[![Build & Publish](https://github.com/yaseenkadlemakki/clawaudit/actions/workflows/build.yml/badge.svg)](https://github.com/yaseenkadlemakki/clawaudit/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

> Forensic security auditor for OpenClaw deployments — 43 checks, real-time monitoring, automated remediation, and a live dashboard.

---

## Quick Start

```bash
pip install -e .
clawaudit quickstart
```

That's it. `quickstart` detects your environment, locates OpenClaw, runs a full security scan, and shows you what to do next.

### Individual commands

```bash
clawaudit doctor                # validate environment
clawaudit scan                  # full security scan
clawaudit findings              # view findings from last scan
clawaudit findings --severity CRITICAL
clawaudit monitor               # continuous monitoring
clawaudit remediate             # preview auto-fixes
clawaudit report -o report.md   # export compliance report
```

See [docs/quickstart.md](docs/quickstart.md) for the full walkthrough.

---

## Features

### Security Audit Engine
43 checks across 6 domains — configuration hardening, skill permissions, secrets, network exposure, supply chain, and observability.

| Domain | Checks |
|--------|--------|
| Configuration Hardening | 8 checks — debug mode, bind address, auth, agent limits, HITL gates |
| Skill Permission Audit | 10 checks per skill — tool allowlists, shell access, injection risk |
| Secrets & Credential Hygiene | 6 checks — hardcoded keys, env var usage, log masking |
| Network Exposure & Egress | 7 checks — loopback binding, TLS, egress allowlists, webhooks |
| Supply Chain Risk | 7 checks — version pinning, publisher identity, dependency locking |
| Audit Logging & Observability | 5 checks — invocation logging, SIEM shipping, alerting, retention |

### Advanced Detection (5 rules)
- **ADV-001** Unrestricted shell execution (HIGH)
- **ADV-002** Unknown publisher/provenance (MEDIUM)
- **ADV-003** Supply chain risk — unlisted outbound domains (HIGH)
- **ADV-004** Unsigned skill (LOW)
- **ADV-005** Credentials exposed in SKILL.md (CRITICAL)

### Remediation Engine
Automatically proposes and applies fixes with dry-run preview and snapshot-based rollback.

```bash
clawaudit remediate                          # dry-run: list proposals
clawaudit remediate --apply --yes            # apply all proposals
clawaudit remediate --skill my-skill --check ADV-001 --apply
clawaudit snapshots list                     # list available snapshots
clawaudit snapshots rollback <snapshot-name> # restore from snapshot
```

### Real-time Monitoring
Five background collectors watch for runtime security events:

| Collector | What it watches |
|-----------|-----------------|
| **ConfigCollector** | Gateway config drift (polling + hash comparison) |
| **SessionCollector** | Active agent sessions |
| **CronCollector** | Scheduled jobs |
| **LogCollector** | Agent execution logs (async tail) |
| **SkillCollector** | Skill directory for new/modified skills |

```bash
clawaudit monitor                # start all collectors (60s default)
clawaudit monitor --interval 30  # custom interval
```

### Policy Engine
Runtime policy enforcement with configurable actions (ALLOW, WARN, ALERT, BLOCK, QUARANTINE), hot-reloadable YAML rules, and a management UI.

```bash
clawaudit policies --list       # list loaded rules
clawaudit policies --validate   # validate policy files
```

### Alert Routing
Routes findings and runtime events to multiple channels with deduplication.

| Channel | Description |
|---------|-------------|
| **File** | Appends to `~/.openclaw/sentinel/alerts.jsonl` (default) |
| **Webhook** | HTTP POST with JSON payload to any URL |
| **OpenClaw** | Routes through gateway to Discord, Telegram, etc. |

### Skill Lifecycle Management
Install, enable, disable, uninstall, and recover skills with a JSON-backed registry, trash-based recovery, and protected-path enforcement.

```bash
clawaudit skills list                        # list all skills
clawaudit skills install ./my-skill.skill    # install from file
clawaudit skills enable <name>               # enable a disabled skill
clawaudit skills disable <name>              # disable a skill
clawaudit skills uninstall <name>            # move to trash
clawaudit skills recover <trash-name>        # recover from trash
clawaudit skills health <name>               # run security analysis
```

---

## Architecture

```
clawaudit/
├── backend/                  FastAPI async API server
│   ├── api/routes/           REST endpoints (scans, findings, skills, lifecycle, remediation, chat, graph, policies, ws)
│   ├── engine/               Audit engine, risk scoring, knowledge graph, chat engine, scan manager
│   └── models/               SQLAlchemy models (scan, skill, finding, policy, remediation)
├── frontend/                 Next.js 15 dashboard UI
│   ├── src/app/              Pages: dashboard, audit, findings, skills, remediation, chat, policies
│   └── src/components/       Shared components: InvestigationPanel, Sidebar, QuarantineBadge, ...
├── sentinel/                 Python CLI + audit engine
│   ├── analyzer/             Skill analyzer, config auditor, injection detector, secret scanner
│   ├── alerts/               Alert engine + channels (file, webhook, OpenClaw)
│   ├── collector/            Runtime collectors (config, session, cron, log, skill)
│   ├── guard/                Command guard (code block detection)
│   ├── lifecycle/            Skill installer, registry, toggler, uninstaller
│   ├── policy/               Policy engine, loader, actions
│   ├── remediation/          Remediation engine, strategies, rollback
│   └── reporter/             Compliance reporter, renderers
├── docker/                   Dockerfiles + docker-compose
├── docs/                     Documentation
├── data/
│   └── hardening-rules.yaml  Check registry (43 checks across 6 domains)
├── references/
│   ├── domains.md            Per-domain check definitions
│   ├── scoring.md            Severity classification rules
│   └── report-template.md    Report structure and formatting
├── SKILL.md                  ClawAudit audit skill orchestration
└── tests/                    Test suite (unit, functional, integration)
```

Data flow: **Collectors → Events → PolicyEngine → AlertEngine → Channels**

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `clawaudit quickstart` | Full onboarding flow |
| `clawaudit version` | Version, Python, platform, OpenClaw status |
| `clawaudit doctor` | Validate environment readiness |
| `clawaudit scan` | Full security scan |
| `clawaudit findings` | View findings from last scan |
| `clawaudit monitor` | Continuous monitoring daemon |
| `clawaudit audit` | Security scan (original name) |
| `clawaudit watch` | Monitoring (original name) |
| `clawaudit skills` | Skill trust scores |
| `clawaudit skills list/install/enable/disable/uninstall/recover/health/verify` | Skill lifecycle |
| `clawaudit remediate` | Preview or apply remediations |
| `clawaudit report` | Generate compliance report |
| `clawaudit policies` | List or validate policy rules |
| `clawaudit alerts` | View recent alerts |
| `clawaudit baseline` | Manage config baselines |
| `clawaudit snapshots` | Manage remediation snapshots |
| `clawaudit config show/init` | Manage configuration |
| `clawaudit hooks status/register/unregister/events/simulate` | Runtime hook integration |

---

## Dashboard

Next.js 15 SPA with real-time scan progress via WebSocket.

| Page | Description |
|------|-------------|
| `/dashboard` | Risk gauge, findings breakdown, skill trust matrix, investigation panel |
| `/audit` | Trigger and manage audit scans |
| `/findings` | Findings list with severity/policy/skill filtering |
| `/skills` | Skill explorer with lifecycle controls |
| `/remediation` | View proposals, apply fixes, rollback history |
| `/chat` | Security investigation chat |
| `/policies` | Policy engine — manage rules, view violations |

### Docker deployment

```bash
cp docker/.env.example docker/.env
# Edit docker/.env and set POSTGRES_PASSWORD
docker compose --env-file docker/.env -f docker/docker-compose.yml up
```

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:3000 |
| API | http://localhost:18790 |
| API Docs | http://localhost:18790/docs |

---

## Remediation

```bash
clawaudit remediate                          # dry-run: list proposals
clawaudit remediate --apply --yes            # apply all proposals
clawaudit remediate --skill my-skill --check ADV-001 --apply
clawaudit snapshots list
clawaudit snapshots rollback <snapshot-name>
```

**API:**
```
GET    /api/v1/remediation/proposals
POST   /api/v1/remediation/apply
POST   /api/v1/remediation/rollback
GET    /api/v1/remediation/history
```

---

## CI Integration

Add ClawAudit to your CI pipeline:

```yaml
# .github/workflows/security.yml
- name: Security Scan
  run: |
    pip install -e .
    clawaudit scan --format json --output security-report.json
```

The `scan` command exits with code 1 when `FAIL` findings are detected, making it suitable as a CI gate.

---

## Configuration

Sentinel configuration lives at `~/.openclaw/sentinel/sentinel.yaml`. Initialize with defaults:

```bash
clawaudit config init
clawaudit config show
```

Environment variables can be interpolated using `${ENV_VAR}` syntax in the YAML config.

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

This project is licensed under the [Apache License 2.0](LICENSE).
