# ClawAudit

[![Test Suite](https://github.com/yaseenkadlemakki/clawaudit/actions/workflows/test.yml/badge.svg)](https://github.com/yaseenkadlemakki/clawaudit/actions/workflows/test.yml)
[![Build & Publish](https://github.com/yaseenkadlemakki/clawaudit/actions/workflows/build.yml/badge.svg)](https://github.com/yaseenkadlemakki/clawaudit/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**OpenClaw Security Intelligence Platform**

ClawAudit audits OpenClaw deployments for security risks — exposed credentials, supply chain threats, shell-execution abuse, and policy violations — and surfaces everything through a live web dashboard, AI-powered investigation chat, automated remediation, and full skill lifecycle management.

---

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/yaseenkadlemakki/clawaudit.git
cd clawaudit

cp docker/.env.example docker/.env
# Edit docker/.env and set POSTGRES_PASSWORD

docker compose --env-file docker/.env -f docker/docker-compose.yml up
```

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:3000 |
| API | http://localhost:18790 |
| API Docs | http://localhost:18790/docs |

### Pull pre-built images

Images are published to GitHub Container Registry on every release:

```bash
docker pull ghcr.io/yaseenkadlemakki/clawaudit-backend:latest
docker pull ghcr.io/yaseenkadlemakki/clawaudit-frontend:latest
```

### Local (without Docker)

```bash
pip install -e ".[backend,dev]"
cd frontend && npm install && cd ..

# Terminal 1 — backend
uvicorn backend.main:app --host 0.0.0.0 --port 18790 --reload

# Terminal 2 — frontend
cd frontend && npm run dev
```

### CLI

```bash
sentinel audit                              # full security scan
sentinel audit --format json --output r.json # export as JSON
sentinel watch                              # continuous monitoring (60s default)
sentinel skills list                        # list installed skills
sentinel skills install ./my.skill          # install a skill
sentinel remediate                          # preview remediation proposals
sentinel remediate --apply                  # apply fixes (with snapshots)
sentinel report                             # generate compliance report
sentinel alerts                             # view recent alerts
sentinel policies --list                    # list loaded policy rules
```

---

## Features

### Security Audit Engine
43 checks across 6 domains — configuration hardening, skill permissions, secrets, network exposure, supply chain, and observability.

### Advanced Detection (5 rules)
- **ADV-001** Unrestricted shell execution (HIGH)
- **ADV-002** Unknown publisher/provenance (MEDIUM)
- **ADV-003** Supply chain risk — unlisted outbound domains (HIGH)
- **ADV-004** Unsigned skill (LOW)
- **ADV-005** Credentials exposed in SKILL.md (CRITICAL)

### Remediation Engine
Automatically proposes and applies fixes for security findings with dry-run preview and snapshot-based rollback.

- **Three strategies**: restrict shell access (ADV-001), redact exposed secrets (ADV-005), restrict overly-broad permissions (PERM-001)
- **Dry-run by default** — preview proposals before applying
- **Snapshot rollback** — every applied fix creates a snapshot; roll back with one command
- **Protected paths** — system skills cannot be modified

```bash
sentinel remediate                          # dry-run: list proposals
sentinel remediate --apply --yes            # apply all proposals
sentinel remediate --skill my-skill --check ADV-001 --apply
sentinel snapshots list                     # list available snapshots
sentinel snapshots rollback <snapshot-name> # restore from snapshot
```

**API:**
```
GET    /api/v1/remediation/proposals      # list proposed remediations
POST   /api/v1/remediation/apply          # apply a remediation
POST   /api/v1/remediation/rollback       # restore from snapshot
GET    /api/v1/remediation/history        # remediation history
```

### Skill Lifecycle Management
Install, enable, disable, uninstall, and recover skills — with a JSON-backed registry, trash-based recovery, and protected-path enforcement.

- **Install** from local `.skill` (tar.gz) files or HTTPS URLs
- **Enable/disable** via `SKILL.md` <-> `SKILL.md.disabled` rename (fully reversible)
- **Uninstall to trash** — never deletes, always recoverable from `~/.openclaw/sentinel/skill-trash/`
- **Health check** — run the security analyzer against a single skill on demand
- **Protected paths** — system skills under `/opt/homebrew/lib/node_modules/openclaw/skills/` are blocked from all operations

```bash
sentinel skills list                                     # list all skills with status
sentinel skills install ./my-skill.skill                 # install from file
sentinel skills install https://clawhub.com/skills/x     # install from URL
sentinel skills enable <name>                            # enable a disabled skill
sentinel skills disable <name>                           # disable a skill
sentinel skills uninstall <name>                         # move to trash
sentinel skills recover <trash-name>                     # recover from trash
sentinel skills health <name>                            # run security analysis
```

**API:**
```
GET    /api/v1/lifecycle/skills              # list all skills with status
POST   /api/v1/lifecycle/skills/install      # install from file path or URL
POST   /api/v1/lifecycle/skills/{name}/enable
POST   /api/v1/lifecycle/skills/{name}/disable
DELETE /api/v1/lifecycle/skills/{name}       # uninstall to trash
GET    /api/v1/lifecycle/skills/{name}/health # single-skill audit pass
```

### Policy Engine
Runtime policy enforcement that intercepts every tool execution via the `before_tool_call` hook, with configurable actions and a live management UI.

- **Actions**: ALLOW, WARN, ALERT, BLOCK, QUARANTINE
- **Condition operators**: `equals`, `not_equals`, `contains`, `gt`, `gte`, `exists`, `in`, and more
- **Five built-in starter policies**: PTY exec blocking, credential file read alerts, elevated execution alerts, external browser navigation alerts, message-send alerts
- **`/policies` management UI** — create, edit, enable/disable, delete custom policies with real-time violations feed
- **Sub-500ms evaluation** — `POST /api/v1/policies/evaluate` powers the enforcement hook
- **Default policy** ships in `sentinel/policies/default.yaml`
- **Hot-reload** via `PolicyEngine.reload()` — no restart needed

```bash
sentinel policies --list                    # list loaded rules
sentinel policies --validate                # validate policy files
```

**API:**
```
GET    /api/v1/policies                     # list policies
POST   /api/v1/policies                     # create policy
PUT    /api/v1/policies/{id}                # update policy
DELETE /api/v1/policies/{id}                # delete policy
POST   /api/v1/policies/evaluate            # evaluate a tool call against policies
GET    /api/v1/policies/stats               # violation counts for the dashboard
```

### Skill Quarantine
When a QUARANTINE policy action fires, the offending skill is flagged as quarantined in the database and shown with a `QuarantineBadge` in the UI. Skills can be unquarantined via the API or management UI. Quarantine state is visible in the Skills list, skill detail pages, and surfaced as findings in the Findings Explorer.

### Alert Routing
Routes findings and runtime events to multiple channels with configurable deduplication.

| Channel | Description |
|---------|-------------|
| **File** | Appends to `~/.openclaw/sentinel/alerts.jsonl` (default) |
| **Webhook** | HTTP POST with JSON payload to any URL |
| **OpenClaw** | Routes through gateway to Discord, Telegram, etc. |

```bash
sentinel alerts                             # view recent alerts
sentinel alerts --last 50                   # show last 50
sentinel alerts --ack <id>                  # acknowledge an alert
```

### Real-time Monitoring
Five background collectors continuously watch for runtime security events:

| Collector | What it watches |
|-----------|-----------------|
| **ConfigCollector** | Gateway config drift (polling + hash comparison) |
| **SessionCollector** | Active agent sessions |
| **CronCollector** | Scheduled jobs |
| **LogCollector** | Agent execution logs (async tail) |
| **SkillCollector** | Skill directory for new/modified skills |

```bash
sentinel watch                              # start all collectors (60s default)
sentinel watch --interval 30                # custom interval
```

### Command Guard
Pre-execution classifier that detects non-shell code blocks (Python, TypeScript, Go, Rust, YAML) being mistakenly executed as shell commands. Returns verdicts with confidence levels and suggested actions (WRITE_FILE, EXECUTE, or REVIEW).

### Security Investigation Chat
Ask natural-language questions about your scan data. Two modes:
- **OpenClaw mode** — routes through your local OpenClaw gateway (no data leaves your machine)
- **BYOLLM mode** — calls Anthropic directly with your own API key

### Knowledge Graph
In-memory security knowledge graph tracking relationships between skills, tools, files, network endpoints, and policies. Queryable by risk score, tool usage, and skill name.

**API:**
```
GET    /api/v1/graph                        # full graph (JSON)
GET    /api/v1/graph/skill/{name}           # single skill subgraph
```

### Compliance Reporting
Generate markdown or JSON compliance reports with unified findings, severity sorting, and run IDs.

```bash
sentinel report                             # print markdown report
sentinel report --format json --output r.json
sentinel baseline --create                  # snapshot current config
sentinel baseline --diff                    # compare against baseline
```

### Live Dashboard
Next.js 14 SPA with real-time scan progress via WebSocket.

| Page | Description |
|------|-------------|
| `/dashboard` | Risk gauge, findings breakdown, skill trust matrix |
| `/audit` | Trigger and manage audit scans |
| `/findings` | Findings list with severity/policy/skill filtering |
| `/skills` | Skill explorer with lifecycle controls (install, enable/disable, uninstall) |
| `/skills/[id]` | Individual skill detail and health report |
| `/remediation` | View proposals, apply fixes, rollback history |
| `/chat` | AI-powered security investigation |
| `/policies` | Policy Engine — manage rules, view violations feed, quarantine skills |

---

## What it audits

| Domain | Checks |
|--------|--------|
| Configuration Hardening | 8 checks — debug mode, bind address, auth, agent limits, HITL gates |
| Skill Permission Audit | 10 checks per skill — tool allowlists, shell access, injection risk |
| Secrets & Credential Hygiene | 6 checks — hardcoded keys, env var usage, log masking |
| Network Exposure & Egress | 7 checks — loopback binding, TLS, egress allowlists, webhooks |
| Supply Chain Risk | 7 checks — version pinning, publisher identity, dependency locking |
| Audit Logging & Observability | 5 checks — invocation logging, SIEM shipping, alerting, retention |

---

## Documentation

| Doc | Description |
|-----|-------------|
| [docs/setup.md](docs/setup.md) | Full setup guide — local + Docker |
| [docs/architecture.md](docs/architecture.md) | System design, data flows, component overview |
| [docs/risk-scoring.md](docs/risk-scoring.md) | How risk scores are calculated; ADV-* check details |
| [docs/chat-investigation.md](docs/chat-investigation.md) | Investigation chat usage + example questions |
| [docs/ci-cd.md](docs/ci-cd.md) | CI/CD pipeline stages and how to extend them |

---

## Repository Structure

```
clawaudit/
├── backend/                  FastAPI async API server
│   ├── api/routes/           REST endpoints (scans, findings, skills, lifecycle, remediation, chat, graph, policies, ws)
│   ├── engine/               Audit engine, risk scoring, knowledge graph, chat engine, scan manager
│   └── models/               SQLAlchemy models (scan, skill, finding, policy, remediation)
├── frontend/                 Next.js 14 dashboard UI
│   └── src/app/              Pages: dashboard, audit, findings, skills, remediation, chat
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
├── tests/                    Test suite (815+ tests across 60 files, 80% coverage gate)
└── .github/
    ├── workflows/            test.yml + build.yml
    └── dependabot.yml        Weekly version bumps (Actions, pip, npm)
```

---

## CI/CD Pipeline

| Stage | Description |
|-------|-------------|
| YAML Lint | Validates all YAML files |
| Python Audit | `pip-audit` on dependencies |
| Node Audit | `npm audit` on frontend |
| Lint | `ruff check` + `ruff format --check` |
| Test | pytest with 80% coverage gate (Python 3.10/3.11/3.12) |
| Docker Build | Multi-stage build (backend + frontend), cached via GitHub Actions |
| Publish | Push to GHCR on version tags (`v*.*.*`) with stable + latest image tags |
| Dependabot | Weekly PRs for Actions, pip, and npm dependency updates |

---

## Design Principles

- **Read-only audits**: The audit engine only reads files and queries the gateway config. It never writes, edits, or executes.
- **Safe remediation**: Remediations are dry-run by default. Applied fixes create snapshots for instant rollback. System skills are protected.
- **No secret leakage**: Pattern matches report type + location only. Secret values are redacted before entering any event evidence.
- **Conservative scoring**: UNKNOWN results count as FAIL.
- **Hostile-content isolation**: Skill bodies are treated as untrusted text — never evaluated or executed.
- **Trash, not delete**: Skill uninstalls move to trash. Nothing is permanently deleted.

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to get started, report bugs, and submit pull requests.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

---

## Version

**Phase 8 · v0.4.0** — see [CHANGELOG.md](CHANGELOG.md) for history.
