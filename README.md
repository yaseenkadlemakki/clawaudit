# ClawAudit

[![Test Suite](https://github.com/yaseenkadlemakki/clawaudit/actions/workflows/test.yml/badge.svg)](https://github.com/yaseenkadlemakki/clawaudit/actions/workflows/test.yml)
[![Build & Publish](https://github.com/yaseenkadlemakki/clawaudit/actions/workflows/build.yml/badge.svg)](https://github.com/yaseenkadlemakki/clawaudit/actions/workflows/build.yml)

**OpenClaw Security Intelligence Platform**

ClawAudit audits OpenClaw deployments for security risks — exposed credentials, supply chain threats, shell-execution abuse, and policy violations — and surfaces everything through a live web dashboard and AI-powered investigation chat.

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
sentinel audit                              # audit all installed skills
sentinel audit --skill my-skill            # audit one skill
sentinel watch                             # continuous monitoring (60s interval)
sentinel findings                          # view recent findings
```

---

## Features

### 🔍 Security Audit Engine
43 checks across 6 domains — configuration hardening, skill permissions, secrets, network exposure, supply chain, and observability.

### 🚨 Advanced Detection (5 rules)
- **ADV-001** Unrestricted shell execution (HIGH)
- **ADV-002** Unknown publisher/provenance (MEDIUM)
- **ADV-003** Supply chain risk — unlisted outbound domains (HIGH)
- **ADV-004** Unsigned skill (LOW)
- **ADV-005** Credentials exposed in SKILL.md (CRITICAL)

### 🤖 Security Investigation Chat
Ask natural-language questions about your scan data. Two modes:
- **OpenClaw mode** — routes through your local OpenClaw gateway (no data leaves your machine)
- **BYOLLM mode** — calls Anthropic directly with your own API key

### 📊 Live Dashboard
Real-time scan progress via WebSocket, risk score gauge, findings breakdown, skill trust matrix, and knowledge graph.

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
├── frontend/                 Next.js 14 dashboard UI
├── sentinel/                 Python CLI + audit engine
├── docker/                   Dockerfiles + docker-compose
├── docs/                     Documentation
├── data/
│   └── hardening-rules.yaml  Check registry (43 checks across 6 domains)
├── references/
│   ├── domains.md            Per-domain check definitions
│   ├── scoring.md            Severity classification rules
│   └── report-template.md   Report structure and formatting
├── tests/                    Test suite (679 tests, 80% coverage gate)
└── .github/
    └── workflows/            test.yml + build.yml
```

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

## Design Principles

- **Read-only**: ClawAudit only reads files and queries the gateway config. It never writes, edits, or executes.
- **No secret leakage**: Pattern matches report type + location only. Secret values are redacted before entering any event evidence.
- **Conservative scoring**: UNKNOWN results count as FAIL.
- **Hostile-content isolation**: Skill bodies are treated as untrusted text — never evaluated or executed.

---

## Version

**Phase 4 · v1.0.0** — see [CHANGELOG.md](CHANGELOG.md) for history.
