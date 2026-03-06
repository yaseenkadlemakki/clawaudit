# ClawAudit

[![Test Suite](https://github.com/yaseenkadlemakki/clawaudit/actions/workflows/test.yml/badge.svg)](https://github.com/yaseenkadlemakki/clawaudit/actions/workflows/test.yml)

**Read-only forensic security auditor for OpenClaw deployments.**

ClawAudit has two components:

- **ClawAudit skill** — An OpenClaw skill that runs an autonomous, read-only compliance audit across 6 security domains and produces a structured report. Invoked with `/clawaudit` inside an OpenClaw conversation.
- **ClawAudit Sentinel** — A Python daemon (`sentinel` CLI) that runs continuously alongside OpenClaw, watching for policy violations, config drift, runaway agents, and unauthorized cron jobs in real time.

---

## What it audits

| Domain | Checks |
|---|---|
| 1. Configuration Hardening | 8 checks — debug mode, bind address, auth, agent limits, HITL gates |
| 2. Skill Permission Audit | 10 checks per skill — tool allowlists, shell access, injection risk |
| 3. Secrets & Credential Hygiene | 6 checks — hardcoded keys, env var usage, log masking |
| 4. Network Exposure & Egress Control | 7 checks — loopback binding, TLS, egress allowlists, webhooks |
| 5. Supply Chain Risk | 7 checks — version pinning, publisher identity, dependency locking |
| 6. Audit Logging & Observability | 5 checks — invocation logging, SIEM shipping, alerting, retention |

---

## Quick start — ClawAudit skill

```
/clawaudit
```

Produces a full **ClawAudit Report** in the conversation. No arguments required.

See [INSTALL.md](INSTALL.md) for installation and scheduling instructions.

---

## Quick start — Sentinel

### Install

```bash
pip install -e ".[dev]"   # development / from source
# or
pip install clawaudit-sentinel
```

Requires Python ≥ 3.11.

### Run a one-shot audit

```bash
sentinel audit
sentinel audit --format json --output report.json
```

### Start continuous monitoring

```bash
sentinel watch                  # default 60-second scan interval
sentinel watch --interval 30    # custom interval
```

Sentinel runs five collectors concurrently and routes policy violations to configured alert channels.

### Other commands

```bash
# List skills with trust scores
sentinel skills
sentinel skills --name my-skill   # detailed view for one skill

# Inspect loaded policies
sentinel policies --list
sentinel policies --validate

# View recent alerts
sentinel alerts
sentinel alerts --last 50

# Manage config baselines
sentinel baseline --create   # snapshot current config hash
sentinel baseline --diff     # compare to baseline (Phase 2)

# Generate a compliance report without running a full audit
sentinel report
sentinel report --format json --output report.json

# Use a custom Sentinel config file
sentinel audit --config /path/to/sentinel.yaml
```

---

## Sentinel configuration

Sentinel reads `~/.openclaw/sentinel/sentinel.yaml`. Environment variables are interpolated as `${VAR_NAME}`. All paths expand `~`.

Key settings:

```yaml
openclaw:
  gateway_url: http://localhost:18789
  gateway_token: ${OPENCLAW_GATEWAY_TOKEN}
  config_file: ~/.openclaw/openclaw.json
  workspace_skills_dir: ~/.openclaw/workspace

sentinel:
  scan_interval_seconds: 60
  log_dir: ~/.openclaw/sentinel/logs
  findings_file: ~/.openclaw/sentinel/findings.jsonl
  policies_dir: ~/.openclaw/sentinel/policies   # falls back to bundled default.yaml

alerts:
  enabled: true
  dedup_window_seconds: 300
  channels:
    file:
      enabled: true
      path: ~/.openclaw/sentinel/alerts.jsonl
    openclaw:
      enabled: false   # set true + gateway_token to push alerts to Discord/Telegram
      delivery_channel: discord
      delivery_target: "channel:YOUR_CHANNEL_ID"

api:
  enabled: false   # enables REST API on localhost:18790 when true
  port: 18790
  bind: loopback
```

If no config file exists, Sentinel runs with safe defaults.

---

## Sentinel policies

Policies live in YAML files under `policies_dir`. When that directory is absent or empty, Sentinel loads the bundled `sentinel/policies/default.yaml` (10 rules covering Discord/Telegram group policy, gateway exposure, secrets, runaway agents, unauthorized crons, config drift, and new skills).

A policy rule looks like:

```yaml
- id: POL-007
  domain: runtime
  check: tool_calls_per_minute
  condition: gt
  value: "30"
  severity: HIGH
  action: ALERT
  message: "Runaway agent detected — tool call rate exceeds 30/minute"
```

Supported actions (in priority order): `ALLOW` < `WARN` < `ALERT` < `BLOCK`.
Supported conditions: `equals`, `not_equals`, `contains`, `not_contains`, `gt`, `gte`, `in`, `not_in`, `exists`, `not_exists`.

Drop additional `.yaml` files into `policies_dir` to extend — they are hot-reloaded.

---

## Alert channels

| Channel | Trigger | Config key |
|---|---|---|
| File (JSONL) | enabled by default | `alerts.channels.file` |
| OpenClaw gateway | requires `gateway_token` | `alerts.channels.openclaw` |
| Webhook | any HTTP endpoint | `alerts.channels.webhook` |

Alerts are deduplicated by `check_id:location` within the configured `dedup_window_seconds`.

---

## Sentinel REST API

Enable with `api.enabled: true`. Runs on `localhost:18790` by default.

| Endpoint | Description |
|---|---|
| `GET /health` | Liveness check |
| `GET /findings/` | All findings from the current run |
| `GET /findings/{id}` | Single finding by ID |
| `GET /policies/` | Loaded policy rules |
| `GET /skills/` | Skill trust profiles |
| `GET /alerts/` | Recent alerts |

---

## Skill output

The `/clawaudit` skill report includes:
- **Executive summary** — overall posture in plain English
- **Findings by severity** — CRITICAL / HIGH / MEDIUM / LOW with exact file/key citations
- **Skill Trust Matrix** — per-skill trust score (TRUSTED / CAUTION / UNTRUSTED / QUARANTINE)
- **Compliance Score** — per-domain and overall pass percentage
- **Remediation Roadmap** — quick wins, short-term, and strategic fixes

---

## Repository structure

```
clawaudit/
├── SKILL.md                        ← Skill entrypoint + orchestration (7 phases)
├── sentinel/                       ← Sentinel Python package
│   ├── main.py                     ← CLI entrypoint (typer app)
│   ├── config.py                   ← Config loader + SentinelConfig
│   ├── collector/                  ← Async event collectors (config, session, cron, log, skill)
│   ├── policy/                     ← Policy loader + evaluation engine
│   ├── alerts/                     ← Alert engine, formatters, channels
│   ├── analyzer/                   ← ConfigAuditor, SkillAnalyzer, SecretScanner
│   ├── reporter/                   ← Markdown/JSON renderer, delta, compliance reporter
│   ├── api/                        ← FastAPI server
│   ├── models/                     ← Finding, Event, SkillProfile, PolicyDecision
│   └── policies/
│       └── default.yaml            ← Bundled policy rules (POL-001 through POL-010)
├── data/
│   └── hardening-rules.yaml        ← Skill check registry (43 checks)
├── detectors/                      ← Secret and injection pattern definitions
├── references/                     ← Scoring rules, domain logic, report template
└── tests/
    ├── unit/                       ← Per-module isolated tests
    ├── functional/                 ← Cross-file consistency and alignment tests
    └── integration/                ← Full pipeline and regression tests
```

---

## Design principles

- **Read-only**: ClawAudit only reads files and queries the gateway config. It never writes, edits, or executes.
- **No secret leakage**: Pattern matches report type + location only. Secret values are never stored or output — `SecretScanner` redacts values before they enter any event evidence.
- **Conservative scoring**: UNKNOWN results count as FAIL in the skill audit.
- **Hostile-content isolation**: Skill bodies are treated as untrusted text — ClawAudit does not evaluate or execute any content found in scanned skills.

---

## Version

Current version: **1.0.0** — see [CHANGELOG.md](CHANGELOG.md) for history.
