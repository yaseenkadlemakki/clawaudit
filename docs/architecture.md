# ClawAudit Architecture

> Concise but complete reference for contributors and security reviewers.

---

## 1. System Purpose & Overview

ClawAudit is a **real-time security intelligence platform** for [OpenClaw](https://openclaw.dev) deployments. It continuously monitors, scores, and remediates the AI skills (tools) that power an OpenClaw agent, enforcing a defence-in-depth posture across:

- **Shell access control** — which skills can run arbitrary commands
- **Secret exposure** — API keys, tokens, credentials in skill code
- **Injection risk** — prompt-injection patterns in skill definitions
- **Outbound domain allowlisting** — unexpected network egress
- **Filesystem permissions** — world-writable skill files and directories
- **Lifecycle integrity** — install / update / removal event tracking

The system is structured as a **monorepo** with three independently deployable components: a FastAPI backend API, a Next.js web UI, and a standalone `sentinel` Python CLI.

```
┌──────────────────────────────────────────────────────────────────┐
│                        ClawAudit Platform                        │
│                                                                  │
│  ┌──────────────┐    REST/WS    ┌────────────────────────────┐  │
│  │  Next.js UI  │ ◄──────────► │      FastAPI Backend       │  │
│  │  (port 3000) │              │       (port 18790)         │  │
│  └──────────────┘              │                            │  │
│                                │  ┌──────────┐  ┌────────┐  │  │
│  ┌──────────────┐              │  │  Audit   │  │ Chat   │  │  │
│  │  sentinel/   │ ──────────► │  │  Engine  │  │ Engine │  │  │
│  │  CLI         │              │  └──────────┘  └────────┘  │  │
│  └──────────────┘              │  ┌──────────┐  ┌────────┐  │  │
│                                │  │ Advanced │  │ Scan   │  │  │
│  ┌──────────────┐              │  │ Detector │  │ Mgr    │  │  │
│  │  OpenClaw    │ ◄──────────► │  └──────────┘  └────────┘  │  │
│  │  Gateway     │              │         │                   │  │
│  │  (port 18789)│              └─────────┼───────────────────┘  │
│  └──────────────┘                        │                       │
│                                          ▼                       │
│                                ┌──────────────────┐             │
│                                │   PostgreSQL /   │             │
│                                │   SQLite (dev)   │             │
│                                └──────────────────┘             │
└──────────────────────────────────────────────────────────────────┘
```

---

## 2. Backend Modules (`backend/`)

The backend is a **FastAPI async application** served by Uvicorn on port 18790.

### 2.1 Middleware Stack (request order)

| Layer | Class | File | Responsibility |
|-------|-------|------|----------------|
| 1st (outermost) | `MaxBodySizeMiddleware` | `backend/main.py` | Reject `Content-Length > 64 KiB` → 413 |
| 2nd | `AuthMiddleware` | `backend/middleware/auth.py` | Require `Authorization: Bearer <token>`; exempt `/health`, `/docs`, `/api/v1/ws/*`; WS query-param auth |
| 3rd | `CORSMiddleware` | starlette | Restrict cross-origin access to explicit allow-list |

> **Token resolution order:** `CLAWAUDIT_API_TOKEN` env var → `~/.openclaw/sentinel/api-token` file → auto-generate on first startup (written with `0o600` permissions).

### 2.2 API Routes

| Router | Mount prefix | Responsibility |
|--------|-------------|----------------|
| `scans.py` | `/api/v1/scans` | Start / stop / list audit scan runs |
| `findings.py` | `/api/v1/findings` | Query security findings with filters |
| `skills.py` | `/api/v1/skills` | List and retrieve skill risk profiles |
| `policies.py` | `/api/v1/policies` | CRUD for policy rules |
| `graph.py` | `/api/v1/graph` | Knowledge-graph export (nodes + edges) |
| `remediation.py` | `/api/v1/remediation` | Generate proposals, apply patches, rollback |
| `lifecycle.py` | `/api/v1/lifecycle` | Install / uninstall / toggle skill lifecycle |
| `hooks.py` | `/api/v1/hooks` | Ingest tool events, WS stream, plugin management |
| `chat.py` | `/api/v1/chat` | AI-powered investigation chat |
| `ws.py` | `/ws/scans/{id}/stream` | Live scan progress WebSocket stream |

### 2.3 Engine Layer

| Module | Purpose |
|--------|---------|
| `engine/audit_engine.py` | Orchestrates a full scan: runs `ConfigAuditor`, `SkillAnalyzer`, and `AdvancedDetector` per skill; persists `FindingRecord` and `SkillRecord` rows |
| `engine/scan_manager.py` | Manages concurrent scan runs; broadcasts live events to WebSocket subscribers via asyncio queues |
| `engine/chat_engine.py` | Builds context from latest scan findings and submits to OpenClaw gateway or Anthropic API (BYOLLM) |
| `engine/knowledge_graph.py` | In-memory directed graph of skills, findings, and their relationships; exported via `/api/v1/graph` |
| `engine/risk_scoring.py` | Computes composite risk scores and trust levels per skill |
| `engine/advanced_detection.py` | Wraps `sentinel` analysers (secret scanner, injection detector, script scanner) for backend use |

### 2.4 Models & Storage

| Module | ORM Table | Key columns |
|--------|-----------|-------------|
| `models/scan.py` | `scan_runs` | `id`, `status`, `started_at`, `completed_at`, counts |
| `models/finding.py` | `findings` | `scan_id`, `check_id`, `domain`, `severity`, `location` |
| `models/skill.py` | `skills` | `scan_id`, `name`, `risk_score`, `risk_level`, `shell_access`, `outbound_domains` |
| `models/remediation.py` | `remediation_events` | `proposal_id`, `skill_name`, `check_id`, `status`, `snapshot_path` |
| `models/chat.py` | `chat_messages` | `question`, `answer`, `mode`, `context_scan_id` |

Migrations are managed with **Alembic** (`backend/migrations/`). SQLite is used for local development; PostgreSQL is the production default.

---

## 3. Sentinel Modules (`sentinel/`)

The `sentinel/` package is a standalone CLI and library that shares domain logic with the backend but has **no FastAPI dependency**.

```
sentinel/
├── analyzer/          # Per-skill static analysis
│   ├── skill_analyzer.py    # Master analyser; drives all sub-checks
│   ├── config_auditor.py    # YAML config and CORS checks
│   ├── secret_scanner.py    # Token / API key detection
│   ├── injection_detector.py # Prompt-injection pattern matching
│   └── script_scanner.py    # Shell command safety checks
├── collector/         # Data sources fed into audit engine
│   ├── skill_collector.py   # Discovers installed OpenClaw skills
│   ├── config_collector.py  # Reads sentinel and skill config files
│   ├── session_collector.py # OpenClaw session metadata
│   ├── log_collector.py     # Log file parsing
│   └── cron_collector.py    # Scheduled cron job inspection
├── policy/            # Policy evaluation engine
│   ├── engine.py            # Evaluates findings against policy rules
│   ├── loader.py            # Loads YAML/JSON policy definitions
│   └── actions.py           # Policy action handlers
├── remediation/       # Automated fix engine
│   ├── engine.py            # RemediationEngine: propose, apply, rollback
│   ├── actions.py           # RemediationProposal / RemediationResult types
│   ├── rollback.py          # Snapshot (tar.gz) create / restore
│   └── strategies/          # Per-check-id patch implementations
├── alerts/            # Alert routing and formatting
│   ├── engine.py            # AlertEngine: rule evaluation + dispatch
│   ├── formatters.py        # Alert message formatting
│   └── channels/            # OpenClaw, webhook, file output
├── hooks/             # OpenClaw plugin + real-time event bus
│   ├── bus.py               # Async publish/subscribe event bus
│   ├── event.py             # ToolEvent dataclass + sanitisation
│   ├── plugin.py            # ClawAuditPlugin registration manager
│   ├── rules.py             # Alerting rules over tool-event streams
│   └── store.py             # SQLite-backed persistent event store
├── lifecycle/         # Skill lifecycle management
│   ├── installer.py         # Install new skills with audit trail
│   ├── uninstaller.py       # Remove skills (protected-path aware)
│   ├── toggler.py           # Enable / disable skills at runtime
│   └── registry.py          # SkillRegistry: skill inventory management
├── guard/             # Command-safety guard
│   └── command_guard.py     # Allow/deny shell commands before execution
├── reporter/          # Compliance report generation
│   ├── compliance.py        # Produces markdown / JSON audit reports
│   ├── delta.py             # Diff / delta reporting between scans
│   └── renderer.py          # Report rendering and output formatting
└── config.py          # SentinelConfig: paths, thresholds, alert rules
```

---

## 4. Frontend Pages & Data Flow

The frontend is a **Next.js 14 App Router** SPA with Tailwind CSS. All backend communication uses `NEXT_PUBLIC_API_URL` (REST) and `NEXT_PUBLIC_WS_URL` (WebSocket).

> ⚠️ Ensure `frontend/.env.local` is populated with `NEXT_PUBLIC_API_TOKEN` before running `npm run build`,
> otherwise the token bakes in as `undefined`.

| Page | Route | Data source | Description |
|------|-------|-------------|-------------|
| Dashboard | `/dashboard` | `GET /api/v1/dashboard` | Overall posture score, finding counts, risk distribution |
| Audit | `/audit` | `POST /api/v1/scans`, WS stream | Start scan; live progress via WebSocket |
| Findings | `/findings` | `GET /api/v1/findings` | Paginated finding list with severity filters |
| Skills | `/skills`, `/skills/[id]` | `GET /api/v1/skills`, `GET /api/v1/skills/{name}` | Risk profiles, trust scores, domain list |
| Remediation | `/remediation` | `GET /api/v1/remediation/proposals`, `POST /api/v1/remediation/apply` | One-click remediation with diff preview |
| Hooks | `/hooks` | `GET /api/v1/hooks/events`, WS `/api/v1/hooks/stream` | Live tool-event feed and alert history |
| Chat | `/chat` | `POST /api/v1/chat` | AI investigation with scan context |

**Client-side data flow:**

```
User action
  │
  ▼
lib/api.ts  ──(fetch with Bearer token)──►  FastAPI backend
  │                                              │
  │  JSON response                               │  DB query / engine call
  ◄──────────────────────────────────────────────┘
  │
React state update → re-render
```

---

## 5. Data Pipeline: Tool Events → Findings → Remediation

### 5.1 Audit Scan Pipeline

```
User/CLI triggers scan
  │
  ▼
ScanManager.start_scan()
  ├── Creates ScanRun row (status=RUNNING)
  └── Spawns AuditEngine.run_full_audit() [background task]
        │
        ├── SkillCollector.collect()       discover installed skills
        │
        ├── ConfigAuditor.audit()          → FindingRecord rows (config checks)
        │
        └── per skill:
              SkillAnalyzer.analyze()      → SkillRecord (risk profile)
              AdvancedDetector.run_all()
                ├── SecretScanner          → FindingRecord (ADV-005)
                ├── InjectionDetector      → FindingRecord (ADV-002, ADV-003)
                └── ScriptScanner          → FindingRecord (ADV-001)
                          │
                          └── ScanRun updated (status=COMPLETED, counts)
```

### 5.2 Runtime Hook Pipeline

```
OpenClaw executes a tool
  │
  ▼
ClawAuditPlugin (hooks/plugin.py)
  ├── Signs payload with HMAC-SHA256
  └── POST /api/v1/hooks/tool-event
        │
        ▼
HooksRouter.ingest_tool_event()
  ├── Validates HMAC signature
  ├── Sanitises params (cap at 2000 chars)
  ├── evaluate_rules(event, recent)   → alert_triggered, alert_reasons
  ├── EventStore.save(event)          → SQLite persistence
  ├── HookBus.publish(event)          → async subscribers
  └── Broadcast to WS clients        → real-time UI feed
```

### 5.3 Remediation Pipeline

```
Finding identified (check_id: ADV-001, ADV-005, PERM-001)
  │
  ▼
RemediationEngine.scan_for_proposals(findings)
  ├── Skip if skill_path not found
  ├── Skip if is_protected(skill_path)    ← system skills never modified
  └── Strategy.propose(skill_name, skill_path, finding_id)
        │
        └── RemediationProposal (diff_preview, impact, reversible)
              │
              ▼ (user approves via UI or --apply flag)
        RemediationEngine.apply_proposal()
          ├── create_snapshot(skill_path)  → .tar.gz backup
          ├── Strategy.apply_patch(skill_path)
          └── RemediationEvent persisted
                │
                └── (on error) RemediationEngine.rollback(snapshot_path)
```

**Protected prefixes** (never modified, proposals silently skipped):
- `/opt/homebrew/lib/node_modules/openclaw`
- `/usr/local/lib/node_modules/openclaw`
- `/usr/lib/node_modules/openclaw`

---

## 6. WebSocket Flows

### 6.1 Scan Progress Stream (`/ws/scans/{scan_id}/stream`)

Auth is handled by `AuthMiddleware` via `?token=` query parameter. The endpoint:

1. Accepts the connection and subscribes an asyncio queue to the scan
2. Streams JSON events until `{"type": "completed"}` or `{"type": "error"}`
3. Sends `{"type": "ping"}` keepalives every 30s on idle
4. Unsubscribes on disconnect

Event types: `finding`, `skill`, `progress`, `completed`, `error`, `ping`

### 6.2 Hook Event Stream (`/api/v1/hooks/stream`)

This endpoint uses **first-message authentication** (token is never transmitted in the URL):

```
Client connects (no token in URL)
  │
  ▼
Server accepts connection
  │  (5-second timeout)
  ▼
Client sends {"type": "auth", "token": "<bearer-token>"}
  │
  ├── Invalid / timeout / wrong token
  │     └── server closes: code=4001, reason="unauthorized|auth timeout|..."
  │
  └── Valid token
        └── server sends {"type": "auth_ok"}
              │
              └── bidirectional stream; server pushes ToolEvent dicts
                  keepalive {"type": "ping"} every 30s
```

---

## 7. Database Schema Overview

```
scan_runs
  id (PK), status, started_at, completed_at,
  total_findings, critical_count, high_count, medium_count, low_count,
  skills_scanned, triggered_by, error_message

findings
  id (PK), scan_id (FK→scan_runs), check_id, domain,
  title, description, severity, result, evidence,
  location, remediation, skill_name, detected_at

skills
  id (PK), scan_id (FK→scan_runs), name, source, path,
  shell_access, outbound_domains (JSON), injection_risk,
  trust_score, risk_score, risk_level, content_hash, detected_at

remediation_events
  id (PK), proposal_id, skill_name, check_id, action_type,
  status, description, diff_preview, impact (JSON),
  snapshot_path, applied_at, error

chat_messages
  id (PK), question, answer, mode, context_scan_id, created_at

policies
  id (PK), name, domain, check, severity, action,
  enabled, description, created_at, updated_at

tool_events (SQLite, hooks/store.py)
  id, session_id, skill_name, tool_name, params_summary,
  alert_triggered, alert_reasons (JSON), timestamp
```

Migrations are in `backend/migrations/versions/`. `alembic upgrade head` applies all pending migrations.

---

## 8. Test Coverage Summary

| Tier | Count / Coverage | Notes |
|------|-----------------|-------|
| Backend unit + API tests | **88% line coverage** | `pytest tests/unit/ tests/backend/` — covers middleware, routes, engine, repository |
| Frontend E2E (Playwright) | **160+ tests** | `frontend/e2e/` — auth flows, dashboard, findings, audit page, error states |
| Functional / cross-reference | ~30 tests | `tests/functional/` — YAML rule coverage, domain coverage, CLI behaviours |
| Integration | ~20 tests | `tests/integration/` — full pipeline, regression, hooks pipeline |
| Security validation | **21 tests** (`tests/unit/test_security_validation.py`) | Auth bypass, body size limits, WS auth (4001), path traversal, protected paths, token leak |

Coverage is enforced at **80% minimum** via `pytest --cov` with `fail_under = 80`.

---

## 9. Known Gaps & Risks

| Area | Gap / Risk | Severity |
|------|-----------|----------|
| **WS path auth** | `/ws/scans/{id}/stream` accepts token via URL query param (`?token=`). Tokens in URLs can appear in server logs and browser history. | Medium |
| **Chunked upload bypass** | `MaxBodySizeMiddleware` checks `Content-Length` only. Chunked-encoded requests with no `Content-Length` header bypass the 64 KiB limit (mitigated only by Pydantic field limits). | Medium |
| **SQLite concurrency** | Development SQLite store is not safe for concurrent writes. Production deployments require PostgreSQL. | High (prod) |
| **No rate limiting** | The API has no rate limiting middleware. Brute-force token guessing and scan-spam are possible. | Medium |
| **Snapshot path validation** | Rollback endpoint validates snapshot path is within `~/.openclaw/sentinel/snapshots/` but the check uses string prefix comparison, not `Path.is_relative_to()`. | Low |
| **Tool event HMAC secret bootstrap** | If the ClawAudit plugin is not registered, `_read_hmac_secret()` returns `None` and all tool events are rejected. Startup order matters. | Low |
| **Frontend token storage** | The bearer token is stored in browser `localStorage`/cookies by the UI; this should be reviewed against the threat model. | Medium |
| **Playwright test failures** | 2 Playwright tests have known intermittent failures (auth banner and empty-state tests) in CI — `test-results/` contains failure artifacts. | Low |
| ~~**Token leak coverage**~~ | ~~API responses were only checked for 3 endpoints.~~ Covered by PR #73 — all major API endpoints now verified to not leak the bearer token. | ~~Medium~~ Resolved |
| ~~**Body size streaming**~~ | ~~MaxBodySizeMiddleware test only forged Content-Length header.~~ PR #73 now sends actual oversized bodies to confirm rejection at the middleware layer. | ~~Medium~~ Resolved |
| **No mTLS between services** | Backend ↔ OpenClaw gateway communication uses plain HTTP (no mTLS). Appropriate for localhost-only deployments; requires hardening for multi-host. | Low |
