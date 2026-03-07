# Architecture

ClawAudit is a monorepo security intelligence platform built on top of OpenClaw.

## Component Overview

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

## Layers

### Frontend (`frontend/`)
Next.js 14 App Router SPA with Tailwind CSS and shadcn/ui components. Communicates with the backend exclusively over:
- **REST** (`NEXT_PUBLIC_API_URL`) — dashboard stats, findings, skills, chat history
- **WebSocket** (`NEXT_PUBLIC_WS_URL`) — live scan progress streaming

### Backend (`backend/`)
FastAPI async API server. Structured into:

| Package | Purpose |
|---------|---------|
| `backend/api/routes/` | HTTP route handlers (audit, chat, dashboard, findings, skills, graph, policies) |
| `backend/engine/` | Business logic: `AuditEngine`, `ScanManager`, `ChatEngine`, `AdvancedDetector` |
| `backend/models/` | SQLAlchemy ORM models (ScanRun, FindingRecord, SkillRecord, ChatMessage) |
| `backend/database.py` | Async engine + session factory |
| `backend/config.py` | All configuration via env vars |

### Sentinel (`sentinel/`)
Standalone Python CLI for running audits from the terminal. Shares domain logic with the backend but has no FastAPI dependency. Usable independently of the web UI.

### OpenClaw Integration
The backend connects to the local OpenClaw gateway (`OPENCLAW_GATEWAY_URL`) for AI-powered investigation chat. Skills scanned by ClawAudit are themselves OpenClaw skills — ClawAudit audits the tools that power the platform.

## Data Flow — Audit Scan

```
User triggers scan (UI or CLI)
  │
  ▼
ScanManager.start_scan()
  │  creates ScanRun row (status=RUNNING)
  │  broadcasts via WebSocket
  ▼
AuditEngine.run_full_audit()
  │
  ├── ConfigAuditor.audit()          → FindingRecord rows
  ├── per skill:
  │     SkillAnalyzer.analyze()      → SkillRecord row
  │     AdvancedDetector.run_all()   → FindingRecord rows (ADV-*)
  │
  └── ScanRun updated (status=COMPLETED, counts)
        │
        └── WebSocket terminal event broadcast to UI
```

## Data Flow — Investigation Chat

```
User submits question (OpenClaw or BYOLLM mode)
  │
  ▼
ChatEngine.ask()
  │
  ├── _build_context()   → fetches latest scan findings + skill scores from DB
  ├── _build_prompt()    → injects context into structured system prompt
  │
  ├── [openclaw mode]  POST /api/agent/ask → OpenClaw gateway
  └── [byollm mode]    AsyncAnthropic.messages.create() → Anthropic API
        │
        └── ChatMessage row persisted, answer returned
```

## Database Schema (key tables)

| Table | Purpose |
|-------|---------|
| `scan_runs` | One row per audit run; tracks status, counts, timestamps |
| `skill_records` | Risk profile per skill per scan: scores, flags, domains |
| `finding_records` | Individual policy violations; linked to scan + skill |
| `chat_messages` | Investigation chat history; stores question, answer, mode |
