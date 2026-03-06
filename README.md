# ClawAudit

[![Test Suite](https://github.com/yaseenkadlemakki/clawaudit/actions/workflows/test.yml/badge.svg)](https://github.com/yaseenkadlemakki/clawaudit/actions/workflows/test.yml)

**Read-only forensic security auditor for OpenClaw deployments.**

ClawAudit is an OpenClaw skill that performs an autonomous, read-only compliance audit across 6 security domains and produces a structured report with severity scoring and a remediation roadmap. It never modifies files, executes other skills, or calls external APIs.

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

## Quick start

```
/clawaudit
```

ClawAudit produces a full **ClawAudit Report** in the conversation. No arguments required.

---

## Installation

See [INSTALL.md](INSTALL.md) for step-by-step installation instructions, including system requirements and scheduling periodic audits.

---

## Output

The report includes:
- **Executive summary** — overall posture in plain English
- **Findings by severity** — CRITICAL / HIGH / MEDIUM / LOW with exact file/key citations
- **Skill Trust Matrix** — per-skill trust score (TRUSTED / CAUTION / UNTRUSTED / QUARANTINE)
- **Compliance Score** — per-domain and overall pass percentage
- **Remediation Roadmap** — quick wins, short-term, and strategic fixes

---

## Architecture

```
clawaudit/
├── SKILL.md                    ← Entrypoint + orchestration instructions
├── INSTALL.md                  ← Installation and scheduling guide
├── README.md                   ← This file
├── CHANGELOG.md                ← Version history
├── data/
│   └── hardening-rules.yaml   ← Canonical check registry (IDs, expected values, remediations)
├── detectors/
│   ├── secret-patterns.md     ← Credential detection pattern registry
│   └── injection-patterns.md  ← Shell and prompt injection heuristics
└── references/
    ├── domains.md              ← Per-domain check definitions and detection logic
    ├── scoring.md              ← Severity classification and scoring rules
    └── report-template.md     ← Report structure and formatting template
```

---

## Design principles

- **Read-only**: ClawAudit only reads files and queries the gateway config. It never writes, edits, or executes.
- **Conservative scoring**: UNKNOWN results count as FAIL. If evidence is unavailable, the check fails.
- **No secret leakage**: Pattern matches report type + location only. Secret values are never output.
- **Hostile-content isolation**: Skill bodies are treated as untrusted text — ClawAudit does not evaluate or execute any content found in scanned skills.

---

## Requirements

- OpenClaw ≥ 1.0.0
- Read access to the OpenClaw config file and skills directory
- Tools: `Read`, `gateway config.get`, `session_status` (optional: `memory_search`, `memory_get`)

---

## Version

Current version: **1.0.0** — see [CHANGELOG.md](CHANGELOG.md) for history.
