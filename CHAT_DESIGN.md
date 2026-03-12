# Security Investigation Chat — Current Design & Issue Analysis

**Document date:** 2026-03-12  
**Status:** Broken in production — no AI responses are being generated  
**Component:** `backend/engine/chat_engine.py` · `backend/api/routes/chat.py` · `frontend/src/components/InvestigationPanel.tsx`

---

## Current Architecture

```
User types question in InvestigationPanel
        │
        ▼
POST /api/v1/chat
  { question, mode: "openclaw"|"byollm", api_key? }
        │
        ▼
ChatEngine.ask()
  1. _build_context()   → pulls latest scan from DB
  2. _build_prompt()    → assembles a text prompt
  3. _ask_openclaw()    → POST gateway /api/agent/ask  [❌ BROKEN]
     OR
     _ask_anthropic()   → Anthropic SDK direct        [⚠️ WORKS IF key supplied]
        │
        ▼
Returns (answer, context_used) → HTTP 200 always
        │
        ▼
InvestigationPanel renders answer as chat bubble
```

---

## Issues Found (Research Summary)

### 🔴 ISSUE 1 — OpenClaw mode calls a non-existent gateway endpoint
**Severity: Showstopper**  
**File:** `backend/engine/chat_engine.py` → `_ask_openclaw()`  
**Line:** `resp = await client.post(f"{OPENCLAW_GATEWAY_URL}/api/agent/ask", ...)`

The gateway **does not have** a `/api/agent/ask` route. Confirmed with live probing:
all paths return HTTP 404. The OpenClaw gateway exposes an OpenAI-compatible
`/v1/chat/completions` endpoint — but that endpoint is **disabled by default** and
requires `gateway.http.endpoints.chatCompletions.enabled = true` in `openclaw.json`.
Current `openclaw.json` has `gateway.http: {}` — not set.

**Result:** Every OpenClaw-mode request immediately throws `RuntimeError("OpenClaw
gateway error: 404")` and falls through to the canned fallback string. No LLM is
ever called. No AI reasoning ever happens.

---

### 🔴 ISSUE 2 — Fallback is a hardcoded non-answer, rendered as success
**Severity: Showstopper**  
**File:** `backend/engine/chat_engine.py` → `ask()`  
**Lines:** fallback block in the `except RuntimeError` handler

When the gateway call fails, the backend returns HTTP 200 with:
```
"OpenClaw gateway unavailable (OpenClaw gateway error: 404).

Based on scan data, here's what I can tell you:

**Scan summary:** 252 findings across 52 skills.

To get full AI analysis, ensure the OpenClaw gateway is running or switch
to BYOLLM mode with your Anthropic API key."
```

This string is hardcoded. It carries zero intelligence and does not answer the
user's question. For "what does a score of 20 mean?" — the response ignores the
question entirely.

**Compound problem:** `InvestigationPanel.tsx` renders this as a normal assistant
chat bubble — no warning state, no error indicator, no "switch to BYOLLM" prompt.
The user cannot distinguish a real AI answer from this canned fallback.

---

### 🔴 ISSUE 3 — Context missing the data users actually ask about
**Severity: Critical**  
**File:** `backend/engine/chat_engine.py` → `_build_context()`

`_build_context()` fetches a scan record and returns findings + skills.
What it **does not include:**

| Missing data | Why it matters | Where it lives |
|---|---|---|
| `overall_score` (e.g. 20) | The dashboard score users see and ask about | Computed in `main.py`: `100 - avg(risk_score)`, never stored on scan record |
| `high_count`, `medium_count`, `low_count`, `critical_count` | Severity breakdown visible on dashboard | On `ScanRun` record — fetched but not added to context dict |
| **Risk scoring rubric** | Without this no LLM can explain "score of 20" | `risk_scoring.py`: ≤20=Low, ≤40=Medium, ≤70=High, >70=Critical |
| **Risk factor weights** | Shell execution=30pts, injection HIGH=25pts, etc. | `RISK_FACTORS` dict in `risk_scoring.py` |
| Active policies + violations | Users ask "what policies fired?" | `/api/v1/policies/stats` endpoint exists, not queried |
| Quarantined skills | Users ask "what's quarantined and why?" | `SkillRecord.trust_score == "QUARANTINE"` — not surfaced |
| Domain breakdown | Config/skills/secrets/network/supply-chain/observability | `FindingRecord.domain` — groupable, not grouped |
| **Total DB scope** | 1,562 skills in DB; context only shows top 20 | No mention of total skill count |

**Context is truncated to 30 findings and 20 skills out of 252 findings / 1,562
skills.** The prompt does not acknowledge this truncation.

---

### 🔴 ISSUE 4 — Every message is stateless — no conversation threading
**Severity: Major**  
**Files:** `backend/engine/chat_engine.py`, `frontend/src/components/InvestigationPanel.tsx`

`chat_engine.ask()` signature:
```python
async def ask(self, question: str, mode: str, api_key: str | None) -> tuple[str, dict]
```

There is no `history` parameter. Each call builds a fresh context and sends a
single-turn prompt. If the user asks:
1. "Which skills are critical?" → gets an answer
2. "How do I fix them?" → **no memory of Q1** — treated as a standalone question

The `InvestigationPanel` maintains local message state in React, but **none of
that history is sent to the backend**. The backend also has a `GET /api/v1/chat/history`
endpoint (returns 5 stored items) but `ask()` never writes to it and never reads
from it when building context. The history endpoint is decorative.

---

### 🟡 ISSUE 5 — `_build_prompt()` has no system-level security analyst framing
**Severity: Major (quality)**  
**File:** `backend/engine/chat_engine.py` → `_build_prompt()`

The current prompt injects scan data as a flat text block but:
- Provides no explanation of the scoring model to the LLM
- Does not tell the LLM what ClawAudit is or what it monitors
- Does not tell the LLM what the check domains mean
- Does not instruct the LLM to answer questions it can't answer from data by
  explaining the scoring model conceptually
- Truncates findings to 15 in the prompt string (already fetching only 30)
- Dumps skill data as one-liners with no semantic grouping

A question like "what does a score of 20 mean?" requires the LLM to know:
- `overall_score = 100 - avg(skill_risk_score)` — a safety score (higher = safer)
- Thresholds: ≤20=Low, ≤40=Medium, ≤70=High, >70=Critical
- The risk factors that drive individual skill scores

None of this is in the prompt.

---

### 🟡 ISSUE 6 — BYOLLM uses weakest model; no model selection
**Severity: Minor**  
**File:** `backend/engine/chat_engine.py` line 1
```python
BYOLLM_MODEL = os.getenv("BYOLLM_MODEL", "claude-haiku-4-5-20251001")
```

Haiku is the cheapest/fastest but weakest model. For security analysis with
large context payloads (30 findings + 20 skills + metadata), Sonnet-class models
produce substantially better answers. No UI exists to switch model. No env var
is documented.

---

## Data Flow Diagram (Current — Broken)

```
User: "what does score of 20 mean?"
        │
        ▼
InvestigationPanel.tsx
  fetch POST /api/v1/chat
  body: { question: "what does score of 20 mean?", mode: "openclaw" }
  headers: { Authorization: "Bearer <token>" }          ✅ (fixed in 05d2872)
        │
        ▼
chat route → chat_engine.ask()
        │
        ▼
_build_context():
  - Fetches ScanRun (latest completed)                   ✅
  - Returns: scan_id, total_findings=252, skills_scanned=52
  - Returns: top 30 findings (severity order)            ✅ (but truncated)
  - Returns: top 20 skills (risk_score desc)             ✅ (but truncated)
  - MISSING: overall_score                               ❌
  - MISSING: high/medium/low/critical counts             ❌
  - MISSING: scoring rubric + factor weights             ❌
  - MISSING: policies / violations                       ❌
  - MISSING: domain breakdown                            ❌
        │
        ▼
_build_prompt():
  - Builds flat text with findings list
  - No scoring model explanation                         ❌
  - No system analyst framing                            ❌
  - Truncates to 15 findings in the string               ❌
        │
        ▼
_ask_openclaw():
  POST http://localhost:18789/api/agent/ask              ❌ 404
  → raises RuntimeError("OpenClaw gateway error: 404")
        │
        ▼
Fallback handler:
  returns hardcoded "252 findings across 52 skills"      ❌
  HTTP 200 (looks like success)
        │
        ▼
InvestigationPanel renders as normal chat bubble         ❌
User sees: "To get full AI analysis, ensure gateway..."
Question is completely unanswered.
```

---

## Data Flow Diagram (Target — Fixed)

```
User: "what does score of 20 mean?"
        │
        ▼
InvestigationPanel.tsx
  fetch POST /api/v1/chat
  body: {
    question: "what does score of 20 mean?",
    mode: "openclaw",
    history: [/* prior Q&A pairs */]
  }
        │
        ▼
chat_engine.ask(question, mode, api_key, history)
        │
        ▼
_build_context():
  + overall_score from dashboard computation             ✅
  + severity breakdown (high/med/low/critical counts)   ✅
  + scoring rubric (thresholds + factor weights)        ✅
  + policy stats (active policies, violation counts)    ✅
  + domain breakdown (grouped findings by domain)       ✅
  + quarantined skills list                             ✅
  + total_skills in DB                                  ✅
        │
        ▼
_build_prompt():
  system: "You are an expert security analyst for ClawAudit..."
  + scoring model explanation embedded
  + full context block (structured, not flat text)
  + prior conversation history as message thread
        │
        ▼
OpenClaw mode → /v1/chat/completions (gateway, enabled)
  OR direct Anthropic SDK call (configured model)
        │
        ▼
Real LLM answer: "A score of 20 means your deployment has a HIGH average
skill risk. ClawAudit scores safety on a 0–100 scale where higher = safer.
Your average skill risk score is ~80, driven by 26 skills with shell
execution (+30pts each) and 8 with HIGH injection risk (+25pts each)..."
        │
        ▼
Exchange stored to chat history DB
        │
        ▼
InvestigationPanel:
  - Renders real answer                                  ✅
  - On gateway failure: warning banner + BYOLLM CTA     ✅
  - History sent with next message                      ✅
```

---

## Files to Change

| File | Change type | Summary |
|---|---|---|
| `backend/engine/chat_engine.py` | Rewrite | Fix gateway endpoint, enrich context, rewrite prompt, add history |
| `backend/api/routes/chat.py` | Extend | Add `history` field to request schema, persist exchanges |
| `backend/models/` | New model (optional) | `ChatMessage` table for persistent history |
| `frontend/src/components/InvestigationPanel.tsx` | Extend | Send history[], handle gateway-fail warning state |
| `~/.openclaw/openclaw.json` | Config change | Enable `gateway.http.endpoints.chatCompletions.enabled: true` |

---

## What is NOT broken

- Auth header (`Authorization: Bearer`) — fixed in `05d2872` ✅
- BYOLLM mode (Anthropic SDK path) — works if user provides API key ✅
- Context DB queries — correct tables, correct join logic ✅
- `/api/v1/chat` route — auth, request parsing, response schema all correct ✅
- InvestigationPanel UI — collapse/expand, suggested questions, mode toggle all work ✅

---

*Ready to implement on your go-ahead.*
