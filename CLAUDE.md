# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

Two distinct layers in one repo:

1. **ClawAudit skill** — A read-only OpenClaw skill (markdown orchestration system) that runs forensic security audits on OpenClaw deployments. The skill itself is `SKILL.md` + supporting markdown/YAML files. No compiled code.

2. **ClawAudit Sentinel** — A Python package (`sentinel/`) providing real-time continuous monitoring, a policy engine, and alert routing. Installed as the `sentinel` CLI.

## Commands

```bash
# Install sentinel and dev deps (requires Python 3.11+)
pip install -e ".[dev]"

# Run all tests
python3.11 -m pytest tests/

# Run by layer
python3.11 -m pytest tests/unit/ -m unit
python3.11 -m pytest tests/functional/ -m functional
python3.11 -m pytest tests/integration/ -m integration

# Run a single test file or test
python3.11 -m pytest tests/unit/test_policy_engine.py
python3.11 -m pytest tests/unit/test_policy_engine.py::TestPolicyEngine::test_no_match_allows

# Lint
ruff check sentinel/

# Sentinel CLI
sentinel audit               # one-shot scan
sentinel watch               # continuous monitoring daemon
sentinel skills              # list skills with trust scores
sentinel policies --list     # show loaded policy rules
sentinel alerts --last 20    # view recent alerts
```

## Architecture

### Sentinel Python package (`sentinel/`)

Data flow: **Collectors → Events → PolicyEngine → AlertEngine → Channels**

- **`sentinel/config.py`** — `SentinelConfig` wraps a merged dict. `load_config()` reads `~/.openclaw/sentinel/sentinel.yaml`, deep-merges with defaults, and interpolates `${ENV_VAR}` references. `get_config()` returns a module-level singleton.

- **`sentinel/collector/`** — Five async collectors run concurrently via `asyncio.gather()` in `watch`:
  - `ConfigCollector` — polls `openclaw.json` hash for drift
  - `SessionCollector` — scans session log files for runaway agents (>30 tool calls/min; threshold defined as `TOOL_CALL_LIMIT_PER_MINUTE` constant — must stay in sync with POL-007)
  - `CronCollector` — detects new cron jobs against a baseline set
  - `LogCollector` — tails `.log`/`.jsonl` files in `log_dir` for suspicious patterns and secrets
  - `SkillCollector` — watches `skills_dir` for new or changed skills

- **`sentinel/policy/`** — YAML-based rules loaded from `policies_dir` (falls back to bundled `sentinel/policies/default.yaml`). `PolicyEngine.evaluate(event)` and `evaluate_finding(finding)` return a `PolicyDecision` with action `ALLOW < WARN < ALERT < BLOCK` (priority via `resolve_action`).

- **`sentinel/alerts/`** — `AlertEngine.send()` deduplicates by `check_id:location` key with a configurable time window, then fans out to configured channels (`FileAlertChannel`, `OpenClawAlertChannel`, `WebhookAlertChannel`). Secret values are **never** stored in `SecretMatch` — use `secret_scanner.sanitize_line()` before putting text into event evidence.

- **`sentinel/analyzer/`** — Static analysis run during `audit`:
  - `ConfigAuditor` — runs 8 named checks (CONF-01 through CONF-08) against an openclaw.json dict; CONF-01/CONF-02 always emit a finding (PASS or FAIL), the rest only emit on FAIL
  - `SkillAnalyzer` — scores skills 0–100 by trust level (TRUSTED/CAUTION/UNTRUSTED/QUARANTINE)
  - `SecretScanner` — pattern-based credential detection; `sanitize_line()` applies `re.sub` in-place (the `.context` field on `SecretMatch` is NOT a substring of the original line — do not use it for replacement)

- **`sentinel/reporter/`** — `ComplianceReporter.run_full_audit()` → findings list → `render_markdown`/`render_json`. `delta.py` computes new/resolved findings between runs via JSONL append log.

- **`sentinel/api/`** — Optional FastAPI server (disabled by default). Routes: `/health`, `/findings/`, `/findings/{id}`, `/policies/`, `/skills/`, `/alerts/`.

### ClawAudit skill (markdown layer)

`SKILL.md` orchestrates a 7-phase read-only audit:
- `data/hardening-rules.yaml` — canonical check registry (43 checks, 6 domains)
- `references/domains.md` — per-domain detection logic (authoritative source of truth for CONF-01 absent-key behavior)
- `detectors/secret-patterns.md` / `detectors/injection-patterns.md` — detection patterns

## Tests

Test markers: `unit`, `functional`, `integration`. Async tests use `asyncio_mode = "auto"` (add `@pytest.mark.asyncio` explicitly for resilience to config changes).

- **`tests/unit/`** — isolated per-module tests; sentinel modules require `pip install -e ".[dev]"`, markdown/YAML skill tests need only `requirements-dev.txt`
- **`tests/functional/`** — cross-file consistency checks (e.g. YAML check IDs referenced in domains.md, policy↔collector constant alignment)
- **`tests/integration/`** — full pipeline tests using `tmp_path`; `test_regression.py` contains hard regression guards

CI (`test.yml`): lint-yaml → unit-tests (3.10/3.11/3.12 matrix) → functional + integration (parallel) → coverage → sentinel-tests → gate. The `sentinel-tests` job installs via `pip install -e ".[dev]"` while other jobs use `requirements-dev.txt`.

## Key invariants

- `TOOL_CALL_LIMIT_PER_MINUTE` in `session_collector.py` must equal POL-007's `value` (enforced by `test_pol_007_threshold_matches_session_collector`)
- POL-008/009/010 `value` fields must match the exact `event_type` strings emitted by their respective collectors
- All policy rule IDs must follow `POL-NNN` format
- `SecretMatch.context` contains `<REDACTED>` not the raw value — always use `sanitize_line()` to redact from strings
