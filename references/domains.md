# ClawAudit — Domain Definitions

## Domain 1: Configuration Hardening

Evidence source: `gateway config.get` (parsed config JSON).

| Check ID | Key Path | Expected | Severity if Failed |
|---|---|---|---|
| CONF-01 | `debug` | absent or `false` | MEDIUM |
| CONF-02 | `gateway.bind` | `"loopback"` or `"127.0.0.1"` | CRITICAL |
| CONF-03 | `gateway.auth.mode` | `"token"` or `"oauth"` | CRITICAL |
| CONF-04 | `agents.defaults.maxSteps` or `maxTokens` | present and > 0 | HIGH |
| CONF-05 | `hooks.internal.entries.command-logger.enabled` | `true` | HIGH |
| CONF-06 | any HITL gate key (e.g. `agents.defaults.humanGate`) | present | HIGH |
| CONF-07 | `agents.defaults.skillTimeoutSeconds` or similar | present | MEDIUM |
| CONF-08 | `agents.defaults.allowedModels` | present and non-empty | HIGH |

### Detection Logic

- Load config via `gateway config.get`.
- For each check: navigate the parsed JSON to the key path.
- If key absent → FAIL (or UNKNOWN if the config schema could represent it differently).
- If key present but wrong value → FAIL.
- If key present and matches expected → PASS.

### Evidence Collection

Record: exact key path, observed value (redact token/secret values), expected value, result.

---

## Domain 2: Skill Permission Audit

Evidence source: SKILL.md frontmatter + body for each discovered skill.

| Check ID | What to look for | Severity if Failed |
|---|---|---|
| SKILL-01 | `allowed-tools` list in frontmatter | MEDIUM |
| SKILL-02 | Shell/exec access: body mentions `exec`, `pty`, `bash`, shell commands | HIGH |
| SKILL-03 | Filesystem access outside skill dir: body references paths outside workspace | MEDIUM |
| SKILL-04 | Outbound HTTP: body references `curl`, `fetch`, `http`, external domains | LOW (list domains) |
| SKILL-05 | Raw user input to shell: user args interpolated into shell without sanitization | HIGH |
| SKILL-06 | Invokes undeclared skills | MEDIUM |
| SKILL-07 | Version pinned: frontmatter `version` key or pinned hash | LOW |
| SKILL-08 | Cryptographic signature: frontmatter `signature` key | MEDIUM |
| SKILL-09 | Author + source repo declared in frontmatter `metadata` | LOW |
| SKILL-10 | Stores/logs external data: body references writing external content to files | LOW |

### Trust Scoring

| Score | Criteria |
|---|---|
| TRUSTED | allowed-tools declared; no shell exec; no injection risk; author declared |
| CAUTION | shell exec present but scoped; or missing allowed-tools; low injection risk |
| UNTRUSTED | shell exec + injection risk; or missing author + unsigned |
| QUARANTINE | active injection patterns detected; or calls undeclared external endpoints |

### Detection Logic — Shell Access (SKILL-02)

Scan SKILL.md body text for patterns:
- `exec`, `pty:true`, `bash`, `sh -c`, `shell`, `command:`, `os.system`, `subprocess`
- Presence of code blocks containing shell commands
- Instructions to run `git`, `curl`, `npm`, `pip`, etc. directly

### Detection Logic — Injection Risk (SKILL-05)

Scan for patterns where user-supplied variables are interpolated into shell strings:
- `{user_input}` or `{args}` inside backticks or shell command strings
- Phase parsing that passes raw flags directly to curl/git without validation mention
- No mention of "sanitize", "validate", "escape" near argument handling

---

## Domain 3: Secrets & Credential Hygiene

See `detectors/secret-patterns.md` for regex patterns.

| Check ID | What | Severity |
|---|---|---|
| SEC-01 | Hardcoded credential patterns in skill files + config | CRITICAL |
| SEC-02 | Secrets in env vars vs embedded in YAML/JSON | HIGH |
| SEC-03 | Secrets manager integration present | HIGH |
| SEC-04 | Log files checked for secret masking | HIGH |
| SEC-05 | API keys scoped to least privilege | MEDIUM |
| SEC-06 | Key rotation policy or TTL defined | LOW |

### Evidence Collection

For any pattern match: record FILE PATH + APPROXIMATE LINE RANGE + CREDENTIAL TYPE.
**Never record or output the matched value.**

---

## Domain 4: Network Exposure & Egress Control

Evidence source: `gateway config.get` → `gateway.*`, `channels.*`.

| Check ID | Key/Condition | Expected | Severity |
|---|---|---|---|
| NET-01 | `gateway.bind` | loopback, not `0.0.0.0` | CRITICAL |
| NET-02 | TLS for inbound: `gateway.tls` or `gateway.mode` | present if exposed | HIGH |
| NET-03 | Egress allowlist: `agents.defaults.egressAllowlist` or similar | present | HIGH |
| NET-04 | Webhook HMAC: `gateway.webhooks.*.hmac` | present if webhooks configured | HIGH |
| NET-05 | Rate limiting: `gateway.rateLimit` or similar | present | MEDIUM |
| NET-06 | DNS restriction for skills | any DNS filter config | LOW |
| NET-07 | Skill execution isolation (container/namespace) | any isolation config | MEDIUM |

---

## Domain 5: Supply Chain Risk

Evidence source: skill frontmatter `metadata`, OpenClaw npm lockfile.

| Check ID | Check | Severity |
|---|---|---|
| SC-01 | Record name, version, publisher, source URL per skill | INFO |
| SC-02 | Publisher has established identity (multiple skills / known org) | LOW |
| SC-03 | Source repo has recent commits + open issues (requires web check — flag UNKNOWN if unavailable) | LOW |
| SC-04 | Skill pinned to version hash | MEDIUM |
| SC-05 | Source repo deleted or private | HIGH |
| SC-06 | External deps (npm/pip) without pinned versions in skill scripts | MEDIUM |
| SC-07 | Skill calls home to non-declared endpoint on first load | HIGH |

---

## Domain 6: Audit Logging & Observability

Evidence source: `gateway config.get` → `hooks.*`.

| Check ID | Check | Severity |
|---|---|---|
| OBS-01 | Every skill invocation logged (command-logger hook enabled) | HIGH |
| OBS-02 | Logs tamper-evident or shipped to external SIEM | HIGH |
| OBS-03 | Alerting on repeated failures or anomalous patterns | MEDIUM |
| OBS-04 | Mechanism to replay agent decision chain | MEDIUM |
| OBS-05 | Audit log retention policy defined | LOW |
