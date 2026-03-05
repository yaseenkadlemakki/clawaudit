# ClawAudit — Secret Detection Patterns

**Rules:**
1. These patterns are for DETECTION ONLY — never output matched values.
2. If a pattern matches, record: CREDENTIAL TYPE + FILE PATH + APPROXIMATE LINE/KEY.
3. If the value is already `__OPENCLAW_REDACTED__` or `***` → mark as MASKED (PASS).
4. Scan: config JSON values, skill SKILL.md bodies, .env files, workspace files.

---

## Pattern Registry

| Credential Type | Pattern Description | Severity |
|---|---|---|
| Anthropic API Key | Value starting with `sk-ant-` followed by alphanumeric string | CRITICAL |
| OpenAI API Key | Value starting with `sk-` followed by alphanumeric string (non-Anthropic) | CRITICAL |
| AWS Access Key ID | Value matching `AKIA` followed by 16 uppercase alphanumeric chars | CRITICAL |
| AWS Secret Access Key | 40-char base64-like string adjacent to `AWS_SECRET` or `aws_secret` key | CRITICAL |
| GitHub Personal Access Token | Value starting with `ghp_`, `gho_`, `ghs_`, `ghr_` | CRITICAL |
| GitHub Fine-grained PAT | Value starting with `github_pat_` | CRITICAL |
| Google API Key | Value starting with `AIza` followed by 35 chars | HIGH |
| Google OAuth Client Secret | Value starting with `GOCSPX-` | HIGH |
| Telegram Bot Token | Numeric string followed by `:` followed by alphanumeric (bot token format) | HIGH |
| Discord Bot Token | Multi-segment base64-like string matching Discord token format | HIGH |
| Generic Bearer Token | `Bearer ` followed by a token string in config values (not in HTTP example docs) | MEDIUM |
| JWT Token | Three base64url segments separated by `.` starting with `eyJ` | MEDIUM |
| Generic API Key | Key names containing `api_key`, `apikey`, `api-key`, `secret`, `token`, `password` with non-empty, non-placeholder values | MEDIUM |
| Private Key PEM | `-----BEGIN RSA PRIVATE KEY-----` or `-----BEGIN PRIVATE KEY-----` | CRITICAL |
| SSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----` | CRITICAL |

---

## Scan Locations (in priority order)

1. `~/.openclaw/openclaw.json` — all string values in the JSON tree
2. `~/.openclaw/.env` (if exists)
3. All `SKILL.md` files in skill directories
4. `~/.openclaw/workspace/**/*.md` and `*.yaml` and `*.json`
5. OpenClaw log files (check for accidental secret logging)

---

## False Positive Reduction

Skip matches if:
- Value equals `__OPENCLAW_REDACTED__`, `***`, `<redacted>`, `YOUR_TOKEN_HERE`, `example`, `placeholder`
- Value is inside a markdown code block that is clearly documentation/example (check context)
- Pattern appears in a comment line starting with `#` or `//`

When in doubt: **flag it** — do not assume safe.

---

## Secrets Manager Check (SEC-03)

Look for any of these in config, indicating secrets manager integration:
- Key names: `vault`, `aws_secrets_manager`, `keychain`, `1password`, `doppler`
- Values referencing `arn:aws:secretsmanager:`, `vault://`, `op://`
- Environment variable references: `${SECRET_NAME}` pattern

If none found: FAIL for SEC-03.

---

## Log Masking Check (SEC-04)

Look in config for log masking / redaction configuration:
- Keys: `log.redact`, `logging.mask`, `redactPatterns`, `maskSecrets`

If none found: UNKNOWN (cannot confirm without log file access).
