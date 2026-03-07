# Risk Scoring Model

ClawAudit assigns a **risk score (0–100)** to each OpenClaw skill based on a weighted combination of factors. Higher scores indicate higher risk.

## Score Bands

| Score | Risk Level | Colour |
|-------|-----------|--------|
| 0–25 | Low | 🟢 Green |
| 26–50 | Medium | 🟡 Yellow |
| 51–75 | High | 🟠 Orange |
| 76–100 | Critical | 🔴 Red |

## Scoring Factors

| Factor | Max contribution | Description |
|--------|-----------------|-------------|
| Shell access | +35 | Skill can execute arbitrary shell commands (`bash`, `exec`, `subprocess`) |
| Injection risk | +20 | Skill constructs shell or SQL commands from user input |
| Outbound domains | +15 | Number and trustworthiness of external domains contacted |
| Trust score (inverse) | +15 | Low publisher trust (no author, unverified source) |
| Policy violations | +15 | Number and severity of policy findings |

Scores are computed by `sentinel/skill_analyzer.py` and stored in `skill_records.risk_score`.

---

## Advanced Detection Checks (ADV-*)

These checks run after the main audit on every skill. Each generates a `FindingRecord` with a fixed `check_id`.

### ADV-001 — Unrestricted Shell Execution
**Severity:** HIGH  
**Domain:** `capability`

Triggered when a skill's SKILL.md or configuration declares or demonstrates shell execution capability with no explicit sandboxing or restriction policy.

**Remediation:** Restrict shell commands to a fixed allowlist. Document the specific commands used and why they are needed.

---

### ADV-002 — Unknown Publisher
**Severity:** MEDIUM  
**Domain:** `provenance`

Triggered when a skill has no declared `author` or `source` field, making provenance unverifiable.

**Remediation:** Add an `author` field to SKILL.md or claw.yaml. Only install skills from verified, trusted publishers.

---

### ADV-003 — Supply Chain Risk
**Severity:** HIGH  
**Domain:** `network`

Triggered when a skill contacts domains not in the ClawAudit safe-domain allowlist. The allowlist includes well-known AI provider APIs, package registries, and GitHub.

**Safe domains include:** `github.com`, `api.anthropic.com`, `api.openai.com`, `pypi.org`, `registry.npmjs.org`, `huggingface.co`, and others.

**Remediation:** Review all outbound domains. Add a `network_policy` section to SKILL.md explicitly listing required domains and their purpose.

---

### ADV-004 — Unsigned Skill
**Severity:** LOW  
**Domain:** `integrity`

Triggered when a skill has no cryptographic signature. Without a signature, there is no way to verify the skill has not been tampered with since publication.

**Remediation:** Sign skills using the OpenClaw signing mechanism before deploying in production environments.

---

### ADV-005 — Secrets Exposed in SKILL.md
**Severity:** CRITICAL  
**Domain:** `secrets`

Triggered when patterns resembling credentials are found in SKILL.md content. Detected patterns include:
- API keys (Anthropic, OpenAI, AWS, GitHub, Stripe, etc.)
- Passwords and tokens in config-style assignments
- Bearer tokens and private keys

**Remediation:** Remove all credentials from SKILL.md immediately. Use environment variables or a secrets manager. Rotate any exposed credentials.
