# Security Investigation Chat

The Investigation page (`/chat`) lets you query your scan data in natural language. You don't need to know SQL or the API schema — just ask.

## Modes

### OpenClaw Mode (default)
Routes your question through the local OpenClaw gateway. The gateway uses your configured AI model (default: Claude) with the full scan context injected as a system prompt.

**Requirements:**
- OpenClaw gateway running (`openclaw gateway status`)
- `OPENCLAW_GATEWAY_TOKEN` set if your gateway requires auth

### BYOLLM Mode
Calls the Anthropic API directly using your own API key. Useful when:
- The OpenClaw gateway is unavailable
- You want to use a different model
- You're testing in a CI/staging environment

**Requirements:**
- Anthropic API key (entered in the UI, never stored server-side)
- `BYOLLM_MODEL` env var to override the default model (`claude-haiku-4-5`)

---

## Example Questions

**Risk overview**
> Which skills have the highest risk scores?

> How many Critical findings does my current scan have?

**Shell access**
> Which skills allow shell execution?

> Are any HIGH-severity shell findings remediable without removing the skill?

**Supply chain**
> Which skills contact external domains that aren't in the safe list?

> What outbound domains does the `web-search` skill use?

**Secrets**
> Do any of my skills have exposed credentials?

**Remediation**
> What are the top 3 things I should fix first to reduce my overall risk score?

> Walk me through remediating the ADV-003 finding for `code-runner`.

---

## How Context is Built

Before sending your question, the chat engine:

1. Queries the latest completed scan from the database
2. Fetches the top 30 findings (ordered by severity) and top 20 skills (ordered by risk score)
3. Injects a structured summary into the system prompt

This means answers are grounded in your actual scan data, not generic security advice.

---

## Privacy

- In **OpenClaw mode**, your question and scan context are sent to the OpenClaw gateway (local process on your machine). No data leaves your machine unless the gateway is configured to forward to a remote model.
- In **BYOLLM mode**, your question and scan context are sent to Anthropic's API. Your API key is used only for that request and is not stored by ClawAudit.
- All chat history is stored locally in the ClawAudit database.
