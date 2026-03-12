# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v0.4.x  | ✅ Current — actively patched |
| < v0.4  | ❌ No longer supported |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

We take security seriously. If you discover a vulnerability in ClawAudit, please report it through one of the following private channels:

### Option 1: GitHub Security Advisories (preferred)

Use GitHub's private vulnerability reporting:
👉 [Report a vulnerability](https://github.com/yaseenkadlemakki/clawaudit/security/advisories/new)

This creates a private thread between you and the maintainers. No public disclosure until a fix is ready.

### Option 2: Email

Send details to **security@clawaudit.dev**.

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce (proof of concept if available)
- Affected versions
- Any suggested mitigations

We will acknowledge receipt within **48 hours** and keep you updated throughout the process.

---

## Response SLA

| Severity | Acknowledgement | Patch Target |
|----------|----------------|--------------|
| Critical | 48 hours | 14 days |
| High | 48 hours | 30 days |
| Medium | 72 hours | 60 days |
| Low | 1 week | Next release cycle |

We aim to coordinate public disclosure with the reporter once a patch is available.

---

## Scope

### In Scope

The following are considered valid security vulnerabilities:

- **API authentication bypass** — unauthorized access to ClawAudit API endpoints
- **Remote code execution (RCE)** — any path to executing arbitrary code via ClawAudit
- **Credential or secret exposure** — ClawAudit leaking secrets it scans or its own credentials
- **Privilege escalation** — accessing data or functions beyond your authorization level
- **Injection vulnerabilities** — SQL injection, command injection, SSTI, etc.
- **Broken access control** — accessing another user's data in multi-tenant scenarios
- **Security misconfiguration** in default Docker/deployment setups that exposes the instance

### Out of Scope

The following are generally **not** considered vulnerabilities:

- Denial-of-service attacks against a self-hosted localhost instance
- Vulnerabilities in self-hosted deployments that require physical access to the host
- Issues requiring the attacker to already have admin credentials to ClawAudit
- Rate limiting on a locally-bound service
- Missing security headers on a development server
- Theoretical vulnerabilities without a working proof of concept
- Issues in third-party dependencies that do not affect ClawAudit directly (report those upstream)

---

## Disclosure Policy

We follow **coordinated disclosure**:

1. Reporter submits details privately
2. Maintainers confirm and investigate (within 48h)
3. Fix is developed and tested privately
4. Fix is released
5. Public advisory published (CVE requested if appropriate)
6. Reporter credited (unless they prefer anonymity)

Thank you for helping keep ClawAudit and its users safe.
