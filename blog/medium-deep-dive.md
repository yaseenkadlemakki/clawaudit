# ClawAudit: What Building a Security Tool with AI Agents Taught Me About the Future of Software Engineering

## The Experiment

I have spent the better part of a decade leading platform engineering teams at Juniper Networks — building CI/CD pipelines, Kubernetes infrastructure, and developer productivity tooling for organizations that ship networking software at scale. I know what production-grade engineering looks like. I also know how long it takes.

So when I decided to build ClawAudit — a forensic security auditor for AI agent deployments — I set myself a constraint: **build it using AI agents as my engineering team.** Not as autocomplete. Not as a copilot for boilerplate. As the primary implementation layer, with me operating as the architect, reviewer, and decision-maker.

The result is a codebase I would put in front of any senior engineering leader and defend. Here is what I built, how I built it, and what it means for the industry.

## The Problem: AI Agents Are a New Attack Surface

The AI industry is sprinting toward autonomous agents. OpenClaw, LangChain, AutoGPT, CrewAI — these frameworks give AI systems access to real tools: shell execution, file systems, HTTP clients, databases. An AI agent with shell access and no permission boundaries is functionally equivalent to giving an untrusted contractor root access to your production servers.

Most organizations deploying AI agents today have:
- No audit trail of what agents execute
- No permission boundaries on skill-level tool access
- No supply chain verification for community-authored skills
- No runtime monitoring for credential exposure or prompt injection
- No policy enforcement for agent behavior

This is the gap ClawAudit addresses. It runs 43 security checks across six domains, provides continuous monitoring through five async collectors, enforces runtime policies, and generates compliance reports — all read-only, never modifying the systems it audits.

## Architecture: What a Senior Engineer Builds

Let me walk through the architecture, because the technical choices reveal whether this is a toy or a tool.

### Three-Layer Design

ClawAudit has three distinct layers:

**1. The Skill Layer** — A markdown-based orchestration file (`SKILL.md`) that runs as a read-only OpenClaw skill. It executes a 7-phase audit: setup, configuration hardening, skill permissions, secrets hygiene, network exposure, supply chain risk, and audit logging. This layer uses no compiled code — it is pure declarative orchestration with safety rules baked in ("never write, execute, or modify anything").

**2. The Sentinel CLI** — A Python package providing the `clawaudit` command-line tool with 20+ subcommands: `scan`, `monitor`, `remediate`, `policies`, `skills`, `findings`, `report`, and more. Built on Typer with Rich for terminal output, it follows the data flow pattern: **Collectors → Events → PolicyEngine → AlertEngine → Channels**.

**3. The Dashboard** — A full-stack application with a FastAPI async backend (SQLAlchemy, PostgreSQL, WebSocket support) and a Next.js 15 frontend. Seven pages: dashboard with risk gauge, audit runner, findings explorer, skill manager, remediation console, security investigation chat, and policy management.

### Collector Pipeline

Five async collectors run concurrently via `asyncio.gather()`:

- **ConfigCollector** — Polls `openclaw.json` hash for configuration drift
- **SessionCollector** — Scans session logs for runaway agents exceeding tool call thresholds
- **CronCollector** — Detects new cron jobs against a known baseline
- **LogCollector** — Tails log files for suspicious patterns and credential exposure
- **SkillCollector** — Watches the skills directory for new or modified skills

Each collector emits typed `Event` objects that flow through the policy engine. The engine evaluates YAML-based rules and resolves actions on a priority scale: ALLOW < WARN < ALERT < BLOCK. The alert engine deduplicates by check ID and location with configurable time windows, then fans out to file, webhook, or OpenClaw channels.

### Policy Engine

The policy system deserves specific attention. Rules are defined in YAML, hot-reloadable, and follow a `POL-NNN` naming convention. The engine supports pattern matching on event types, configurable thresholds (e.g., POL-007 triggers when tool calls exceed 30/minute — a constant kept in sync between the policy file and the session collector via an enforced functional test), and graduated response actions.

This is not a hardcoded rule set. It is an extensible policy framework that an enterprise security team could adapt without touching Python code.

### Engineering Quality Markers

- **Test coverage**: 80%+ enforced in CI, with unit, functional, and integration test tiers
- **CI pipeline**: 9 parallel jobs including YAML lint, Python 3.10/3.11/3.12 matrix testing, backend API tests, shell script validation, and a final gate
- **Dependency management**: Hatchling build system, pinned dependencies, optional dependency groups for backend and dev
- **Code quality**: Ruff linting, strict markers, async-safe test configuration
- **Security practices**: Pinned GitHub Actions by SHA, least-privilege workflow permissions, secret sanitization throughout (the `SecretMatch` model never stores raw values)

These are not afterthoughts. They are the kind of choices a platform engineering team makes when building something intended to last.

## The Development Story: AI-Orchestrated Engineering

Here is where it gets interesting for engineering leaders.

I built ClawAudit using OpenClaw and Claude Code. The workflow:

**OpenClaw** is a framework for orchestrating AI agents. You instruct agents through Discord — natural language commands that get routed to AI models with access to defined toolsets. Each "skill" is a markdown file that defines what the agent can do, what tools it has access to, and what constraints it operates under.

**Claude Code** is Anthropic's CLI for Claude, purpose-built for software engineering tasks. It reads files, writes code, runs tests, and manages git — operating as a capable junior engineer that never gets tired.

My development cycle looked like this:

1. **Architecture in my head** — I sketched the collector pipeline, policy engine, and alert routing on paper
2. **Intent through Discord** — I described components to OpenClaw agents: "Build a config collector that detects drift using SHA-256 hash comparison, emitting events compatible with the policy engine"
3. **Claude Code for implementation** — The agent produced Python modules, test files, type hints, and docstrings
4. **Review and steer** — I evaluated architectural fit, caught misaligned abstractions, and redirected
5. **Iterate rapidly** — Changes that would take a team days compressed into hours

This is what "vibe coding" looks like when practiced by a senior engineer. It is not abdication of engineering responsibility. It is elevation. The cognitive work shifts from "how do I implement this async generator" to "should this collector emit events synchronously or batch them, and what are the backpressure implications?"

## Market Opportunity: A VC-Style Assessment

Let me be direct about where ClawAudit sits as a potential product.

### Strengths
- **Category timing**: AI agent security is an emerging space with no dominant player. The need is real and growing
- **Technical credibility**: The architecture is extensible, well-tested, and demonstrates engineering maturity
- **Open-source positioning**: Apache 2.0 license, clean repo, CI badges — ready for community adoption
- **Multi-surface coverage**: CLI + API + dashboard covers developer, automation, and operator personas

### Risks and Gaps
- **No customer validation**: No evidence of production deployments or user feedback loops
- **Single-platform dependency**: Tightly coupled to OpenClaw; the market may consolidate around different agent frameworks
- **Missing enterprise features**: No multi-tenancy, RBAC, SSO, or audit log export to enterprise SIEMs
- **No SaaS offering**: On-premise only; enterprise buyers expect hosted options
- **Remediation coverage**: Three strategies (secrets, shell access, permissions) — needs 10-20x more to be comprehensive

### What Would Make This Fundable
- **Platform abstraction**: Support LangChain, CrewAI, and AutoGPT alongside OpenClaw
- **Customer pilots**: Three enterprise deployments with documented findings and remediation outcomes
- **Compliance mapping**: Map the 43 checks to SOC 2, ISO 27001, and emerging AI governance frameworks (EU AI Act, NIST AI RMF)
- **Managed service**: SaaS dashboard with team workspaces, SSO, and API access tiers
- **Threat intelligence feed**: Continuously updated skill reputation scores and known-bad patterns

The category is real. The timing is early. The builder has credibility. The product needs market validation and enterprise hardening.

## What This Means for Engineering Leaders

Three strategic observations:

**The staffing model is changing.** A senior engineer with AI orchestration tools can produce what previously required a small team. This does not mean fewer engineers — it means each engineer's leverage increases dramatically. The organizations that figure out how to structure teams around AI-augmented individuals will ship faster than those still optimizing sprint velocity.

**Security tooling must evolve for the agent era.** Your SAST scanner does not know what an OpenClaw skill is. Your DAST tool cannot detect prompt injection. Your SBOM does not include AI agent skill dependencies. The entire AppSec toolchain was built for a world where humans write all the code and HTTP is the primary interface. That world is ending.

**The build-vs-buy equation has flipped.** The cost of building internal tooling just dropped by 10x. That compliance dashboard, that security audit CLI, that developer portal — a senior engineer with the right AI tooling can build production-quality versions during a focused sprint. Engineering leaders should be asking: what internal tools have we been deferring because the cost was too high?

## The Honest Takeaway

ClawAudit is not a finished product. It is an early-stage project that demonstrates two things simultaneously: that AI agent security is a real and growing need, and that AI-orchestrated development can produce genuinely high-quality software.

The codebase is open. The commit history is transparent. The CI pipeline runs green. I built it to prove that a senior engineer, armed with the right AI tools and the right judgment, can operate at a fundamentally different scale.

The future of engineering leadership is not about writing more code. It is about making better decisions, faster, with AI systems that handle the implementation. ClawAudit is my proof of concept for that thesis.

---

*Yaseen Kadlemakki is a Director of Engineering at Juniper Networks, focused on platform engineering, CI/CD infrastructure, and developer productivity. ClawAudit is open-source under Apache 2.0 at [github.com/yaseenkadlemakki/clawaudit](https://github.com/yaseenkadlemakki/clawaudit).*
