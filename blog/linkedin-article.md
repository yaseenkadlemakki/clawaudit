# I Built a Production Security Tool Without Writing Most of the Code. Here's What I Learned About the Future of Engineering.

Six months ago, I started an experiment. As a Director of Engineering at Juniper Networks, I spend my days thinking about platform engineering, CI/CD pipelines, and developer productivity at scale. I wanted to answer a simple question: **What happens when a single engineer uses AI agents as their entire development team?**

The result is [ClawAudit](https://github.com/yaseenkadlemakki/clawaudit) — a forensic security auditor for AI agent deployments. 75 commits. 29,000 lines of Python. A Next.js dashboard. A CLI with 20+ commands. Five async runtime collectors. A policy engine. A remediation system with rollback. Docker deployment. A full CI pipeline with 9 parallel jobs.

Built by one person, orchestrating AI agents through Discord and Claude Code.

## The Problem Nobody Is Talking About

We are deploying AI agents into production faster than we are securing them. Every AI agent framework — OpenClaw, LangChain, CrewAI — gives agents access to tools: shell execution, file systems, APIs, databases. Most deployments have no audit trail, no permission boundaries, no supply chain verification for the "skills" these agents run.

ClawAudit addresses this gap with 43 security checks across six domains: configuration hardening, skill permissions, secrets hygiene, network exposure, supply chain risk, and audit logging. It watches for config drift, detects credential leaks, scores skill trust levels, and enforces runtime policies — all without modifying the systems it audits.

This is not hypothetical risk. If you are running AI agents with shell access and no egress allowlist, you have a security problem today.

## What "Vibe Coding" Actually Looks Like in Practice

The term "vibe coding" gets tossed around dismissively. In practice, what I experienced was something more disciplined: **AI-orchestrated development**.

Using OpenClaw — a framework that lets you instruct AI agents through Discord — I described what I needed in natural language. Claude Code handled implementation. I reviewed, steered, and course-corrected. The workflow looked like:

1. **Describe intent** — "Build an async collector that watches for config drift using file hash comparison"
2. **Review output** — The agent produces code, tests, and documentation
3. **Steer architecture** — "This needs to integrate with the policy engine pipeline, not run standalone"
4. **Iterate** — Refinement cycles that would normally take days compressed into hours

The key insight: I was not writing code. I was making engineering decisions. Architecture choices. Security trade-offs. Integration patterns. The cognitive work shifted from syntax to strategy.

## Why This Matters for Engineering Leaders

Three implications I see clearly now:

**1. The 10x engineer is becoming the 100x engineer.** Not through heroic coding sessions, but through orchestration. A senior engineer who can decompose problems, evaluate architectural trade-offs, and steer AI agents will ship at team-level velocity. The bottleneck moves from implementation to judgment.

**2. Security tooling must evolve for AI agents.** Traditional AppSec tools scan code for vulnerabilities. But AI agents introduce a new threat surface: dynamic skill execution, prompt injection, credential exposure through agent context, supply chain risks from community-authored skills. We need tools that understand agent-specific risk models. ClawAudit is an early attempt at this.

**3. The build-vs-buy calculus has permanently shifted.** The cost of building custom internal tooling just dropped by an order of magnitude. That security audit tool your team has been wanting? That compliance dashboard? The internal CLI your platform team needs? A senior engineer with AI agents can build production-quality versions in weeks, not quarters.

## An Honest Assessment

ClawAudit is not a finished product. It lacks multi-tenancy. The dashboard needs authentication hardening. The remediation engine covers three strategies — it needs twenty. There is no SaaS offering, no paid tier, no customer validation.

But the architecture is sound. Clean separation between collectors, policy engine, and alert channels. Async throughout. 80%+ test coverage enforced in CI. YAML-driven policies that can be extended without code changes. A plugin-ready hook system. These are not weekend-project patterns — they reflect real engineering discipline, even when AI agents wrote most of the implementation.

## The Shift That Is Already Happening

Every engineering leader I talk to is asking the same question: how do we integrate AI into our development workflows without sacrificing quality? The answer is not "let AI write all the code." The answer is **let AI implement while humans architect**.

ClawAudit exists because I wanted to prove — to myself and to my peers — that this workflow produces real, auditable, production-grade software. The codebase is open. The commit history is transparent. The CI pipeline passes.

The future of engineering leadership is not about managing larger teams. It is about orchestrating smarter systems.

---

*Yaseen Kadlemakki is a Director of Engineering at Juniper Networks. ClawAudit is an open-source project available at [github.com/yaseenkadlemakki/clawaudit](https://github.com/yaseenkadlemakki/clawaudit).*
