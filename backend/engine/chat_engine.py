"""Security investigation chat engine.

Supports two modes:
  - openclaw: routes query through the local OpenClaw gateway
  - byollm:   calls the Anthropic API directly with the user's key
"""

from __future__ import annotations

import json
import logging
import os
from collections import defaultdict
from typing import Any

import httpx
from sqlalchemy import func, select

from backend.database import AsyncSessionLocal
from backend.models.finding import FindingRecord
from backend.models.policy import PolicyRecord
from backend.models.scan import ScanRun, ScanStatus
from backend.models.skill import SkillRecord

logger = logging.getLogger(__name__)

OPENCLAW_GATEWAY_URL = os.getenv("OPENCLAW_GATEWAY_URL", "http://localhost:18789")
OPENCLAW_GATEWAY_TOKEN = os.getenv("OPENCLAW_GATEWAY_TOKEN")  # None if not set
BYOLLM_MODEL = os.getenv("BYOLLM_MODEL", "claude-sonnet-4-6")

SYSTEM_PROMPT = """\
You are an expert security analyst for ClawAudit, an AI security compliance platform that audits \
OpenClaw agentic AI deployments. ClawAudit monitors six security domains: Configuration, Skills, \
Secrets, Network, Supply Chain, and Observability.

SCORING MODEL:
- overall_score = 100 - average(skill_risk_score). Range 0-100. Higher = safer.
- Thresholds: >=80 Low risk | 60-79 Medium | 30-59 High | <30 Critical
- Key risk factors per skill: shell_execution (+30pts), HIGH injection (+25pts), \
MEDIUM injection (+10pts), credential_access (+20pts), network_outbound (+15pts)

INSTRUCTIONS:
- Answer the user's question directly using the scan data provided.
- If the question is about scoring or risk, explain using the scoring model above.
- If you cannot find the answer in the provided data, say so and explain what additional \
data would help. Do not hallucinate finding names or scores.
- Keep answers concise but technically precise. Use markdown for lists and tables."""


class ChatEngine:
    """Query ClawAudit scan data using natural language."""

    # ── Context building ───────────────────────────────────────────────────

    async def _build_context(self) -> dict[str, Any]:
        """Fetch latest scan data from DB to inject as context."""
        async with AsyncSessionLocal() as db:
            # Latest completed scan
            result = await db.execute(
                select(ScanRun)
                .where(ScanRun.status == ScanStatus.COMPLETED)
                .order_by(ScanRun.started_at.desc())
                .limit(1)
            )
            latest_scan = result.scalar_one_or_none()

            if not latest_scan:
                return {"error": "No completed scans available."}

            scan_id = latest_scan.id

            # Top findings
            findings_result = await db.execute(
                select(FindingRecord)
                .where(FindingRecord.scan_id == scan_id)
                .order_by(FindingRecord.severity)
                .limit(30)
            )
            findings = findings_result.scalars().all()

            # Top risky skills
            skills_result = await db.execute(
                select(SkillRecord)
                .where(SkillRecord.scan_id == scan_id)
                .order_by(SkillRecord.risk_score.desc())
                .limit(20)
            )
            skills = skills_result.scalars().all()

            # Total skills in DB for this scan
            total_skills_result = await db.execute(
                select(func.count()).select_from(SkillRecord).where(SkillRecord.scan_id == scan_id)
            )
            total_skills_in_db = total_skills_result.scalar() or 0

            # Quarantined skills
            quarantined_result = await db.execute(
                select(SkillRecord.name)
                .where(SkillRecord.scan_id == scan_id)
                .where(SkillRecord.trust_score == "QUARANTINE")
            )
            quarantined_skills = [row[0] for row in quarantined_result.all()]

            # Domain breakdown
            domain_result = await db.execute(
                select(FindingRecord.domain, func.count())
                .where(FindingRecord.scan_id == scan_id)
                .group_by(FindingRecord.domain)
            )
            domain_breakdown = {row[0]: row[1] for row in domain_result.all() if row[0]}

            # Policy stats — query DB directly, no HTTP self-call
            policy_total = await db.execute(select(func.count()).select_from(PolicyRecord))
            policy_enabled = await db.execute(
                select(func.count()).select_from(PolicyRecord).where(PolicyRecord.enabled.is_(True))
            )
            policy_violations = await db.execute(
                select(func.coalesce(func.sum(PolicyRecord.violation_count), 0))
            )
            policy_stats = {
                "total_policies": policy_total.scalar() or 0,
                "enabled_policies": policy_enabled.scalar() or 0,
                "violation_count": policy_violations.scalar() or 0,
            }

        # Compute overall score
        risk_scores = [s.risk_score for s in skills if s.risk_score is not None]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        overall_score = max(0, 100 - int(avg_risk))

        top_findings = [
            {
                "title": f.title,
                "severity": f.severity,
                "skill": f.skill_name,
                "domain": f.domain,
                "remediation": f.remediation,
            }
            for f in findings
        ]
        top_skills = [
            {
                "name": s.name,
                "risk_score": s.risk_score,
                "risk_level": s.risk_level,
                "shell_access": s.shell_access,
                "trust_score": s.trust_score,
                "injection_risk": s.injection_risk,
                "outbound_domains": json.loads(s.outbound_domains) if s.outbound_domains else [],
            }
            for s in skills
        ]

        return {
            "scan_id": scan_id,
            "scan_status": latest_scan.status,
            "total_findings": latest_scan.total_findings,
            "skills_scanned": latest_scan.skills_scanned,
            "top_findings": top_findings,
            "top_skills": top_skills,
            "overall_score": overall_score,
            "severity_counts": {
                "critical": latest_scan.critical_count,
                "high": latest_scan.high_count,
                "medium": latest_scan.medium_count,
                "low": latest_scan.low_count,
            },
            "scoring_rubric": {
                "formula": "overall_score = 100 - avg(skill_risk_score). Higher = safer.",
                "thresholds": {
                    "low": ">=80",
                    "medium": "60-79",
                    "high": "30-59",
                    "critical": "<30",
                },
                "risk_factors": {
                    "shell_execution": 30,
                    "injection_HIGH": 25,
                    "injection_MEDIUM": 10,
                    "credential_access": 20,
                    "network_outbound": 15,
                },
            },
            "domain_breakdown": domain_breakdown,
            "quarantined_skills": quarantined_skills,
            "total_skills_in_db": total_skills_in_db,
            "policy_stats": policy_stats,
        }

    def _build_prompt(
        self,
        question: str,
        context: dict[str, Any],
        history: list[dict] | None = None,
    ) -> list[dict[str, str]]:
        """Build a structured message list with system prompt, history, and context."""
        if "error" in context:
            return [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"The user asked: {question}\n\n"
                        f"Unfortunately, no scan data is available yet: {context['error']}\n"
                        "Please advise them to run a Full Audit first."
                    ),
                },
            ]

        # Group findings by domain
        findings_by_domain: dict[str, list[dict]] = defaultdict(list)
        for f in context["top_findings"]:
            domain = f.get("domain") or "Unknown"
            findings_by_domain[domain].append(f)

        findings_block = ""
        for domain, domain_findings in sorted(findings_by_domain.items()):
            findings_block += f"\n### {domain}\n"
            for f in domain_findings:
                findings_block += (
                    f"- [{f['severity'].upper()}] {f['title']} (skill: {f['skill'] or 'N/A'})"
                )
                if f.get("remediation"):
                    findings_block += f" — {f['remediation']}"
                findings_block += "\n"

        skills_block = "\n".join(
            f"- {s['name']}: risk={s['risk_score']}/100 ({s['risk_level']}), "
            f"shell={'yes' if s['shell_access'] else 'no'}, trust={s['trust_score']}, "
            f"injection={s['injection_risk']}"
            for s in context["top_skills"]
        )

        context_block = f"""\
SCAN SUMMARY:
- Scan ID: {context["scan_id"]}
- Overall Score: {context["overall_score"]}/100
- Total findings: {context["total_findings"]}
- Skills scanned: {context["skills_scanned"]}

SEVERITY BREAKDOWN:
- Critical: {context["severity_counts"]["critical"]}
- High: {context["severity_counts"]["high"]}
- Medium: {context["severity_counts"]["medium"]}
- Low: {context["severity_counts"]["low"]}

DOMAIN BREAKDOWN:
{json.dumps(context["domain_breakdown"], indent=2)}

QUARANTINED SKILLS: {", ".join(context["quarantined_skills"]) or "None"}

POLICY STATS:
- Total policies: {context["policy_stats"]["total_policies"]}
- Enabled: {context["policy_stats"]["enabled_policies"]}
- Violations: {context["policy_stats"]["violation_count"]}

[Showing top 30 of {context["total_findings"]} findings and top 20 of {context["total_skills_in_db"]} skills by risk score]

FINDINGS BY DOMAIN:
{findings_block or "None"}

TOP RISKY SKILLS:
{skills_block or "None"}"""

        messages: list[dict[str, str]] = [{"role": "system", "content": SYSTEM_PROMPT}]

        # Thread conversation history
        for h in history or []:
            messages.append({"role": "user", "content": h.get("question", "")})
            messages.append({"role": "assistant", "content": h.get("answer", "")})

        # Current question with context
        messages.append(
            {"role": "user", "content": f"Context:\n{context_block}\n\nQuestion: {question}"}
        )

        return messages

    # ── OpenClaw mode ──────────────────────────────────────────────────────

    async def _ask_openclaw(self, messages: list[dict[str, str]]) -> str:
        """Route query through OpenClaw gateway.

        # gateway requires gateway.http.endpoints.chatCompletions.enabled = true in openclaw.json
        """
        if not OPENCLAW_GATEWAY_TOKEN:
            raise RuntimeError("OPENCLAW_GATEWAY_TOKEN not configured")

        headers = {
            "Authorization": f"Bearer {OPENCLAW_GATEWAY_TOKEN}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": "openclaw:main",
            "messages": messages,
            "max_tokens": 1024,
        }

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{OPENCLAW_GATEWAY_URL}/v1/chat/completions",
                    headers=headers,
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                return data["choices"][0]["message"]["content"]
        except httpx.HTTPStatusError as exc:
            logger.warning("OpenClaw gateway returned %s", exc.response.status_code)
            raise RuntimeError(f"OpenClaw gateway error: {exc.response.status_code}") from exc
        except httpx.ConnectError:
            raise RuntimeError(
                f"Cannot reach OpenClaw gateway at {OPENCLAW_GATEWAY_URL}. Is it running?"
            )

    # ── BYOLLM mode ────────────────────────────────────────────────────────

    async def _ask_anthropic(self, messages: list[dict[str, str]], api_key: str) -> str:
        """Call Anthropic API directly with user-provided key."""
        try:
            import anthropic  # type: ignore
        except ImportError:
            raise RuntimeError("anthropic SDK not installed. Run: pip install anthropic")

        # Anthropic SDK uses system param separately
        system_content = ""
        api_messages = []
        for m in messages:
            if m["role"] == "system":
                system_content = m["content"]
            else:
                api_messages.append({"role": m["role"], "content": m["content"]})

        client = anthropic.AsyncAnthropic(api_key=api_key)
        try:
            message = await client.messages.create(
                model=BYOLLM_MODEL,
                max_tokens=1024,
                system=system_content,
                messages=api_messages,
            )
            return message.content[0].text
        except Exception as exc:
            logger.error("Anthropic API error: %s", exc)
            raise RuntimeError(f"Anthropic API error: {exc}") from exc

    # ── Public API ─────────────────────────────────────────────────────────

    async def ask(
        self,
        question: str,
        mode: str = "openclaw",
        api_key: str | None = None,
        history: list[dict] | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """
        Answer a security investigation question.

        Returns:
            (answer, context_used)
        """
        if mode == "byollm" and not api_key:
            raise ValueError("api_key is required for byollm mode")

        context = await self._build_context()
        messages = self._build_prompt(question, context, history)

        if mode == "byollm":
            answer = await self._ask_anthropic(messages, api_key)
        else:
            # Default: openclaw mode — let RuntimeError propagate to route handler
            answer = await self._ask_openclaw(messages)

        return answer, context


chat_engine = ChatEngine()
