"""Security investigation chat engine.

Supports two modes:
  - openclaw: routes query through the local OpenClaw gateway
  - byollm:   calls the Anthropic API directly with the user's key
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx
from sqlalchemy import select

from backend.database import AsyncSessionLocal
from backend.models.finding import FindingRecord
from backend.models.scan import ScanRun, ScanStatus
from backend.models.skill import SkillRecord

logger = logging.getLogger(__name__)

OPENCLAW_GATEWAY_URL = os.getenv("OPENCLAW_GATEWAY_URL", "http://localhost:18789")
OPENCLAW_GATEWAY_TOKEN = os.getenv("OPENCLAW_GATEWAY_TOKEN")  # None if not set
BYOLLM_MODEL = os.getenv("BYOLLM_MODEL", "claude-haiku-4-5-20251001")


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

        return {
            "scan_id": scan_id,
            "scan_status": latest_scan.status,
            "total_findings": latest_scan.total_findings,
            "skills_scanned": latest_scan.skills_scanned,
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "skill": f.skill_name,
                    "domain": f.domain,
                    "remediation": f.remediation,
                }
                for f in findings
            ],
            "skills": [
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
            ],
        }

    def _build_prompt(self, question: str, context: dict[str, Any]) -> str:
        """Build a structured prompt with scan context injected."""
        if "error" in context:
            return (
                f"The user asked: {question}\n\n"
                f"Unfortunately, no scan data is available yet: {context['error']}\n"
                "Please advise them to run a Full Audit first."
            )

        findings_summary = "\n".join(
            f"- [{f['severity'].upper()}] {f['title']} (skill: {f['skill'] or 'N/A'}, domain: {f['domain'] or 'N/A'})"
            for f in context["findings"][:15]
        )
        skills_summary = "\n".join(
            f"- {s['name']}: risk={s['risk_score']}/100 ({s['risk_level']}), "
            f"shell={'yes' if s['shell_access'] else 'no'}, trust={s['trust_score']}, "
            f"injection={s['injection_risk']}"
            for s in context["skills"][:10]
        )

        return f"""You are a security analyst assistant for the ClawAudit security intelligence platform.

You have access to the latest OpenClaw security scan data:

SCAN SUMMARY:
- Scan ID: {context['scan_id']}
- Total findings: {context['total_findings']}
- Skills scanned: {context['skills_scanned']}

TOP FINDINGS:
{findings_summary or 'None'}

TOP RISKY SKILLS:
{skills_summary or 'None'}

USER QUESTION: {question}

Answer concisely and accurately based on the scan data above. Include specific skill names, 
finding titles, risk scores, and remediation advice where relevant. If the question cannot 
be answered from the available data, say so clearly."""

    # ── OpenClaw mode ──────────────────────────────────────────────────────

    async def _ask_openclaw(self, prompt: str) -> str:
        """Route query through OpenClaw gateway."""
        if not OPENCLAW_GATEWAY_TOKEN:
            raise RuntimeError("OPENCLAW_GATEWAY_TOKEN not configured")
        headers = {"Authorization": f"Bearer {OPENCLAW_GATEWAY_TOKEN}"}
        payload = {"message": prompt}

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{OPENCLAW_GATEWAY_URL}/api/agent/ask",
                    headers=headers,
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                return data.get("reply") or data.get("message") or str(data)
        except httpx.HTTPStatusError as exc:
            logger.warning("OpenClaw gateway returned %s", exc.response.status_code)
            raise RuntimeError(f"OpenClaw gateway error: {exc.response.status_code}") from exc
        except httpx.ConnectError:
            raise RuntimeError(
                f"Cannot reach OpenClaw gateway at {OPENCLAW_GATEWAY_URL}. Is it running?"
            )

    # ── BYOLLM mode ────────────────────────────────────────────────────────

    async def _ask_anthropic(self, prompt: str, api_key: str) -> str:
        """Call Anthropic API directly with user-provided key."""
        try:
            import anthropic  # type: ignore
        except ImportError:
            raise RuntimeError("anthropic SDK not installed. Run: pip install anthropic")

        client = anthropic.AsyncAnthropic(api_key=api_key)
        try:
            message = await client.messages.create(
                model=BYOLLM_MODEL,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
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
    ) -> tuple[str, dict[str, Any]]:
        """
        Answer a security investigation question.

        Returns:
            (answer, context_used)
        """
        if mode == "byollm" and not api_key:
            raise ValueError("api_key is required for byollm mode")

        context = await self._build_context()
        prompt = self._build_prompt(question, context)

        if mode == "byollm":
            answer = await self._ask_anthropic(prompt, api_key)
        else:
            # Default: openclaw mode
            try:
                answer = await self._ask_openclaw(prompt)
            except RuntimeError as exc:
                # Fallback: return a helpful error with context summary
                logger.warning("OpenClaw gateway unavailable, returning context summary: %s", exc)
                answer = (
                    f"OpenClaw gateway unavailable ({exc}).\n\n"
                    f"Based on scan data, here's what I can tell you:\n\n"
                    f"**Scan summary:** {context.get('total_findings', 0)} findings across "
                    f"{context.get('skills_scanned', 0)} skills.\n\n"
                    f"To get full AI analysis, ensure the OpenClaw gateway is running or "
                    f"switch to BYOLLM mode with your Anthropic API key."
                )

        return answer, context


chat_engine = ChatEngine()
