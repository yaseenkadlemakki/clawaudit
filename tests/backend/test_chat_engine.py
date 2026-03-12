"""Tests for backend.engine.chat_engine."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.engine.chat_engine import ChatEngine


def _make_full_context(**overrides):
    """Return a minimal valid context dict with all required keys."""
    base = {
        "scan_id": "x",
        "scan_status": "completed",
        "total_findings": 0,
        "skills_scanned": 0,
        "top_findings": [],
        "top_skills": [],
        "overall_score": 100,
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "scoring_rubric": {
            "formula": "overall_score = 100 - avg(skill_risk_score). Higher = safer.",
            "thresholds": {"low": ">=80", "medium": "60-79", "high": "40-59", "critical": "<40"},
            "risk_factors": {
                "shell_execution": 30,
                "injection_HIGH": 25,
                "injection_MEDIUM": 15,
                "secret_exposure": 20,
                "network_call_unvalidated": 10,
            },
        },
        "domain_breakdown": {},
        "quarantined_skills": [],
        "total_skills_in_db": 0,
        "policy_stats": {"total_policies": 0, "enabled_policies": 0, "violation_count": 0},
    }
    base.update(overrides)
    return base


def _messages_text(messages):
    """Join all message contents for assertion convenience."""
    return " ".join(m["content"] for m in messages)


class TestBuildPrompt:
    def test_prompt_contains_question(self):
        engine = ChatEngine()
        context = _make_full_context(scan_id="abc123", total_findings=5, skills_scanned=10)
        messages = engine._build_prompt("Which skills use shell?", context)
        assert isinstance(messages, list)
        text = _messages_text(messages)
        assert "Which skills use shell?" in text

    def test_prompt_contains_scan_summary(self):
        engine = ChatEngine()
        context = _make_full_context(scan_id="abc123", total_findings=42, skills_scanned=15)
        messages = engine._build_prompt("test question", context)
        text = _messages_text(messages)
        assert "42" in text
        assert "15" in text

    def test_prompt_handles_error_context(self):
        engine = ChatEngine()
        context = {"error": "No completed scans available."}
        messages = engine._build_prompt("test", context)
        text = _messages_text(messages)
        assert "No completed scans" in text
        assert "run a full audit" in text.lower()

    def test_prompt_includes_findings(self):
        engine = ChatEngine()
        context = _make_full_context(
            total_findings=1,
            skills_scanned=1,
            top_findings=[
                {
                    "title": "Shell Escape",
                    "severity": "HIGH",
                    "skill": "bad-skill",
                    "domain": "capability",
                    "remediation": "fix",
                }
            ],
        )
        messages = engine._build_prompt("test", context)
        text = _messages_text(messages)
        assert "Shell Escape" in text
        assert "bad-skill" in text

    def test_prompt_includes_skills(self):
        engine = ChatEngine()
        context = _make_full_context(
            skills_scanned=1,
            top_skills=[
                {
                    "name": "risky-skill",
                    "risk_score": 95,
                    "risk_level": "Critical",
                    "shell_access": True,
                    "trust_score": "QUARANTINE",
                    "injection_risk": "HIGH",
                    "outbound_domains": ["evil.io"],
                }
            ],
        )
        messages = engine._build_prompt("test", context)
        text = _messages_text(messages)
        assert "risky-skill" in text
        assert "95" in text

    def test_prompt_threads_history(self):
        engine = ChatEngine()
        context = _make_full_context()
        history = [
            {"question": "What is the overall score?", "answer": "The score is 80."},
        ]
        messages = engine._build_prompt("Why?", context, history=history)
        roles = [m["role"] for m in messages]
        # system, user (history), assistant (history), user (current)
        assert roles == ["system", "user", "assistant", "user"]
        text = _messages_text(messages)
        assert "What is the overall score?" in text
        assert "The score is 80." in text
        assert "Why?" in text


class TestDefaultModelAndEndpoint:
    """Verify the model name constant and gateway endpoint."""

    def test_default_byollm_model_is_valid_anthropic_id(self):
        """BYOLLM_MODEL default must be a valid claude-sonnet-4-6 ID."""
        from backend.engine.chat_engine import BYOLLM_MODEL

        assert BYOLLM_MODEL == "claude-sonnet-4-6", (
            f"BYOLLM_MODEL '{BYOLLM_MODEL}' is not a valid Anthropic model ID. "
            "Expected 'claude-sonnet-4-6' (see docs.anthropic.com/en/docs/about-claude/models)."
        )

    @pytest.mark.asyncio
    async def test_gateway_posts_to_v1_chat_completions(self):
        """_ask_openclaw must call /v1/chat/completions, not /api/agent/ask."""
        engine = ChatEngine()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"choices": [{"message": {"content": "ok"}}]}

        with patch("backend.engine.chat_engine.OPENCLAW_GATEWAY_TOKEN", "tok"):
            with patch("backend.engine.chat_engine.OPENCLAW_GATEWAY_URL", "http://gw:1234"):
                with patch("backend.engine.chat_engine.httpx.AsyncClient") as mock_cls:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock(return_value=False)
                    mock_client.post = AsyncMock(return_value=mock_resp)
                    mock_cls.return_value = mock_client

                    await engine._ask_openclaw([{"role": "user", "content": "test"}])

        called_url = mock_client.post.call_args[0][0]
        assert "/v1/chat/completions" in called_url, (
            f"Expected /v1/chat/completions but got: {called_url}"
        )
        assert "/api/agent/ask" not in called_url


class TestAskOpenClaw:
    @pytest.mark.asyncio
    async def test_raises_when_token_not_configured(self):
        engine = ChatEngine()
        with patch("backend.engine.chat_engine.OPENCLAW_GATEWAY_TOKEN", None):
            with pytest.raises(RuntimeError, match="OPENCLAW_GATEWAY_TOKEN not configured"):
                await engine._ask_openclaw([{"role": "user", "content": "test"}])

    @pytest.mark.asyncio
    async def test_posts_to_gateway_and_returns_reply(self):
        engine = ChatEngine()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"choices": [{"message": {"content": "Here is the answer"}}]}

        with patch("backend.engine.chat_engine.OPENCLAW_GATEWAY_TOKEN", "test-token"):
            with patch("backend.engine.chat_engine.httpx.AsyncClient") as mock_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.post = AsyncMock(return_value=mock_resp)
                mock_cls.return_value = mock_client

                result = await engine._ask_openclaw([{"role": "user", "content": "test"}])

        assert result == "Here is the answer"

    @pytest.mark.asyncio
    async def test_raises_on_connect_error(self):
        engine = ChatEngine()
        import httpx

        with patch("backend.engine.chat_engine.OPENCLAW_GATEWAY_TOKEN", "test-token"):
            with patch("backend.engine.chat_engine.httpx.AsyncClient") as mock_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
                mock_cls.return_value = mock_client

                with pytest.raises(RuntimeError, match="Cannot reach"):
                    await engine._ask_openclaw([{"role": "user", "content": "test"}])

    @pytest.mark.asyncio
    async def test_raises_on_http_status_error(self):
        engine = ChatEngine()
        import httpx

        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "401", request=MagicMock(), response=MagicMock(status_code=401)
        )

        with patch("backend.engine.chat_engine.OPENCLAW_GATEWAY_TOKEN", "test-token"):
            with patch("backend.engine.chat_engine.httpx.AsyncClient") as mock_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.post = AsyncMock(return_value=mock_resp)
                mock_cls.return_value = mock_client

                with pytest.raises(RuntimeError, match="gateway error"):
                    await engine._ask_openclaw([{"role": "user", "content": "test"}])


class TestAskAnthropic:
    @pytest.mark.asyncio
    async def test_calls_anthropic_with_key(self):
        engine = ChatEngine()
        mock_anthropic = MagicMock()
        mock_client_instance = MagicMock()
        mock_message = MagicMock()
        mock_message.content = [MagicMock(text="Anthropic answer")]
        mock_client_instance.messages.create = AsyncMock(return_value=mock_message)
        mock_anthropic.AsyncAnthropic.return_value = mock_client_instance

        messages = [
            {"role": "system", "content": "You are a security analyst."},
            {"role": "user", "content": "test prompt"},
        ]

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            result = await engine._ask_anthropic(messages, "sk-test-key")

        assert result == "Anthropic answer"
        mock_anthropic.AsyncAnthropic.assert_called_once_with(api_key="sk-test-key")

    @pytest.mark.asyncio
    async def test_raises_on_api_error(self):
        engine = ChatEngine()
        mock_anthropic = MagicMock()
        mock_client_instance = MagicMock()
        mock_client_instance.messages.create = AsyncMock(side_effect=Exception("Invalid API key"))
        mock_anthropic.AsyncAnthropic.return_value = mock_client_instance

        messages = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "test"},
        ]

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            with pytest.raises(RuntimeError, match="Anthropic API error"):
                await engine._ask_anthropic(messages, "bad-key")

    @pytest.mark.asyncio
    async def test_raises_when_sdk_missing(self):
        engine = ChatEngine()

        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "anthropic":
                raise ImportError("No module named 'anthropic'")
            return real_import(name, *args, **kwargs)

        messages = [{"role": "user", "content": "test"}]

        with patch("builtins.__import__", side_effect=mock_import):
            with pytest.raises(RuntimeError, match="not installed"):
                await engine._ask_anthropic(messages, "key")


class TestAsk:
    @pytest.mark.asyncio
    async def test_openclaw_mode_returns_answer_and_context(self):
        engine = ChatEngine()
        mock_context = _make_full_context(scan_id="x", total_findings=5, skills_scanned=3)

        with patch.object(
            engine, "_build_context", new_callable=AsyncMock, return_value=mock_context
        ):
            with patch.object(
                engine, "_ask_openclaw", new_callable=AsyncMock, return_value="gateway answer"
            ):
                answer, context = await engine.ask("test question", mode="openclaw")

        assert answer == "gateway answer"
        assert context == mock_context

    @pytest.mark.asyncio
    async def test_byollm_requires_api_key(self):
        engine = ChatEngine()
        with pytest.raises(ValueError, match="api_key is required"):
            await engine.ask("test", mode="byollm", api_key=None)

    @pytest.mark.asyncio
    async def test_byollm_mode_calls_anthropic(self):
        engine = ChatEngine()
        mock_context = _make_full_context()

        with patch.object(
            engine, "_build_context", new_callable=AsyncMock, return_value=mock_context
        ):
            with patch.object(
                engine,
                "_ask_anthropic",
                new_callable=AsyncMock,
                return_value="anthropic answer",
            ):
                answer, _ = await engine.ask("test", mode="byollm", api_key="sk-test")

        assert answer == "anthropic answer"

    @pytest.mark.asyncio
    async def test_openclaw_gateway_down_raises_runtime_error(self):
        """Gateway failure must propagate as RuntimeError (route returns 503)."""
        engine = ChatEngine()
        mock_context = _make_full_context(total_findings=5, skills_scanned=3)

        with patch.object(
            engine, "_build_context", new_callable=AsyncMock, return_value=mock_context
        ):
            with patch.object(
                engine,
                "_ask_openclaw",
                new_callable=AsyncMock,
                side_effect=RuntimeError("gateway down"),
            ):
                with pytest.raises(RuntimeError, match="gateway down"):
                    await engine.ask("test", mode="openclaw")

    @pytest.mark.asyncio
    async def test_no_scan_data_returns_helpful_message(self):
        engine = ChatEngine()
        with patch.object(
            engine,
            "_build_context",
            new_callable=AsyncMock,
            return_value={"error": "No completed scans available."},
        ):
            with patch.object(
                engine,
                "_ask_openclaw",
                new_callable=AsyncMock,
                return_value="Please run a scan first",
            ):
                answer, _ = await engine.ask("test")

        assert answer

    @pytest.mark.asyncio
    async def test_history_passed_through(self):
        """History list is forwarded to _build_prompt and ultimately to the LLM."""
        engine = ChatEngine()
        mock_context = _make_full_context()
        history = [{"question": "Q1", "answer": "A1"}]

        with patch.object(
            engine, "_build_context", new_callable=AsyncMock, return_value=mock_context
        ):
            with patch.object(
                engine, "_ask_openclaw", new_callable=AsyncMock, return_value="answer"
            ) as mock_ask:
                await engine.ask("Q2", mode="openclaw", history=history)

        # Verify history was threaded into the messages
        call_messages = mock_ask.call_args[0][0]
        contents = [m["content"] for m in call_messages]
        assert any("Q1" in c for c in contents)
        assert any("A1" in c for c in contents)


class TestBuildContextIntegration:
    """Integration test exercising _build_context against a real in-memory DB."""

    @pytest.mark.asyncio
    async def test_build_context_returns_correct_shape(self):
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        from backend.database import Base
        from backend.models.finding import FindingRecord
        from backend.models.policy import PolicyRecord  # noqa: F401 — needed for table creation
        from backend.models.scan import ScanRun, ScanStatus
        from backend.models.skill import SkillRecord

        test_engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        TestSession = async_sessionmaker(test_engine, expire_on_commit=False)

        async with test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async with TestSession() as db:
            scan = ScanRun(
                id="scan-1",
                status=ScanStatus.COMPLETED,
                total_findings=1,
                skills_scanned=1,
            )
            finding = FindingRecord(
                id="f-1",
                scan_id="scan-1",
                check_id="CONF-01",
                domain="configuration",
                title="Test finding",
                description="desc",
                severity="HIGH",
                result="FAIL",
                evidence="none",
                location="/tmp",
                remediation="fix it",
                skill_name="test-skill",
            )
            skill = SkillRecord(
                id="s-1",
                scan_id="scan-1",
                name="test-skill",
                path="/tmp/test-skill",
                risk_score=75,
                risk_level="High",
            )
            db.add_all([scan, finding, skill])
            await db.commit()

        engine = ChatEngine()
        with patch("backend.engine.chat_engine.AsyncSessionLocal", TestSession):
            context = await engine._build_context()

        assert context["scan_id"] == "scan-1"
        assert context["total_findings"] == 1
        assert len(context["top_findings"]) == 1
        assert len(context["top_skills"]) == 1
        assert context["top_findings"][0]["domain"] == "configuration"
        # Verify new enriched fields
        assert "overall_score" in context
        assert "severity_counts" in context
        assert "domain_breakdown" in context
        assert "quarantined_skills" in context
        assert "total_skills_in_db" in context
        assert "policy_stats" in context
        assert context["overall_score"] == 25  # 100 - 75

        await test_engine.dispose()
