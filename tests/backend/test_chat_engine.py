"""Tests for backend.engine.chat_engine."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.engine.chat_engine import ChatEngine


class TestBuildPrompt:
    def test_prompt_contains_question(self):
        engine = ChatEngine()
        context = {
            "scan_id": "abc123",
            "scan_status": "completed",
            "total_findings": 5,
            "skills_scanned": 10,
            "findings": [],
            "skills": [],
        }
        prompt = engine._build_prompt("Which skills use shell?", context)
        assert "Which skills use shell?" in prompt

    def test_prompt_contains_scan_summary(self):
        engine = ChatEngine()
        context = {
            "scan_id": "abc123",
            "scan_status": "completed",
            "total_findings": 42,
            "skills_scanned": 15,
            "findings": [],
            "skills": [],
        }
        prompt = engine._build_prompt("test question", context)
        assert "42" in prompt
        assert "15" in prompt

    def test_prompt_handles_error_context(self):
        engine = ChatEngine()
        context = {"error": "No completed scans available."}
        prompt = engine._build_prompt("test", context)
        assert "No completed scans" in prompt
        assert "run a full audit" in prompt.lower()

    def test_prompt_includes_findings(self):
        engine = ChatEngine()
        context = {
            "scan_id": "x",
            "scan_status": "completed",
            "total_findings": 1,
            "skills_scanned": 1,
            "findings": [{"title": "Shell Escape", "severity": "HIGH", "skill": "bad-skill", "policy": "P1", "remediation": "fix"}],
            "skills": [],
        }
        prompt = engine._build_prompt("test", context)
        assert "Shell Escape" in prompt
        assert "bad-skill" in prompt

    def test_prompt_includes_skills(self):
        engine = ChatEngine()
        context = {
            "scan_id": "x",
            "scan_status": "completed",
            "total_findings": 0,
            "skills_scanned": 1,
            "findings": [],
            "skills": [{"name": "risky-skill", "risk_score": 95, "risk_level": "Critical",
                        "shell_access": True, "trust_score": "QUARANTINE",
                        "injection_risk": "HIGH", "outbound_domains": ["evil.io"]}],
        }
        prompt = engine._build_prompt("test", context)
        assert "risky-skill" in prompt
        assert "95" in prompt


class TestAskOpenClaw:
    @pytest.mark.asyncio
    async def test_posts_to_gateway_and_returns_reply(self):
        engine = ChatEngine()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"reply": "Here is the answer"}

        with patch("backend.engine.chat_engine.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_cls.return_value = mock_client

            result = await engine._ask_openclaw("test prompt")

        assert result == "Here is the answer"

    @pytest.mark.asyncio
    async def test_raises_on_connect_error(self):
        engine = ChatEngine()
        import httpx

        with patch("backend.engine.chat_engine.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
            mock_cls.return_value = mock_client

            with pytest.raises(RuntimeError, match="Cannot reach"):
                await engine._ask_openclaw("test")

    @pytest.mark.asyncio
    async def test_raises_on_http_status_error(self):
        engine = ChatEngine()
        import httpx

        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "401", request=MagicMock(), response=MagicMock(status_code=401)
        )

        with patch("backend.engine.chat_engine.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_cls.return_value = mock_client

            with pytest.raises(RuntimeError, match="gateway error"):
                await engine._ask_openclaw("test")

    @pytest.mark.asyncio
    async def test_falls_back_to_message_key(self):
        engine = ChatEngine()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"message": "fallback answer"}

        with patch("backend.engine.chat_engine.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_cls.return_value = mock_client

            result = await engine._ask_openclaw("test")

        assert result == "fallback answer"


class TestAskAnthropic:
    @pytest.mark.asyncio
    async def test_calls_anthropic_with_key(self):
        engine = ChatEngine()
        mock_anthropic = MagicMock()
        mock_client_instance = MagicMock()
        mock_message = MagicMock()
        mock_message.content = [MagicMock(text="Anthropic answer")]
        mock_client_instance.messages.create.return_value = mock_message
        mock_anthropic.Anthropic.return_value = mock_client_instance

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            result = await engine._ask_anthropic("test prompt", "sk-test-key")

        assert result == "Anthropic answer"
        mock_anthropic.Anthropic.assert_called_once_with(api_key="sk-test-key")

    @pytest.mark.asyncio
    async def test_raises_on_api_error(self):
        engine = ChatEngine()
        mock_anthropic = MagicMock()
        mock_client_instance = MagicMock()
        mock_client_instance.messages.create.side_effect = Exception("Invalid API key")
        mock_anthropic.Anthropic.return_value = mock_client_instance

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            with pytest.raises(RuntimeError, match="Anthropic API error"):
                await engine._ask_anthropic("test", "bad-key")

    @pytest.mark.asyncio
    async def test_raises_when_sdk_missing(self):
        engine = ChatEngine()
        mock_anthropic = MagicMock()
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = ImportError("No module named 'anthropic'")
        mock_anthropic.Anthropic.return_value = mock_client

        # Simulate ImportError inside the function by making import fail
        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "anthropic":
                raise ImportError("No module named 'anthropic'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            with pytest.raises(RuntimeError, match="not installed"):
                await engine._ask_anthropic("test", "key")


class TestAsk:
    @pytest.mark.asyncio
    async def test_openclaw_mode_returns_answer_and_context(self):
        engine = ChatEngine()
        mock_context = {"scan_id": "x", "total_findings": 5, "skills_scanned": 3,
                        "findings": [], "skills": [], "scan_status": "completed"}

        with patch.object(engine, "_build_context", new_callable=AsyncMock, return_value=mock_context):
            with patch.object(engine, "_ask_openclaw", new_callable=AsyncMock, return_value="gateway answer"):
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
        mock_context = {"scan_id": "x", "total_findings": 0, "skills_scanned": 0,
                        "findings": [], "skills": [], "scan_status": "completed"}

        with patch.object(engine, "_build_context", new_callable=AsyncMock, return_value=mock_context):
            with patch.object(engine, "_ask_anthropic", new_callable=AsyncMock, return_value="anthropic answer"):
                answer, _ = await engine.ask("test", mode="byollm", api_key="sk-test")

        assert answer == "anthropic answer"

    @pytest.mark.asyncio
    async def test_openclaw_gateway_down_returns_fallback(self):
        engine = ChatEngine()
        mock_context = {"scan_id": "x", "total_findings": 5, "skills_scanned": 3,
                        "findings": [], "skills": [], "scan_status": "completed"}

        with patch.object(engine, "_build_context", new_callable=AsyncMock, return_value=mock_context):
            with patch.object(engine, "_ask_openclaw", new_callable=AsyncMock,
                              side_effect=RuntimeError("gateway down")):
                answer, _ = await engine.ask("test", mode="openclaw")

        assert "unavailable" in answer.lower() or "gateway" in answer.lower()

    @pytest.mark.asyncio
    async def test_no_scan_data_returns_helpful_message(self):
        engine = ChatEngine()
        with patch.object(engine, "_build_context", new_callable=AsyncMock,
                          return_value={"error": "No completed scans available."}):
            with patch.object(engine, "_ask_openclaw", new_callable=AsyncMock,
                              return_value="Please run a scan first"):
                answer, _ = await engine.ask("test")

        assert answer
