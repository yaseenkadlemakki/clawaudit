"""Tests for sentinel.alerts.channels.openclaw."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

from sentinel.alerts.channels.openclaw import OpenClawAlertChannel
from sentinel.models.finding import Finding
from sentinel.models.policy import PolicyDecision


def _finding() -> Finding:
    return Finding(
        check_id="TEST-01",
        domain="config",
        title="Test",
        description="d",
        severity="HIGH",
        result="FAIL",
        location="loc",
        evidence="ev",
        remediation="fix",
        run_id="run-1",
    )


def _decision() -> PolicyDecision:
    d = MagicMock(spec=PolicyDecision)
    d.action = "ALERT"
    return d


def _channel() -> OpenClawAlertChannel:
    return OpenClawAlertChannel(
        gateway_url="http://localhost:18789",
        gateway_token="test-token",
        delivery_channel="discord",
        delivery_target="123456",
    )


class TestOpenClawAlertChannelInit:
    def test_strips_trailing_slash(self):
        ch = OpenClawAlertChannel("http://localhost:18789/", "tok", "discord", "123")
        assert ch._gateway_url == "http://localhost:18789"

    def test_stores_credentials(self):
        ch = _channel()
        assert ch._token == "test-token"
        assert ch._channel == "discord"
        assert ch._target == "123456"


class TestSendAsync:
    @pytest.mark.asyncio
    async def test_posts_correct_payload(self):
        ch = _channel()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            await ch.send_async("Alert message", _finding(), _decision())

        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args
        assert call_kwargs[1]["json"]["message"] == "Alert message"
        assert call_kwargs[1]["json"]["channel"] == "discord"
        assert call_kwargs[1]["json"]["to"] == "123456"
        assert "Bearer test-token" in call_kwargs[1]["headers"]["Authorization"]

    @pytest.mark.asyncio
    async def test_silences_http_error(self):
        ch = _channel()

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
            mock_client_cls.return_value = mock_client

            # Should not raise
            await ch.send_async("msg", _finding(), _decision())

    @pytest.mark.asyncio
    async def test_handles_raise_for_status_error(self):
        ch = _channel()
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "500", request=MagicMock(), response=MagicMock()
        )

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            # Should not raise
            await ch.send_async("msg", _finding(), _decision())


class TestSend:
    def test_send_schedules_task_in_running_loop(self):
        import asyncio
        ch = _channel()

        async def _run():
            with patch.object(ch, "send_async", new_callable=AsyncMock) as mock_async:
                ch.send("msg", _finding(), _decision())
                await asyncio.sleep(0)  # let task run
                mock_async.assert_called_once()

        asyncio.run(_run())

    def test_send_falls_back_to_asyncio_run_outside_loop(self):
        ch = _channel()
        with patch.object(ch, "send_async", new_callable=AsyncMock) as mock_async:
            with patch("asyncio.get_running_loop", side_effect=RuntimeError("no loop")):
                with patch("asyncio.run") as mock_run:
                    ch.send("msg", _finding(), _decision())
                    mock_run.assert_called_once()
