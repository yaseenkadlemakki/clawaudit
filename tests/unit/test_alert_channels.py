"""Unit tests for alert delivery channels."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.alerts.channels.file import FileAlertChannel
from sentinel.alerts.channels.webhook import WebhookAlertChannel
from sentinel.models.finding import Finding
from sentinel.models.policy import PolicyDecision


def _finding(**kwargs) -> Finding:
    defaults = dict(
        check_id="CONF-01",
        domain="config",
        title="Test",
        description="",
        severity="HIGH",
        result="FAIL",
        evidence="ev",
        location="loc",
        remediation="",
        run_id="r1",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _decision(**kwargs) -> PolicyDecision:
    return PolicyDecision(
        action=kwargs.get("action", "ALERT"),
        reason="test",
        policy_ids=kwargs.get("policy_ids", ["POL-001"]),
    )


# ── FileAlertChannel ──────────────────────────────────────────────────────────


@pytest.mark.unit
class TestFileAlertChannel:
    def test_creates_parent_directory(self, tmp_path):
        p = tmp_path / "nested" / "dir" / "alerts.jsonl"
        FileAlertChannel(p)
        assert p.parent.exists()

    def test_send_writes_jsonl_record(self, tmp_path):
        p = tmp_path / "alerts.jsonl"
        ch = FileAlertChannel(p)
        ch.send("msg", _finding(), _decision())
        lines = p.read_text().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["check_id"] == "CONF-01"

    def test_send_record_has_required_fields(self, tmp_path):
        p = tmp_path / "alerts.jsonl"
        ch = FileAlertChannel(p)
        ch.send("alert message", _finding(), _decision())
        record = json.loads(p.read_text().strip())
        for field in (
            "ts",
            "finding_id",
            "check_id",
            "severity",
            "action",
            "message",
            "policy_ids",
        ):
            assert field in record, f"Missing field: {field}"

    def test_send_severity_stored(self, tmp_path):
        p = tmp_path / "alerts.jsonl"
        FileAlertChannel(p).send("m", _finding(severity="CRITICAL"), _decision())
        assert json.loads(p.read_text())["severity"] == "CRITICAL"

    def test_send_action_stored(self, tmp_path):
        p = tmp_path / "alerts.jsonl"
        FileAlertChannel(p).send("m", _finding(), _decision(action="BLOCK"))
        assert json.loads(p.read_text())["action"] == "BLOCK"

    def test_multiple_sends_append(self, tmp_path):
        p = tmp_path / "alerts.jsonl"
        ch = FileAlertChannel(p)
        ch.send("m1", _finding(check_id="A"), _decision())
        ch.send("m2", _finding(check_id="B"), _decision())
        lines = p.read_text().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["check_id"] == "A"
        assert json.loads(lines[1])["check_id"] == "B"

    def test_message_stored(self, tmp_path):
        p = tmp_path / "alerts.jsonl"
        FileAlertChannel(p).send("hello sentinel", _finding(), _decision())
        assert json.loads(p.read_text())["message"] == "hello sentinel"

    def test_policy_ids_stored(self, tmp_path):
        p = tmp_path / "alerts.jsonl"
        FileAlertChannel(p).send("m", _finding(), _decision(policy_ids=["POL-001", "POL-005"]))
        assert json.loads(p.read_text())["policy_ids"] == ["POL-001", "POL-005"]


# ── WebhookAlertChannel ───────────────────────────────────────────────────────


@pytest.mark.unit
class TestWebhookAlertChannel:
    def test_has_send_method(self):
        ch = WebhookAlertChannel("http://localhost/hook")
        assert callable(ch.send)

    def test_has_send_async_method(self):
        ch = WebhookAlertChannel("http://localhost/hook")
        assert callable(ch.send_async)

    def test_custom_headers_stored(self):
        ch = WebhookAlertChannel("http://localhost/hook", headers={"X-Token": "abc"})
        assert ch._headers == {"X-Token": "abc"}

    def test_default_headers_empty(self):
        ch = WebhookAlertChannel("http://localhost/hook")
        assert ch._headers == {}

    async def test_send_async_posts_payload(self):
        ch = WebhookAlertChannel("http://localhost/hook")
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with patch("httpx.AsyncClient", return_value=mock_client):
            await ch.send_async("msg", _finding(), _decision())

        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["text"] == "msg"
        assert payload["severity"] == "HIGH"

    async def test_send_async_silences_http_errors(self):
        import httpx

        ch = WebhookAlertChannel("http://localhost/hook")
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=httpx.ConnectError("down"))
            mock_cls.return_value = mock_client
            # Should not raise
            await ch.send_async("m", _finding(), _decision())
