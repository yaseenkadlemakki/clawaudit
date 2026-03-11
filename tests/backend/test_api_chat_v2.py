"""Tests for backend chat API routes — improves coverage of chat.py lines 36-78."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

# ---------------------------------------------------------------------------
# POST /api/v1/chat  (lines 36-68)
# ---------------------------------------------------------------------------


@pytest.mark.backend
@pytest.mark.asyncio
async def test_chat_byollm_requires_api_key(client):
    """byollm mode without api_key should return 422."""
    resp = await client.post(
        "/api/v1/chat",
        json={"question": "What risks exist?", "mode": "byollm", "api_key": None},
    )
    assert resp.status_code == 422
    assert "api_key" in resp.json()["detail"].lower()


@pytest.mark.backend
@pytest.mark.asyncio
async def test_chat_openclaw_mode_success(client):
    """Happy path: openclaw mode returns answer, mode, and context_used."""
    mock_context = {
        "scan_id": "scan-1",
        "scan_status": "completed",
        "total_findings": 3,
        "skills_scanned": 5,
        "findings": [],
        "skills": [],
    }

    with patch("backend.api.routes.chat.chat_engine") as mock_engine:
        mock_engine.ask = AsyncMock(return_value=("42 skills scanned", mock_context))
        resp = await client.post(
            "/api/v1/chat",
            json={"question": "How many skills were scanned?", "mode": "openclaw"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["answer"] == "42 skills scanned"
    assert data["mode"] == "openclaw"
    assert "context_used" in data


@pytest.mark.backend
@pytest.mark.asyncio
async def test_chat_value_error_returns_422(client):
    """ValueError from chat_engine should map to 422."""
    with patch("backend.api.routes.chat.chat_engine") as mock_engine:
        mock_engine.ask = AsyncMock(side_effect=ValueError("Invalid mode"))
        resp = await client.post(
            "/api/v1/chat",
            json={"question": "test", "mode": "openclaw"},
        )

    assert resp.status_code == 422
    assert "Invalid mode" in resp.json()["detail"]


@pytest.mark.backend
@pytest.mark.asyncio
async def test_chat_runtime_error_returns_503(client):
    """RuntimeError from chat_engine should map to 503."""
    with patch("backend.api.routes.chat.chat_engine") as mock_engine:
        mock_engine.ask = AsyncMock(side_effect=RuntimeError("Gateway down"))
        resp = await client.post(
            "/api/v1/chat",
            json={"question": "test", "mode": "openclaw"},
        )

    assert resp.status_code == 503
    assert "Gateway down" in resp.json()["detail"]


@pytest.mark.backend
@pytest.mark.asyncio
async def test_chat_generic_exception_returns_500(client):
    """Unexpected exceptions from chat_engine should map to 500."""
    with patch("backend.api.routes.chat.chat_engine") as mock_engine:
        mock_engine.ask = AsyncMock(side_effect=Exception("Unknown error"))
        resp = await client.post(
            "/api/v1/chat",
            json={"question": "test", "mode": "openclaw"},
        )

    assert resp.status_code == 500
    assert "internal" in resp.json()["detail"].lower()


@pytest.mark.backend
@pytest.mark.asyncio
async def test_chat_byollm_mode_with_api_key(client):
    """byollm mode with api_key provided should succeed."""
    mock_context = {
        "scan_id": "scan-2",
        "scan_status": "completed",
        "total_findings": 0,
        "skills_scanned": 0,
        "findings": [],
        "skills": [],
    }

    with patch("backend.api.routes.chat.chat_engine") as mock_engine:
        mock_engine.ask = AsyncMock(return_value=("byollm answer", mock_context))
        resp = await client.post(
            "/api/v1/chat",
            json={"question": "Analyse risks", "mode": "byollm", "api_key": "sk-test-123"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["mode"] == "byollm"
    assert data["answer"] == "byollm answer"


@pytest.mark.backend
@pytest.mark.asyncio
async def test_chat_persists_message_to_db(client):
    """Successful chat should persist the exchange in the DB."""
    mock_context = {
        "scan_id": "scan-3",
        "scan_status": "completed",
        "total_findings": 1,
        "skills_scanned": 1,
        "findings": [],
        "skills": [],
    }

    with patch("backend.api.routes.chat.chat_engine") as mock_engine:
        mock_engine.ask = AsyncMock(return_value=("Answer stored", mock_context))
        await client.post(
            "/api/v1/chat",
            json={"question": "Persisted question?", "mode": "openclaw"},
        )

    # Check the exchange was stored by querying history
    history_resp = await client.get("/api/v1/chat/history?limit=10")
    assert history_resp.status_code == 200
    history = history_resp.json()
    questions = [m["question"] for m in history]
    assert "Persisted question?" in questions


# ---------------------------------------------------------------------------
# GET /api/v1/chat/history  (lines 74-78)
# ---------------------------------------------------------------------------


@pytest.mark.backend
@pytest.mark.asyncio
async def test_chat_history_empty(client):
    resp = await client.get("/api/v1/chat/history")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.backend
@pytest.mark.asyncio
async def test_chat_history_returns_recent_exchanges(client):
    """POST two chat messages then verify history returns them in order."""
    mock_context = {"scan_id": "x", "scan_status": "completed",
                    "total_findings": 0, "skills_scanned": 0,
                    "findings": [], "skills": []}

    with patch("backend.api.routes.chat.chat_engine") as mock_engine:
        mock_engine.ask = AsyncMock(return_value=("answer-1", mock_context))
        await client.post("/api/v1/chat", json={"question": "Q1", "mode": "openclaw"})
        mock_engine.ask = AsyncMock(return_value=("answer-2", mock_context))
        await client.post("/api/v1/chat", json={"question": "Q2", "mode": "openclaw"})

    resp = await client.get("/api/v1/chat/history?limit=5")
    assert resp.status_code == 200
    history = resp.json()
    assert len(history) == 2
    # History should be in chronological order (reversed from desc)
    questions = [m["question"] for m in history]
    assert "Q1" in questions
    assert "Q2" in questions


@pytest.mark.backend
@pytest.mark.asyncio
async def test_chat_history_limit_respected(client):
    mock_context = {"scan_id": "x", "scan_status": "completed",
                    "total_findings": 0, "skills_scanned": 0,
                    "findings": [], "skills": []}

    with patch("backend.api.routes.chat.chat_engine") as mock_engine:
        for i in range(5):
            mock_engine.ask = AsyncMock(return_value=(f"answer-{i}", mock_context))
            await client.post("/api/v1/chat", json={"question": f"Q{i}", "mode": "openclaw"})

    resp = await client.get("/api/v1/chat/history?limit=2")
    assert resp.status_code == 200
    assert len(resp.json()) == 2
