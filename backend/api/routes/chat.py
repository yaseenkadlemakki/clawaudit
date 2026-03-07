"""Chat investigation API routes."""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.engine.chat_engine import chat_engine
from backend.models.chat import ChatMessage

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/chat", tags=["chat"])


class ChatRequest(BaseModel):
    question: str
    mode: str = "openclaw"  # "openclaw" | "byollm"
    api_key: Optional[str] = None


class ChatResponse(BaseModel):
    answer: str
    mode: str
    context_used: dict


@router.post("", response_model=ChatResponse)
async def ask(request: ChatRequest, db: AsyncSession = Depends(get_db)):
    """Answer a security investigation question using scan data."""
    if request.mode == "byollm" and not request.api_key:
        raise HTTPException(
            status_code=422,
            detail="api_key is required when mode is 'byollm'",
        )

    try:
        answer, context = await chat_engine.ask(
            question=request.question,
            mode=request.mode,
            api_key=request.api_key,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        logger.exception("Chat engine error: %s", exc)
        raise HTTPException(status_code=500, detail="Internal chat engine error")

    # Persist the exchange
    import json
    msg = ChatMessage(
        question=request.question,
        answer=answer,
        mode=request.mode,
        context_snapshot=json.dumps({"scan_id": context.get("scan_id")}),
    )
    db.add(msg)
    await db.commit()

    return ChatResponse(answer=answer, mode=request.mode, context_used=context)


@router.get("/history")
async def get_history(limit: int = 20, db: AsyncSession = Depends(get_db)):
    """Return recent chat exchanges."""
    result = await db.execute(
        select(ChatMessage).order_by(ChatMessage.created_at.desc()).limit(limit)
    )
    messages = result.scalars().all()
    return [m.to_dict() for m in reversed(messages)]
