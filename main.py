"""
FastAPI Webhook Receiver
Captures incoming webhooks, validates payloads, logs to file and Supabase.
Endpoints: GET /health  |  POST /webhook  |  GET /logs
"""

import hashlib
import hmac
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Optional
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from supabase import create_client, Client

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

WEBHOOK_SECRET: str = os.getenv("WEBHOOK_SECRET", "")
SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY: str = os.getenv("SUPABASE_KEY", "")
SUPABASE_TABLE: str = os.getenv("SUPABASE_TABLE", "webhook_logs")
MAX_LOGS_RESPONSE: int = int(os.getenv("MAX_LOGS_RESPONSE", "50"))


# ---------------------------------------------------------------------------
# Supabase client (optional — graceful fallback)
# ---------------------------------------------------------------------------

_supabase: Optional[Client] = None


def get_supabase() -> Optional[Client]:
    global _supabase
    if _supabase is None and SUPABASE_URL and SUPABASE_KEY:
        _supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    return _supabase


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class WebhookEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    source: Optional[str] = None
    event_type: Optional[str] = None
    payload: dict[str, Any] = Field(default_factory=dict)
    received_at: str = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    supabase_connected: bool


class LogsResponse(BaseModel):
    count: int
    logs: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------

def verify_signature(raw_body: bytes, signature_header: str) -> bool:
    """Verify HMAC-SHA256 signature if WEBHOOK_SECRET is configured."""
    if not WEBHOOK_SECRET:
        return True  # Skip verification when secret not configured
    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode(), raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


# ---------------------------------------------------------------------------
# In-memory log store (fallback when Supabase not configured)
# ---------------------------------------------------------------------------

_memory_logs: list[dict[str, Any]] = []


def store_event(event: WebhookEvent) -> None:
    """Persist event to Supabase; fall back to in-memory store."""
    record = event.model_dump()
    db = get_supabase()
    if db:
        try:
            db.table(SUPABASE_TABLE).insert(record).execute()
            logger.info("Event %s stored in Supabase.", event.event_id)
            return
        except Exception as exc:
            logger.warning("Supabase insert failed: %s — falling back to memory.", exc)

    _memory_logs.append(record)
    # Cap in-memory store at 500 entries
    if len(_memory_logs) > 500:
        _memory_logs.pop(0)
    logger.info("Event %s stored in memory.", event.event_id)


def fetch_logs(limit: int = MAX_LOGS_RESPONSE) -> list[dict[str, Any]]:
    """Retrieve most recent logs from Supabase or in-memory store."""
    db = get_supabase()
    if db:
        try:
            res = (
                db.table(SUPABASE_TABLE)
                .select("*")
                .order("received_at", desc=True)
                .limit(limit)
                .execute()
            )
            return res.data
        except Exception as exc:
            logger.warning("Supabase fetch failed: %s — returning memory logs.", exc)

    return list(reversed(_memory_logs[-limit:]))


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("Webhook receiver starting up.")
    db = get_supabase()
    logger.info("Supabase connected: %s", db is not None)
    yield
    logger.info("Webhook receiver shutting down.")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Webhook Receiver",
    description="Production-ready webhook handler with logging and DB integration.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health", response_model=HealthResponse, tags=["ops"])
async def health_check() -> HealthResponse:
    """Liveness probe — returns service status."""
    return HealthResponse(
        status="ok",
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        supabase_connected=get_supabase() is not None,
    )


@app.post("/webhook", status_code=status.HTTP_202_ACCEPTED, tags=["webhook"])
async def receive_webhook(
    request: Request,
    x_hub_signature_256: str = Header(default=""),
    x_event_source: str = Header(default="unknown"),
    x_event_type: str = Header(default="generic"),
) -> JSONResponse:
    """
    Accept and process an incoming webhook.
    Optionally verifies HMAC-SHA256 signature via X-Hub-Signature-256 header.
    """
    raw_body = await request.body()

    if WEBHOOK_SECRET and not verify_signature(raw_body, x_hub_signature_256):
        logger.warning("Invalid webhook signature from %s", request.client.host)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid signature.",
        )

    try:
        payload: dict[str, Any] = await request.json()
    except Exception:
        payload = {"raw": raw_body.decode("utf-8", errors="replace")}

    event = WebhookEvent(
        source=x_event_source,
        event_type=x_event_type,
        payload=payload,
    )

    store_event(event)
    logger.info("Webhook received — source=%s type=%s id=%s", event.source, event.event_type, event.event_id)

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={"accepted": True, "event_id": event.event_id},
    )


@app.get("/logs", response_model=LogsResponse, tags=["ops"])
async def get_logs(limit: int = MAX_LOGS_RESPONSE) -> LogsResponse:
    """Retrieve the most recent webhook events (default: last 50)."""
    limit = min(limit, 200)
    logs = fetch_logs(limit)
    return LogsResponse(count=len(logs), logs=logs)
