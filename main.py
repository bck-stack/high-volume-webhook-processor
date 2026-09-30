"""
FastAPI Webhook Receiver
Captures incoming webhooks, validates signatures, de-duplicates deliveries and
persists them to Supabase through a background batch writer (in-memory fallback).
Endpoints: GET /health  |  GET /metrics  |  POST /webhook  |  GET /logs
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from collections import OrderedDict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Optional
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

load_dotenv(Path(__file__).resolve().parent / ".env")

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


class Settings:
    def __init__(self) -> None:
        self.webhook_secret: str = os.getenv("WEBHOOK_SECRET", "")
        # Refuse unsigned webhooks unless explicitly allowed (handy for local testing only).
        self.allow_unsigned: bool = _bool("ALLOW_UNSIGNED", False)
        self.logs_api_key: str = os.getenv("LOGS_API_KEY", "")
        self.supabase_url: str = os.getenv("SUPABASE_URL", "")
        self.supabase_key: str = os.getenv("SUPABASE_KEY", "")
        self.supabase_table: str = os.getenv("SUPABASE_TABLE", "webhook_logs")
        self.max_logs_response: int = int(os.getenv("MAX_LOGS_RESPONSE", "50"))
        self.max_memory_logs: int = int(os.getenv("MAX_MEMORY_LOGS", "500"))
        self.max_body_bytes: int = int(os.getenv("MAX_BODY_BYTES", str(1024 * 1024)))
        self.queue_size: int = int(os.getenv("QUEUE_SIZE", "10000"))
        self.batch_size: int = int(os.getenv("BATCH_SIZE", "100"))
        self.batch_interval: float = float(os.getenv("BATCH_INTERVAL", "0.5"))
        self.dedup_window: int = int(os.getenv("DEDUP_WINDOW", "10000"))


settings = Settings()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class WebhookEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    delivery_id: Optional[str] = None
    source: Optional[str] = None
    event_type: Optional[str] = None
    payload: Any = Field(default_factory=dict)
    received_at: str = Field(default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    supabase_connected: bool
    queue_depth: int


class LogsResponse(BaseModel):
    count: int
    logs: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------

def compute_signature(secret: str, raw_body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()


def verify_signature(raw_body: bytes, signature_header: str, secret: Optional[str] = None) -> bool:
    """Constant-time HMAC-SHA256 check. Accepts 'sha256=<hex>' or a bare hex digest."""
    secret = settings.webhook_secret if secret is None else secret
    if not secret or not signature_header:
        return False
    provided = signature_header.strip()
    if not provided.startswith("sha256="):
        provided = "sha256=" + provided
    return hmac.compare_digest(compute_signature(secret, raw_body), provided.lower())


# ---------------------------------------------------------------------------
# Storage: Supabase via background batch writer, memory ring buffer fallback
# ---------------------------------------------------------------------------

class EventStore:
    def __init__(self, cfg: Settings) -> None:
        self.cfg = cfg
        self.memory: deque[dict[str, Any]] = deque(maxlen=cfg.max_memory_logs)
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=cfg.queue_size)
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._client = None
        self._worker: Optional[asyncio.Task] = None
        self.stats = {"received": 0, "duplicates": 0, "rejected": 0, "persisted": 0, "persist_errors": 0}
        self.started = time.time()

    # -- supabase -----------------------------------------------------------
    @property
    def supabase(self):
        if self._client is None and self.cfg.supabase_url and self.cfg.supabase_key:
            try:
                from supabase import create_client

                self._client = create_client(self.cfg.supabase_url, self.cfg.supabase_key)
            except Exception as exc:
                logger.error("Supabase client could not be created: %s", exc)
        return self._client

    # -- de-duplication -----------------------------------------------------
    def is_duplicate(self, delivery_id: Optional[str]) -> bool:
        if not delivery_id:
            return False
        if delivery_id in self._seen:
            self._seen.move_to_end(delivery_id)
            return True
        self._seen[delivery_id] = None
        if len(self._seen) > self.cfg.dedup_window:
            self._seen.popitem(last=False)
        return False

    # -- write path ---------------------------------------------------------
    def enqueue(self, record: dict[str, Any]) -> bool:
        """Non-blocking: the HTTP response never waits for the database."""
        self.memory.append(record)
        if self.supabase is None:
            return True
        try:
            self.queue.put_nowait(record)
            return True
        except asyncio.QueueFull:
            return False

    async def _flush(self, batch: list[dict[str, Any]]) -> None:
        for attempt in range(1, 4):
            try:
                await asyncio.to_thread(
                    lambda: self.supabase.table(self.cfg.supabase_table)
                    .upsert(batch, on_conflict="event_id", ignore_duplicates=True)
                    .execute()
                )
                self.stats["persisted"] += len(batch)
                return
            except Exception as exc:
                logger.warning("Supabase batch insert failed (attempt %d/3, %d rows): %s", attempt, len(batch), exc)
                await asyncio.sleep(2 ** attempt)
        self.stats["persist_errors"] += len(batch)
        logger.error("Dropped %d events after 3 failed attempts (still available in memory)", len(batch))

    async def run_writer(self) -> None:
        while True:
            batch = [await self.queue.get()]
            deadline = time.monotonic() + self.cfg.batch_interval
            while len(batch) < self.cfg.batch_size:
                timeout = deadline - time.monotonic()
                if timeout <= 0:
                    break
                try:
                    batch.append(await asyncio.wait_for(self.queue.get(), timeout))
                except asyncio.TimeoutError:
                    break
            await self._flush(batch)
            for _ in batch:
                self.queue.task_done()

    async def start(self) -> None:
        if self.supabase is not None and self._worker is None:
            self._worker = asyncio.create_task(self.run_writer())

    async def stop(self) -> None:
        if self._worker:
            try:
                await asyncio.wait_for(self.queue.join(), timeout=10)  # drain before exit
            except asyncio.TimeoutError:
                logger.warning("Shutdown with %d events still queued", self.queue.qsize())
            self._worker.cancel()

    # -- read path ----------------------------------------------------------
    async def fetch(self, limit: int, source: Optional[str], event_type: Optional[str]) -> list[dict[str, Any]]:
        if self.supabase is not None:
            try:
                def query():
                    q = self.supabase.table(self.cfg.supabase_table).select("*")
                    if source:
                        q = q.eq("source", source)
                    if event_type:
                        q = q.eq("event_type", event_type)
                    return q.order("received_at", desc=True).limit(limit).execute()

                return (await asyncio.to_thread(query)).data
            except Exception as exc:
                logger.warning("Supabase fetch failed: %s — returning memory logs.", exc)
        rows = [r for r in reversed(self.memory)
                if (not source or r.get("source") == source) and (not event_type or r.get("event_type") == event_type)]
        return rows[:limit]


store = EventStore(settings)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("Webhook receiver starting up.")
    if not settings.webhook_secret:
        if settings.allow_unsigned:
            logger.warning("WEBHOOK_SECRET not set and ALLOW_UNSIGNED=true — accepting unsigned webhooks.")
        else:
            logger.error("WEBHOOK_SECRET not set — all webhooks will be rejected (set ALLOW_UNSIGNED=true for local tests).")
    if not settings.logs_api_key:
        logger.warning("LOGS_API_KEY not set — GET /logs is disabled.")
    await store.start()
    logger.info("Supabase connected: %s", store.supabase is not None)
    yield
    await store.stop()
    logger.info("Webhook receiver shutting down.")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Webhook Receiver",
    description="Production-ready webhook handler with signature checks, de-duplication and batched DB writes.",
    version="2.0.0",
    lifespan=lifespan,
)


def require_api_key(x_api_key: str = Header(default="")) -> None:
    if not settings.logs_api_key:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Log access is disabled (LOGS_API_KEY not configured).")
    if not secrets.compare_digest(x_api_key, settings.logs_api_key):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key.")


@app.get("/health", response_model=HealthResponse, tags=["ops"])
async def health_check() -> HealthResponse:
    """Liveness probe — returns service status."""
    return HealthResponse(
        status="ok",
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        supabase_connected=store.supabase is not None,
        queue_depth=store.queue.qsize(),
    )


@app.get("/metrics", tags=["ops"], dependencies=[Depends(require_api_key)])
async def metrics() -> dict[str, Any]:
    """Counters since start-up."""
    return {
        **store.stats,
        "queue_depth": store.queue.qsize(),
        "memory_buffer": len(store.memory),
        "uptime_seconds": round(time.time() - store.started),
    }


@app.post("/webhook", status_code=status.HTTP_202_ACCEPTED, tags=["webhook"])
async def receive_webhook(
    request: Request,
    x_hub_signature_256: str = Header(default=""),
    x_signature: str = Header(default=""),
    x_event_source: str = Header(default="unknown"),
    x_event_type: str = Header(default="generic"),
    x_delivery_id: str = Header(default=""),
    x_github_delivery: str = Header(default=""),
    x_github_event: str = Header(default=""),
) -> JSONResponse:
    """
    Accept and process an incoming webhook.
    Signature: X-Hub-Signature-256 (or X-Signature) = sha256=HMAC(secret, body).
    Duplicate deliveries (same X-Delivery-Id / X-GitHub-Delivery) are acknowledged but stored once.
    """
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > settings.max_body_bytes:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Payload too large.")
    raw_body = await request.body()
    if len(raw_body) > settings.max_body_bytes:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Payload too large.")

    client_host = request.client.host if request.client else "?"
    signature = x_hub_signature_256 or x_signature
    if settings.webhook_secret:
        if not verify_signature(raw_body, signature):
            store.stats["rejected"] += 1
            logger.warning("Invalid webhook signature from %s", client_host)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid signature.")
    elif not settings.allow_unsigned:
        store.stats["rejected"] += 1
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Receiver not configured (WEBHOOK_SECRET missing).")

    delivery_id = x_delivery_id or x_github_delivery or None
    if store.is_duplicate(delivery_id):
        store.stats["duplicates"] += 1
        logger.info("Duplicate delivery %s ignored", delivery_id)
        return JSONResponse(status_code=status.HTTP_200_OK, content={"accepted": True, "duplicate": True, "delivery_id": delivery_id})

    try:
        payload: Any = json.loads(raw_body) if raw_body else {}
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = {"raw": raw_body.decode("utf-8", errors="replace")}

    event = WebhookEvent(
        delivery_id=delivery_id,
        source="github" if x_github_event and x_event_source == "unknown" else x_event_source,
        event_type=x_github_event or x_event_type,
        payload=payload,
    )
    if not store.enqueue(event.model_dump()):
        store.stats["rejected"] += 1
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Queue full, retry later.", headers={"Retry-After": "5"})

    store.stats["received"] += 1
    logger.info("Webhook received — source=%s type=%s id=%s", event.source, event.event_type, event.event_id)
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={"accepted": True, "event_id": event.event_id},
    )


@app.get("/logs", response_model=LogsResponse, tags=["ops"], dependencies=[Depends(require_api_key)])
async def get_logs(
    limit: int = Query(default=settings.max_logs_response, ge=1, le=200),
    source: Optional[str] = None,
    event_type: Optional[str] = None,
) -> LogsResponse:
    """Retrieve the most recent webhook events (requires X-API-Key)."""
    logs = await store.fetch(limit, source, event_type)
    return LogsResponse(count=len(logs), logs=logs)
