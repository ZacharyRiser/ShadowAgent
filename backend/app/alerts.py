"""Outbound webhook alerting for intercept events.

Intercepts are enqueued from request handlers (thread-safe, never blocking)
and delivered by a background dispatcher task started in the app lifespan.
Delivery is best-effort with bounded retries — the database audit log stays
the authoritative record.

Configuration (read lazily so tests/operators can change it without restart):
- ``SHADOW_AGENT_ALERT_WEBHOOK_URL``: target URL (Slack / Feishu / DingTalk /
  generic receiver). Unset => dispatching is a no-op.
- ``SHADOW_AGENT_ALERT_WEBHOOK_SECRET``: when set, every delivery carries
  ``X-ShadowAgent-Signature: sha256=<hex hmac>`` over the exact body bytes so
  receivers can verify authenticity.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from app.config import _alert_webhook_secret, _alert_webhook_url

logger = logging.getLogger("shadow_agent.alerts")

_MAX_QUEUE_SIZE = 500
_MAX_ATTEMPTS = 3
_RETRY_DELAYS: tuple[float, ...] = (1.0, 4.0)
_TIMEOUT_SECONDS = 5.0

_lock = threading.Lock()
_main_loop: asyncio.AbstractEventLoop | None = None
_queue: asyncio.Queue[dict[str, Any]] | None = None


def bind_main_loop(loop: asyncio.AbstractEventLoop | None) -> None:
    """Bind (or unbind with None) the serving loop for the alert queue."""
    global _main_loop, _queue
    with _lock:
        _main_loop = loop
        _queue = asyncio.Queue(maxsize=_MAX_QUEUE_SIZE) if loop is not None else None


def webhook_configured() -> bool:
    return bool(_alert_webhook_url())


def enqueue_alert(event: dict[str, Any]) -> None:
    """Queue an alert for webhook delivery. Thread-safe, never raises."""
    if not webhook_configured():
        return

    stamped = {**event, "ts": event.get("ts") or time.time()}
    try:
        with _lock:
            loop = _main_loop
            queue = _queue

        if loop is None or queue is None or loop.is_closed():
            return  # no serving loop (unit tests / shutdown): drop quietly

        def _put() -> None:
            if queue.full():
                try:
                    queue.get_nowait()  # drop oldest for slow consumers
                except asyncio.QueueEmpty:
                    pass
            queue.put_nowait(stamped)

        loop.call_soon_threadsafe(_put)
    except Exception:  # pragma: no cover - alerting must never break requests
        logger.exception("Failed to enqueue webhook alert")


async def alert_dispatcher_loop() -> None:
    """Consume queued alerts and deliver them (started in app lifespan)."""
    while True:
        with _lock:
            queue = _queue
        if queue is None:
            await asyncio.sleep(1.0)
            continue

        event = await queue.get()
        try:
            await deliver_webhook(event)
        except Exception:
            logger.exception("Webhook dispatcher iteration failed")
        finally:
            queue.task_done()


def _build_payload(event: dict[str, Any]) -> dict[str, Any]:
    timestamp = event.get("ts") or time.time()
    return {
        "source": "shadow-agent",
        "event": event.get("type", "intercept"),
        "timestamp": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
        "request_id": event.get("request_id"),
        "threat_type": event.get("threat_type"),
        "category": event.get("category"),
        "categories": event.get("categories"),
        "risk_score": event.get("risk_score"),
        "layer": event.get("layer"),
        "reason": event.get("reason"),
        "recommended_action": event.get("recommended_action"),
        "action_taken": event.get("action_taken", "Blocked"),
    }


def _signature_header(body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


async def deliver_webhook(
    event: dict[str, Any],
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> bool:
    """POST one alert to the configured webhook. Returns True on 2xx.

    Retries up to ``_MAX_ATTEMPTS`` with backoff on failures. ``transport``
    is injectable for tests.
    """
    url = _alert_webhook_url()
    if not url:
        return False

    payload = _build_payload(event)
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "ShadowAgent-Webhook/1.0",
    }
    secret = _alert_webhook_secret()
    if secret:
        headers["X-ShadowAgent-Signature"] = _signature_header(body, secret)

    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            async with httpx.AsyncClient(
                timeout=_TIMEOUT_SECONDS,
                transport=transport,
            ) as client:
                response = await client.post(url, content=body, headers=headers)
            if 200 <= response.status_code < 300:
                return True
            logger.warning(
                "Webhook delivery attempt %d/%d returned HTTP %d",
                attempt,
                _MAX_ATTEMPTS,
                response.status_code,
            )
        except Exception as exc:
            logger.warning(
                "Webhook delivery attempt %d/%d failed: %s",
                attempt,
                _MAX_ATTEMPTS,
                exc,
            )

        if attempt < _MAX_ATTEMPTS:
            delay = _RETRY_DELAYS[min(attempt - 1, len(_RETRY_DELAYS) - 1)]
            await asyncio.sleep(delay)

    logger.error("Webhook delivery gave up after %d attempts", _MAX_ATTEMPTS)
    return False
