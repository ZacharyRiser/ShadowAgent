"""In-process event bus for real-time SSE push (security dashboard).

Intercepted requests are published here by the audit trail and fanned out to
all connected SSE subscribers (``GET /api/v1/events/stream``). A bounded
history ring is kept so newly connected dashboards immediately see recent
events.

Design notes:
- Single-instance by design (same as the rate limiter's memory mode); the
  authoritative record is always the database, the bus is best-effort push.
- publish_event() is thread-safe: it may be called from request handlers
  (event-loop thread) or worker threads.
- Slow subscribers never block publishers: each queue is bounded and drops
  the oldest event when full.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections import deque
from typing import Any

logger = logging.getLogger("shadow_agent.events")

_MAX_HISTORY = 50
_MAX_QUEUE_SIZE = 200
_MAX_SUBSCRIBERS = 64

_lock = threading.Lock()
_subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
_history: deque[dict[str, Any]] = deque(maxlen=_MAX_HISTORY)
_main_loop: asyncio.AbstractEventLoop | None = None


def bind_main_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Record the serving event loop so worker threads can publish safely."""
    global _main_loop
    with _lock:
        _main_loop = loop


def _dispatch(event: dict[str, Any]) -> None:
    """Fan out one event to every subscriber (must run on the event loop)."""
    _history.append(event)
    for queue in list(_subscribers):
        if queue.full():
            try:
                queue.get_nowait()  # drop oldest for slow consumers
            except asyncio.QueueEmpty:
                pass
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.warning("SSE subscriber queue full; event dropped")


def publish_event(event: dict[str, Any]) -> None:
    """Publish an event to all SSE subscribers. Thread-safe, never raises."""
    stamped = {**event, "ts": event.get("ts") or time.time()}
    try:
        with _lock:
            loop = _main_loop
            if loop is None or loop.is_closed():
                # No serving loop bound (e.g. unit tests): keep history only.
                _history.append(stamped)
                return

        loop.call_soon_threadsafe(_dispatch, stamped)
    except RuntimeError:
        # Loop closed concurrently during shutdown; swallow.
        with _lock:
            _history.append(stamped)
    except Exception:  # pragma: no cover - defensive: push must never break request handling
        logger.exception("Failed to publish SSE event")


def subscribe() -> asyncio.Queue[dict[str, Any]]:
    """Register a new SSE subscriber queue (with replay history attached)."""
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=_MAX_QUEUE_SIZE)
    with _lock:
        if len(_subscribers) >= _MAX_SUBSCRIBERS:
            raise ConnectionRefusedError("too many SSE subscribers")
        _subscribers.add(queue)
    # Replay recent history so dashboards render instantly on connect.
    for event in list(_history):
        queue.put_nowait(event)
    return queue


def unsubscribe(queue: asyncio.Queue[dict[str, Any]]) -> None:
    with _lock:
        _subscribers.discard(queue)


def event_history() -> list[dict[str, Any]]:
    with _lock:
        return list(_history)


def subscriber_count() -> int:
    with _lock:
        return len(_subscribers)
