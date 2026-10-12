"""Request guards: reject hostile or accidentally huge payloads early.

The gateway's job is to *inspect* traffic, which means it has to hold each
request in memory before any detector can look at it. That is exactly the shape
of an unauthenticated memory-amplification bug: an attacker does not need to
break a detection rule, only to send a body large enough that parsing it costs
more than the request is worth. Nothing in the stack capped body size before
this guard, so a single multi-gigabyte POST was bounded only by the host's
memory.

``SHADOW_AGENT_MAX_BODY_BYTES`` (default 2 MiB) sets the ceiling;
``0`` disables the guard for a deployment that fronts the gateway with its own
size limit and would rather not have two.

Enforcement has two paths on purpose:

* ``Content-Length`` above the ceiling is refused before a single body byte is
  read -- the cheap case, and the one an honest client always hits.
* Otherwise every ``http.request`` chunk is counted as it arrives, and the
  request is aborted the moment the running total crosses the ceiling. A client
  can understate or omit ``Content-Length`` (chunked encoding), so the declared
  check alone would be a suggestion rather than a limit.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Awaitable, Callable

from starlette.responses import JSONResponse

from app.metrics import record_body_rejected

logger = logging.getLogger("shadow_agent.gateway")

DEFAULT_MAX_BODY_BYTES = 2 * 1024 * 1024


def max_body_bytes() -> int:
    """Configured ceiling, or ``0`` when the guard is disabled.

    Read per request so a test or an operator can change it without rebuilding
    the app. An unparseable value falls back to the default rather than to
    "unlimited": a typo must not remove the ceiling.
    """
    raw = os.getenv("SHADOW_AGENT_MAX_BODY_BYTES", "").strip()
    if not raw:
        return DEFAULT_MAX_BODY_BYTES
    try:
        parsed = int(raw)
    except ValueError:
        logger.warning(
            "Invalid SHADOW_AGENT_MAX_BODY_BYTES=%r, falling back to %d bytes",
            raw,
            DEFAULT_MAX_BODY_BYTES,
        )
        return DEFAULT_MAX_BODY_BYTES
    return max(0, parsed)


def _declared_content_length(scope: dict[str, Any]) -> int | None:
    for name, value in scope.get("headers") or ():
        if name == b"content-length":
            try:
                return int(value.decode("latin-1").strip())
            except (ValueError, UnicodeDecodeError):
                return None
    return None


class _BodyTooLarge(Exception):
    """Raised from the wrapped ``receive`` to unwind a body in progress."""

    def __init__(self, total: int) -> None:
        super().__init__(total)
        self.total = total


class BodySizeLimitMiddleware:
    """Pure ASGI middleware: cap the bytes the application may read.

    Deliberately not a ``BaseHTTPMiddleware``: that would have to re-wrap the
    request stream, and the whole point here is to sit *below* the stream and
    count what actually crosses it.
    """

    def __init__(self, app: Callable[..., Awaitable[None]]) -> None:
        self.app = app

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        limit = max_body_bytes()
        if scope["type"] != "http" or limit <= 0:
            await self.app(scope, receive, send)
            return

        declared = _declared_content_length(scope)
        if declared is not None and declared > limit:
            await _reject(scope, send, limit=limit, observed=declared, reason="declared")
            return

        total = 0
        response_started = False

        async def counting_receive() -> dict[str, Any]:
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > limit:
                    raise _BodyTooLarge(total)
            return message

        async def tracking_send(message: dict[str, Any]) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _BodyTooLarge as exc:
            # A response already on the wire cannot be replaced; let the server
            # see the fault rather than corrupting the stream with a second one.
            if response_started:
                raise
            await _reject(
                scope, send, limit=limit, observed=exc.total, reason="actual"
            )


async def _reject(
    scope: dict[str, Any],
    send: Callable[[dict[str, Any]], Awaitable[None]],
    *,
    limit: int,
    observed: int,
    reason: str,
) -> None:
    record_body_rejected(reason=reason)
    logger.warning(
        "Rejected oversized request body: path=%s declared_or_observed=%d limit=%d reason=%s",
        scope.get("path", ""),
        observed,
        limit,
        reason,
    )
    response = JSONResponse(
        status_code=413,
        content={
            "error": "payload_too_large",
            "message": (
                "Request body exceeds the gateway limit. Lower the payload or "
                "raise SHADOW_AGENT_MAX_BODY_BYTES."
            ),
            "max_body_bytes": limit,
            "observed_bytes": observed,
        },
    )
    await response(scope, _empty_receive, send)


async def _empty_receive() -> dict[str, Any]:
    """Stand-in receive for a response sent without reading the request body."""
    return {"type": "http.disconnect"}
