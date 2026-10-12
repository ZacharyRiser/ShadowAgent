"""Retry, backoff and circuit breaking for the upstream LLM connection.

**Why the default policy is this narrow.** A chat completion is not idempotent.
If a retry follows a request the provider already executed, the same tokens are
billed twice and a tool call can run twice — in an agent gateway that is a
correctness bug, not just a cost issue. So the default retries *only* the
failures that provably never reached the model:

* **Connect-phase errors** (DNS, TCP, TLS, proxy, pool exhaustion). No request
  byte was delivered, so a second attempt cannot duplicate work.
* **HTTP 429.** The provider refused before doing any work, and a delay is
  exactly what the rate limiter asked for. ``Retry-After`` is honoured, clamped
  by the backoff cap.

Read timeouts, mid-stream protocol errors and 5xx responses are *not* retried by
default — the provider may have generated tokens already.
``SHADOW_AGENT_UPSTREAM_RETRY_UNSAFE=1`` opts into retrying those for
deployments that accept the duplicate-work risk.

**Circuit breaker.** Repeated failures trip a breaker that fails fast instead of
queueing request after request behind a dead upstream. Open for a cooldown, then
one half-open probe: success closes it, failure re-opens it with a doubled (and
capped) cooldown. Only failures that indicate upstream trouble count towards the
threshold — a 4xx caused by our own request shape must not take the whole
gateway offline.
"""

from __future__ import annotations

import asyncio
import logging
import math
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx
from fastapi import HTTPException

from app.config import (
    _upstream_circuit_cooldown_seconds,
    _upstream_circuit_threshold,
    _upstream_retry_base_delay_seconds,
    _upstream_retry_budget_seconds,
    _upstream_retry_max,
    _upstream_retry_unsafe,
    _upstream_timeout_seconds,
)

logger = logging.getLogger("shadow_agent.upstream")

# Backoff is capped so a long retry chain cannot outlive the request budget.
MAX_BACKOFF_SECONDS = 2.0

RETRY_REASON_CONNECT = "connect"
RETRY_REASON_RATE_LIMIT = "rate_limit"
RETRY_REASON_TIMEOUT = "timeout"
RETRY_REASON_SERVER_ERROR = "server_error"

CIRCUIT_STATE_CLOSED = "closed"
CIRCUIT_STATE_OPEN = "open"
CIRCUIT_STATE_HALF_OPEN = "half_open"

#: Connect-phase failures: the request never reached the provider.
_CONNECT_PHASE_ERRORS = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.PoolTimeout,
    httpx.ProxyError,
)

#: Failures where the request may already have been executed upstream.
_DELIVERY_UNCERTAIN_ERRORS = (
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.RemoteProtocolError,
)


def _retry_after_seconds(response: httpx.Response) -> float | None:
    """Parse ``Retry-After`` (delta-seconds form only) within sane bounds."""
    raw = response.headers.get("retry-after")
    if not raw:
        return None
    try:
        parsed = float(raw.strip())
    except ValueError:
        # HTTP-date form: not worth a date parser, fall back to our own backoff.
        return None
    if parsed < 0:
        return None
    return min(parsed, MAX_BACKOFF_SECONDS)


def _backoff_seconds(attempt: int, *, override: float | None = None) -> float:
    """Exponential backoff with full jitter, capped.

    Jitter matters here: every gateway instance hitting the same failing
    upstream would otherwise retry in lockstep.
    """
    if override is not None:
        return override
    base = _upstream_retry_base_delay_seconds()
    ceiling = min(base * (2 ** max(0, attempt - 1)), MAX_BACKOFF_SECONDS)
    return random.uniform(0.0, ceiling)


@dataclass
class _BreakerState:
    failures: int = 0
    opened_at: float | None = None
    cooldown: float = 0.0
    probe_in_flight: bool = False
    opened_total: int = 0


def _circuit_open_exception(remaining: float, *, probing: bool = False) -> HTTPException:
    # Round the advertised wait UP: a truncated value sends the client back
    # while the breaker is still open, so it gets a second 503 for its trouble.
    retry_after = max(1, math.ceil(remaining))
    if probing:
        return HTTPException(
            status_code=503,
            detail={
                "error": "upstream_circuit_open",
                "message": (
                    "The gateway is probing a recovering upstream provider; this "
                    "request was shed rather than queued."
                ),
                "retry_after_seconds": round(remaining, 3),
            },
            headers={"Retry-After": str(retry_after)},
        )
    return HTTPException(
        status_code=503,
        detail={
            "error": "upstream_circuit_open",
            "message": (
                "The gateway is failing fast: the upstream LLM provider has failed "
                "repeatedly and the circuit breaker is open."
            ),
            "retry_after_seconds": round(remaining, 3),
        },
        headers={"Retry-After": str(retry_after)},
    )


class UpstreamCircuitBreaker:
    """Fail fast while the upstream is known to be down."""

    def __init__(self) -> None:
        self._state = _BreakerState()
        self._lock = threading.Lock()

    def reset(self) -> None:
        with self._lock:
            self._state = _BreakerState()

    def _threshold(self) -> int:
        return _upstream_circuit_threshold()

    def state_name(self) -> str:
        with self._lock:
            return self._state_name_locked()

    def _state_name_locked(self) -> str:
        state = self._state
        if state.opened_at is None:
            return CIRCUIT_STATE_CLOSED
        if time.monotonic() - state.opened_at >= state.cooldown:
            return CIRCUIT_STATE_HALF_OPEN
        return CIRCUIT_STATE_OPEN

    def is_open(self) -> bool:
        """True while the breaker is shedding traffic (open, not probing)."""
        with self._lock:
            return self._state_name_locked() == CIRCUIT_STATE_OPEN

    def retry_after_seconds(self) -> float:
        with self._lock:
            state = self._state
            if state.opened_at is None:
                return 0.0
            remaining = state.cooldown - (time.monotonic() - state.opened_at)
            return max(0.0, remaining)

    def open_total(self) -> int:
        with self._lock:
            return self._state.opened_total

    def acquire(self) -> None:
        """Raise 503 when the breaker is open; reserve the probe when half-open."""
        threshold = self._threshold()
        if threshold <= 0:
            return
        with self._lock:
            state = self._state
            if state.opened_at is None:
                return
            elapsed = time.monotonic() - state.opened_at
            if elapsed < state.cooldown:
                raise _circuit_open_exception(state.cooldown - elapsed)
            # Cooldown elapsed: let exactly one probe through.
            if state.probe_in_flight:
                raise _circuit_open_exception(state.cooldown, probing=True)
            state.probe_in_flight = True

    def record_failure(self) -> None:
        threshold = self._threshold()
        if threshold <= 0:
            return
        with self._lock:
            state = self._state
            state.failures += 1
            if state.opened_at is not None:
                # A failed half-open probe re-opens with a longer cooldown.
                state.cooldown = min(state.cooldown * 2, 600.0)
                state.opened_at = time.monotonic()
                state.probe_in_flight = False
                state.opened_total += 1
                logger.warning(
                    "upstream circuit re-opened after failed probe (cooldown %.1fs)",
                    state.cooldown,
                )
                return
            if state.failures >= threshold:
                state.cooldown = _upstream_circuit_cooldown_seconds()
                state.opened_at = time.monotonic()
                state.probe_in_flight = False
                state.opened_total += 1
                logger.warning(
                    "upstream circuit opened after %d consecutive failures "
                    "(cooldown %.1fs)",
                    state.failures,
                    state.cooldown,
                )

    def record_success(self) -> None:
        with self._lock:
            state = self._state
            was_open = state.opened_at is not None
            self._state = _BreakerState()
            if was_open:
                logger.info("upstream circuit closed after a successful probe")


_breaker = UpstreamCircuitBreaker()


def upstream_circuit_breaker() -> UpstreamCircuitBreaker:
    return _breaker


def reset_upstream_resilience() -> None:
    """Drop all breaker state. Used by tests and on client shutdown."""
    _breaker.reset()


@dataclass
class _AttemptOutcome:
    """Result of one delivery attempt."""

    response: httpx.Response | None = None
    retry_reason: str | None = None
    error: Exception | None = None


@dataclass
class _RetryPolicy:
    max_retries: int = field(default_factory=_upstream_retry_max)
    budget_seconds: float = field(default_factory=_upstream_retry_budget_seconds)
    allow_unsafe: bool = field(default_factory=_upstream_retry_unsafe)


def _classify_exception(
    exc: Exception, *, allow_unsafe: bool
) -> tuple[str | None, bool]:
    """``(retry_reason, counts_as_upstream_failure)`` for a transport error."""
    if isinstance(exc, _CONNECT_PHASE_ERRORS):
        return RETRY_REASON_CONNECT, True
    if isinstance(exc, _DELIVERY_UNCERTAIN_ERRORS):
        # The request was delivered; a retry is only safe if the operator said so.
        return (RETRY_REASON_TIMEOUT if allow_unsafe else None), True
    if isinstance(exc, httpx.TimeoutException):
        return (RETRY_REASON_TIMEOUT if allow_unsafe else None), True
    if isinstance(exc, httpx.HTTPError):
        return RETRY_REASON_CONNECT, True
    return None, False


def _classify_response(
    response: httpx.Response, *, allow_unsafe: bool
) -> tuple[str | None, bool]:
    """``(retry_reason, counts_as_upstream_failure)`` for an HTTP response."""
    status = response.status_code
    if status == 429:
        return RETRY_REASON_RATE_LIMIT, False
    if 500 <= status < 600:
        # A 5xx may follow a fully generated completion, so it is opt-in and it
        # counts towards the breaker either way.
        return (RETRY_REASON_SERVER_ERROR if allow_unsafe else None), True
    return None, False


async def send_with_resilience(
    *,
    deliver: Callable[[], Any],
    request_id: str,
) -> httpx.Response:
    """Run one upstream call under the retry policy and the circuit breaker.

    ``deliver`` performs a single attempt and returns an ``httpx.Response``.
    Responses that are discarded for a retry are closed here, so a retry chain
    cannot leak a streamed connection per attempt.
    """
    policy = _RetryPolicy()
    breaker = _breaker
    breaker.acquire()

    started = time.monotonic()
    attempt = 0

    while True:
        attempt += 1
        try:
            response = await deliver()
        except Exception as exc:  # noqa: BLE001 - re-raised unless classified
            retry_reason, counts_as_failure = _classify_exception(
                exc, allow_unsafe=policy.allow_unsafe
            )
            if counts_as_failure:
                breaker.record_failure()
            if breaker.is_open():
                # This call just tripped the breaker. Retrying now would be the
                # exact hammering the breaker exists to stop.
                raise _circuit_open_exception(breaker.retry_after_seconds()) from exc
            if retry_reason is None or not _budget_left(policy, started, attempt):
                raise
            delay = _backoff_seconds(attempt)
            logger.warning(
                "upstream attempt %d/%d failed (%s): %s -- retrying in %.3fs",
                attempt,
                policy.max_retries + 1,
                retry_reason,
                exc,
                delay,
            )
            _record_retry(reason=retry_reason, attempt=attempt, request_id=request_id)
            await asyncio.sleep(delay)
            continue

        retry_reason, counts_as_failure = _classify_response(
            response, allow_unsafe=policy.allow_unsafe
        )
        if retry_reason is None:
            if counts_as_failure:
                breaker.record_failure()
                if breaker.is_open():
                    await response.aclose()
                    raise _circuit_open_exception(breaker.retry_after_seconds())
            else:
                breaker.record_success()
            return response

        if not _budget_left(policy, started, attempt):
            if counts_as_failure:
                breaker.record_failure()
            else:
                breaker.record_success()
            return response

        status = response.status_code
        retry_after = _retry_after_seconds(response)
        # Release the discarded response before retrying, or the pool keeps a
        # stream open for every attempt.
        await response.aclose()
        delay = _backoff_seconds(
            attempt,
            override=retry_after if retry_reason == RETRY_REASON_RATE_LIMIT else None,
        )
        logger.warning(
            "upstream attempt %d/%d returned HTTP %d (%s) -- retrying in %.3fs",
            attempt,
            policy.max_retries + 1,
            status,
            retry_reason,
            delay,
        )
        _record_retry(reason=retry_reason, attempt=attempt, request_id=request_id)
        await asyncio.sleep(delay)


def _budget_left(policy: _RetryPolicy, started: float, attempt: int) -> bool:
    """Whether one more attempt fits in the retry budget and retry count."""
    if attempt > policy.max_retries:
        return False
    if policy.budget_seconds <= 0:
        return True
    elapsed = time.monotonic() - started
    # Charge the next attempt its own timeout, so the budget covers the whole
    # logical call rather than just what has already been spent.
    return elapsed + _upstream_timeout_seconds() <= policy.budget_seconds


def _record_retry(*, reason: str, attempt: int, request_id: str) -> None:
    try:
        from app.metrics import record_upstream_retry

        record_upstream_retry(reason=reason)
    except Exception:  # pragma: no cover - metrics must never break forwarding
        logger.debug("failed to record upstream retry metric", exc_info=True)
    logger.info(
        "upstream retry %d scheduled (reason=%s, request_id=%s)",
        attempt,
        reason,
        request_id,
    )
