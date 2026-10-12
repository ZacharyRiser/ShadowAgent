"""Upstream retry/backoff and circuit breaking must be safe by default.

The properties asserted here are the ones a reader would otherwise have to take
on faith:

* **Only failures that provably never reached the model are retried.** A
  connect-phase error and a 429 are retried; a read timeout and a 5xx are not,
  because the provider may already have generated (and billed) a completion.
* **Retrying is bounded** — by an attempt count, by a wall-clock budget, and by
  a cap on the backoff, so a dead upstream cannot hold a caller for minutes.
* **The breaker fails fast** rather than queueing requests behind a dead
  provider, and a half-open probe is what closes it again.
* **A discarded response is closed before the next attempt**, so retries do not
  leak a connection each.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import httpx
import pytest
from fastapi import HTTPException

from app import upstream_resilience as ur
from app.upstream_resilience import (
    CIRCUIT_STATE_CLOSED,
    CIRCUIT_STATE_HALF_OPEN,
    CIRCUIT_STATE_OPEN,
    MAX_BACKOFF_SECONDS,
    RETRY_REASON_CONNECT,
    RETRY_REASON_RATE_LIMIT,
    RETRY_REASON_SERVER_ERROR,
    _backoff_seconds,
    _classify_exception,
    _classify_response,
    _retry_after_seconds,
    reset_upstream_resilience,
    send_with_resilience,
    upstream_circuit_breaker,
)

_MANAGED_ENV = (
    "SHADOW_AGENT_UPSTREAM_RETRY_MAX",
    "SHADOW_AGENT_UPSTREAM_RETRY_BASE_DELAY_SECONDS",
    "SHADOW_AGENT_UPSTREAM_RETRY_BUDGET_SECONDS",
    "SHADOW_AGENT_UPSTREAM_RETRY_UNSAFE",
    "SHADOW_AGENT_UPSTREAM_CIRCUIT_THRESHOLD",
    "SHADOW_AGENT_UPSTREAM_CIRCUIT_COOLDOWN_SECONDS",
    "SHADOW_AGENT_UPSTREAM_TRUST_ENV",
    "SHADOW_AGENT_UPSTREAM_BASE_URL",
    "SHADOW_AGENT_UPSTREAM_CHAT_COMPLETIONS_URL",
    "SHADOW_AGENT_UPSTREAM_MODEL",
    "SHADOW_AGENT_UPSTREAM_TIMEOUT_SECONDS",
)


@pytest.fixture(autouse=True)
def _clean_env():
    saved = {name: os.environ.get(name) for name in _MANAGED_ENV}
    for name in _MANAGED_ENV:
        os.environ.pop(name, None)
    reset_upstream_resilience()
    try:
        yield
    finally:
        reset_upstream_resilience()
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch):
    """Keep the suite fast and capture the delays the policy asked for."""
    delays: list[float] = []

    async def _fake_sleep(seconds: float) -> None:
        delays.append(seconds)

    monkeypatch.setattr(ur.asyncio, "sleep", _fake_sleep)
    return delays


class _SpyResponse(httpx.Response):
    """Response that records whether the retry path released it."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.close_calls = 0

    async def aclose(self) -> None:
        self.close_calls += 1
        await super().aclose()


def _ok(payload: dict | None = None) -> httpx.Response:
    return httpx.Response(200, json=payload or {"choices": [{"message": {"content": "ok"}}]})


def _failure_threshold_two() -> None:
    os.environ["SHADOW_AGENT_UPSTREAM_CIRCUIT_THRESHOLD"] = "2"
    os.environ["SHADOW_AGENT_UPSTREAM_CIRCUIT_COOLDOWN_SECONDS"] = "60"


# --- configuration ----------------------------------------------------------


def test_default_policy_is_conservative() -> None:
    policy = ur._RetryPolicy()
    assert policy.max_retries == 2
    assert policy.allow_unsafe is False
    assert policy.budget_seconds == 90.0


def test_invalid_env_values_fall_back_to_defaults() -> None:
    os.environ["SHADOW_AGENT_UPSTREAM_RETRY_MAX"] = "not-a-number"
    os.environ["SHADOW_AGENT_UPSTREAM_RETRY_BUDGET_SECONDS"] = "soon"
    assert ur._RetryPolicy().max_retries == 2
    assert ur._RetryPolicy().budget_seconds == 90.0


def test_retry_count_cannot_be_negative() -> None:
    os.environ["SHADOW_AGENT_UPSTREAM_RETRY_MAX"] = "-5"
    assert ur._RetryPolicy().max_retries == 0


def test_circuit_can_be_disabled() -> None:
    os.environ["SHADOW_AGENT_UPSTREAM_CIRCUIT_THRESHOLD"] = "0"
    breaker = upstream_circuit_breaker()
    for _ in range(10):
        breaker.record_failure()
    # Never opens, so it never sheds: 0 means "no breaker", not "always open".
    breaker.acquire()
    assert breaker.state_name() == CIRCUIT_STATE_CLOSED


# --- classification ---------------------------------------------------------


def test_connect_phase_errors_are_retryable_by_default() -> None:
    for exc in (
        httpx.ConnectError("refused"),
        httpx.ConnectTimeout("no handshake"),
        httpx.PoolTimeout("no slot"),
        httpx.ProxyError("proxy down"),
    ):
        reason, counts = _classify_exception(exc, allow_unsafe=False)
        assert reason == RETRY_REASON_CONNECT, exc
        assert counts is True


def test_read_timeout_is_not_retried_by_default() -> None:
    """The request was delivered; a retry could bill the same tokens twice."""
    reason, counts = _classify_exception(httpx.ReadTimeout("slow"), allow_unsafe=False)
    assert reason is None
    assert counts is True, "a read timeout still means the upstream is unhealthy"


def test_read_timeout_is_retried_when_unsafe_is_enabled() -> None:
    os.environ["SHADOW_AGENT_UPSTREAM_RETRY_UNSAFE"] = "1"
    reason, _ = _classify_exception(httpx.ReadTimeout("slow"), allow_unsafe=True)
    assert reason == ur.RETRY_REASON_TIMEOUT


def test_http_429_is_retried_without_tripping_the_breaker() -> None:
    response = httpx.Response(429, headers={"Retry-After": "1"})
    reason, counts = _classify_response(response, allow_unsafe=False)
    assert reason == RETRY_REASON_RATE_LIMIT
    assert counts is False, "our own throttling must not open the breaker"


def test_http_5xx_is_not_retried_but_does_count_as_failure() -> None:
    reason, counts = _classify_response(httpx.Response(503), allow_unsafe=False)
    assert reason is None
    assert counts is True

    os.environ["SHADOW_AGENT_UPSTREAM_RETRY_UNSAFE"] = "1"
    reason, _ = _classify_response(httpx.Response(503), allow_unsafe=True)
    assert reason == RETRY_REASON_SERVER_ERROR


def test_client_errors_are_not_retried_and_never_count() -> None:
    """A 400 caused by our own payload must not take the gateway offline."""
    for status in (400, 401, 403, 404, 422):
        reason, counts = _classify_response(httpx.Response(status), allow_unsafe=True)
        assert reason is None and counts is False


def test_unknown_transport_error_is_not_retried() -> None:
    reason, counts = _classify_exception(ValueError("bug"), allow_unsafe=True)
    assert reason is None and counts is False


# --- backoff ----------------------------------------------------------------


def test_backoff_is_exponential_and_capped() -> None:
    os.environ["SHADOW_AGENT_UPSTREAM_RETRY_BASE_DELAY_SECONDS"] = "0.25"
    for attempt in (1, 2, 3, 4, 10):
        for _ in range(50):
            delay = _backoff_seconds(attempt)
            assert 0.0 <= delay <= MAX_BACKOFF_SECONDS


def test_retry_after_header_is_clamped_and_parsed() -> None:
    assert _retry_after_seconds(httpx.Response(429, headers={"Retry-After": "1.5"})) == 1.5
    # HTTP-date form is not parsed; our own backoff takes over instead.
    assert _retry_after_seconds(
        httpx.Response(429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"})
    ) is None
    assert _retry_after_seconds(httpx.Response(429, headers={"Retry-After": "-1"})) is None
    assert _retry_after_seconds(
        httpx.Response(429, headers={"Retry-After": "9999"})
    ) == MAX_BACKOFF_SECONDS
    assert _retry_after_seconds(httpx.Response(429)) is None


# --- retry loop -------------------------------------------------------------


def test_connect_error_then_success_returns_the_second_response() -> None:
    attempts = {"n": 0}
    expected = _ok()

    async def deliver() -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise httpx.ConnectError("refused")
        return expected

    response = asyncio.run(send_with_resilience(deliver=deliver, request_id="req-1"))
    assert response is expected
    assert attempts["n"] == 2
    assert upstream_circuit_breaker().state_name() == CIRCUIT_STATE_CLOSED


def test_retries_stop_after_the_configured_maximum() -> None:
    os.environ["SHADOW_AGENT_UPSTREAM_RETRY_MAX"] = "2"
    attempts = {"n": 0}

    async def deliver() -> httpx.Response:
        attempts["n"] += 1
        raise httpx.ConnectError("refused")

    with pytest.raises(httpx.ConnectError):
        asyncio.run(send_with_resilience(deliver=deliver, request_id="req-2"))
    assert attempts["n"] == 3, "one initial attempt plus two retries"


def test_zero_retries_means_a_single_attempt() -> None:
    os.environ["SHADOW_AGENT_UPSTREAM_RETRY_MAX"] = "0"
    attempts = {"n": 0}

    async def deliver() -> httpx.Response:
        attempts["n"] += 1
        raise httpx.ConnectError("refused")

    with pytest.raises(httpx.ConnectError):
        asyncio.run(send_with_resilience(deliver=deliver, request_id="req-3"))
    assert attempts["n"] == 1


def test_budget_stops_retries_even_when_attempts_remain() -> None:
    """A long read timeout must not be multiplied by the retry count."""
    os.environ["SHADOW_AGENT_UPSTREAM_RETRY_MAX"] = "5"
    os.environ["SHADOW_AGENT_UPSTREAM_RETRY_BUDGET_SECONDS"] = "1"
    os.environ["SHADOW_AGENT_UPSTREAM_TIMEOUT_SECONDS"] = "60"
    attempts = {"n": 0}

    async def deliver() -> httpx.Response:
        attempts["n"] += 1
        raise httpx.ConnectError("refused")

    with pytest.raises(httpx.ConnectError):
        asyncio.run(send_with_resilience(deliver=deliver, request_id="req-4"))
    assert attempts["n"] == 1, "60s timeout cannot fit in a 1s budget"


def test_rate_limited_then_success_closes_the_discarded_response() -> None:
    first = _SpyResponse(429, headers={"Retry-After": "1"}, json={"error": "slow down"})
    second = _ok()
    responses = [first, second]

    async def deliver() -> httpx.Response:
        return responses.pop(0)

    response = asyncio.run(send_with_resilience(deliver=deliver, request_id="req-5"))
    assert response is second
    assert first.close_calls == 1, "an abandoned response must be released"


def test_exhausted_retries_return_the_last_response_not_an_exception() -> None:
    """A 429 we cannot escape is still an answer: the caller maps it to a 502."""
    os.environ["SHADOW_AGENT_UPSTREAM_RETRY_MAX"] = "1"
    last = httpx.Response(429, headers={"Retry-After": "0"}, json={"error": "slow down"})

    async def deliver() -> httpx.Response:
        return last

    response = asyncio.run(send_with_resilience(deliver=deliver, request_id="req-6"))
    assert response is last


def test_retry_delay_honours_retry_after(_no_real_sleep: list[float]) -> None:
    os.environ["SHADOW_AGENT_UPSTREAM_RETRY_MAX"] = "1"
    responses = [
        httpx.Response(429, headers={"Retry-After": "1.25"}),
        _ok(),
    ]

    async def deliver() -> httpx.Response:
        return responses.pop(0)

    asyncio.run(send_with_resilience(deliver=deliver, request_id="req-7"))
    assert _no_real_sleep == [1.25]


# --- circuit breaker --------------------------------------------------------


def test_breaker_opens_after_threshold_and_fails_fast_with_retry_after() -> None:
    _failure_threshold_two()
    os.environ["SHADOW_AGENT_UPSTREAM_RETRY_MAX"] = "0"

    async def deliver() -> httpx.Response:
        raise httpx.ConnectError("refused")

    # The first failure is still reported as a transport error; the second one
    # crosses the threshold, so the caller learns the breaker is now open.
    with pytest.raises(httpx.ConnectError):
        asyncio.run(send_with_resilience(deliver=deliver, request_id="req-8a"))
    with pytest.raises(HTTPException) as tripped:
        asyncio.run(send_with_resilience(deliver=deliver, request_id="req-8b"))
    assert tripped.value.detail["error"] == "upstream_circuit_open"

    breaker = upstream_circuit_breaker()
    assert breaker.state_name() == CIRCUIT_STATE_OPEN

    async def _never_called() -> httpx.Response:  # pragma: no cover - must not run
        raise AssertionError("an open breaker must not reach the provider")

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(send_with_resilience(deliver=_never_called, request_id="req-9"))
    assert excinfo.value.status_code == 503
    assert excinfo.value.detail["error"] == "upstream_circuit_open"
    assert excinfo.value.headers["Retry-After"] == "60"


def test_circuit_opening_mid_call_stops_the_retry_chain() -> None:
    """Once this call trips the breaker, retrying is the hammering it prevents."""
    _failure_threshold_two()
    os.environ["SHADOW_AGENT_UPSTREAM_RETRY_MAX"] = "5"
    attempts = {"n": 0}

    async def deliver() -> httpx.Response:
        attempts["n"] += 1
        raise httpx.ConnectError("refused")

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(send_with_resilience(deliver=deliver, request_id="req-mid"))

    assert excinfo.value.status_code == 503
    assert attempts["n"] == 2, "the third attempt was cancelled, not spent"
    assert upstream_circuit_breaker().state_name() == CIRCUIT_STATE_OPEN


def test_success_resets_the_failure_streak() -> None:
    os.environ["SHADOW_AGENT_UPSTREAM_CIRCUIT_THRESHOLD"] = "3"
    os.environ["SHADOW_AGENT_UPSTREAM_RETRY_MAX"] = "0"
    breaker = upstream_circuit_breaker()

    async def failing() -> httpx.Response:
        raise httpx.ConnectError("refused")

    for _ in range(2):
        with pytest.raises(httpx.ConnectError):
            asyncio.run(send_with_resilience(deliver=failing, request_id="req-10"))

    async def succeeding() -> httpx.Response:
        return _ok()

    asyncio.run(send_with_resilience(deliver=succeeding, request_id="req-11"))
    assert breaker.state_name() == CIRCUIT_STATE_CLOSED

    # The streak restarted, so two more failures still do not open it.
    for _ in range(2):
        with pytest.raises(httpx.ConnectError):
            asyncio.run(send_with_resilience(deliver=failing, request_id="req-12"))
    assert breaker.state_name() == CIRCUIT_STATE_CLOSED


def test_half_open_probe_closes_the_breaker(monkeypatch) -> None:
    _failure_threshold_two()
    clock = {"t": 1000.0}
    monkeypatch.setattr(ur.time, "monotonic", lambda: clock["t"])
    breaker = upstream_circuit_breaker()

    for _ in range(2):
        breaker.record_failure()
    assert breaker.state_name() == CIRCUIT_STATE_OPEN

    clock["t"] += 60  # cooldown elapsed
    assert breaker.state_name() == CIRCUIT_STATE_HALF_OPEN

    breaker.acquire()  # reserves the single probe
    breaker.record_success()
    assert breaker.state_name() == CIRCUIT_STATE_CLOSED


def test_failed_probe_reopens_with_a_longer_cooldown(monkeypatch) -> None:
    _failure_threshold_two()
    clock = {"t": 1000.0}
    monkeypatch.setattr(ur.time, "monotonic", lambda: clock["t"])
    breaker = upstream_circuit_breaker()

    for _ in range(2):
        breaker.record_failure()
    assert breaker.retry_after_seconds() == 60.0

    clock["t"] += 60
    breaker.acquire()
    breaker.record_failure()  # the probe failed

    assert breaker.state_name() == CIRCUIT_STATE_OPEN
    assert breaker.retry_after_seconds() == 120.0, "cooldown doubles"
    assert breaker.open_total() == 2


def test_half_open_sheds_concurrent_requests() -> None:
    """Exactly one probe is allowed; the rest are shed instead of queued."""
    _failure_threshold_two()
    os.environ["SHADOW_AGENT_UPSTREAM_CIRCUIT_COOLDOWN_SECONDS"] = "0"
    breaker = upstream_circuit_breaker()

    for _ in range(2):
        breaker.record_failure()

    breaker.acquire()  # reserves the probe
    with pytest.raises(HTTPException) as excinfo:
        breaker.acquire()
    assert excinfo.value.status_code == 503
    assert "probing" in excinfo.value.detail["message"]


# --- trust_env --------------------------------------------------------------


def test_upstream_client_does_not_inherit_environment_proxies(monkeypatch) -> None:
    from app import upstream

    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setattr(upstream, "_upstream_client", None)

    client = upstream._get_upstream_client()
    try:
        assert client.trust_env is False
    finally:
        asyncio.run(client.aclose())
        monkeypatch.setattr(upstream, "_upstream_client", None)


def test_upstream_client_can_opt_into_environment_proxies(monkeypatch) -> None:
    from app import upstream

    monkeypatch.setenv("SHADOW_AGENT_UPSTREAM_TRUST_ENV", "true")
    monkeypatch.setattr(upstream, "_upstream_client", None)

    client = upstream._get_upstream_client()
    try:
        assert client.trust_env is True
    finally:
        asyncio.run(client.aclose())
        monkeypatch.setattr(upstream, "_upstream_client", None)


# --- integration with the forwarding paths ----------------------------------


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _FlakyHandler(BaseHTTPRequestHandler):
    """Fails the first ``fail_times`` calls with 429, then answers normally."""

    fail_times = 0
    calls = 0

    def do_POST(self) -> None:  # noqa: N802
        type(self).calls += 1
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        if type(self).calls <= type(self).fail_times:
            self.send_response(429)
            self.send_header("Retry-After", "0")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps(
            {
                "id": "flaky-ok",
                "object": "chat.completion",
                "model": "deepseek-flash",
                "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": "recovered"}}
                ],
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:  # keep pytest output clean
        return


def _start_flaky_server(fail_times: int) -> tuple[ThreadingHTTPServer, str, type]:
    handler = type("_Handler", (_FlakyHandler,), {"fail_times": fail_times, "calls": 0})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}", handler


def _forward(payload: dict) -> dict:
    from app.schemas import ChatCompletionRequest
    from app.upstream import _forward_to_upstream

    request = ChatCompletionRequest(**payload)
    return asyncio.run(
        _forward_to_upstream(
            request,
            request_id="integration",
            separated={"trusted_instruction": "", "untrusted_data": ""},
        )
    )


def test_forward_to_upstream_recovers_from_rate_limiting(monkeypatch) -> None:
    from app import upstream

    server, base_url, handler = _start_flaky_server(fail_times=2)
    monkeypatch.setenv("SHADOW_AGENT_UPSTREAM_BASE_URL", base_url)
    client = httpx.AsyncClient(timeout=5.0, trust_env=False)
    monkeypatch.setattr(upstream, "_get_upstream_client", lambda: client)
    try:
        result = _forward(payload={"model": "deepseek-flash", "messages": [{"role": "user", "content": "hi"}]})
    finally:
        asyncio.run(client.aclose())
        server.shutdown()

    assert handler.calls == 3, "two throttled attempts plus one success"
    assert result["choices"][0]["message"]["content"] == "recovered"


def test_forward_to_upstream_reports_a_dead_provider_as_502(monkeypatch) -> None:
    """A refused connection is retried, then surfaced as a transport failure."""
    from app import upstream

    monkeypatch.setenv("SHADOW_AGENT_UPSTREAM_BASE_URL", f"http://127.0.0.1:{_free_port()}")
    monkeypatch.setenv("SHADOW_AGENT_UPSTREAM_RETRY_MAX", "2")
    attempts = {"n": 0}
    real_client = httpx.AsyncClient(timeout=5.0, trust_env=False)

    class _CountingClient:
        def post(self, *args, **kwargs):
            attempts["n"] += 1
            return real_client.post(*args, **kwargs)

    monkeypatch.setattr(upstream, "_get_upstream_client", lambda: _CountingClient())
    try:
        with pytest.raises(HTTPException) as excinfo:
            _forward(payload={"model": "deepseek-flash", "messages": [{"role": "user", "content": "hi"}]})
    finally:
        asyncio.run(real_client.aclose())

    assert excinfo.value.status_code == 502
    assert excinfo.value.detail["error"] == "upstream_transport_error"
    assert attempts["n"] == 3


def test_metrics_expose_retries_and_breaker_state() -> None:
    from app.metrics import metrics_snapshot, record_upstream_retry, render_metrics

    before = metrics_snapshot()["upstream_retries"]
    record_upstream_retry(reason=RETRY_REASON_CONNECT)
    record_upstream_retry(reason=RETRY_REASON_RATE_LIMIT)
    record_upstream_retry(reason="unexpected-reason")
    after = metrics_snapshot()["upstream_retries"]

    # Counters are process-wide and other tests in this file also retry, so the
    # assertion is on the delta rather than an absolute value.
    assert after.get("connect", 0) == before.get("connect", 0) + 1
    assert after.get("rate_limit", 0) == before.get("rate_limit", 0) + 1
    assert after.get("other", 0) == before.get("other", 0) + 1, (
        "an unknown reason must collapse into the bounded label"
    )

    text = render_metrics()
    assert 'shadow_agent_upstream_retries_total{reason="connect"}' in text
    assert 'shadow_agent_upstream_retries_total{reason="server_error"}' in text
    assert 'shadow_agent_upstream_circuit_state{state="closed"} 1' in text
    assert "shadow_agent_upstream_circuit_opened_total" in text
