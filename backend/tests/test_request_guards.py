"""Body-size guard: the ceiling, both enforcement paths, and its metrics.

Two properties matter and are tested separately: an honest oversized request is
refused from ``Content-Length`` alone, and a client that omits or understates
that header is still stopped by counting the bytes that actually arrive. Only
testing the first would leave the guard trivially bypassable with chunked
encoding -- which is precisely how an attacker would send it.
"""

from __future__ import annotations

import asyncio
import json
import logging

import pytest
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.metrics import metrics_snapshot
from app.request_guards import (
    DEFAULT_MAX_BODY_BYTES,
    BodySizeLimitMiddleware,
    max_body_bytes,
)
from conftest import normal_payload

_SMALL_LIMIT = "256"


def _post_chat(client: TestClient, headers: dict, **kwargs):
    response = client.post("/api/v1/chat/completions", headers=headers, **kwargs)
    return response


# --- configuration ----------------------------------------------------------


def test_default_limit_is_two_mib(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SHADOW_AGENT_MAX_BODY_BYTES", raising=False)
    assert max_body_bytes() == DEFAULT_MAX_BODY_BYTES == 2 * 1024 * 1024


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("1024", 1024),
        ("0", 0),
        ("-5", 0),
        ("", DEFAULT_MAX_BODY_BYTES),
        ("banana", DEFAULT_MAX_BODY_BYTES),
    ],
)
def test_limit_parsing_and_fallbacks(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: int
) -> None:
    monkeypatch.setenv("SHADOW_AGENT_MAX_BODY_BYTES", raw)
    assert max_body_bytes() == expected


def test_unparseable_value_warns_before_falling_back(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("SHADOW_AGENT_MAX_BODY_BYTES", "2MB")
    with caplog.at_level(logging.WARNING, logger="shadow_agent.gateway"):
        assert max_body_bytes() == DEFAULT_MAX_BODY_BYTES
    assert any("Invalid SHADOW_AGENT_MAX_BODY_BYTES" in r.message for r in caplog.records)


# --- enforcement ------------------------------------------------------------


def test_body_under_the_limit_is_untouched(
    client: TestClient, client_headers: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SHADOW_AGENT_MAX_BODY_BYTES", "1000000")
    response = _post_chat(client, client_headers, json=normal_payload())
    assert response.status_code == 200


def test_request_without_a_body_is_unaffected(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SHADOW_AGENT_MAX_BODY_BYTES", "16")
    assert client.get("/health").status_code == 200


def test_declared_oversized_body_is_rejected_before_being_read(
    client: TestClient, client_headers: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SHADOW_AGENT_MAX_BODY_BYTES", _SMALL_LIMIT)
    before = metrics_snapshot()["body_rejected"].get("declared", 0)

    response = _post_chat(client, client_headers, json=normal_payload())

    assert response.status_code == 413
    body = response.json()
    assert body["error"] == "payload_too_large"
    assert body["max_body_bytes"] == int(_SMALL_LIMIT)
    assert body["observed_bytes"] > int(_SMALL_LIMIT)
    assert metrics_snapshot()["body_rejected"].get("declared", 0) == before + 1


def test_chunked_body_without_content_length_is_still_capped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The path an attacker actually uses: no declared length to check.

    Driven at the ASGI level rather than through the test client. httpx's sync
    client cannot stream a generator request body into Starlette's in-process
    transport -- it arrives empty and FastAPI answers 400 before any guard runs,
    which would make this test pass for the wrong reason. Feeding the middleware
    the ``receive`` callbacks directly is what the guard actually sees, so this
    is the honest place to assert it.
    """
    monkeypatch.setenv("SHADOW_AGENT_MAX_BODY_BYTES", _SMALL_LIMIT)
    before = metrics_snapshot()["body_rejected"].get("actual", 0)

    status, counted = asyncio.run(_drive_chunked_upload(chunk_size=64))

    assert status == 413
    assert counted > int(_SMALL_LIMIT)
    assert metrics_snapshot()["body_rejected"].get("actual", 0) == before + 1


async def _drive_chunked_upload(*, chunk_size: int) -> tuple[int, int]:
    """Run the middleware over a body split into chunks, no Content-Length.

    Returns ``(status, bytes_counted)`` -- ``bytes_counted`` is how much of the
    body the counter actually saw before it refused the request.
    """
    payload = json.dumps(normal_payload()).encode("utf-8")
    chunks = [payload[i : i + chunk_size] for i in range(0, len(payload), chunk_size)]
    pending = list(chunks)
    read = 0

    async def receive():
        nonlocal read
        if pending:
            chunk = pending.pop(0)
            read += len(chunk)
            return {"type": "http.request", "body": chunk, "more_body": bool(pending)}
        return {"type": "http.request", "body": b"", "more_body": False}

    sent: list[dict] = []

    async def send(message: dict) -> None:
        sent.append(message)

    async def reading_app(scope, inner_receive, inner_send) -> None:
        """Consume the whole body, then answer 200 -- i.e. a real handler."""
        while True:
            message = await inner_receive()
            if message["type"] != "http.request" or not message.get("more_body"):
                break
        await JSONResponse({"ok": True})(scope, inner_receive, inner_send)

    scope = {"type": "http", "method": "POST", "path": "/x", "headers": []}
    await BodySizeLimitMiddleware(reading_app)(scope, receive, send)

    starts = [message for message in sent if message["type"] == "http.response.start"]
    assert starts, "the middleware never produced a response"
    return starts[0]["status"], read


def test_rejection_is_readable_from_a_browser_origin(
    client: TestClient, client_headers: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CORS has to wrap the guard, or a browser sees an opaque network error."""
    monkeypatch.setenv("SHADOW_AGENT_MAX_BODY_BYTES", _SMALL_LIMIT)
    response = _post_chat(
        client,
        {**client_headers, "origin": "http://localhost:3000"},
        json=normal_payload(),
    )
    assert response.status_code == 413
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"


def test_zero_disables_the_guard(
    client: TestClient, client_headers: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SHADOW_AGENT_MAX_BODY_BYTES", "0")
    assert _post_chat(client, client_headers, json=normal_payload()).status_code == 200


def test_metrics_expose_the_rejection_counter(
    client: TestClient, client_headers: dict, admin_headers: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SHADOW_AGENT_MAX_BODY_BYTES", _SMALL_LIMIT)
    _post_chat(client, client_headers, json=normal_payload())

    text = client.get("/metrics", headers=admin_headers).text
    assert "shadow_agent_body_rejected_total" in text
    assert 'shadow_agent_body_rejected_total{reason="declared"}' in text
