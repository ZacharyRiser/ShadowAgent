"""Shared pytest fixtures for the Shadow Agent backend test suite.

Environment variables are pinned BEFORE importing ``main`` so every test run
uses an isolated temporary database and a local mock upstream instead of any
developer-configured provider.
"""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

# --- environment isolation (must precede `from main import app`) ---
os.environ["SHADOW_AGENT_ADMIN_API_KEY"] = "test-admin-key"
os.environ["SHADOW_AGENT_CLIENT_API_KEY"] = "test-client-key"
os.environ["SHADOW_AGENT_ALLOW_SIMULATED_RESPONSES"] = "true"
os.environ["SHADOW_AGENT_JWT_SECRET"] = "test-jwt-secret-value-32-characters-minimum"
os.environ["SHADOW_AGENT_API_KEY_PEPPER"] = "test-api-key-pepper-value-32-characters"
os.environ["SHADOW_AGENT_CONSOLE_BOOTSTRAP_TOKEN"] = "pytest-bootstrap-token"
os.environ["SHADOW_AGENT_LOGIN_MAX_FAILURES"] = "3"
os.environ["SHADOW_AGENT_LOGIN_LOCKOUT_SECONDS"] = "60"
# The whole suite shares one TestClient host, so the per-path rate limiter must
# not interfere with endpoint tests (login lockout has its own throttle).
os.environ["SHADOW_AGENT_RATE_LIMIT_PER_MINUTE"] = "10000"
os.environ["SHADOW_AGENT_LOG_RATE_LIMIT_PER_MINUTE"] = "10000"
# Pin the semantic layer to its production default so suite behavior is
# deterministic even when a developer's local .env selects another mode.
os.environ["SHADOW_AGENT_SEMANTIC_MODE"] = "enforce"
os.environ["SHADOW_AGENT_DATABASE_PATH"] = os.path.join(
    tempfile.gettempdir(),
    f"shadow-agent-pytest-{uuid.uuid4().hex}.db",
)
os.environ["SHADOW_AGENT_UPSTREAM_BASE_URL"] = ""

from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402


def _sse_chunk(delta: dict) -> bytes:
    event = {"id": "chunk", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": delta}]}
    return ("data: " + json.dumps(event) + "\n\n").encode("utf-8")


class MockUpstreamHandler(BaseHTTPRequestHandler):
    """Mock OpenAI-compatible upstream supporting normal and SSE responses."""

    captured_requests: list[dict] = []

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/chat/completions":
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
        self.__class__.captured_requests.append(payload)

        messages = payload.get("messages") or []
        wants_dlp_demo = any(
            "__dlp_demo__" in str(message.get("content", ""))
            for message in messages
            if isinstance(message, dict)
        )
        # Marker for "the model answers with a tool call whose arguments carry
        # a secret", so the DLP tool-argument path can be tested end to end.
        wants_tool_call_demo = any(
            "__tool_call_demo__" in str(message.get("content", ""))
            for message in messages
            if isinstance(message, dict)
        )

        if payload.get("stream"):
            if wants_tool_call_demo:
                # Arguments are split inside the key on purpose: the streaming
                # hold-back window must still catch the assembled secret.
                arguments = json.dumps(
                    {"path": "config.txt", "content": "key AKIAIOSFODNN7EXAMPLE"}
                )
                split_at = arguments.index("AKIA") + 4
                body = (
                    _sse_chunk(
                        {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {
                                        "name": "write_file",
                                        "arguments": arguments[:split_at],
                                    },
                                }
                            ]
                        }
                    )
                    + _sse_chunk(
                        {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "function": {"arguments": arguments[split_at:]},
                                }
                            ]
                        }
                    )
                    + b"data: [DONE]\n\n"
                )
            elif wants_dlp_demo:
                # The AWS key is split across chunk boundaries on purpose so
                # tests prove the streaming hold-back scanner still catches it.
                body = (
                    b'data: {"id":"c1","choices":[{"delta":{"content":"export: "}}]}\n\n'
                    b'data: {"id":"c2","choices":[{"delta":{"content":"AKIAIOSFODN"}}]}\n\n'
                    b'data: {"id":"c3","choices":[{"delta":{"content":"N7EXAMPLE ok"}}]}\n\n'
                    b"data: [DONE]\n\n"
                )
            else:
                body = (
                    b'data: {"id":"chunk-1","choices":[{"delta":{"content":"mock "}}]}\n\n'
                    b'data: {"id":"chunk-2","choices":[{"delta":{"content":"stream ok"}}]}\n\n'
                    b"data: [DONE]\n\n"
                )
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if wants_tool_call_demo:
            # A tool-calling assistant turn: content is null on the OpenAI wire.
            response_body = {
                "id": "mock-upstream-tool-call",
                "object": "chat.completion",
                "created": 1,
                "model": payload.get("model"),
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {
                                        "name": "write_file",
                                        "arguments": json.dumps(
                                            {
                                                "path": "config.txt",
                                                "content": "key AKIAIOSFODNN7EXAMPLE",
                                            }
                                        ),
                                    },
                                }
                            ],
                        },
                        "finish_reason": "tool_calls",
                    }
                ],
            }
            encoded = json.dumps(response_body).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            return

        if wants_dlp_demo:
            response_content = (
                "Config export: AKIAIOSFODNN7EXAMPLE and token "
                "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCDE plus key "
                "sk-proj-abcdefghij1234567890abcdefghij. Done."
            )
        else:
            response_content = "mock upstream ok"
        response_body = {
            "id": "mock-upstream-response",
            "object": "chat.completion",
            "created": 1,
            "model": payload.get("model"),
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": response_content},
                    "finish_reason": "stop",
                }
            ],
        }
        encoded = json.dumps(response_body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


_server = HTTPServer(("127.0.0.1", 0), MockUpstreamHandler)
Thread(target=_server.serve_forever, daemon=True).start()
os.environ["SHADOW_AGENT_UPSTREAM_BASE_URL"] = f"http://127.0.0.1:{_server.server_port}"
os.environ["SHADOW_AGENT_UPSTREAM_MODEL"] = "mock-upstream-model"

import pytest  # noqa: E402


@pytest.fixture(scope="session")
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(scope="session")
def admin_session(client: TestClient) -> tuple[str, str]:
    """Register the single bootstrap admin once per test session.

    The bootstrap gate closes after the first admin exists, so this fixture
    must be the ONLY bootstrap registration in the suite.
    """
    email = "root-admin-pytest@example.com"
    response = client.post(
        "/api/v1/auth/register",
        json={"name": "Pytest Root Admin", "email": email, "password": "pass-123456"},
        headers={
            "x-shadow-agent-bootstrap-token": os.environ[
                "SHADOW_AGENT_CONSOLE_BOOTSTRAP_TOKEN"
            ]
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["user"]["role"] == "admin"
    return body["access_token"], email


@pytest.fixture(scope="session")
def admin_auth(admin_session) -> dict[str, str]:
    token, _ = admin_session
    return {"authorization": f"Bearer {token}"}


@pytest.fixture
def client_headers() -> dict[str, str]:
    return {"x-api-key": "test-client-key"}


@pytest.fixture
def admin_headers() -> dict[str, str]:
    return {"x-api-key": "test-admin-key"}


@pytest.fixture
def unique_id() -> str:
    return uuid.uuid4().hex[:8]


def normal_payload() -> dict:
    return {
        "model": "shadow-agent-simulated",
        "messages": [
            {"role": "system", "content": "You are a security assistant."},
            {"role": "user", "content": "Summarize the search result."},
        ],
        "external_context": "<context>OAuth token rotation best practices.</context>",
        "tool_name": "search_web",
        "parameters": {"query": "OAuth token rotation"},
    }
