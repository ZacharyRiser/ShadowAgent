"""Docs / OpenAPI exposure is opt-in.

``/openapi.json`` is a complete route map -- including the admin-only endpoints
-- and ``/docs`` renders it as a clickable client. Nothing in the product needs
either at runtime, so they must not be served unless an operator asks for them.
These tests pin the default (off) and the parsing of the opt-in flag, then check
the running app really does 404.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import docs_urls


@pytest.fixture
def docs_flag(monkeypatch: pytest.MonkeyPatch):
    def _set(value: str | None) -> None:
        if value is None:
            monkeypatch.delenv("SHADOW_AGENT_DOCS_ENABLED", raising=False)
        else:
            monkeypatch.setenv("SHADOW_AGENT_DOCS_ENABLED", value)

    monkeypatch.delenv("SHADOW_AGENT_DOCS_ENABLED", raising=False)
    yield _set
    monkeypatch.delenv("SHADOW_AGENT_DOCS_ENABLED", raising=False)


def test_disabled_when_unset(docs_flag) -> None:
    docs_flag(None)
    assert docs_urls() == (None, None, None)


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on", " On "])
def test_enabled_values(docs_flag, value: str) -> None:
    docs_flag(value)
    assert docs_urls() == ("/docs", "/redoc", "/openapi.json")


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "", "banana"])
def test_stays_disabled_for_anything_else(docs_flag, value: str) -> None:
    docs_flag(value)
    assert docs_urls() == (None, None, None)


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_running_app_does_not_serve_them_by_default(client: TestClient, path: str) -> None:
    """Not 'served but hidden' -- the routes are never registered."""
    assert client.get(path).status_code == 404


def test_schema_is_still_available_to_the_application(client: TestClient) -> None:
    """Disabling the HTTP surface must not remove the schema itself.

    ``app.openapi()`` drives internal tooling (and the FastAPI test client's
    route introspection); only the public endpoints are gone.
    """
    from main import app

    schema = app.openapi()
    assert schema["openapi"].startswith("3.")
    assert "/api/v1/chat/completions" in schema["paths"]
