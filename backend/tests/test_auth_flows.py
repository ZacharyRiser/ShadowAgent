"""Console auth flows, registration policy, and managed API key lifecycle.

NOTE: registration tests depend on execution order — the session-scoped
``admin_session`` fixture performs the ONLY bootstrap registration, and
``test_register_requires_bootstrap_token`` must run before it is triggered
(pytest default collection order guarantees this within this file).
"""

from __future__ import annotations

import os

from fastapi.testclient import TestClient


def _register(client: TestClient, email: str, password: str, headers: dict | None = None):
    return client.post(
        "/api/v1/auth/register",
        json={"name": "Pytest User", "email": email, "password": password},
        headers=headers or {},
    )


def test_bootstrap_status(client: TestClient):
    response = client.get("/api/v1/auth/bootstrap-status")
    assert response.status_code == 200


def test_register_requires_bootstrap_token(client: TestClient, unique_id: str):
    """Must run before admin_session triggers the first bootstrap registration."""
    response = _register(client, f"no-bootstrap-{unique_id}@example.com", "pass-123456")
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "bootstrap_token_required"


def test_bootstrap_register_creates_admin(client: TestClient, admin_session):
    token, email = admin_session
    me = client.get("/api/v1/auth/me", headers={"authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["user"]["email"] == email
    assert me.json()["user"]["role"] == "admin"


def test_second_register_rejected_then_invite(
    client: TestClient, admin_session, unique_id: str, monkeypatch
):
    email = f"client-{unique_id}@example.com"
    blocked = _register(client, email, "pass-123456")
    assert blocked.status_code == 403
    assert blocked.json()["detail"]["error"] == "registration_disabled"

    monkeypatch.setenv("SHADOW_AGENT_CONSOLE_INVITE_TOKEN", f"invite-{unique_id}")
    wrong = _register(
        client, email, "pass-123456", {"x-shadow-agent-invite-token": "wrong"}
    )
    assert wrong.status_code == 403

    ok = _register(
        client,
        email,
        "pass-123456",
        {"x-shadow-agent-invite-token": f"invite-{unique_id}"},
    )
    assert ok.status_code == 200
    assert ok.json()["user"]["role"] == "client"


def test_login_and_me(client: TestClient, admin_session):
    _, email = admin_session

    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "pass-123456"},
    )
    assert login.status_code == 200
    assert login.json()["access_token"]

    me = client.get(
        "/api/v1/auth/me",
        headers={"authorization": f"Bearer {login.json()['access_token']}"},
    )
    assert me.status_code == 200
    assert me.json()["user"]["email"] == email


def test_login_wrong_password(client: TestClient, admin_session):
    _, email = admin_session
    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "wrong-password"},
    )
    assert response.status_code == 401


def test_managed_api_key_lifecycle(client: TestClient, admin_auth: dict, unique_id: str):
    created = client.post(
        "/api/v1/api-keys",
        json={"name": f"key-{unique_id}", "role": "admin", "expires_in_days": 7},
        headers=admin_auth,
    )
    assert created.status_code == 200
    key_id = created.json()["item"]["id"]
    raw_key = created.json()["api_key"]
    assert raw_key.startswith("sak_adm_")
    assert created.json()["item"]["masked_key"] != raw_key

    analyze = client.post(
        "/api/v1/analyze",
        json={"prompt": "safe", "tool_name": "search_web"},
        headers={"x-api-key": raw_key},
    )
    assert analyze.status_code == 200
    assert analyze.json()["decision"] == "allowed"

    rotated = client.post(
        f"/api/v1/api-keys/{key_id}/rotate", json={}, headers=admin_auth
    )
    assert rotated.status_code == 200
    new_key = rotated.json()["api_key"]
    assert new_key != raw_key

    old_rejected = client.get(
        "/api/v1/logs?limit=1", headers={"x-api-key": raw_key}
    )
    assert old_rejected.status_code == 401

    new_accepted = client.get(
        "/api/v1/logs?limit=1", headers={"x-api-key": new_key}
    )
    assert new_accepted.status_code == 200

    revoked = client.post(f"/api/v1/api-keys/{key_id}/revoke", headers=admin_auth)
    assert revoked.status_code == 200
    assert revoked.json()["item"]["is_active"] is False

    revoked_rejected = client.get(
        "/api/v1/logs?limit=1", headers={"x-api-key": new_key}
    )
    assert revoked_rejected.status_code == 401

    deleted = client.delete(f"/api/v1/api-keys/{key_id}", headers=admin_auth)
    assert deleted.status_code == 200


def test_client_key_cannot_read_admin_logs(client: TestClient, admin_auth: dict, unique_id: str):
    created = client.post(
        "/api/v1/api-keys",
        json={"name": f"cli-{unique_id}", "role": "client"},
        headers=admin_auth,
    )
    raw_key = created.json()["api_key"]

    response = client.get("/api/v1/logs?limit=1", headers={"x-api-key": raw_key})
    assert response.status_code == 403


def test_unauthenticated_requests_rejected(client: TestClient):
    assert client.get("/api/v1/logs").status_code == 401
    assert client.get("/api/v1/policies").status_code == 401
    assert client.get("/api/v1/api-keys").status_code == 401
    assert client.get("/api/v1/approvals").status_code == 401
    assert client.get("/api/v1/alerts").status_code == 401
    assert client.get("/api/v1/replays").status_code == 401


def test_health(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
