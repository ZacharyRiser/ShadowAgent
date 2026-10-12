"""OIDC SSO (Authorization Code + PKCE) tests against a local mock IdP.

The mock identity provider is a real threaded HTTP server that implements the
pieces the backend actually consumes:

- ``GET /.well-known/openid-configuration`` — discovery document
- ``GET /authorize`` — validates PKCE S256 params, issues a one-time code,
  redirects back to the backend callback
- ``POST /token`` — enforces client credentials AND the PKCE code_verifier,
  returns an RS256-signed ID token (nonce bound to the authorize request)
- ``GET /jwks.json`` — the signing key for ID token verification

Tests drive the full browser-side flow: backend login redirect -> IdP
authorize -> backend callback -> console fragment session.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Any
from urllib.parse import parse_qsl, quote, urlsplit

import httpx
import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient

# --- module-level RSA signing key (generated once per test session) ----------

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KID = "mock-idp-key-1"
_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_PEM = _PRIVATE_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode("ascii")


def _b64url_uint(value: int) -> str:
    byte_length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _jwk() -> dict[str, Any]:
    numbers = _PRIVATE_KEY.public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": KID,
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }


# --- mock IdP state (configurable per test) ----------------------------------

IDP: dict[str, Any] = {
    "base_url": "",
    "client_id": "mock-client",
    "client_secret": "mock-secret",
    "user": {"sub": "mock-sub-1", "email": "", "name": "Mock SSO User"},
    "nonce_override": None,   # set to tamper with the ID token nonce
    "reject_verifier": False, # set to make the token endpoint reject PKCE
    "codes": {},              # code -> {challenge, nonce, redirect_uri, client_id}
    "last_token_request": {}, # captured backend token exchange params
}


class _MockIdPHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        base = IDP["base_url"]

        if parsed.path == "/.well-known/openid-configuration":
            self._send_json(
                200,
                {
                    "issuer": base,
                    "authorization_endpoint": f"{base}/authorize",
                    "token_endpoint": f"{base}/token",
                    "jwks_uri": f"{base}/jwks.json",
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
            )
            return

        if parsed.path == "/jwks.json":
            self._send_json(200, {"keys": [_jwk()]})
            return

        if parsed.path == "/authorize":
            params = dict(parse_qsl(parsed.query))
            required = (
                "response_type",
                "client_id",
                "redirect_uri",
                "state",
                "nonce",
                "code_challenge",
                "code_challenge_method",
            )
            if any(not params.get(name) for name in required):
                self._send_json(400, {"error": "invalid_request"})
                return
            if params["response_type"] != "code" or params["code_challenge_method"] != "S256":
                self._send_json(400, {"error": "unsupported_response_type"})
                return

            code = secrets.token_urlsafe(16)
            IDP["codes"][code] = {
                "challenge": params["code_challenge"],
                "nonce": params["nonce"],
                "redirect_uri": params["redirect_uri"],
                "client_id": params["client_id"],
            }
            separator = "&" if "?" in params["redirect_uri"] else "?"
            self._redirect(
                f'{params["redirect_uri"]}{separator}'
                f'code={quote(code)}&state={quote(params["state"])}'
            )
            return

        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path != "/token":
            self._send_json(404, {"error": "not_found"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        form = dict(parse_qsl(self.rfile.read(length).decode("utf-8")))
        IDP["last_token_request"] = form

        if form.get("grant_type") != "authorization_code":
            self._send_json(400, {"error": "unsupported_grant_type"})
            return
        issued = IDP["codes"].pop(form.get("code", ""), None)
        if issued is None:
            self._send_json(400, {"error": "invalid_grant"})
            return
        if (
            form.get("client_id") != IDP["client_id"]
            or form.get("client_secret") != IDP["client_secret"]
        ):
            self._send_json(401, {"error": "invalid_client"})
            return

        verifier = form.get("code_verifier", "")
        computed = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
            .decode("ascii")
            .rstrip("=")
        )
        if IDP["reject_verifier"] or not verifier or computed != issued["challenge"]:
            self._send_json(
                400,
                {"error": "invalid_grant", "error_description": "PKCE verification failed"},
            )
            return

        now = int(time.time())
        user = IDP["user"]
        claims = {
            "iss": IDP["base_url"],
            "sub": user["sub"],
            "aud": IDP["client_id"],
            "exp": now + 300,
            "iat": now,
            "nonce": IDP["nonce_override"] or issued["nonce"],
            "email": user["email"],
            "email_verified": True,
            "name": user["name"],
        }
        id_token = pyjwt.encode(claims, PRIVATE_PEM, algorithm="RS256", headers={"kid": KID})
        self._send_json(
            200,
            {"access_token": "mock-access-token", "id_token": id_token, "token_type": "Bearer"},
        )

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


_idp_server = HTTPServer(("127.0.0.1", 0), _MockIdPHandler)
Thread(target=_idp_server.serve_forever, daemon=True).start()
IDP["base_url"] = f"http://127.0.0.1:{_idp_server.server_port}"

from app import sso as sso_module  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_sso_state() -> Any:
    """Isolate SSO module state and mock IdP configuration per test."""
    IDP["codes"].clear()
    IDP["last_token_request"] = {}
    IDP["nonce_override"] = None
    IDP["reject_verifier"] = False
    IDP["user"] = {
        "sub": f"mock-sub-{uuid.uuid4().hex[:8]}",
        "email": f"sso-{uuid.uuid4().hex[:10]}@example.com",
        "name": "Mock SSO User",
    }
    sso_module._pending_states.clear()
    sso_module._discovery_cache.clear()
    yield
    IDP["codes"].clear()
    sso_module._pending_states.clear()
    sso_module._discovery_cache.clear()


# --- helpers ------------------------------------------------------------------


def _upsert_sso(
    client: TestClient,
    admin_headers: dict[str, str],
    org_id: int,
    **overrides: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "provider_name": "Mock IdP",
        "client_id": IDP["client_id"],
        "client_secret": IDP["client_secret"],
        "issuer_url": IDP["base_url"],
        "scopes": "openid email profile",
        "jit_enabled": True,
        "default_role": "admin",
        "enabled": True,
    }
    payload.update(overrides)
    response = client.put(f"/api/v1/orgs/{org_id}/sso", headers=admin_headers, json=payload)
    assert response.status_code == 200, response.text
    return response.json()["item"]


def _create_org_with_sso(
    client: TestClient,
    admin_headers: dict[str, str],
    slug: str,
    **sso_overrides: Any,
) -> dict[str, Any]:
    response = client.post(
        "/api/v1/orgs", headers=admin_headers, json={"slug": slug, "name": slug.replace("-", " ")}
    )
    assert response.status_code == 200, response.text
    org = response.json()["item"]
    _upsert_sso(client, admin_headers, org["id"], **sso_overrides)
    return org


def _start_login(client: TestClient, org_slug: str) -> str:
    """Backend login endpoint -> IdP authorize URL (no redirect following)."""
    response = client.get(f"/api/v1/auth/sso/{org_slug}/login", follow_redirects=False)
    assert response.status_code == 307, response.text
    return response.headers["location"]


def _authorize_at_idp(authorize_url: str) -> str:
    """Simulate the browser + IdP: authorize URL -> backend callback URL."""
    response = httpx.get(authorize_url, follow_redirects=False)
    assert response.status_code == 302, response.text
    return response.headers["location"]


def _finish_flow(client: TestClient, callback_url: str) -> dict[str, str]:
    """Backend callback -> console SPA fragment (access token or error)."""
    response = client.get(callback_url, follow_redirects=False)
    assert response.status_code in (302, 307), response.text
    location = response.headers["location"]
    assert "/sso/callback#" in location, location
    return dict(parse_qsl(urlsplit(location).fragment))


def _run_sso_flow(client: TestClient, org_slug: str) -> dict[str, str]:
    callback_url = _authorize_at_idp(_start_login(client, org_slug))
    return _finish_flow(client, callback_url)


# --- provider status (public login-page lookup) -------------------------------


def test_provider_status_public_lookup(
    client: TestClient, admin_headers: dict[str, str], unique_id: str
) -> None:
    # unknown organization
    body = client.get(f"/api/v1/auth/sso/providers/ghost-{unique_id}").json()
    assert body == {"enabled": False, "provider_name": ""}

    # organization without a configured connection
    response = client.post(
        "/api/v1/orgs", headers=admin_headers, json={"slug": f"nosso-{unique_id}", "name": "No SSO"}
    )
    org_id = response.json()["item"]["id"]
    body = client.get(f"/api/v1/auth/sso/providers/nosso-{unique_id}").json()
    assert body["enabled"] is False

    # configured organization
    _upsert_sso(client, admin_headers, org_id)
    body = client.get(f"/api/v1/auth/sso/providers/nosso-{unique_id}").json()
    assert body["enabled"] is True
    assert body["provider_name"] == "Mock IdP"
    assert body["login_url"] == f"/api/v1/auth/sso/nosso-{unique_id}/login"


# --- login redirect (discovery + PKCE) ----------------------------------------


def test_login_redirect_uses_discovery_and_pkce(
    client: TestClient, admin_headers: dict[str, str], unique_id: str
) -> None:
    _create_org_with_sso(client, admin_headers, f"pkce-{unique_id}")

    authorize_url = _start_login(client, f"pkce-{unique_id}")
    assert authorize_url.startswith(f"{IDP['base_url']}/authorize?")

    params = dict(parse_qsl(urlsplit(authorize_url).query))
    assert params["response_type"] == "code"
    assert params["client_id"] == IDP["client_id"]
    assert params["redirect_uri"].endswith("/api/v1/auth/sso/callback")
    assert "openid" in params["scope"]
    assert params["code_challenge_method"] == "S256"
    # S256 challenge: base64url(sha256(verifier)) without padding, 43 chars
    assert len(params["code_challenge"]) == 43
    assert "=" not in params["code_challenge"]
    assert len(params["state"]) >= 32
    assert len(params["nonce"]) >= 16


def test_login_for_unconfigured_or_disabled_org(
    client: TestClient, admin_headers: dict[str, str], unique_id: str
) -> None:
    # unknown organization slug
    response = client.get(
        f"/api/v1/auth/sso/ghost-{unique_id}/login", follow_redirects=False
    )
    assert response.status_code == 404

    # organization without SSO
    response = client.post(
        "/api/v1/orgs", headers=admin_headers, json={"slug": f"plain-{unique_id}", "name": "Plain"}
    )
    org_id = response.json()["item"]["id"]
    response = client.get(
        f"/api/v1/auth/sso/plain-{unique_id}/login", follow_redirects=False
    )
    assert response.status_code == 404

    # disabled connection
    _upsert_sso(client, admin_headers, org_id, enabled=False)
    response = client.get(
        f"/api/v1/auth/sso/plain-{unique_id}/login", follow_redirects=False
    )
    assert response.status_code == 404


# --- full flow -----------------------------------------------------------------


def test_full_flow_jit_provisions_user_and_org_membership(
    client: TestClient, admin_headers: dict[str, str], unique_id: str
) -> None:
    org = _create_org_with_sso(client, admin_headers, f"acme-{unique_id}")
    email = IDP["user"]["email"]

    fragment = _run_sso_flow(client, f"acme-{unique_id}")
    assert fragment.get("token_type") == "bearer"
    assert fragment.get("access_token")
    assert fragment.get("expires_at")

    # the backend must have exchanged the code with secret + PKCE verifier
    token_request = IDP["last_token_request"]
    assert token_request["grant_type"] == "authorization_code"
    assert token_request["client_id"] == IDP["client_id"]
    assert token_request["client_secret"] == IDP["client_secret"]
    assert token_request["code_verifier"]

    # the fragment token is a working console session in the org context
    auth = {"authorization": f"Bearer {fragment['access_token']}"}
    me = client.get("/api/v1/auth/me", headers=auth).json()
    assert me["user"]["email"] == email
    assert me["user"]["role"] == "admin"  # from the connection default_role
    assert me["org_id"] == org["id"]
    assert me["org_role"] == "member"
    assert any(item["id"] == org["id"] for item in me["orgs"])

    # JIT membership is visible to the platform admin
    members = client.get(f"/api/v1/orgs/{org['id']}/members", headers=admin_headers).json()["items"]
    assert any(item["email"] == email and item["org_role"] == "member" for item in members)


def test_full_flow_matches_existing_console_user(
    client: TestClient,
    admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    unique_id: str,
) -> None:
    org = _create_org_with_sso(client, admin_headers, f"match-{unique_id}")

    # pre-register a console user with the same email the IdP will assert
    email = f"existing-{unique_id}@example.com"
    monkeypatch.setenv("SHADOW_AGENT_CONSOLE_INVITE_TOKEN", "sso-invite-token")
    monkeypatch.setenv("SHADOW_AGENT_CONSOLE_DEFAULT_ROLE", "client")
    registered = client.post(
        "/api/v1/auth/register",
        json={"name": "Existing User", "email": email, "password": "pass-123456"},
        headers={"x-shadow-agent-invite-token": "sso-invite-token"},
    ).json()
    user_id = registered["user"]["id"]

    IDP["user"]["email"] = email
    fragment = _run_sso_flow(client, f"match-{unique_id}")
    assert fragment.get("access_token")

    me = client.get(
        "/api/v1/auth/me", headers={"authorization": f"Bearer {fragment['access_token']}"}
    ).json()
    # linked to the EXISTING account (no duplicate), platform role preserved
    assert me["user"]["id"] == user_id
    assert me["user"]["role"] == "client"
    assert me["org_id"] == org["id"]


def test_inactive_user_cannot_sso(
    client: TestClient,
    admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    unique_id: str,
) -> None:
    _create_org_with_sso(client, admin_headers, f"inactive-{unique_id}")

    email = f"disabled-{unique_id}@example.com"
    monkeypatch.setenv("SHADOW_AGENT_CONSOLE_INVITE_TOKEN", "sso-invite-token")
    client.post(
        "/api/v1/auth/register",
        json={"name": "Disabled User", "email": email, "password": "pass-123456"},
        headers={"x-shadow-agent-invite-token": "sso-invite-token"},
    )

    from database import SessionLocal
    from models import ConsoleUser

    db = SessionLocal()
    try:
        db.query(ConsoleUser).filter(ConsoleUser.email == email).update({"is_active": False})
        db.commit()
    finally:
        db.close()

    IDP["user"]["email"] = email
    fragment = _run_sso_flow(client, f"inactive-{unique_id}")
    assert fragment.get("error") == "sso_user_inactive"
    assert "access_token" not in fragment


# --- callback hardening ---------------------------------------------------------


def test_state_is_single_use(
    client: TestClient, admin_headers: dict[str, str], unique_id: str
) -> None:
    _create_org_with_sso(client, admin_headers, f"replay-{unique_id}")

    authorize_url = _start_login(client, f"replay-{unique_id}")
    callback_url = _authorize_at_idp(authorize_url)

    first = _finish_flow(client, callback_url)
    assert first.get("access_token")

    # replaying the same callback (same code + state) must fail
    replay = _finish_flow(client, callback_url)
    assert replay.get("error") == "sso_invalid_state"
    assert "access_token" not in replay

    # unknown / forged state
    forged = _finish_flow(
        client, "http://localhost:8000/api/v1/auth/sso/callback?code=x&state=forged"
    )
    assert forged.get("error") == "sso_invalid_state"


def test_idp_error_and_missing_params_passthrough(client: TestClient) -> None:
    response = client.get(
        "/api/v1/auth/sso/callback?error=access_denied&error_description=user+cancelled",
        follow_redirects=False,
    )
    assert response.status_code in (302, 307)
    fragment = dict(parse_qsl(urlsplit(response.headers["location"]).fragment))
    assert fragment["error"] == "access_denied"
    assert fragment["error_description"] == "user cancelled"

    fragment = _finish_flow(client, "http://localhost:8000/api/v1/auth/sso/callback?state=abc")
    assert fragment["error"] == "sso_missing_code"


def test_jit_disabled_rejects_unknown_user(
    client: TestClient, admin_headers: dict[str, str], unique_id: str
) -> None:
    _create_org_with_sso(client, admin_headers, f"nojit-{unique_id}", jit_enabled=False)

    fragment = _run_sso_flow(client, f"nojit-{unique_id}")
    assert fragment.get("error") == "sso_user_not_provisioned"
    assert "access_token" not in fragment


def test_wrong_nonce_rejected(
    client: TestClient, admin_headers: dict[str, str], unique_id: str
) -> None:
    _create_org_with_sso(client, admin_headers, f"nonce-{unique_id}")
    IDP["nonce_override"] = "tampered-nonce"

    fragment = _run_sso_flow(client, f"nonce-{unique_id}")
    assert fragment.get("error") == "sso_invalid_id_token"
    assert "access_token" not in fragment


def test_pkce_verifier_enforced_by_idp(
    client: TestClient, admin_headers: dict[str, str], unique_id: str
) -> None:
    _create_org_with_sso(client, admin_headers, f"pkcefail-{unique_id}")
    IDP["reject_verifier"] = True

    fragment = _run_sso_flow(client, f"pkcefail-{unique_id}")
    assert fragment.get("error") == "sso_token_exchange_failed"
    # the backend did send a verifier; the IdP rejected it on purpose
    assert IDP["last_token_request"].get("code_verifier")


# --- SSO connection management API ----------------------------------------------


def test_sso_config_management_and_secret_masking(
    client: TestClient, admin_headers: dict[str, str], unique_id: str
) -> None:
    response = client.post(
        "/api/v1/orgs",
        headers=admin_headers,
        json={"slug": f"ssocfg-{unique_id}", "name": "SSO Config"},
    )
    org_id = response.json()["item"]["id"]

    # no connection yet
    assert client.get(f"/api/v1/orgs/{org_id}/sso", headers=admin_headers).json()["item"] is None

    created = _upsert_sso(client, admin_headers, org_id)
    assert created["provider_name"] == "Mock IdP"
    assert created["client_id"] == IDP["client_id"]
    assert created["jit_enabled"] is True
    assert created["enabled"] is True
    # the secret never leaves the API — only a masked hint
    assert "client_secret" not in created
    assert created["client_secret_masked"].endswith(IDP["client_secret"][-4:])

    updated = _upsert_sso(client, admin_headers, org_id, provider_name="Corporate IdP")
    assert updated["provider_name"] == "Corporate IdP"

    deleted = client.delete(f"/api/v1/orgs/{org_id}/sso", headers=admin_headers)
    assert deleted.status_code == 200
    assert client.get(f"/api/v1/orgs/{org_id}/sso", headers=admin_headers).json()["item"] is None
    # and the public login lookup is disabled again
    body = client.get(f"/api/v1/auth/sso/providers/ssocfg-{unique_id}").json()
    assert body["enabled"] is False
