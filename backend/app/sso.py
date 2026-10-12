"""OIDC single sign-on (Authorization Code + PKCE) for organizations.

Flow
----
1. ``GET /api/v1/auth/sso/{org_slug}/login``
   Discovers the IdP endpoints from the org's ``SsoConnection.issuer_url``,
   stores a one-time ``state`` → {code_verifier, nonce, org_id} entry and
   redirects the browser to the IdP authorization endpoint with an S256
   PKCE challenge.
2. ``GET /api/v1/auth/sso/callback``
   Exchanges the authorization code at the token endpoint (client secret +
   PKCE verifier), verifies the returned ID token against the IdP JWKS
   (signature, issuer, audience, expiry, nonce), then:
   - matches the ``email`` claim to an existing console user, or
   - just-in-time provisions one when the connection allows it,
   - ensures the user is a member of the organization,
   - issues a console JWT carrying the org context and redirects to the
     console single-page callback: ``{console}/sso/callback#access_token=..``.

State entries are single-use and expire after 10 minutes; discovery documents
are cached per issuer for 5 minutes. PKCE makes the flow safe for public
clients; the client secret is only used server-side during code exchange.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt as pyjwt
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.auth_helpers import _normalize_console_role
from app.utils import _normalized_email
from database import get_db
from models import ConsoleUser, Organization, OrganizationMembership, SsoConnection
from security_controls import hash_password

logger = logging.getLogger("shadow_agent.sso")

router = APIRouter(prefix="/api/v1/auth/sso", tags=["sso"])

_STATE_TTL_SECONDS = 600
_DISCOVERY_TTL_SECONDS = 300
_ALLOWED_SIGNING_ALGORITHMS = ("RS256", "RS384", "ES256", "ES384")


@dataclass(slots=True)
class _PendingLogin:
    org_id: int
    code_verifier: str
    nonce: str
    redirect_uri: str
    created_at: float = field(default_factory=time.time)


_pending_states: dict[str, _PendingLogin] = {}
_discovery_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def _prune_expired_states() -> None:
    now = time.time()
    expired = [
        state for state, entry in _pending_states.items()
        if now - entry.created_at > _STATE_TTL_SECONDS
    ]
    for state in expired:
        _pending_states.pop(state, None)


def _env_text(name: str, default: str = "") -> str:
    import os

    value = os.getenv(name)
    return value.strip() if value and value.strip() else default


def _console_base_url() -> str:
    return _env_text("SHADOW_AGENT_CONSOLE_URL", "http://localhost:3000").rstrip("/")


def _public_base_url() -> str:
    return _env_text("SHADOW_AGENT_PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")


def _sso_callback_url() -> str:
    return f"{_public_base_url()}/api/v1/auth/sso/callback"


def _error_redirect(message: str, description: str = "") -> RedirectResponse:
    fragment = urlencode({"error": message, "error_description": description})
    return RedirectResponse(f"{_console_base_url()}/sso/callback#{fragment}")


def _load_enabled_connection(db: Session, org_slug: str) -> tuple[Organization, SsoConnection]:
    org = db.query(Organization).filter(Organization.slug == org_slug.strip().lower()).one_or_none()
    if org is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "sso_not_configured", "message": "No SSO connection is configured for that organization."},
        )
    connection = (
        db.query(SsoConnection)
        .filter(SsoConnection.org_id == org.id, SsoConnection.enabled.is_(True))
        .one_or_none()
    )
    if connection is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "sso_not_configured", "message": "No SSO connection is configured for that organization."},
        )
    return org, connection


async def _discover_issuer(issuer_url: str) -> dict[str, Any]:
    """Fetch (and cache) the OIDC discovery document for an issuer."""
    now = time.time()
    cached = _discovery_cache.get(issuer_url)
    if cached is not None and now - cached[0] < _DISCOVERY_TTL_SECONDS:
        return cached[1]

    discovery_url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(discovery_url)
            response.raise_for_status()
            document = response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail={
                "error": "sso_discovery_failed",
                "message": f"Could not fetch the identity provider discovery document: {exc}",
            },
        ) from exc

    for required in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not document.get(required):
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "sso_discovery_invalid",
                    "message": f"Discovery document is missing '{required}'.",
                },
            )

    _discovery_cache[issuer_url] = (now, document)
    return document


def _validate_id_token(
    id_token: str,
    *,
    connection: SsoConnection,
    document: dict[str, Any],
    expected_nonce: str,
) -> dict[str, Any]:
    """Verify the IdP-signed ID token; return its claims.

    Signature verification uses the IdP JWKS (asymmetric algorithms only);
    issuer, audience, expiry and nonce are all enforced.
    """
    jwks_client = pyjwt.PyJWKClient(document["jwks_uri"], cache_keys=True)
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        claims = pyjwt.decode(
            id_token,
            signing_key.key,
            algorithms=list(_ALLOWED_SIGNING_ALGORITHMS),
            audience=connection.client_id,
            issuer=connection.issuer_url.rstrip("/"),
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
        )
    except pyjwt.PyJWTError as exc:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "sso_invalid_id_token",
                "message": f"The identity provider returned an invalid ID token: {exc}",
            },
        ) from exc

    if claims.get("nonce") != expected_nonce:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "sso_invalid_nonce",
                "message": "ID token nonce mismatch (possible replay).",
            },
        )
    return claims


@router.get("/providers/{org_slug}")
async def get_sso_provider_status(
    org_slug: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Public login-page lookup: is SSO available for this organization?"""
    try:
        _, connection = _load_enabled_connection(db, org_slug)
    except HTTPException:
        return {"enabled": False, "provider_name": ""}
    return {
        "enabled": True,
        "provider_name": connection.provider_name,
        "login_url": f"/api/v1/auth/sso/{org_slug.strip().lower()}/login",
    }


@router.get("/{org_slug}/login")
async def start_sso_login(
    org_slug: str,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    """Redirect the browser to the organization's IdP authorization endpoint."""
    _, connection = _load_enabled_connection(db, org_slug)
    document = await _discover_issuer(connection.issuer_url)

    _prune_expired_states()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(24)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge_b64 = (
        base64.urlsafe_b64encode(code_challenge).decode("ascii").rstrip("=")
    )

    _pending_states[state] = _PendingLogin(
        org_id=connection.org_id,
        code_verifier=code_verifier,
        nonce=nonce,
        redirect_uri=_sso_callback_url(),
    )

    params = urlencode(
        {
            "response_type": "code",
            "client_id": connection.client_id,
            "redirect_uri": _sso_callback_url(),
            "scope": connection.scopes or "openid email profile",
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge_b64,
            "code_challenge_method": "S256",
        }
    )
    return RedirectResponse(f"{document['authorization_endpoint']}?{params}")


@router.get("/callback", response_model=None)
async def sso_callback(
    code: str = "",
    state: str = "",
    error: str = "",
    error_description: str = "",
    db: Session = Depends(get_db),
) -> JSONResponse | RedirectResponse:
    """Complete the OIDC flow and hand the session token to the console SPA."""
    if error:
        return _error_redirect(error or "sso_failed", error_description)
    if not code or not state:
        return _error_redirect("sso_missing_code", "The identity provider did not return an authorization code.")

    _prune_expired_states()
    pending = _pending_states.pop(state, None)
    if pending is None or time.time() - pending.created_at > _STATE_TTL_SECONDS:
        return _error_redirect("sso_invalid_state", "Unknown or expired login state; restart the login flow.")

    connection = (
        db.query(SsoConnection)
        .filter(SsoConnection.org_id == pending.org_id)
        .one_or_none()
    )
    if connection is None or not connection.enabled:
        return _error_redirect("sso_not_configured", "SSO is no longer enabled for this organization.")

    document = await _discover_issuer(connection.issuer_url)

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            token_response = await client.post(
                document["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": pending.redirect_uri,
                    "client_id": connection.client_id,
                    "client_secret": connection.client_secret,
                    "code_verifier": pending.code_verifier,
                },
                headers={"Accept": "application/json"},
            )
    except httpx.HTTPError as exc:
        logger.error("SSO token exchange failed: %s", exc)
        return _error_redirect("sso_token_exchange_failed", "Could not reach the identity provider token endpoint.")

    if token_response.is_error:
        logger.warning(
            "SSO token endpoint rejected the code: status=%s body=%s",
            token_response.status_code,
            token_response.text[:300],
        )
        return _error_redirect("sso_token_exchange_failed", "The identity provider rejected the authorization code.")

    try:
        token_payload = token_response.json()
    except ValueError:
        return _error_redirect("sso_token_exchange_failed", "Token endpoint returned a non-JSON response.")
    id_token = token_payload.get("id_token")
    if not isinstance(id_token, str) or not id_token:
        return _error_redirect("sso_missing_id_token", "Token response did not include an id_token.")

    try:
        claims = _validate_id_token(
            id_token,
            connection=connection,
            document=document,
            expected_nonce=pending.nonce,
        )
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        return _error_redirect("sso_invalid_id_token", str(detail.get("message", "")))

    email = _normalized_email(str(claims.get("email") or ""))
    if not email:
        return _error_redirect("sso_missing_email", "The ID token does not contain an email claim.")

    user = db.query(ConsoleUser).filter(ConsoleUser.email == email).one_or_none()
    if user is None:
        if not connection.jit_enabled:
            return _error_redirect(
                "sso_user_not_provisioned",
                "No console account exists for this email and just-in-time provisioning is disabled.",
            )
        display_name = str(
            claims.get("name") or claims.get("preferred_username") or email.split("@", 1)[0]
        )[:128]
        user = ConsoleUser(
            name=display_name,
            email=email,
            # SSO users authenticate via the IdP only; the local password is an
            # unguessable random value nobody is told.
            password_hash=hash_password(secrets.token_urlsafe(32)),
            role=_normalize_console_role(connection.default_role, "client"),
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info("SSO JIT-provisioned console user email=%s org_id=%s", email, pending.org_id)

    if not user.is_active:
        return _error_redirect("sso_user_inactive", "This console account has been deactivated.")

    membership = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.org_id == pending.org_id,
        )
        .one_or_none()
    )
    org_role = membership.role if membership else "member"
    if membership is None:
        db.add(
            OrganizationMembership(
                user_id=user.id,
                org_id=pending.org_id,
                role=org_role,
            )
        )

    from app.audit import _record_auth_event

    _record_auth_event(db, "sso_login_success", email)
    db.commit()

    from app.routers.auth import _auth_session_payload_for_org

    session = _auth_session_payload_for_org(user, db, pending.org_id, org_role)
    fragment = urlencode(
        {
            "access_token": session["access_token"],
            "expires_at": session["expires_at"],
            "token_type": session["token_type"],
        }
    )
    return RedirectResponse(f"{_console_base_url()}/sso/callback#{fragment}")
