"""Authentication, rate limiting, and redaction helpers for Shadow Agent."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import jwt as pyjwt

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security.utils import get_authorization_scheme_param

from database import SessionLocal
from models import ConsoleUser, ManagedApiKey

logger = logging.getLogger("shadow_agent.security")


ADMIN_ROLES = {"admin", "security_admin"}
CLIENT_ROLES = ADMIN_ROLES | {"client", "gateway"}
SENSITIVE_KEYS = {
    "access_token",
    "api_key",
    "authorization",
    "cookie",
    "password",
    "refresh_token",
    "secret",
    "token",
}
SENSITIVE_TEXT_PATTERNS = [
    re.compile(
        r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password)"
        r"\s*[:=]\s*['\"]?([^\s,'\"}]+)"
    ),
    re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{12,}"),
]
REQUEST_ID_PATTERN = re.compile(r"[^a-zA-Z0-9_.:-]")
PASSWORD_HASH_ITERATIONS = 120_000
MANAGED_API_KEY_PREFIX = "sak"


@dataclass(frozen=True, slots=True)
class Principal:
    """Authenticated caller.

    ``org_id`` / ``org_role`` carry the active tenant context: console JWTs
    always include the organization the user switched into, managed API keys
    resolve to the organization that owns them. ``org_id is None`` marks a
    *platform* principal (static env keys, platform-managed keys) which keeps
    pre-tenancy, see-everything behavior.
    """

    subject: str
    role: str
    auth_method: str
    org_id: int | None = None
    org_role: str | None = None


class InMemoryRateLimiter:
    """Small fixed-window limiter for local/prototype deployments."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        now = time.monotonic()
        bucket = self._hits[key]
        while bucket and now - bucket[0] > window_seconds:
            bucket.popleft()

        if len(bucket) >= limit:
            retry_after = max(1, int(window_seconds - (now - bucket[0])))
            return False, retry_after

        bucket.append(now)
        return True, 0


class InMemoryLoginThrottle:
    """Track failed console logins per account to slow brute-force attacks."""

    def __init__(self) -> None:
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, key: str, now: float, window_seconds: float) -> None:
        bucket = self._failures[key]
        while bucket and now - bucket[0] > window_seconds:
            bucket.popleft()

    def locked_out_remaining(
        self,
        key: str,
        *,
        max_failures: int,
        window_seconds: float,
    ) -> int:
        now = time.monotonic()
        self._prune(key, now, window_seconds)
        bucket = self._failures[key]
        if len(bucket) >= max(1, max_failures):
            return max(1, int(window_seconds - (now - bucket[0])))
        return 0

    def record_failure(self, key: str, *, window_seconds: float) -> None:
        now = time.monotonic()
        self._prune(key, now, window_seconds)
        self._failures[key].append(now)

    def record_success(self, key: str) -> None:
        self._failures.pop(key, None)


# --- Optional Redis-backed shared state for multi-instance deployments ---
#
# Set SHADOW_AGENT_REDIS_URL to share the rate limiter and login throttle
# across gateway replicas. Without it (or when Redis is unreachable at
# startup) the process-local in-memory implementations below are used, which
# is correct for single-instance deployments.
#
# Runtime Redis failures degrade fail-open with an error log: availability of
# the gateway takes precedence over throttling precision.

_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
if count >= limit then
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    if #oldest > 1 then
        local retry = math.ceil(window - (now - tonumber(oldest[2])))
        if retry < 1 then retry = 1 end
        return {0, retry}
    end
    return {0, 1}
end
redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, math.ceil(window * 1000 * 2))
return {1, 0}
"""

_LOCKOUT_REMAINING_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local max_failures = tonumber(ARGV[3])

redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
if count >= max_failures then
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    if #oldest > 1 then
        local retry = math.ceil(window - (now - tonumber(oldest[2])))
        if retry < 1 then retry = 1 end
        return retry
    end
    return math.ceil(window)
end
return 0
"""

_shared_redis_client: Any = None
_shared_redis_initialized = False


def _get_shared_redis_client() -> Any:
    """Lazily connect to Redis when SHADOW_AGENT_REDIS_URL is configured.

    Returns None (single-instance memory mode) when the variable is unset,
    the redis package is missing, or the server cannot be reached.
    """
    global _shared_redis_client, _shared_redis_initialized

    if _shared_redis_initialized:
        return _shared_redis_client

    _shared_redis_initialized = True
    _shared_redis_client = None

    url = os.getenv("SHADOW_AGENT_REDIS_URL", "").strip()
    if not url:
        return None

    try:
        import redis
    except ImportError:
        logger.error(
            "SHADOW_AGENT_REDIS_URL is set but the 'redis' package is not installed; "
            "falling back to in-memory shared state (single-instance mode). "
            "Install it with: pip install redis"
        )
        return None

    try:
        client = redis.Redis.from_url(url, socket_timeout=2, socket_connect_timeout=2)
        client.ping()
    except Exception as exc:
        logger.error(
            "Cannot reach Redis at the configured SHADOW_AGENT_REDIS_URL; falling "
            "back to in-memory shared state (single-instance mode): %s",
            exc,
        )
        return None

    logger.info("Shared state backend: Redis (%s)", url)
    _shared_redis_client = client
    return _shared_redis_client


class RedisRateLimiter:
    """Sliding-window rate limiter backed by a Redis sorted set (atomic via Lua)."""

    def __init__(self, client: Any, prefix: str = "shadow_agent:rate") -> None:
        self._client = client
        self._prefix = prefix
        self._check_script = client.register_script(_SLIDING_WINDOW_LUA)

    def check(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        try:
            allowed, retry_after = self._check_script(
                keys=[f"{self._prefix}:{key}"],
                args=[time.time(), window_seconds, limit, uuid.uuid4().hex],
            )
            return bool(int(allowed)), int(retry_after)
        except Exception as exc:
            logger.error("Redis rate limiter failed; allowing request (fail-open): %s", exc)
            return True, 0


class RedisLoginThrottle:
    """Login failure tracking backed by Redis so lockouts span all replicas."""

    def __init__(self, client: Any, prefix: str = "shadow_agent:login") -> None:
        self._client = client
        self._prefix = prefix
        self._lockout_script = client.register_script(_LOCKOUT_REMAINING_LUA)

    def locked_out_remaining(
        self,
        key: str,
        *,
        max_failures: int,
        window_seconds: float,
    ) -> int:
        try:
            return int(
                self._lockout_script(
                    keys=[f"{self._prefix}:{key}"],
                    args=[time.time(), window_seconds, max(1, max_failures)],
                )
            )
        except Exception as exc:
            logger.error("Redis login throttle lookup failed (fail-open): %s", exc)
            return 0

    def record_failure(self, key: str, *, window_seconds: float) -> None:
        try:
            redis_key = f"{self._prefix}:{key}"
            now = time.time()
            pipe = self._client.pipeline()
            pipe.zremrangebyscore(redis_key, 0, now - window_seconds)
            pipe.zadd(redis_key, {uuid.uuid4().hex: now})
            pipe.pexpire(redis_key, int(window_seconds * 1000 * 2))
            pipe.execute()
        except Exception as exc:
            logger.error("Redis login throttle record failed: %s", exc)

    def record_success(self, key: str) -> None:
        try:
            self._client.delete(f"{self._prefix}:{key}")
        except Exception as exc:
            logger.error("Redis login throttle reset failed: %s", exc)


def _build_rate_limiter() -> InMemoryRateLimiter | RedisRateLimiter:
    client = _get_shared_redis_client()
    if client is not None:
        return RedisRateLimiter(client)
    return InMemoryRateLimiter()


def _build_login_throttle() -> InMemoryLoginThrottle | RedisLoginThrottle:
    client = _get_shared_redis_client()
    if client is not None:
        return RedisLoginThrottle(client)
    return InMemoryLoginThrottle()


def shared_state_backend() -> str:
    """Report which backend holds rate-limit/lockout state (for /health)."""
    return "redis" if _get_shared_redis_client() is not None else "memory"


rate_limiter = _build_rate_limiter()
login_throttle = _build_login_throttle()


def _env_secret(name: str) -> str | None:
    value = os.getenv(name)
    if value and value.strip():
        return value.strip()
    return None


def _jwt_secret() -> str | None:
    # The JWT signing key must be configured explicitly. Deriving it from the
    # static API keys would let any client-key holder forge admin JWTs, so that
    # fallback has been removed (console login now requires SHADOW_AGENT_JWT_SECRET).
    return _env_secret("SHADOW_AGENT_JWT_SECRET")


def _api_key_pepper() -> str | None:
    configured = _env_secret("SHADOW_AGENT_API_KEY_PEPPER")
    if configured:
        return configured

    # Fallback chain preserves hashes created by earlier versions:
    # explicit pepper -> JWT secret -> derived from static API keys.
    jwt_secret = _env_secret("SHADOW_AGENT_JWT_SECRET")
    if jwt_secret:
        return jwt_secret

    admin_key = _env_secret("SHADOW_AGENT_ADMIN_API_KEY") or ""
    client_key = _env_secret("SHADOW_AGENT_CLIENT_API_KEY") or ""
    if not admin_key and not client_key:
        return None

    return hashlib.sha256(f"{admin_key}|{client_key}|shadow-agent-jwt".encode("utf-8")).hexdigest()


def _unauthorized(message: str = "Authentication required.") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "unauthorized", "message": message},
        headers={"WWW-Authenticate": "Bearer"},
    )


def _forbidden(message: str = "Insufficient permissions.") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"error": "forbidden", "message": message},
    )


def _auth_not_configured() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "error": "auth_not_configured",
            "message": (
                "Set SHADOW_AGENT_ADMIN_API_KEY, SHADOW_AGENT_CLIENT_API_KEY, "
                "SHADOW_AGENT_JWT_SECRET, or create managed API keys before using protected endpoints."
            ),
        },
    )


def _api_key_pepper_not_configured() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "error": "api_key_pepper_not_configured",
            "message": (
                "Set SHADOW_AGENT_API_KEY_PEPPER or SHADOW_AGENT_JWT_SECRET before "
                "creating or verifying managed API keys."
            ),
        },
    )


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_HASH_ITERATIONS,
    )
    return f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${salt}${derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations_text, salt, expected_hash = stored_hash.split("$", 3)
    except ValueError:
        return False

    if algorithm != "pbkdf2_sha256":
        return False

    try:
        iterations = int(iterations_text)
    except ValueError:
        return False

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    )
    return hmac.compare_digest(derived.hex(), expected_hash)


def _hash_managed_api_key(raw_key: str) -> str:
    pepper = _api_key_pepper()
    if not pepper:
        raise _api_key_pepper_not_configured()
    return hashlib.sha256(f"{pepper}:{raw_key}".encode("utf-8")).hexdigest()


def _normalize_source_host(raw_value: str) -> str:
    value = raw_value.strip().strip("\"")
    if not value or value.lower() == "unknown":
        return ""

    bracket_match = re.match(r"^\[([^\]]+)\](?::\d+)?$", value)
    if bracket_match:
        candidate = bracket_match.group(1).strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            return candidate

    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    if value.count(":") == 1:
        host_candidate, port_candidate = value.rsplit(":", 1)
        if port_candidate.isdigit():
            try:
                ipaddress.ip_address(host_candidate)
                return host_candidate
            except ValueError:
                return host_candidate.strip()

    return value


def _request_source_label(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    forwarded = request.headers.get("forwarded", "")
    real_ip = request.headers.get("x-real-ip", "")

    candidates: list[tuple[str, str]] = []
    if forwarded_for:
        first_forwarded = forwarded_for.split(",", 1)[0].strip()
        if first_forwarded:
            candidates.append((first_forwarded, "x-forwarded-for"))

    if forwarded:
        match = re.search(r"for=(?:\"?\[?)([^;,\]\" ]+)", forwarded, flags=re.IGNORECASE)
        if match:
            candidates.append((match.group(1).strip(), "forwarded"))

    if real_ip:
        candidates.append((real_ip.strip(), "x-real-ip"))

    if request.client and request.client.host:
        candidates.append((request.client.host.strip(), "direct"))

    for raw_value, source in candidates:
        normalized = _normalize_source_host(raw_value)
        if not normalized:
            continue
        try:
            ipaddress.ip_address(normalized)
            return f"{normalized}|{source}"
        except ValueError:
            if normalized.lower() == "unknown":
                continue
            return f"{normalized}|{source}"

    return "unknown|unknown"


def generate_managed_api_key(role: str) -> tuple[str, str, str]:
    key_prefix = f"{MANAGED_API_KEY_PREFIX}_{role[:3].lower()}_{secrets.token_hex(4)}"
    key_secret = secrets.token_urlsafe(32)
    raw_key = f"{key_prefix}.{key_secret}"
    return raw_key, key_prefix, _hash_managed_api_key(raw_key)


def create_jwt(
    subject: str,
    role: str,
    expires_in_seconds: int = 60 * 60 * 12,
    extra_claims: dict[str, Any] | None = None,
) -> tuple[str, int]:
    secret = _jwt_secret()
    if not secret:
        raise _auth_not_configured()
    if len(secret) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "weak_jwt_secret",
                "message": "SHADOW_AGENT_JWT_SECRET must be at least 32 characters.",
            },
        )

    now = int(time.time())
    payload = {
        "sub": subject,
        "role": role,
        "iat": now,
        "nbf": now,
        "exp": now + max(60, expires_in_seconds),
    }
    if extra_claims:
        payload.update(extra_claims)

    token = pyjwt.encode(payload, secret, algorithm="HS256")
    return token, payload["exp"]


def _verify_jwt(token: str) -> Principal | None:
    secret = _jwt_secret()
    if not secret:
        return None
    if len(secret) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "weak_jwt_secret",
                "message": "SHADOW_AGENT_JWT_SECRET must be at least 32 characters.",
            },
        )

    try:
        payload = pyjwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            options={"require": ["exp", "sub"]},
        )
    except pyjwt.ExpiredSignatureError:
        raise _unauthorized("JWT has expired.")
    except pyjwt.ImmatureSignatureError:
        raise _unauthorized("JWT is not valid yet.")
    except pyjwt.InvalidAlgorithmError:
        raise _unauthorized("Unsupported JWT header.")
    except pyjwt.PyJWTError:
        raise _unauthorized("Invalid or malformed JWT.")

    role = str(payload.get("role", "client"))
    subject = str(payload.get("sub", "jwt-subject"))

    org_id: int | None = None
    raw_org_id = payload.get("org_id")
    if isinstance(raw_org_id, int):
        org_id = raw_org_id
    elif isinstance(raw_org_id, str) and raw_org_id.isdigit():
        try:
            org_id = int(raw_org_id)
        except ValueError:
            org_id = None

    org_role = payload.get("org_role")
    org_role = str(org_role) if org_role else None

    return Principal(
        subject=subject,
        role=role,
        auth_method="jwt",
        org_id=org_id,
        org_role=org_role,
    )


def _verify_api_key(request: Request, bearer_credentials: str = "") -> Principal | None:
    presented = (
        request.headers.get("x-api-key")
        or request.headers.get("x-admin-api-key")
        or request.headers.get("x-client-api-key")
        or bearer_credentials
    )
    if not presented:
        return None

    managed_api_key = _verify_managed_api_key(request, presented)
    if managed_api_key is not None:
        return managed_api_key

    admin_key = _env_secret("SHADOW_AGENT_ADMIN_API_KEY")
    client_key = _env_secret("SHADOW_AGENT_CLIENT_API_KEY")

    if admin_key and hmac.compare_digest(presented, admin_key):
        return Principal(subject="api-key-admin", role="admin", auth_method="api_key")
    if client_key and hmac.compare_digest(presented, client_key):
        return Principal(subject="api-key-client", role="client", auth_method="api_key")

    raise _unauthorized("Invalid API key.")


def _verify_managed_api_key(request: Request, presented: str) -> Principal | None:
    if "." not in presented:
        return None

    key_prefix = presented.split(".", 1)[0].strip()
    if not key_prefix.startswith(f"{MANAGED_API_KEY_PREFIX}_"):
        return None

    db = SessionLocal()
    try:
        api_key = (
            db.query(ManagedApiKey)
            .filter(ManagedApiKey.key_prefix == key_prefix)
            .one_or_none()
        )
        if api_key is None:
            return None
        if not api_key.is_active:
            raise _unauthorized("Managed API key is revoked.")
        if api_key.expires_at is not None and api_key.expires_at <= datetime.utcnow():
            raise _unauthorized("Managed API key has expired.")
        if not hmac.compare_digest(api_key.key_hash, _hash_managed_api_key(presented)):
            raise _unauthorized("Invalid API key.")

        api_key.last_used_at = datetime.utcnow()
        api_key.last_used_by = _request_source_label(request)
        db.commit()
        return Principal(
            subject=f"managed-api-key:{api_key.id}",
            role=api_key.role,
            auth_method="managed_api_key",
            org_id=api_key.org_id,
        )
    finally:
        db.close()


def _managed_api_keys_configured() -> bool:
    db = SessionLocal()
    try:
        item = (
            db.query(ManagedApiKey.id)
            .filter(ManagedApiKey.is_active.is_(True))
            .limit(1)
            .one_or_none()
        )
        return item is not None
    except Exception:
        return False
    finally:
        db.close()


def _verify_console_user_active(principal: Principal) -> Principal:
    """Re-check console user state so disabled users lose access immediately.

    Also re-validates the claimed organization: if the user was removed from
    the organization (or the organization was deleted) the token's org claims
    go stale, and every org-scoped request must be rejected.
    """

    prefix = "console-user:"
    if not principal.subject.startswith(prefix):
        return principal

    try:
        user_id = int(principal.subject[len(prefix):])
    except ValueError:
        raise _unauthorized("Invalid console user token.")

    db = SessionLocal()
    try:
        user = db.query(ConsoleUser).filter(ConsoleUser.id == user_id).one_or_none()
        if user is not None and principal.org_id is not None:
            from models import OrganizationMembership

            membership = (
                db.query(OrganizationMembership)
                .filter(
                    OrganizationMembership.user_id == user_id,
                    OrganizationMembership.org_id == principal.org_id,
                )
                .one_or_none()
            )
            if membership is None:
                raise _unauthorized(
                    "Your account no longer has access to this organization."
                )
            if principal.org_role is not None and membership.role != principal.org_role:
                principal = Principal(
                    subject=principal.subject,
                    role=principal.role,
                    auth_method=principal.auth_method,
                    org_id=principal.org_id,
                    org_role=membership.role,
                )
    finally:
        db.close()

    if user is None or not user.is_active:
        raise _unauthorized("Console user is inactive or no longer exists.")
    return principal


def _looks_like_jwt(credentials: str) -> bool:
    """Heuristic: real JWTs are `header.payload.signature` (two dots)."""
    return credentials.count(".") == 2


def _authenticate(request: Request) -> Principal:
    authorization = request.headers.get("authorization")
    scheme, credentials = get_authorization_scheme_param(authorization)
    bearer_credentials = credentials if scheme.lower() == "bearer" and credentials else ""

    # Bearer tokens that look like a JWT must verify as one (errors surface
    # immediately). Anything else (e.g. `sak_...` managed keys or plain env
    # keys sent by OpenAI-style SDKs) falls through to the API-key path.
    if bearer_credentials and _looks_like_jwt(bearer_credentials):
        principal = _verify_jwt(bearer_credentials)
        if principal:
            return _verify_console_user_active(principal)

    principal = _verify_api_key(request, bearer_credentials=bearer_credentials)
    if principal:
        return principal

    if any(
        _env_secret(name)
        for name in (
            "SHADOW_AGENT_ADMIN_API_KEY",
            "SHADOW_AGENT_CLIENT_API_KEY",
            "SHADOW_AGENT_JWT_SECRET",
        )
    ) or _managed_api_keys_configured():
        raise _unauthorized()
    raise _auth_not_configured()


async def require_admin(request: Request) -> Principal:
    principal = _authenticate(request)
    if principal.role not in ADMIN_ROLES:
        raise _forbidden("Admin role required.")
    return principal


async def require_client(request: Request) -> Principal:
    principal = _authenticate(request)
    if principal.role not in CLIENT_ROLES:
        raise _forbidden("Gateway client role required.")
    return principal


def sanitize_request_id(value: str | None) -> str:
    if not value:
        return ""
    return REQUEST_ID_PATTERN.sub("-", value)[:96]


def redact_sensitive_assignments(value: str) -> str:
    """Mask ``key=value`` credential assignments and ``Bearer <token>``.

    Only the two ``SENSITIVE_TEXT_PATTERNS`` shapes; no truncation. Split out of
    :func:`redact_text` so a caller that composes further redaction (see
    ``app.dlp.redact_for_log``) can reuse the exact same substitution instead of
    re-implementing it.
    """
    redacted = value
    for pattern in SENSITIVE_TEXT_PATTERNS:
        redacted = pattern.sub(
            lambda match: (
                f"{match.group(1)}=<redacted>"
                if match.lastindex
                else "Bearer <redacted>"
            ),
            redacted,
        )
    return redacted


def redact_text(value: str, max_chars: int = 4000) -> str:
    redacted = redact_sensitive_assignments(value)
    if len(redacted) > max_chars:
        return redacted[:max_chars] + "...[truncated]"
    return redacted


def sanitize_json(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "<max_depth>"
    if isinstance(value, str):
        return redact_text(value, max_chars=1000)
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in SENSITIVE_KEYS:
                sanitized[key_text] = "<redacted>"
            else:
                sanitized[key_text] = sanitize_json(item, depth + 1)
        return sanitized
    if isinstance(value, list):
        return [sanitize_json(item, depth + 1) for item in value[:50]]
    return value


async def rate_limit_middleware(request: Request, call_next: Any) -> Any:
    if request.url.path.startswith("/api/"):
        default_limit = int(os.getenv("SHADOW_AGENT_RATE_LIMIT_PER_MINUTE", "60"))
        logs_limit = int(os.getenv("SHADOW_AGENT_LOG_RATE_LIMIT_PER_MINUTE", "20"))
        limit = logs_limit if request.url.path == "/api/v1/logs" else default_limit
        client_host = request.client.host if request.client else "unknown"
        key = f"{client_host}:{request.method}:{request.url.path}"

        allowed, retry_after = rate_limiter.check(key, max(1, limit), 60)
        if not allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "rate_limited",
                    "message": "Too many requests. Try again later.",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

    return await call_next(request)
