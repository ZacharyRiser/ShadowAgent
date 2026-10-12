"""Tests for shared-state backends (in-memory and optional Redis).

The Redis-backed tests require a live Redis server reachable at
SHADOW_AGENT_REDIS_TEST_URL (default redis://127.0.0.1:6379/15) and the
redis package; they are skipped automatically otherwise. CI runs them
against a Redis service container.
"""

from __future__ import annotations

import os
import uuid

import pytest

from security_controls import (
    InMemoryLoginThrottle,
    InMemoryRateLimiter,
    RedisLoginThrottle,
    RedisRateLimiter,
    _build_login_throttle,
    _build_rate_limiter,
    shared_state_backend,
)


def _redis_client_for_tests():
    try:
        import redis
    except ImportError:
        return None

    url = os.getenv("SHADOW_AGENT_REDIS_TEST_URL", "redis://127.0.0.1:6379/15")
    client = redis.Redis.from_url(url, socket_timeout=2, socket_connect_timeout=2)
    try:
        client.ping()
    except Exception:
        return None
    return client


# --- In-memory implementations (always run) ---


def test_in_memory_rate_limiter_enforces_window() -> None:
    limiter = InMemoryRateLimiter()
    key = f"test:{uuid.uuid4().hex}"

    assert limiter.check(key, 3, 60)[0] is True
    assert limiter.check(key, 3, 60)[0] is True
    assert limiter.check(key, 3, 60)[0] is True

    allowed, retry_after = limiter.check(key, 3, 60)
    assert allowed is False
    assert retry_after >= 1


def test_in_memory_login_throttle_locks_after_failures() -> None:
    throttle = InMemoryLoginThrottle()
    key = f"login:{uuid.uuid4().hex}"

    assert throttle.locked_out_remaining(key, max_failures=3, window_seconds=60) == 0
    throttle.record_failure(key, window_seconds=60)
    throttle.record_failure(key, window_seconds=60)
    assert throttle.locked_out_remaining(key, max_failures=3, window_seconds=60) == 0
    throttle.record_failure(key, window_seconds=60)

    remaining = throttle.locked_out_remaining(key, max_failures=3, window_seconds=60)
    assert remaining >= 1

    throttle.record_success(key)
    assert throttle.locked_out_remaining(key, max_failures=3, window_seconds=60) == 0


def test_default_builds_are_in_memory_without_redis_url() -> None:
    # The suite never sets SHADOW_AGENT_REDIS_URL, so the factory must pick
    # the in-memory implementations and /health must report "memory".
    assert shared_state_backend() == "memory"
    assert isinstance(_build_rate_limiter(), InMemoryRateLimiter)
    assert isinstance(_build_login_throttle(), InMemoryLoginThrottle)


# --- Redis implementations (skipped without a live Redis) ---


def _redis_backends():
    client = _redis_client_for_tests()
    if client is None:
        pytest.skip("Redis server not available for shared-state tests")
    return RedisRateLimiter(client), RedisLoginThrottle(client), client


def test_redis_rate_limiter_enforces_window() -> None:
    limiter, _, client = _redis_backends()
    key = f"test-rate:{uuid.uuid4().hex}"
    redis_key = f"shadow_agent:rate:{key}"
    try:
        assert limiter.check(key, 3, 60)[0] is True
        assert limiter.check(key, 3, 60)[0] is True
        assert limiter.check(key, 3, 60)[0] is True

        allowed, retry_after = limiter.check(key, 3, 60)
        assert allowed is False
        assert retry_after >= 1
    finally:
        client.delete(redis_key)


def test_redis_rate_limiter_state_is_shared_across_instances() -> None:
    # Two limiter objects pointing at the same Redis must see the same window.
    _, _, client = _redis_backends()
    limiter_a = RedisRateLimiter(client)
    limiter_b = RedisRateLimiter(client)
    key = f"test-shared:{uuid.uuid4().hex}"
    redis_key = f"shadow_agent:rate:{key}"
    try:
        assert limiter_a.check(key, 2, 60)[0] is True
        allowed_b, _ = limiter_b.check(key, 2, 60)
        assert allowed_b is True
        # Both instances have now consumed the window of 2.
        assert limiter_a.check(key, 2, 60)[0] is False
        assert limiter_b.check(key, 2, 60)[0] is False
    finally:
        client.delete(redis_key)


def test_redis_login_throttle_locks_and_resets() -> None:
    _, throttle, client = _redis_backends()
    key = f"test-login:{uuid.uuid4().hex}"
    redis_key = f"shadow_agent:login:{key}"
    try:
        assert throttle.locked_out_remaining(key, max_failures=3, window_seconds=60) == 0
        throttle.record_failure(key, window_seconds=60)
        throttle.record_failure(key, window_seconds=60)
        throttle.record_failure(key, window_seconds=60)
        assert throttle.locked_out_remaining(key, max_failures=3, window_seconds=60) >= 1

        throttle.record_success(key)
        assert throttle.locked_out_remaining(key, max_failures=3, window_seconds=60) == 0
    finally:
        client.delete(redis_key)
