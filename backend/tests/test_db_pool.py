"""Pool-sizing rules for the request path (see `database._pool_kwargs`).

These are pure, deterministic checks: the default QueuePool ceiling (5+10=15)
used to stall the whole event loop at ~32 concurrent clients, and in-memory
SQLite must NOT receive sizing arguments (SingletonThreadPool rejects them).

Run from backend/: python -m pytest tests/test_db_pool.py -v
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import text

from database import _pool_kwargs

SIZED = {"pool_size": 20, "max_overflow": 40, "pool_timeout": 5}

_SIZING_ENV = (
    "SHADOW_AGENT_DB_POOL_SIZE",
    "SHADOW_AGENT_DB_MAX_OVERFLOW",
    "SHADOW_AGENT_DB_POOL_TIMEOUT",
)


@pytest.fixture(autouse=True)
def _clear_sizing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Assertions below are about defaults, so ambient overrides must not leak in."""
    for name in _SIZING_ENV:
        monkeypatch.delenv(name, raising=False)


def test_file_sqlite_is_sized_above_the_default_ceiling() -> None:
    kwargs = _pool_kwargs("sqlite:///C:/tmp/shadow_agent.db")
    assert kwargs == SIZED
    # Ceiling must comfortably exceed the concurrency at which the old default
    # (15 connections) blocked the event loop.
    assert kwargs["pool_size"] + kwargs["max_overflow"] > 32


def test_pool_timeout_is_short_enough_to_fail_fast() -> None:
    # 30s (the SQLAlchemy default) pins the event loop; saturation must surface
    # as an error quickly instead.
    assert _pool_kwargs("sqlite:///tmp/x.db")["pool_timeout"] <= 10


def test_postgres_urls_are_sized_too() -> None:
    assert _pool_kwargs("postgresql+psycopg://u:p@localhost/shadow") == SIZED


@pytest.mark.parametrize(
    "url",
    ["sqlite://", "sqlite:///", "sqlite:///:memory:", "sqlite+pysqlite:///:memory:"],
)
def test_in_memory_sqlite_is_left_alone(url: str) -> None:
    # SingletonThreadPool raises TypeError on pool_size/max_overflow.
    assert _pool_kwargs(url) == {}


def test_engine_actually_received_the_sizing() -> None:
    """Guard against the kwargs being computed but never passed to create_engine."""
    from database import DATABASE_URL, engine

    if _pool_kwargs(DATABASE_URL):
        pool = engine.pool
        assert pool.size() == 20
        assert pool._max_overflow == 40


def test_sizing_is_overridable_per_deployment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PostgreSQL / multi-worker deployments must re-measure, not inherit 20+40."""
    monkeypatch.setenv("SHADOW_AGENT_DB_POOL_SIZE", "7")
    monkeypatch.setenv("SHADOW_AGENT_DB_MAX_OVERFLOW", "3")
    monkeypatch.setenv("SHADOW_AGENT_DB_POOL_TIMEOUT", "2")

    assert _pool_kwargs("sqlite:///tmp/x.db") == {
        "pool_size": 7,
        "max_overflow": 3,
        "pool_timeout": 2,
    }


@pytest.mark.parametrize("bad", ["", "  ", "abc", "0", "-4", "1.5"])
def test_unusable_sizing_override_falls_back_to_default(
    monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    monkeypatch.setenv("SHADOW_AGENT_DB_POOL_SIZE", bad)

    assert _pool_kwargs("sqlite:///tmp/x.db")["pool_size"] == 20


def test_pool_stats_reports_the_ceiling() -> None:
    """The ceiling must be observable, otherwise saturation is invisible."""
    from database import pool_stats

    stats = pool_stats()
    assert stats["size"] == 20
    assert stats["capacity"] == 60
    # Counters must exist even before any traffic.
    for key in ("checkouts", "in_use", "max_in_use", "saturated_checkouts", "timeouts"):
        assert stats[key] is not None and stats[key] >= 0
    assert stats["in_use"] <= stats["max_in_use"]


def test_checkout_listener_actually_counts() -> None:
    """The instrumentation must move with real pool activity, not just exist."""
    from database import SessionLocal, pool_stats

    before = pool_stats()
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
    finally:
        db.close()
    after = pool_stats()

    assert after["checkouts"] > before["checkouts"]
    assert after["max_in_use"] >= 1
    # The connection goes back to the pool when the session closes.
    assert after["in_use"] == 0


def test_metrics_expose_pool_saturation_signals() -> None:
    """Saturation used to be unobservable from the outside; assert it now is."""
    from app.metrics import metrics_snapshot, render_metrics

    body = render_metrics()
    assert "shadow_agent_db_pool_capacity" in body
    assert 'shadow_agent_db_pool_connections{state="in_use"}' in body
    assert "shadow_agent_db_pool_max_in_use_since_start" in body
    # Two distinct counters, deliberately: saturated checkouts is a lower bound,
    # timeouts is the accurate starvation count.
    assert "shadow_agent_db_pool_saturated_checkouts_total" in body
    assert "shadow_agent_db_pool_timeout_total" in body

    snapshot = metrics_snapshot()["db_pool"]
    assert snapshot is not None
    assert snapshot["capacity"] == 60


def test_pool_timeout_is_served_as_503_not_500() -> None:
    """Exhaustion must read as a capacity fault, not as a server bug.

    Verified end-to-end on 2026-09-20: with the ceiling forced back to 15, the
    unhandled ``sqlalchemy.exc.TimeoutError`` left the app as a bare HTTP 500.
    """
    from sqlalchemy.exc import TimeoutError as DatabasePoolTimeout

    import main
    from database import pool_stats

    handler = main.app.exception_handlers[DatabasePoolTimeout]
    before = pool_stats()["timeouts"]

    response = asyncio.run(
        handler(None, DatabasePoolTimeout("QueuePool limit of size 5 overflow 10 reached"))
    )

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "1"
    assert pool_stats()["timeouts"] == before + 1
