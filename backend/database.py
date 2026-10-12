"""Database configuration for Shadow Agent."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from threading import Lock
from typing import Generator

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logger = logging.getLogger("shadow_agent.db")


def _configured_database_url() -> str:
    explicit_url = os.getenv("SHADOW_AGENT_DATABASE_URL", "").strip()
    if explicit_url:
        return explicit_url

    configured_path = os.getenv("SHADOW_AGENT_DATABASE_PATH", "").strip()
    if configured_path:
        database_path = Path(configured_path)
        if not database_path.is_absolute():
            database_path = Path(__file__).resolve().parent / database_path
    else:
        database_path = Path(__file__).resolve().parent / "shadow_agent.db"

    return f"sqlite:///{database_path.resolve().as_posix()}"


DATABASE_URL = _configured_database_url()


DEFAULT_POOL_SIZE = 20
DEFAULT_MAX_OVERFLOW = 40
DEFAULT_POOL_TIMEOUT = 5


def _env_positive_int(name: str, default: int) -> int:
    """Read a positive integer override, falling back on anything unusable."""
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("%s=%r is not an integer; using %d", name, raw, default)
        return default
    if value <= 0:
        logger.warning("%s=%d must be positive; using %d", name, value, default)
        return default
    return value


def _pool_kwargs(database_url: str) -> dict:
    """Connection-pool sizing for the request path.

    SQLAlchemy's default QueuePool ceiling is ``pool_size=5 + max_overflow=10
    = 15``, and ``pool.checkout()`` is a *synchronous* call executed on the
    server's event loop. Once more connections are wanted than exist, the loop
    blocks inside ``pool.checkout()`` instead of serving anything, so every
    request stalls with no 5xx and nothing logged -- it reads like a network
    fault. Measured with pool checkout/checkin events (``chat``, simulated
    upstream):

        original 15, c=32 ->   4.8 rps, 32 x 30s client timeouts,
                               peak held 15, connection hold p95 30046 ms
        fixed    60, c=32 -> 246.4 rps, 0 errors, peak held 23, hold p95 51 ms
        original 15, c=8  -> 283.5 rps, 0 errors, peak held  7, hold p95 15 ms

    The ceiling of 15 was genuinely too low: peak demand at c=32 is 23
    concurrent connections. Note that a connection is held for 8-24 ms, *not*
    for the ~2 ms the handler spends on CPU -- so "the handler is fast, the pool
    must be sufficient" is not a valid inference.

    ``pool_timeout`` is lowered from the 30s default so a future shortage
    surfaces as a fast error instead of pinning the event loop for 30 seconds.

    Override per deployment with ``SHADOW_AGENT_DB_POOL_SIZE``,
    ``SHADOW_AGENT_DB_MAX_OVERFLOW`` and ``SHADOW_AGENT_DB_POOL_TIMEOUT``.
    **The ceiling must exceed peak concurrent connection demand, which is a
    function of concurrency and hold time -- re-measure it before going to
    PostgreSQL or multiple workers; do not assume these numbers carry over.**
    """
    if database_url in ("sqlite://", "sqlite:///") or ":memory:" in database_url:
        # In-memory SQLite is served by SingletonThreadPool, which rejects
        # these arguments (and needs no sizing).
        return {}
    return {
        "pool_size": _env_positive_int("SHADOW_AGENT_DB_POOL_SIZE", DEFAULT_POOL_SIZE),
        "max_overflow": _env_positive_int(
            "SHADOW_AGENT_DB_MAX_OVERFLOW", DEFAULT_MAX_OVERFLOW
        ),
        "pool_timeout": _env_positive_int(
            "SHADOW_AGENT_DB_POOL_TIMEOUT", DEFAULT_POOL_TIMEOUT
        ),
    }


class Base(DeclarativeBase):
    pass


engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
    **_pool_kwargs(DATABASE_URL),
)


if DATABASE_URL.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _configure_sqlite_pragmas(dbapi_connection, _connection_record) -> None:
        """WAL + busy timeout so request writes and audit writes coexist."""
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA busy_timeout=5000")
        finally:
            cursor.close()


# --- connection-pool instrumentation ----------------------------------------
#
# The pool's failure mode is a *silent* stall: `pool.checkout()` runs on the
# event loop, so when every connection is held the process stops serving rather
# than raising, and nothing is logged. That is precisely why the 2026-09-20
# incident took a whole session to localise -- it presented as a network fault
# (zero bytes returned, no errors, `/health` dead too). These counters exist so
# that the next occurrence is one glance at `/metrics`, and so an operator can
# alarm on the ceiling being approached instead of discovering it in an outage.
#
# Cost: one lock acquire plus a few integer updates per checkout/checkin, and a
# `pool.size()` call. Negligible against a request that performs DB I/O.

_pool_lock = Lock()
_pool_state: dict[str, int] = {
    "checkouts": 0,
    "in_use": 0,
    "max_in_use": 0,
    "saturated_checkouts": 0,
    "timeouts": 0,
}
_last_saturation_warning = 0.0
_SATURATION_WARNING_INTERVAL_SECONDS = 10.0


def record_pool_timeout() -> None:
    """Count one request that gave up waiting for a connection.

    This is the *accurate* starvation signal. The ``saturated_checkouts``
    counter below can only see checkouts that eventually succeeded, so it
    undercounts precisely when it matters: a request that blocks in
    ``checkout()`` until ``pool_timeout`` raises never reaches the ``checkout``
    event. Main registers an exception handler for
    ``sqlalchemy.exc.TimeoutError`` that calls this.
    """
    with _pool_lock:
        _pool_state["timeouts"] += 1


def _pool_capacity() -> int | None:
    """Configured ceiling (pool_size + max_overflow), or None if not applicable.

    Returns None for pools that have no ceiling -- notably the
    SingletonThreadPool used by in-memory SQLite.
    """
    pool = engine.pool
    try:
        return int(pool.size()) + int(pool._max_overflow)  # noqa: SLF001
    except (AttributeError, TypeError):
        return None


@event.listens_for(engine, "checkout")
def _on_pool_checkout(_dbapi_connection, _connection_record, _connection_proxy) -> None:
    """Track pool usage and shout once when the ceiling is actually reached."""
    global _last_saturation_warning

    with _pool_lock:
        _pool_state["checkouts"] += 1
        _pool_state["in_use"] += 1
        if _pool_state["in_use"] > _pool_state["max_in_use"]:
            _pool_state["max_in_use"] = _pool_state["in_use"]
        capacity = _pool_capacity()
        saturated = capacity is not None and _pool_state["in_use"] >= capacity
        if saturated:
            _pool_state["saturated_checkouts"] += 1
        now = time.monotonic()
        should_warn = saturated and (
            now - _last_saturation_warning >= _SATURATION_WARNING_INTERVAL_SECONDS
        )
        if should_warn:
            _last_saturation_warning = now
        in_use = _pool_state["in_use"]
        checkouts = _pool_state["checkouts"]
        saturated_checkouts = _pool_state["saturated_checkouts"]
        timeouts = _pool_state["timeouts"]

    if should_warn:
        # Rate-limited: at saturation this fires once per interval, not per
        # request, so it cannot itself flood the log.
        logger.warning(
            "DB connection pool saturated: %d/%s connections held "
            "(%d checkouts, %d saturated, %d requests already timed out waiting "
            "since start). Requests stall while this holds because "
            "pool.checkout() blocks the event loop. Raise "
            "SHADOW_AGENT_DB_POOL_SIZE / SHADOW_AGENT_DB_MAX_OVERFLOW, or lower "
            "client concurrency.",
            in_use,
            capacity,
            checkouts,
            saturated_checkouts,
            timeouts,
        )


@event.listens_for(engine, "checkin")
def _on_pool_checkin(_dbapi_connection, _connection_record) -> None:
    with _pool_lock:
        if _pool_state["in_use"] > 0:
            _pool_state["in_use"] -= 1


def pool_stats() -> dict[str, int | None]:
    """Pool configuration plus live usage, for ``/metrics`` and diagnostics."""
    pool = engine.pool
    with _pool_lock:
        state: dict[str, int | None] = dict(_pool_state)
    state["capacity"] = _pool_capacity()

    def _safe(call) -> int | None:  # noqa: ANN001
        try:
            return int(call())
        except (AttributeError, TypeError):
            return None

    state["size"] = _safe(pool.size)
    state["overflow"] = _safe(pool.overflow)
    state["available"] = _safe(pool.checkedin)
    return state


SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

_init_lock = Lock()


def init_database() -> None:
    with _init_lock:
        import models  # noqa: F401

        Base.metadata.create_all(bind=engine)
        _apply_lightweight_migrations()
        _backfill_intercept_log_request_ids()


def _backfill_intercept_log_request_ids() -> None:
    """Backfill request_id for legacy rows that only carry it inside details JSON."""
    import json

    from models import InterceptLog

    db = SessionLocal()
    try:
        chunk_size = 200
        last_id = 0
        while True:
            rows = (
                db.query(InterceptLog)
                .filter(
                    InterceptLog.id > last_id,
                    InterceptLog.request_id == "",
                )
                .order_by(InterceptLog.id.asc())
                .limit(chunk_size)
                .all()
            )
            if not rows:
                break
            for row in rows:
                last_id = row.id
                try:
                    details = json.loads(row.details)
                except (TypeError, ValueError):
                    continue
                if not isinstance(details, dict):
                    continue
                request_id = details.get("request_id")
                if isinstance(request_id, str) and request_id.strip():
                    row.request_id = request_id.strip()[:96]
            db.commit()
    finally:
        db.close()


def _apply_lightweight_migrations() -> None:
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    with engine.begin() as connection:
        if "security_policies" in existing_tables:
            policy_columns = {column["name"] for column in inspector.get_columns("security_policies")}
            if "severity" not in policy_columns:
                connection.execute(
                    text(
                        "ALTER TABLE security_policies ADD COLUMN severity VARCHAR(32) NOT NULL DEFAULT 'medium'"
                    )
                )
            if "scope" not in policy_columns:
                connection.execute(
                    text(
                        "ALTER TABLE security_policies ADD COLUMN scope VARCHAR(64) NOT NULL DEFAULT 'Prompt'"
                    )
                )
            if "system_managed" not in policy_columns:
                connection.execute(
                    text(
                        "ALTER TABLE security_policies ADD COLUMN system_managed BOOLEAN NOT NULL DEFAULT 0"
                    )
                )

        if "tool_policies" in existing_tables:
            tool_columns = {column["name"] for column in inspector.get_columns("tool_policies")}
            if "system_managed" not in tool_columns:
                connection.execute(
                    text(
                        "ALTER TABLE tool_policies ADD COLUMN system_managed BOOLEAN NOT NULL DEFAULT 0"
                    )
                )

        if "intercept_logs" in existing_tables:
            log_columns = {column["name"] for column in inspector.get_columns("intercept_logs")}
            if "request_id" not in log_columns:
                connection.execute(
                    text(
                        "ALTER TABLE intercept_logs ADD COLUMN request_id VARCHAR(96) NOT NULL DEFAULT ''"
                    )
                )
            connection.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_intercept_logs_request_id "
                    "ON intercept_logs (request_id)"
                )
            )

        if "approval_requests" in existing_tables:
            approval_columns = {column["name"] for column in inspector.get_columns("approval_requests")}
            if "reviewed_by" not in approval_columns:
                connection.execute(
                    text(
                        "ALTER TABLE approval_requests ADD COLUMN reviewed_by VARCHAR(128) NOT NULL DEFAULT ''"
                    )
                )
            if "review_comment" not in approval_columns:
                connection.execute(
                    text(
                        "ALTER TABLE approval_requests ADD COLUMN review_comment TEXT NOT NULL DEFAULT ''"
                    )
                )

        if "console_users" in existing_tables:
            user_columns = {column["name"] for column in inspector.get_columns("console_users")}
            if "is_active" not in user_columns:
                connection.execute(
                    text(
                        "ALTER TABLE console_users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1"
                    )
                )

        _apply_org_tenancy_columns(connection, inspector, existing_tables)


def _apply_org_tenancy_columns(connection, inspector, existing_tables) -> None:
    """Lightweight multi-tenancy migration for pre-Alembic databases.

    Fresh databases get everything from ``Base.metadata.create_all``; this
    only patches tables that already existed without ``org_id``.
    """
    for table in (
        "intercept_logs",
        "audit_logs",
        "security_policies",
        "approval_requests",
        "alert_events",
        "replay_runs",
        "managed_api_keys",
        "tool_policies",
    ):
        if table not in existing_tables:
            continue
        columns = {column["name"] for column in inspector.get_columns(table)}
        if "org_id" not in columns:
            connection.execute(text(f"ALTER TABLE {table} ADD COLUMN org_id INTEGER"))
        connection.execute(
            text(f"CREATE INDEX IF NOT EXISTS ix_{table}_org_id ON {table} (org_id)")
        )

    if "tool_policies" in existing_tables:
        # Replace the global tool_name unique index with the per-organization
        # (org_id, tool_name) one so tenants can override shared defaults.
        index_names = {index["name"] for index in inspector.get_indexes("tool_policies")}
        if "ix_tool_policies_tool_name" in index_names:
            connection.execute(text("DROP INDEX ix_tool_policies_tool_name"))
        connection.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_tool_policy_org_tool "
                "ON tool_policies (org_id, tool_name)"
            )
        )

    if "custom_rules" in existing_tables:
        _apply_custom_rules_tenancy(connection, inspector)


def _apply_custom_rules_tenancy(connection, inspector) -> None:
    """custom_rules: org_id column + per-organization (org_id, name) uniqueness.

    The baseline schema enforced globally-unique rule names with an inline
    table constraint. SQLite implements it as an ``sqlite_autoindex`` that
    cannot be dropped in place, so the table is rebuilt; on Postgres the
    named constraint is dropped directly.
    """
    columns = {column["name"] for column in inspector.get_columns("custom_rules")}
    unique_constraints = inspector.get_unique_constraints("custom_rules")
    legacy_name_unique = any(
        [str(column).lower() for column in constraint.get("column_names", [])] == ["name"]
        for constraint in unique_constraints
    )

    if legacy_name_unique or "org_id" not in columns:
        if engine.dialect.name == "sqlite":
            _rebuild_custom_rules_sqlite(connection, has_org_id="org_id" in columns)
        else:
            if legacy_name_unique:
                connection.execute(
                    text("ALTER TABLE custom_rules DROP CONSTRAINT IF EXISTS custom_rules_name_key")
                )
            if "org_id" not in columns:
                connection.execute(text("ALTER TABLE custom_rules ADD COLUMN org_id INTEGER"))

    connection.execute(
        text("CREATE INDEX IF NOT EXISTS ix_custom_rules_org_id ON custom_rules (org_id)")
    )
    connection.execute(
        text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_custom_rule_org_name "
            "ON custom_rules (org_id, name)"
        )
    )


def _rebuild_custom_rules_sqlite(connection, *, has_org_id: bool) -> None:
    """Rebuild custom_rules on SQLite: adds org_id and drops the legacy
    global UNIQUE(name) autoindex (renaming loses dependent indexes too)."""
    connection.execute(text("ALTER TABLE custom_rules RENAME TO custom_rules_legacy_tenancy"))
    connection.execute(
        text(
            """
            CREATE TABLE custom_rules (
                id INTEGER NOT NULL,
                org_id INTEGER,
                name VARCHAR(128) NOT NULL,
                description TEXT NOT NULL,
                rule_type VARCHAR(16) NOT NULL,
                pattern VARCHAR(512) NOT NULL,
                target VARCHAR(16) NOT NULL,
                action VARCHAR(16) NOT NULL,
                risk_score FLOAT NOT NULL,
                enabled BOOLEAN NOT NULL,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                PRIMARY KEY (id)
            )
            """
        )
    )
    org_source = "org_id" if has_org_id else "NULL"
    connection.execute(
        text(
            "INSERT INTO custom_rules (id, org_id, name, description, rule_type, "
            "pattern, target, action, risk_score, enabled, created_at, updated_at) "
            f"SELECT id, {org_source}, name, description, rule_type, pattern, "
            "target, action, risk_score, enabled, created_at, updated_at "
            "FROM custom_rules_legacy_tenancy"
        )
    )
    connection.execute(text("DROP TABLE custom_rules_legacy_tenancy"))
    for index_column in ("id", "name", "rule_type", "target", "action", "enabled"):
        connection.execute(
            text(
                f"CREATE INDEX IF NOT EXISTS ix_custom_rules_{index_column} "
                f"ON custom_rules ({index_column})"
            )
        )


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
