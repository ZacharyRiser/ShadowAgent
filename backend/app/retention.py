"""Configurable log retention enforcement (GDPR data-minimization support).

Purges rows older than the configured retention window from the operational
log tables. Defaults follow the recommendation in docs/compliance/gdpr.md:

- intercept logs / alert events / replay runs: 180 days
- audit logs: 365 days (longer, they are the accountability record)

Per-table overrides (and <=0 to keep a table forever):

    SHADOW_AGENT_LOG_RETENTION_DAYS            (global default, 180)
    SHADOW_AGENT_INTERCEPT_LOG_RETENTION_DAYS
    SHADOW_AGENT_AUDIT_LOG_RETENTION_DAYS
    SHADOW_AGENT_ALERT_RETENTION_DAYS
    SHADOW_AGENT_REPLAY_RETENTION_DAYS

The cleanup runs at startup and then every
SHADOW_AGENT_RETENTION_CLEANUP_INTERVAL_SECONDS (default 3600, min 60).
Deletion happens in bounded batches so a large first run cannot lock the
database for an unbounded time; remaining rows are picked up by later cycles.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from database import SessionLocal
from models import AlertEvent, AuditLog, InterceptLog, ReplayRun

logger = logging.getLogger("shadow_agent.retention")

DEFAULT_LOG_RETENTION_DAYS = 180
DEFAULT_AUDIT_LOG_RETENTION_DAYS = 365
DEFAULT_CLEANUP_INTERVAL_SECONDS = 3600
_MIN_CLEANUP_INTERVAL_SECONDS = 60
_BATCH_SIZE = 500
_MAX_BATCHES_PER_CYCLE = 200  # 100k rows per table per cycle cap

# (metric table label, model, timestamp column, per-table env override, default days)
_RETENTION_TABLES: tuple[tuple[str, Any, Any, str, int], ...] = (
    ("intercept_logs", InterceptLog, InterceptLog.timestamp, "SHADOW_AGENT_INTERCEPT_LOG_RETENTION_DAYS", DEFAULT_LOG_RETENTION_DAYS),
    ("audit_logs", AuditLog, AuditLog.timestamp, "SHADOW_AGENT_AUDIT_LOG_RETENTION_DAYS", DEFAULT_AUDIT_LOG_RETENTION_DAYS),
    ("alert_events", AlertEvent, AlertEvent.created_at, "SHADOW_AGENT_ALERT_RETENTION_DAYS", DEFAULT_LOG_RETENTION_DAYS),
    ("replay_runs", ReplayRun, ReplayRun.created_at, "SHADOW_AGENT_REPLAY_RETENTION_DAYS", DEFAULT_LOG_RETENTION_DAYS),
)


def _parse_days(raw: str) -> int | None:
    try:
        return int(raw)
    except ValueError:
        return None


def _retention_days(override_env: str, default: int) -> int:
    """Resolve a table's retention window: override -> global -> default."""
    override_raw = os.getenv(override_env, "").strip()
    if override_raw:
        parsed = _parse_days(override_raw)
        if parsed is None:
            logger.warning("Invalid %s=%r; using default retention.", override_env, override_raw)
        else:
            return parsed

    global_raw = os.getenv("SHADOW_AGENT_LOG_RETENTION_DAYS", "").strip()
    if global_raw:
        parsed = _parse_days(global_raw)
        if parsed is None:
            logger.warning("Invalid SHADOW_AGENT_LOG_RETENTION_DAYS=%r; using default retention.", global_raw)
        else:
            return parsed

    return default


def cleanup_interval_seconds() -> int:
    raw = os.getenv("SHADOW_AGENT_RETENTION_CLEANUP_INTERVAL_SECONDS", "").strip()
    if raw:
        try:
            return max(_MIN_CLEANUP_INTERVAL_SECONDS, int(raw))
        except ValueError:
            logger.warning("Invalid SHADOW_AGENT_RETENTION_CLEANUP_INTERVAL_SECONDS=%r; using default.", raw)
    return DEFAULT_CLEANUP_INTERVAL_SECONDS


def _purge_table(db: Session, table_label: str, model: Any, timestamp_column: Any, retention_days: int) -> int:
    """Delete expired rows in bounded batches. Returns number of rows purged."""
    if retention_days <= 0:
        return 0  # keep forever

    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    purged = 0
    for _ in range(_MAX_BATCHES_PER_CYCLE):
        expired_ids = [
            row_id
            for (row_id,) in db.query(model.id)
            .filter(timestamp_column < cutoff)
            .order_by(model.id.asc())
            .limit(_BATCH_SIZE)
            .all()
        ]
        if not expired_ids:
            break

        db.query(model).filter(model.id.in_(expired_ids)).delete(synchronize_session=False)
        db.commit()
        purged += len(expired_ids)

    return purged


def run_retention_cleanup() -> dict[str, int]:
    """Run one retention cycle against all log tables. Returns purged counts."""
    purged_counts: dict[str, int] = {}

    db = SessionLocal()
    try:
        for table_label, model, timestamp_column, override_env, default_days in _RETENTION_TABLES:
            retention_days = _retention_days(override_env, default_days)
            if retention_days <= 0:
                logger.info("Retention disabled for %s (keep forever).", table_label)
                continue

            purged = _purge_table(db, table_label, model, timestamp_column, retention_days)
            purged_counts[table_label] = purged
            if purged:
                logger.info(
                    "Retention purge: removed %d rows older than %d days from %s.",
                    purged,
                    retention_days,
                    table_label,
                )
    finally:
        db.close()

    if any(purged_counts.values()):
        try:
            from app.metrics import record_retention_purged

            for table_label, count in purged_counts.items():
                record_retention_purged(table_label, count)
        except ImportError:
            pass

    return purged_counts
