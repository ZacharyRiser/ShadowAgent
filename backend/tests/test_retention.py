"""Tests for the automatic log retention cleanup (app/retention.py)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from database import SessionLocal
from models import AlertEvent, AuditLog, InterceptLog, ReplayRun


def _seed_log_rows(age_days: int, marker: str) -> None:
    """Insert one row per log table with the given age."""
    old_timestamp = datetime.utcnow() - timedelta(days=age_days)
    db = SessionLocal()
    try:
        db.add(
            InterceptLog(
                request_id=f"retention-{marker}",
                timestamp=old_timestamp,
                threat_type="Prompt Injection",
                action_taken="Blocked",
                original_prompt=f"retention test {marker}",
                details="{}",
            )
        )
        db.add(
            AuditLog(
                timestamp=old_timestamp,
                request_id=f"retention-{marker}",
                original_instruction=f"retention test {marker}",
                risk_level="info",
                triggered_rule_name="retention-test",
                intercept_reason="{}",
            )
        )
        db.add(
            AlertEvent(
                request_id=f"retention-{marker}",
                severity="medium",
                title=f"retention test {marker}",
                created_at=old_timestamp,
            )
        )
        db.add(
            ReplayRun(
                source_request_id=f"retention-{marker}",
                replay_request_id=f"replay-retention-{marker}-{uuid.uuid4().hex[:8]}",
                created_at=old_timestamp,
            )
        )
        db.commit()
    finally:
        db.close()


def _count_rows_with_request_id(request_id: str) -> tuple[int, int, int, int]:
    db = SessionLocal()
    try:
        return (
            db.query(InterceptLog).filter(InterceptLog.request_id == request_id).count(),
            db.query(AuditLog).filter(AuditLog.request_id == request_id).count(),
            db.query(AlertEvent).filter(AlertEvent.request_id == request_id).count(),
            db.query(ReplayRun).filter(ReplayRun.source_request_id == request_id).count(),
        )
    finally:
        db.close()


def test_retention_purges_expired_rows_and_keeps_recent(
    monkeypatch,
) -> None:
    from app.retention import run_retention_cleanup

    old_marker = f"old-{uuid.uuid4().hex[:8]}"
    new_marker = f"new-{uuid.uuid4().hex[:8]}"
    _seed_log_rows(age_days=90, marker=old_marker)
    _seed_log_rows(age_days=1, marker=new_marker)

    # Global retention window of 30 days: 90-day rows must go, 1-day stay.
    monkeypatch.setenv("SHADOW_AGENT_LOG_RETENTION_DAYS", "30")
    purged = run_retention_cleanup()

    assert purged.get("intercept_logs", 0) >= 1
    assert purged.get("audit_logs", 0) >= 1
    assert purged.get("alert_events", 0) >= 1
    assert purged.get("replay_runs", 0) >= 1

    assert _count_rows_with_request_id(f"retention-{old_marker}") == (0, 0, 0, 0)
    assert _count_rows_with_request_id(f"retention-{new_marker}") == (1, 1, 1, 1)


def test_retention_per_table_override_disables_a_table(
    monkeypatch,
) -> None:
    from app.retention import run_retention_cleanup

    marker = f"keep-{uuid.uuid4().hex[:8]}"
    _seed_log_rows(age_days=400, marker=marker)

    monkeypatch.setenv("SHADOW_AGENT_LOG_RETENTION_DAYS", "30")
    # Audit logs kept forever via per-table override (<=0 disables purging).
    monkeypatch.setenv("SHADOW_AGENT_AUDIT_LOG_RETENTION_DAYS", "0")

    run_retention_cleanup()

    intercept, audit, alert, replay = _count_rows_with_request_id(f"retention-{marker}")
    assert intercept == 0  # 400 days > 30-day global window
    assert audit == 1  # override keeps audit logs
    assert alert == 0
    assert replay == 0


def test_retention_counter_exposed_in_metrics(
    monkeypatch,
) -> None:
    from app.metrics import render_metrics
    from app.retention import run_retention_cleanup

    marker = f"metric-{uuid.uuid4().hex[:8]}"
    _seed_log_rows(age_days=400, marker=marker)
    monkeypatch.setenv("SHADOW_AGENT_LOG_RETENTION_DAYS", "30")
    monkeypatch.delenv("SHADOW_AGENT_AUDIT_LOG_RETENTION_DAYS", raising=False)

    run_retention_cleanup()

    body = render_metrics()
    assert "shadow_agent_retention_purged_rows_total" in body
    assert 'table="intercept_logs"' in body


def test_cleanup_interval_config_validation(monkeypatch) -> None:
    from app.retention import cleanup_interval_seconds

    monkeypatch.delenv("SHADOW_AGENT_RETENTION_CLEANUP_INTERVAL_SECONDS", raising=False)
    assert cleanup_interval_seconds() == 3600

    monkeypatch.setenv("SHADOW_AGENT_RETENTION_CLEANUP_INTERVAL_SECONDS", "5")
    assert cleanup_interval_seconds() == 60  # clamped to minimum

    monkeypatch.setenv("SHADOW_AGENT_RETENTION_CLEANUP_INTERVAL_SECONDS", "7200")
    assert cleanup_interval_seconds() == 7200

    monkeypatch.setenv("SHADOW_AGENT_RETENTION_CLEANUP_INTERVAL_SECONDS", "not-a-number")
    assert cleanup_interval_seconds() == 3600  # invalid falls back to default
