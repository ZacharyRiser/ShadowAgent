"""Dependency-free Prometheus exposition metrics for the gateway.

Collects per-route request counters and latency histograms in-process.
Cardinality stays bounded because paths are normalized to route templates
(``/api/v1/logs``) or digit-collapsed fallbacks (``/api/v1/policies/{id}``).
"""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.logging_setup import log_stats
from security_controls import Principal, require_admin


LATENCY_BUCKETS = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
)
_DIGIT_SEGMENTS = re.compile(r"/\d+(/|$)")

_lock = threading.Lock()
_request_counts: dict[tuple[str, str, str], int] = defaultdict(int)
_latency_buckets: dict[tuple[str, float], int] = defaultdict(int)
_latency_sums: dict[str, float] = defaultdict(float)
_latency_counts: dict[str, int] = defaultdict(int)
_retention_purged: dict[str, int] = defaultdict(int)


def record_retention_purged(table: str, count: int) -> None:
    """Track rows removed by the retention cleanup job (see app/retention.py)."""
    if count <= 0:
        return
    with _lock:
        _retention_purged[table] += count


# --- security decision metrics ----------------------------------------------
#
# The question these answer is the one an operator asks first: "how many
# injections did we stop today, and how close is normal traffic to the
# threshold?" Before this, ``/metrics`` only exposed HTTP-level counters, so
# the security posture was invisible to Prometheus/Grafana.
#
# Cardinality is bounded on purpose. ``layer`` and ``threat_type`` are values
# the code itself produces, but they arrive here as free strings, so each label
# family is capped: once ``_MAX_LABEL_VALUES`` distinct values have been seen,
# anything new collapses into ``other``. A novel or hostile value therefore
# cannot grow the label set without bound.

SEMANTIC_SCORE_BUCKETS = (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0)
OTHER_LABEL = "other"
_MAX_LABEL_VALUES = 64
_TOOL_SCOPE_PREFIX = "tool_calls["

_security_actions = frozenset({"Blocked", "Monitored", "Redacted", "Allowed"})

_security_decisions: dict[tuple[str, str, str], int] = defaultdict(int)
_dlp_actions: dict[tuple[str, str], int] = defaultdict(int)
_dlp_matches: dict[str, int] = defaultdict(int)
_semantic_buckets: dict[tuple[str, float], int] = defaultdict(int)
_semantic_sums: dict[str, float] = defaultdict(float)
_semantic_counts: dict[str, int] = defaultdict(int)
_body_rejected: dict[str, int] = defaultdict(int)

_seen_layers: set[str] = set()
_seen_threat_types: set[str] = set()
_seen_dlp_scopes: set[str] = set()


def _bounded_label(seen: set[str], value: str) -> str:
    """Fold unseen label values into ``other`` once the family is saturated."""
    if value in seen:
        return value
    if len(seen) >= _MAX_LABEL_VALUES:
        return OTHER_LABEL
    seen.add(value)
    return value


def _normalize_dlp_scope(raw: object) -> str:
    """Map a scan scope onto a bounded label.

    Streaming scans label their scope ``tool_calls[3].function.arguments``. The
    index is per-request and unbounded, so it must be collapsed before it can
    become a Prometheus label.
    """
    text = raw if isinstance(raw, str) and raw else "unknown"
    if text.startswith(_TOOL_SCOPE_PREFIX):
        text = "tool_arguments"
    return _bounded_label(_seen_dlp_scopes, text)


def record_security_decision(*, layer: str, threat_type: str, action: str) -> None:
    """Count one security decision (block / monitor / redact) by threat type."""
    with _lock:
        _security_decisions[
            (
                _bounded_label(_seen_layers, layer),
                _bounded_label(_seen_threat_types, threat_type),
                action if action in _security_actions else OTHER_LABEL,
            )
        ] += 1


def record_semantic_score(*, layer: str, score: float) -> None:
    """Observe one semantic-layer score, for allowed and blocked traffic alike.

    Recording allowed traffic is the point: the operator needs to see how much
    benign volume is piling up just below the threshold.
    """
    value = float(score)
    with _lock:
        label = _bounded_label(_seen_layers, layer)
        _semantic_counts[label] += 1
        _semantic_sums[label] += value
        for bucket in SEMANTIC_SCORE_BUCKETS:
            if value <= bucket:
                _semantic_buckets[(label, bucket)] += 1
                break
        _semantic_buckets[(label, float("inf"))] += 1


_BODY_REJECT_REASONS = frozenset({"declared", "actual"})

#: Retry reasons emitted by app/upstream_resilience.py. Bounded on purpose: the
#: label is a code-produced constant, not free text.
_UPSTREAM_RETRY_REASONS = frozenset(
    {"connect", "rate_limit", "timeout", "server_error"}
)

_upstream_retries: dict[str, int] = defaultdict(int)


def record_upstream_retry(*, reason: str) -> None:
    """Count one scheduled retry against the upstream provider.

    A rising ``connect`` count means the network path to the provider is
    flapping; ``rate_limit`` means the provider is throttling us; ``timeout`` and
    ``server_error`` only appear when unsafe retries were explicitly enabled.
    """
    with _lock:
        _upstream_retries[
            reason if reason in _UPSTREAM_RETRY_REASONS else OTHER_LABEL
        ] += 1


def record_body_rejected(*, reason: str) -> None:
    """Count a request refused by the body-size guard (app/request_guards.py).

    ``declared`` means ``Content-Length`` alone exceeded the ceiling, so no body
    byte was read; ``actual`` means the running total crossed it while reading,
    i.e. the client lied about or omitted the length. A spike in ``actual`` is a
    different signal from a spike in ``declared``: the first suggests a client
    that is actively trying to get around the check.
    """
    with _lock:
        _body_rejected[
            reason if reason in _BODY_REJECT_REASONS else OTHER_LABEL
        ] += 1


def record_dlp_scan(*, scopes: object, action: str, matches: int) -> None:
    """Count one response-side DLP action across every scope it touched."""
    if isinstance(scopes, str):
        scope_list: list[str] = [scopes]
    elif isinstance(scopes, (list, tuple, set)):
        scope_list = [item for item in scopes if isinstance(item, str)]
    else:
        scope_list = []
    if not scope_list:
        scope_list = ["unknown"]

    normalized = sorted({_normalize_dlp_scope(scope) for scope in scope_list})
    with _lock:
        for scope in normalized:
            _dlp_actions[(scope, action if action in _security_actions else OTHER_LABEL)] += 1
            _dlp_matches[scope] += max(0, int(matches))

router = APIRouter(tags=["metrics"])


class MetricsMiddleware(BaseHTTPMiddleware):
    """Record request count and latency for every served request."""

    async def dispatch(self, request: Request, call_next):
        started = time.perf_counter()
        status_code = 500
        route_template = _route_template(request)
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            if route_template != "/metrics":
                elapsed = time.perf_counter() - started
                _record(route_template, request.method, status_code, elapsed)


def _route_template(request: Request) -> str:
    """Prefer the matched route template; collapse numeric ids otherwise."""
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    if isinstance(path, str) and path:
        return path
    raw_path = request.url.path
    return _DIGIT_SEGMENTS.sub("/{id}\\1", raw_path)


def _record(route: str, method: str, status_code: int, elapsed: float) -> None:
    with _lock:
        _request_counts[(method, str(status_code), route)] += 1
        _latency_counts[route] += 1
        _latency_sums[route] += elapsed
        for bucket in LATENCY_BUCKETS:
            if elapsed <= bucket:
                _latency_buckets[(route, bucket)] += 1
                break
        _latency_buckets[(route, float("inf"))] += 1


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _pool_snapshot() -> dict[str, Any] | None:
    """Live connection-pool state, or None if the DB layer is unavailable.

    Imported lazily so this renderer stays usable (and unit-testable) without
    initialising a database engine.
    """
    try:
        from database import pool_stats
    except ImportError:  # pragma: no cover - only when the DB layer is absent
        return None
    return pool_stats()


def _render_pool_metrics(lines: list[str]) -> None:
    """Expose pool saturation, which used to be invisible from the outside.

    When the pool ceiling is reached, ``pool.checkout()`` blocks the event loop:
    the gateway stops answering with no 5xx and no log line. Nothing about that
    was observable from ``/metrics``, so the 2026-09-20 outage looked like a
    network fault. ``saturation_events_total`` and the ``in_use`` gauge are the
    two signals an operator should alarm on.
    """
    pool = _pool_snapshot()
    if not pool:
        return

    lines.append("# HELP shadow_agent_db_pool_connections DB connection-pool usage.")
    lines.append("# TYPE shadow_agent_db_pool_connections gauge")
    for state in ("in_use", "available", "overflow"):
        value = pool.get(state)
        if value is None:
            continue
        lines.append('shadow_agent_db_pool_connections{state="%s"} %d' % (state, value))

    lines.append("# HELP shadow_agent_db_pool_capacity Configured ceiling (pool_size + max_overflow); 0 means no ceiling.")
    lines.append("# TYPE shadow_agent_db_pool_capacity gauge")
    lines.append("shadow_agent_db_pool_capacity %d" % (pool.get("capacity") or 0))

    lines.append("# HELP shadow_agent_db_pool_checkouts_total Connections handed out since start.")
    lines.append("# TYPE shadow_agent_db_pool_checkouts_total counter")
    lines.append("shadow_agent_db_pool_checkouts_total %d" % (pool.get("checkouts") or 0))

    lines.append("# HELP shadow_agent_db_pool_max_in_use_since_start High-water mark of simultaneously held connections. Approaching capacity means the next traffic burst will stall the gateway.")
    lines.append("# TYPE shadow_agent_db_pool_max_in_use_since_start gauge")
    lines.append(
        "shadow_agent_db_pool_max_in_use_since_start %d" % (pool.get("max_in_use") or 0)
    )

    lines.append("# HELP shadow_agent_db_pool_saturated_checkouts_total Checkouts granted while every connection was already held. A LOWER BOUND: a request that blocks in checkout() and gives up never reaches this event.")
    lines.append("# TYPE shadow_agent_db_pool_saturated_checkouts_total counter")
    lines.append(
        "shadow_agent_db_pool_saturated_checkouts_total %d"
        % (pool.get("saturated_checkouts") or 0)
    )

    lines.append("# HELP shadow_agent_db_pool_timeout_total Requests that gave up waiting for a connection (sqlalchemy.exc.TimeoutError). This is the accurate starvation count: any non-zero value means the gateway stalled.")
    lines.append("# TYPE shadow_agent_db_pool_timeout_total counter")
    lines.append(
        "shadow_agent_db_pool_timeout_total %d" % (pool.get("timeouts") or 0)
    )


def _render_log_metrics(lines: list[str]) -> None:
    """Expose the log path's own health.

    The log sink runs on a background thread by default (app/logging_setup.py),
    which buys latency independence but makes the queue a hidden buffer: if the
    sink is permanently slower than the log rate, the queue fills and records
    start being dropped. ``dropped`` being non-zero is the alarm; ``depth``
    trending up is the early warning.
    """
    stats = log_stats()

    lines.append("# HELP shadow_agent_log_async_enabled 1 when log records are handed to a background sink thread, 0 when the sink runs inline on the caller.")
    lines.append("# TYPE shadow_agent_log_async_enabled gauge")
    lines.append("shadow_agent_log_async_enabled %d" % (1 if stats.get("async_enabled") else 0))

    lines.append("# HELP shadow_agent_log_queue_depth Log records waiting for the sink thread. Sustained growth means the sink cannot keep up.")
    lines.append("# TYPE shadow_agent_log_queue_depth gauge")
    depth = stats.get("queue_depth")
    if depth is not None:
        lines.append("shadow_agent_log_queue_depth %d" % depth)

    lines.append("# HELP shadow_agent_log_queued_total Log records handed to the sink thread.")
    lines.append("# TYPE shadow_agent_log_queued_total counter")
    lines.append("shadow_agent_log_queued_total %d" % (stats.get("queued") or 0))

    lines.append("# HELP shadow_agent_log_dropped_total Log records discarded because the queue was full. Any non-zero value means the log path is losing records.")
    lines.append("# TYPE shadow_agent_log_dropped_total counter")
    lines.append("shadow_agent_log_dropped_total %d" % (stats.get("dropped") or 0))


def _remote_fallback_snapshot() -> dict[str, Any] | None:
    """Remote arbitration state, or None when that module is unavailable."""
    try:
        from app.remote_fallback import remote_fallback_status
    except ImportError:  # pragma: no cover - only when the module is absent
        return None
    return remote_fallback_status()


def _render_remote_fallback_metrics(lines: list[str]) -> None:
    """Expose whether the optional remote channel is on, and how it behaves.

    ``enabled=0`` is the default and the shipping configuration. When it is 1,
    ``outcome="error"`` climbing means the gateway is paying the latency of the
    lookup without getting a verdict, and the caller is falling back to the local
    decision — worth alerting on even though it is not an outage.
    """
    stats = _remote_fallback_snapshot()
    if not stats:
        return

    lines.append("# HELP shadow_agent_remote_fallback_enabled 1 when ambiguous traffic may be arbitrated by a remote LLM, 0 when the gateway calls nothing (default).")
    lines.append("# TYPE shadow_agent_remote_fallback_enabled gauge")
    lines.append("shadow_agent_remote_fallback_enabled %d" % (1 if stats.get("enabled") else 0))

    lines.append("# HELP shadow_agent_remote_fallback_total Remote arbitration outcomes.")
    lines.append("# TYPE shadow_agent_remote_fallback_total counter")
    counters = stats.get("counters") or {}
    for outcome in ("allowed", "blocked", "error", "timeout", "skipped"):
        lines.append(
            'shadow_agent_remote_fallback_total{outcome="%s"} %d'
            % (outcome, counters.get(outcome, 0))
        )

    lines.append("# HELP shadow_agent_remote_fallback_duration_seconds Latency of remote arbitration calls.")
    lines.append("# TYPE shadow_agent_remote_fallback_duration_seconds summary")
    lines.append(
        "shadow_agent_remote_fallback_duration_seconds_sum %.6f"
        % ((stats.get("latency_sum_ms") or 0.0) / 1000.0)
    )
    lines.append(
        "shadow_agent_remote_fallback_duration_seconds_count %d"
        % (stats.get("latency_count") or 0)
    )


def _render_upstream_circuit_metrics(lines: list[str]) -> None:
    """Expose the upstream breaker state.

    ``state="open"`` at 1 means the gateway is shedding traffic on purpose
    because the provider kept failing: callers get a fast 503 instead of a
    queued timeout. ``half_open`` means a single probe is in flight, so a run of
    them that never returns to ``closed`` says the provider is still down.
    """
    try:
        from app.upstream_resilience import upstream_circuit_breaker
    except ImportError:  # pragma: no cover - only when the module is absent
        return

    breaker = upstream_circuit_breaker()
    current = breaker.state_name()

    lines.append("# HELP shadow_agent_upstream_circuit_state Current upstream circuit-breaker state (1 = active).")
    lines.append("# TYPE shadow_agent_upstream_circuit_state gauge")
    for state in ("closed", "half_open", "open"):
        lines.append(
            'shadow_agent_upstream_circuit_state{state="%s"} %d'
            % (state, 1 if current == state else 0)
        )

    lines.append("# HELP shadow_agent_upstream_circuit_opened_total Times the upstream breaker opened or re-opened.")
    lines.append("# TYPE shadow_agent_upstream_circuit_opened_total counter")
    lines.append(
        "shadow_agent_upstream_circuit_opened_total %d" % breaker.open_total()
    )


def render_metrics() -> str:
    """Render counters/histograms in Prometheus text exposition format."""
    lines: list[str] = []

    with _lock:
        request_snapshot = dict(_request_counts)
        bucket_snapshot = dict(_latency_buckets)
        sum_snapshot = dict(_latency_sums)
        count_snapshot = dict(_latency_counts)
        retention_snapshot = dict(_retention_purged)
        decision_snapshot = dict(_security_decisions)
        dlp_action_snapshot = dict(_dlp_actions)
        dlp_match_snapshot = dict(_dlp_matches)
        semantic_bucket_snapshot = dict(_semantic_buckets)
        semantic_sum_snapshot = dict(_semantic_sums)
        semantic_count_snapshot = dict(_semantic_counts)
        body_rejected_snapshot = dict(_body_rejected)
        upstream_retry_snapshot = dict(_upstream_retries)

    lines.append("# HELP shadow_agent_http_requests_total Total HTTP requests handled.")
    lines.append("# TYPE shadow_agent_http_requests_total counter")
    for (method, status, route), count in sorted(request_snapshot.items()):
        lines.append(
            'shadow_agent_http_requests_total{method="%s",status="%s",route="%s"} %d'
            % (_escape_label(method), _escape_label(status), _escape_label(route), count)
        )

    lines.append("# HELP shadow_agent_http_request_duration_seconds HTTP request latency.")
    lines.append("# TYPE shadow_agent_http_request_duration_seconds histogram")
    routes = sorted(set(count_snapshot) | {route for route, _ in bucket_snapshot})
    for route in routes:
        for bucket in LATENCY_BUCKETS:
            lines.append(
                'shadow_agent_http_request_duration_seconds_bucket{route="%s",le="%s"} %d'
                % (_escape_label(route), _format_le(bucket), bucket_snapshot.get((route, bucket), 0))
            )
        lines.append(
            'shadow_agent_http_request_duration_seconds_bucket{route="%s",le="+Inf"} %d'
            % (_escape_label(route), bucket_snapshot.get((route, float("inf")), 0))
        )
        lines.append(
            'shadow_agent_http_request_duration_seconds_sum{route="%s"} %.6f'
            % (_escape_label(route), sum_snapshot.get(route, 0.0))
        )
        lines.append(
            'shadow_agent_http_request_duration_seconds_count{route="%s"} %d'
            % (_escape_label(route), count_snapshot.get(route, 0))
        )

    lines.append("# HELP shadow_agent_security_decisions_total Security decisions by layer, threat type and action.")
    lines.append("# TYPE shadow_agent_security_decisions_total counter")
    for (layer, threat_type, action), count in sorted(decision_snapshot.items()):
        lines.append(
            'shadow_agent_security_decisions_total{layer="%s",threat_type="%s",action="%s"} %d'
            % (
                _escape_label(layer),
                _escape_label(threat_type),
                _escape_label(action),
                count,
            )
        )

    lines.append("# HELP shadow_agent_semantic_score Raw calibrated injection probability from the semantic layer, over every scanned text slice (allowed traffic included).")
    lines.append("# TYPE shadow_agent_semantic_score histogram")
    semantic_labels = sorted(
        set(semantic_count_snapshot) | {label for label, _ in semantic_bucket_snapshot}
    )
    for label in semantic_labels:
        for bucket in SEMANTIC_SCORE_BUCKETS:
            lines.append(
                'shadow_agent_semantic_score_bucket{layer="%s",le="%s"} %d'
                % (
                    _escape_label(label),
                    _format_le(bucket),
                    semantic_bucket_snapshot.get((label, bucket), 0),
                )
            )
        lines.append(
            'shadow_agent_semantic_score_bucket{layer="%s",le="+Inf"} %d'
            % (_escape_label(label), semantic_bucket_snapshot.get((label, float("inf")), 0))
        )
        lines.append(
            'shadow_agent_semantic_score_sum{layer="%s"} %.6f'
            % (_escape_label(label), semantic_sum_snapshot.get(label, 0.0))
        )
        lines.append(
            'shadow_agent_semantic_score_count{layer="%s"} %d'
            % (_escape_label(label), semantic_count_snapshot.get(label, 0))
        )

    lines.append("# HELP shadow_agent_dlp_actions_total Response-side DLP actions by scope.")
    lines.append("# TYPE shadow_agent_dlp_actions_total counter")
    for (scope, action), count in sorted(dlp_action_snapshot.items()):
        lines.append(
            'shadow_agent_dlp_actions_total{scope="%s",action="%s"} %d'
            % (_escape_label(scope), _escape_label(action), count)
        )

    lines.append("# HELP shadow_agent_dlp_matches_total Sensitive-data pattern matches found by the response DLP by scope.")
    lines.append("# TYPE shadow_agent_dlp_matches_total counter")
    for scope, count in sorted(dlp_match_snapshot.items()):
        lines.append(
            'shadow_agent_dlp_matches_total{scope="%s"} %d'
            % (_escape_label(scope), count)
        )

    lines.append("# HELP shadow_agent_body_rejected_total Requests refused by the body-size guard.")
    lines.append("# TYPE shadow_agent_body_rejected_total counter")
    for reason, count in sorted(body_rejected_snapshot.items()):
        lines.append(
            'shadow_agent_body_rejected_total{reason="%s"} %d'
            % (_escape_label(reason), count)
        )

    lines.append("# HELP shadow_agent_retention_purged_rows_total Rows purged by the retention job.")
    lines.append("# TYPE shadow_agent_retention_purged_rows_total counter")
    for table, count in sorted(retention_snapshot.items()):
        lines.append(
            'shadow_agent_retention_purged_rows_total{table="%s"} %d'
            % (_escape_label(table), count)
        )

    lines.append("# HELP shadow_agent_upstream_retries_total Upstream delivery attempts that were retried, by reason.")
    lines.append("# TYPE shadow_agent_upstream_retries_total counter")
    for reason in sorted(_UPSTREAM_RETRY_REASONS | {OTHER_LABEL}):
        lines.append(
            'shadow_agent_upstream_retries_total{reason="%s"} %d'
            % (_escape_label(reason), upstream_retry_snapshot.get(reason, 0))
        )

    _render_upstream_circuit_metrics(lines)
    _render_pool_metrics(lines)
    _render_log_metrics(lines)
    _render_remote_fallback_metrics(lines)

    lines.append("")
    return "\n".join(lines)


def _format_le(bucket: float) -> str:
    text = f"{bucket:g}"
    return text


@router.get("/metrics")
async def metrics_endpoint(
    principal: Principal = Depends(require_admin),
) -> Response:
    """Prometheus scrape endpoint (admin credentials required)."""
    return Response(
        content=render_metrics(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


def metrics_snapshot() -> dict[str, Any]:
    """Structured snapshot for diagnostics/tests."""
    with _lock:
        return {
            "requests": {
                f"{method}|{status}|{route}": count
                for (method, status, route), count in _request_counts.items()
            },
            "latency_counts": dict(_latency_counts),
            "latency_sums": {k: round(v, 6) for k, v in _latency_sums.items()},
            "security_decisions": {
                f"{layer}|{threat_type}|{action}": count
                for (layer, threat_type, action), count in _security_decisions.items()
            },
            "semantic_scores": {
                "counts": dict(_semantic_counts),
                "sums": {k: round(v, 6) for k, v in _semantic_sums.items()},
            },
            "dlp_actions": {
                f"{scope}|{action}": count
                for (scope, action), count in _dlp_actions.items()
            },
            "dlp_matches": dict(_dlp_matches),
            "body_rejected": dict(_body_rejected),
            "upstream_retries": dict(_upstream_retries),
            "db_pool": _pool_snapshot(),
            "logging": log_stats(),
            "remote_fallback": _remote_fallback_snapshot(),
        }
