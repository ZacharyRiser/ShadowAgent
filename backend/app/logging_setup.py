"""Central logging configuration — keeps the sink off the event loop.

``logging.basicConfig`` runs the sink inside whichever thread calls the logger.
The gateway logs from the request path (``app.audit``, ``app.routers.gateway``,
``main``), which on a running server is the asyncio event loop. A synchronous
sink therefore turns log volume into request latency.

Measured with ``tools/bench_log_blocking.py`` (200 records, 50 bursts, worst of
3 runs) — p50 event-loop lag, sink cost per record:

===========================  ==========  ==========  ==========  ==========
sink                         0 ms        1 ms        5 ms        20 ms
===========================  ==========  ==========  ==========  ==========
inline (``basicConfig``)     7.5         17.9        64.7        245.3
queued (``QueueHandler``)    0.1         0.1         4.5         0.2
===========================  ==========  ==========  ==========  ==========

The inline path scales linearly with sink cost — a 20 ms/record sink consumes
the loop for ~245 ms at a time. The queued path is flat, i.e. worst-case latency
stops depending on where the logs are going.

The decoupled path is therefore the default. ``SHADOW_AGENT_LOG_ASYNC=0``
restores strictly synchronous logging.

Trade-off, stated plainly: with the default stderr sink the two modes are
indistinguishable (measured 0.3 ms vs 0.1 ms p50), so this buys insurance
against slow sinks rather than a speedup. In exchange, log records reach the
sink a moment later and a hard ``SIGKILL`` can lose the tail of the queue.
Records dropped because a permanent backlog overflowed the queue are counted
and exported on ``/metrics`` (``shadow_agent_log_dropped_total``) so that a
silent outage of the log path is not possible.
"""

from __future__ import annotations

import atexit
import logging
import logging.handlers
import os
import queue
import threading

__all__ = [
    "configure_logging",
    "shutdown_logging",
    "log_stats",
    "DEFAULT_QUEUE_SIZE",
    "LOG_FORMAT",
]

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
LOG_LEVEL = logging.INFO
DEFAULT_QUEUE_SIZE = 10000

MODE_ASYNC = "async"
MODE_SYNC = "sync"
MODE_UNCONFIGURED = "unconfigured"

_state_lock = threading.Lock()
_queue: queue.Queue | None = None
_listener: logging.handlers.QueueListener | None = None
_installed_handler: logging.Handler | None = None
_active_mode = MODE_UNCONFIGURED


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw not in {"0", "false", "no", "off"}


def _env_non_negative_int(name: str, default: int) -> int:
    """Parse an int env var, falling back (with a warning) when unusable.

    A typo in a deployment's config must not take the gateway down, so an
    unusable value is reported and ignored rather than raised.
    """
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        logging.getLogger("shadow_agent.logging").warning(
            "%s=%r is not an integer; using default %d", name, raw, default
        )
        return default
    if value < 0:
        logging.getLogger("shadow_agent.logging").warning(
            "%s=%d is negative; using default %d", name, value, default
        )
        return default
    return value


class _DropCountingQueueHandler(logging.handlers.QueueHandler):
    """Queue handler that never blocks and never raises when the queue is full.

    A bounded queue protects the gateway from unbounded memory growth when the
    sink cannot keep up. The cost is that a permanent backlog has to drop
    something; ``QueueHandler`` would let ``queue.Full`` escape into
    ``handleError`` (stderr traceback spam, record lost anyway). Here the drop
    is counted instead, and the counter is exported on ``/metrics``.
    """

    def __init__(self, log_queue: queue.Queue) -> None:
        super().__init__(log_queue)
        self.queued = 0
        self.dropped = 0
        self._counter_lock = threading.Lock()

    def enqueue(self, record: logging.LogRecord) -> None:
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            with self._counter_lock:
                self.dropped += 1
            return
        with self._counter_lock:
            self.queued += 1


def configure_logging() -> str:
    """Install the root logging configuration. Returns the active mode.

    Idempotent: a second call with the same process state is a no-op, which
    matters because ``main`` configures at import and tests import ``main``
    repeatedly.
    """
    global _queue, _listener, _installed_handler, _active_mode

    with _state_lock:
        if _active_mode != MODE_UNCONFIGURED:
            return _active_mode

        root = logging.getLogger()
        root.setLevel(LOG_LEVEL)
        for existing in list(root.handlers):
            # Never detach pytest's capture handler. Configuration runs at import
            # time, i.e. during collection, and removing it there would silently
            # disable ``caplog`` for the entire run.
            if type(existing).__module__.startswith("_pytest"):
                continue
            root.removeHandler(existing)

        sink = logging.StreamHandler()
        sink.setFormatter(logging.Formatter(LOG_FORMAT))
        sink.setLevel(LOG_LEVEL)

        if not _env_flag("SHADOW_AGENT_LOG_ASYNC", True):
            root.addHandler(sink)
            _installed_handler = sink
            _active_mode = MODE_SYNC
            return _active_mode

        size = _env_non_negative_int("SHADOW_AGENT_LOG_QUEUE_SIZE", DEFAULT_QUEUE_SIZE)
        log_queue: queue.Queue = queue.Queue(maxsize=size) if size > 0 else queue.Queue()
        handler = _DropCountingQueueHandler(log_queue)
        listener = logging.handlers.QueueListener(log_queue, sink, respect_handler_level=True)
        listener.start()

        root.addHandler(handler)
        _queue, _listener, _installed_handler = log_queue, listener, handler
        _active_mode = MODE_ASYNC
        # Flush the tail on a normal interpreter exit. Deliberately not hooked to
        # the ASGI lifespan: the lifespan ends between TestClient contexts too,
        # and tearing logging down there would leave the process logging into a
        # stopped listener's queue.
        atexit.register(shutdown_logging)
        return _active_mode


def shutdown_logging() -> None:
    """Drain the queue and stop the listener thread. Safe to call twice."""
    global _queue, _listener, _installed_handler, _active_mode

    with _state_lock:
        listener, _listener = _listener, None
        handler, _installed_handler = _installed_handler, None
        _queue = None
        _active_mode = MODE_UNCONFIGURED

    # Detach before stopping: a handler left on the root logger would otherwise
    # keep accepting records into a queue nobody is draining.
    if handler is not None:
        logging.getLogger().removeHandler(handler)
    if listener is not None:
        listener.stop()


def log_stats() -> dict:
    """Snapshot for ``/metrics`` and diagnostics."""
    with _state_lock:
        handler = _installed_handler
        log_queue = _queue
        mode = _active_mode

    depth: int | None = None
    if log_queue is not None:
        try:
            depth = log_queue.qsize()
        except NotImplementedError:  # pragma: no cover - platform dependent
            depth = None

    return {
        "mode": mode,
        "async_enabled": mode == MODE_ASYNC,
        "queue_size": getattr(log_queue, "maxsize", None),
        "queue_depth": depth,
        "queued": getattr(handler, "queued", 0),
        "dropped": getattr(handler, "dropped", 0),
    }
