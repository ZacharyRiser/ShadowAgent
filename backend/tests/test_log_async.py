"""Logging must not execute its sink on the calling (event-loop) thread.

``tools/bench_log_blocking.py`` measures the latency effect; these tests pin the
mechanism, so a refactor back to ``logging.basicConfig`` fails loudly instead of
quietly reintroducing a request-latency coupling.
"""

from __future__ import annotations

import contextlib
import io
import logging
import logging.handlers
import os
import queue
import threading
import time

import pytest

from app import logging_setup
from app.logging_setup import (
    DEFAULT_QUEUE_SIZE,
    MODE_ASYNC,
    MODE_SYNC,
    MODE_UNCONFIGURED,
    configure_logging,
    log_stats,
    shutdown_logging,
)

_TRACKED_ENV = ("SHADOW_AGENT_LOG_ASYNC", "SHADOW_AGENT_LOG_QUEUE_SIZE")


@pytest.fixture(autouse=True)
def _isolated_logging_root():
    """Hand every test a clean logging root, then restore what was there."""
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    saved_env = {name: os.environ.get(name) for name in _TRACKED_ENV}

    shutdown_logging()
    try:
        yield
    finally:
        shutdown_logging()
        for handler in list(root.handlers):
            root.removeHandler(handler)
        for handler in saved_handlers:
            root.addHandler(handler)
        root.setLevel(saved_level)
        for name, value in saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _root_handlers_of_type(handler_cls) -> list[logging.Handler]:
    return [h for h in logging.getLogger().handlers if isinstance(h, handler_cls)]


def test_asynchronous_logging_is_the_default() -> None:
    os.environ.pop("SHADOW_AGENT_LOG_ASYNC", None)

    assert configure_logging() == MODE_ASYNC
    stats = log_stats()
    assert stats["async_enabled"] is True
    assert _root_handlers_of_type(logging.handlers.QueueHandler)


def test_opt_out_keeps_logging_synchronous() -> None:
    os.environ["SHADOW_AGENT_LOG_ASYNC"] = "0"

    assert configure_logging() == MODE_SYNC
    stats = log_stats()
    assert stats["async_enabled"] is False
    assert stats["queue_depth"] is None
    assert not _root_handlers_of_type(logging.handlers.QueueHandler)
    assert _root_handlers_of_type(logging.StreamHandler)


def test_configure_logging_is_idempotent() -> None:
    os.environ.pop("SHADOW_AGENT_LOG_ASYNC", None)

    configure_logging()
    before = [id(handler) for handler in logging.getLogger().handlers]
    configure_logging()
    after = [id(handler) for handler in logging.getLogger().handlers]

    assert before == after, "a second configuration must not add a second sink"


def test_records_reach_the_sink_through_the_queue() -> None:
    """Decoupling must not cost delivery: the record still reaches the sink."""
    os.environ.pop("SHADOW_AGENT_LOG_ASYNC", None)
    buffer = io.StringIO()

    with contextlib.redirect_stderr(buffer):
        configure_logging()
        logging.getLogger("shadow_agent.test.delivery").info("queued-delivery-marker")
        deadline = time.monotonic() + 5.0
        while "queued-delivery-marker" not in buffer.getvalue() and time.monotonic() < deadline:
            time.sleep(0.01)

    assert "queued-delivery-marker" in buffer.getvalue()


def test_sink_executes_on_a_thread_other_than_the_caller() -> None:
    """The load-bearing property: a slow sink cannot occupy the calling thread.

    Asserted through thread identity rather than elapsed time so the test cannot
    become flaky on a loaded machine.
    """
    delivered = threading.Event()
    sink_threads: list[int] = []

    class _ThreadRecordingSink(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            sink_threads.append(threading.get_ident())
            delivered.set()

    log_queue: queue.Queue = queue.Queue()
    listener = logging.handlers.QueueListener(log_queue, _ThreadRecordingSink())
    listener.start()

    logger = logging.getLogger("shadow_agent.test.thread_identity")
    logger.handlers = [logging_setup._DropCountingQueueHandler(log_queue)]
    logger.propagate = False
    logger.setLevel(logging.INFO)

    try:
        caller_thread = threading.get_ident()
        logger.info("thread-identity")
        assert delivered.wait(5.0), "the sink never received the record"
    finally:
        listener.stop()
        logger.handlers = []

    assert sink_threads and sink_threads[0] != caller_thread


def test_full_queue_drops_records_instead_of_raising() -> None:
    """A saturated queue must degrade to dropped+counted, never to an exception
    escaping from a logging call on the request path."""
    handler = logging_setup._DropCountingQueueHandler(queue.Queue(maxsize=1))
    logger = logging.getLogger("shadow_agent.test.drop")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)

    try:
        for index in range(3):
            logger.info("drop-me-%d", index)
    finally:
        logger.handlers = []

    assert handler.queued == 1
    assert handler.dropped == 2


@pytest.mark.parametrize("raw", ["abc", "-5", "1.5"])
def test_unusable_queue_size_falls_back_to_the_default(raw: str) -> None:
    os.environ.pop("SHADOW_AGENT_LOG_ASYNC", None)
    os.environ["SHADOW_AGENT_LOG_QUEUE_SIZE"] = raw

    assert configure_logging() == MODE_ASYNC
    assert log_stats()["queue_size"] == DEFAULT_QUEUE_SIZE


def test_shutdown_detaches_the_handler_and_is_idempotent() -> None:
    os.environ.pop("SHADOW_AGENT_LOG_ASYNC", None)

    configure_logging()
    assert _root_handlers_of_type(logging.handlers.QueueHandler)

    shutdown_logging()
    shutdown_logging()

    assert not _root_handlers_of_type(logging.handlers.QueueHandler)
    assert log_stats()["mode"] == MODE_UNCONFIGURED


def test_metrics_expose_log_path_health() -> None:
    from app.metrics import render_metrics

    text = render_metrics()
    for name in (
        "shadow_agent_log_async_enabled",
        "shadow_agent_log_queue_depth",
        "shadow_agent_log_queued_total",
        "shadow_agent_log_dropped_total",
    ):
        assert f"# TYPE {name}" in text, name
