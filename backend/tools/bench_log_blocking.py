#!/usr/bin/env python
"""Quantify how much a synchronous logging sink stalls the asyncio event loop.

Why this exists
---------------
``logging.basicConfig`` installs a handler that runs *inside the caller*. Every
``logger.info`` / ``logger.warning`` on the request path therefore executes the
sink on the event loop. With the default stderr sink that costs microseconds and
nobody notices; with a slow sink (network syslog, a file on a loaded volume, a
wrapping handler doing I/O) the cost lands on the loop and the gateway's latency
becomes a function of log volume.

This script measures that, and measures the same workload after decoupling via
``logging.handlers.QueueHandler`` + ``QueueListener``. The claim "decoupling
helps" is then a number instead of an assertion.

Usage (run from ``backend/``)::

    python tools/bench_log_blocking.py
    python tools/bench_log_blocking.py --sink-ms 1,5,20 --requests 50 --per-request 4
    python tools/bench_log_blocking.py --json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import logging.handlers
import queue
import statistics
import sys
import threading
import time

TICK_INTERVAL = 0.001
LOG_MESSAGE = (
    "ShadowAgent intercepted request_id=%s layer=prompt_injection "
    "reason=injection_signature category=prompt_injection risk_score=0.93"
)


MODE_INLINE = "inline"
MODE_QUEUED = "queued"
MODE_QUEUED_YIELD = "queued-yield"
MODES = (MODE_INLINE, MODE_QUEUED, MODE_QUEUED_YIELD)


class SlowSink(logging.Handler):
    """A sink whose per-record cost is a known, configurable sleep."""

    def __init__(self, delay_seconds: float) -> None:
        super().__init__()
        self.delay = delay_seconds
        self.seen = 0

    def emit(self, record: logging.LogRecord) -> None:
        self.seen += 1
        if self.delay > 0:
            time.sleep(self.delay)


class YieldingQueueListener(logging.handlers.QueueListener):
    """A ``QueueListener`` that releases the interpreter lock periodically.

    The stock listener drains its queue in a tight ``while`` loop. Under load it
    can therefore hold the GIL for a whole switch interval (5 ms by default),
    which shows up on the event loop as a tail spike. Yielding every
    ``yield_every`` records bounds that spike; the queue depth absorbs the cost.
    """

    def __init__(self, *args, yield_every: int = 32, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.yield_every = max(1, int(yield_every))
        self._dequeued = 0

    def dequeue(self, block: bool):  # type: ignore[override]
        record = super().dequeue(block)
        if record is not None:
            self._dequeued += 1
            if self._dequeued % self.yield_every == 0:
                time.sleep(0)
        return record


def _build_logger(
    name: str,
    sink: logging.Handler,
    *,
    mode: str,
    queue_size: int,
    yield_every: int = 32,
) -> tuple[logging.Logger, logging.handlers.QueueListener | None]:
    logger = logging.getLogger(name)
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(logging.INFO)
    if mode == MODE_INLINE:
        logger.addHandler(sink)
        return logger, None

    log_queue: queue.Queue = queue.Queue(maxsize=queue_size) if queue_size > 0 else queue.Queue()
    if mode == MODE_QUEUED_YIELD:
        listener = YieldingQueueListener(
            log_queue, sink, respect_handler_level=True, yield_every=yield_every
        )
    else:
        listener = logging.handlers.QueueListener(
            log_queue, sink, respect_handler_level=True
        )
    listener.start()
    logger.addHandler(logging.handlers.QueueHandler(log_queue))
    return logger, listener


async def _emitter(logger: logging.Logger, requests: int, per_request: int) -> None:
    """Emit ``requests`` bursts, yielding to the loop between them.

    Yielding between requests is what a real server does: each request logs a few
    lines and then awaits I/O. What the loop cannot do is preempt a synchronous
    ``emit`` already in progress.
    """
    for request_index in range(requests):
        for _ in range(per_request):
            logger.info(LOG_MESSAGE, request_index)
        await asyncio.sleep(0)


async def _ticker(stop: threading.Event, lags: list[float]) -> None:
    loop = asyncio.get_running_loop()
    expected = loop.time() + TICK_INTERVAL
    while not stop.is_set():
        delay = expected - loop.time()
        await asyncio.sleep(delay if delay > 0 else 0)
        now = loop.time()
        lags.append(max(0.0, now - expected))
        expected = now + TICK_INTERVAL


def measure(
    *,
    delay_seconds: float,
    requests: int,
    per_request: int,
    mode: str,
    queue_size: int,
    label: str,
    yield_every: int = 32,
    sink_factory=None,
) -> dict:
    sink = sink_factory(delay_seconds) if sink_factory else SlowSink(delay_seconds)
    name = "shadow_agent.bench.%s.%s" % (label, time.time_ns())
    logger, listener = _build_logger(
        name, sink, mode=mode, queue_size=queue_size, yield_every=yield_every
    )

    stop = threading.Event()
    lags: list[float] = []

    async def run() -> float:
        ticker = asyncio.create_task(_ticker(stop, lags))
        await asyncio.sleep(0)
        started = time.perf_counter()
        await _emitter(logger, requests, per_request)
        elapsed = time.perf_counter() - started
        stop.set()
        await ticker
        return elapsed

    try:
        elapsed = asyncio.run(run())
    finally:
        if listener is not None:
            listener.stop()
        logger.handlers.clear()

    emitted = requests * per_request
    return {
        "label": label,
        "mode": mode,
        "sink_delay_ms": round(delay_seconds * 1000, 3),
        "requests": requests,
        "per_request": per_request,
        "records": emitted,
        "emit_wall_ms": round(elapsed * 1000, 3),
        "loop_lag_p50_ms": round(statistics.median(lags) * 1000, 3),
        "loop_lag_p95_ms": round(_percentile(lags, 95) * 1000, 3),
        "loop_lag_max_ms": round(max(lags) * 1000, 3) if lags else 0.0,
        "loop_lag_samples": len(lags),
        "sink_records_seen": getattr(sink, "seen", None),
    }


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = (len(ordered) - 1) * (percentile / 100.0)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


def _parse_delays(raw: str) -> list[float]:
    return [float(part) / 1000.0 for part in raw.split(",") if part.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sink-ms", default="0,1,5,20", help="comma-separated per-record sink costs")
    parser.add_argument("--requests", type=int, default=50)
    parser.add_argument("--per-request", type=int, default=4)
    parser.add_argument("--queue-size", type=int, default=10000)
    parser.add_argument("--yield-every", type=int, default=32)
    parser.add_argument("--repeat", type=int, default=1, help="runs per cell; the max lag is reported")
    parser.add_argument("--include-stderr", action="store_true", default=True)
    parser.add_argument("--json", action="store_true", help="emit raw measurements as JSON")
    args = parser.parse_args(argv)

    rows: list[dict] = []
    for delay in _parse_delays(args.sink_ms):
        for mode in MODES:
            rows.append(
                _repeat_best(
                    delay_seconds=delay,
                    requests=args.requests,
                    per_request=args.per_request,
                    mode=mode,
                    queue_size=args.queue_size,
                    yield_every=args.yield_every,
                    label=mode,
                    repeat=args.repeat,
                )
            )

    if args.include_stderr:
        factory = lambda _delay: logging.StreamHandler(sys.stderr)  # noqa: E731
        for mode in MODES:
            rows.append(
                _repeat_best(
                    delay_seconds=0.0,
                    requests=args.requests,
                    per_request=args.per_request,
                    mode=mode,
                    queue_size=args.queue_size,
                    yield_every=args.yield_every,
                    label="stderr" if mode == MODE_INLINE else f"stderr+{mode}",
                    repeat=args.repeat,
                    sink_factory=factory,
                )
            )

    if args.json:
        print(json.dumps({"runner": "bench_log_blocking", "rows": rows}, indent=2))
        return 0

    header = (
        "%-18s %10s %8s %12s %12s %12s"
        % ("sink", "delay(ms)", "records", "p50 lag(ms)", "p95 lag(ms)", "max lag(ms)")
    )
    print(header)
    print("-" * len(header))
    for row in rows:
        print(
            "%-18s %10.3f %8d %12.3f %12.3f %12.3f"
            % (
                row["label"],
                row["sink_delay_ms"],
                row["records"],
                row["loop_lag_p50_ms"],
                row["loop_lag_p95_ms"],
                row["loop_lag_max_ms"],
            )
        )
    return 0


def _repeat_best(repeat: int, **kwargs) -> dict:
    """Run a cell ``repeat`` times and keep the worst max lag (least flattering)."""
    runs = [measure(**kwargs) for _ in range(max(1, repeat))]
    return max(runs, key=lambda row: row["loop_lag_max_ms"])


if __name__ == "__main__":
    raise SystemExit(main())
