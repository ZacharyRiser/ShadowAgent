"""Concurrency / saturation gate with *relative* criteria.

Why relative
------------
Absolute throughput on a developer laptop is not reproducible: the same commit
measured 13-20% apart across sessions, and a pristine ``git archive HEAD``
reproduced the lower figure, so the drift is machine load rather than code (see
``docs/launch-checklist.md`` section 6). A gate on "health must reach 841 rps"
would therefore fail for reasons that have nothing to do with the change under
test. What *is* stable, and what actually regressed in the 2026-09-20 incident,
is the shape of the load response:

  * the gateway must not return 5xx, and must not leave clients timing out
  * the blocked path must not be dramatically slower than the allowed path
    (coarse; its own run-to-run spread is 2.66x-3.59x on passing runs)
  * the process must still answer after the load (the old failure mode was a
    silent stall: zero bytes, no error, ``/health`` dead too)
  * the connection pool must not have starved any request

Those hold on any hardware, so they are the gate. Two tiers, because offered
concurrency has to exceed the pool ceiling for the ceiling to be tested at all:
the original defect was invisible at c=8 (pool peak 7 of 15) and only appeared
at c=32 (peak 23).

Verified both ways on 2026-09-20: with ``SHADOW_AGENT_DB_POOL_SIZE=5
SHADOW_AGENT_DB_MAX_OVERFLOW=10`` the gate exits 1 on four criteria
(``timeout_total=12``), and with the shipped defaults it exits 0.

Usage (from ``backend/``):
    python tools/perf_gate.py
    python tools/perf_gate.py --base-url http://127.0.0.1:8018 \
        --client-key <key> --admin-key <key>

Exit codes: 0 = pass, 1 = criteria failed, 2 = gate could not run.
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

# Scenarios with a single meaning each. `mixed` is deliberately excluded: it
# expands to 9 scenarios x concurrency (72 workers at c=8) and is not
# comparable to the single-scenario rows.
SCENARIOS = ["health", "chat", "injection", "analyze", "logs"]
ALLOWED_PATH = "chat"
BLOCKED_PATH = "injection"

failures: list[str] = []
notes: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if condition else 'FAIL'}] {name} {detail}")
    if not condition:
        failures.append(name)


def load_harness():
    """Import ``perf/load_test.py`` by path (``perf`` is not a package).

    The module must be registered in ``sys.modules`` before execution: the
    ``@dataclass`` decorator resolves annotations through
    ``sys.modules[cls.__module__]`` and raises ``AttributeError: 'NoneType'
    object has no attribute '__dict__'`` if the entry is missing.
    """
    path = BACKEND / "perf" / "load_test.py"
    spec = importlib.util.spec_from_file_location("shadow_perf_load_test", path)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise SystemExit(f"cannot load harness from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def build_env(db_path: str) -> dict:
    """Server environment. Every entry here is required for a valid run.

    ``SHADOW_AGENT_LOG_RATE_LIMIT_PER_MINUTE`` and the pinned upstream are easy
    to forget and neither omission is self-announcing: the first makes the
    ``logs`` scenario measure 429s, the second makes ``chat`` forward upstream
    and answer 502.
    """
    env = dict(os.environ)
    env.update({
        "SHADOW_AGENT_DATABASE_PATH": db_path,
        "SHADOW_AGENT_RATE_LIMIT_PER_MINUTE": "1000000",
        "SHADOW_AGENT_LOG_RATE_LIMIT_PER_MINUTE": "1000000",
        "SHADOW_AGENT_ALLOW_SIMULATED_RESPONSES": "true",
        "SHADOW_AGENT_UPSTREAM_BASE_URL": " ",
        "SHADOW_AGENT_ALLOWED_ORIGINS": "http://127.0.0.1:3000",
        "PYTHONUNBUFFERED": "1",
    })
    env.setdefault("SHADOW_AGENT_JWT_SECRET", "perf-gate-secret-" + "x" * 32)
    env.setdefault("SHADOW_AGENT_API_KEY_PEPPER", "perf-gate-pepper-" + "y" * 32)
    env.setdefault("SHADOW_AGENT_ADMIN_API_KEY", "perf-gate-admin")
    env.setdefault("SHADOW_AGENT_CLIENT_API_KEY", "perf-gate-client")
    # An ambient proxy would add a hop to every loopback sample and can answer
    # 502/503 under load, which reads as a gateway failure.
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        env.pop(key, None)
    return env


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_healthy(base_url: str, proc: subprocess.Popen, timeout: float = 30.0) -> bool:
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=1.0) as response:
                if response.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.25)
    return False


def probe_health(base_url: str, timeout: float) -> float | None:
    """Return the round-trip time of ``/health`` in ms, or None if it failed."""
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(f"{base_url}/health", timeout=timeout) as response:
            if response.status != 200:
                return None
    except (urllib.error.URLError, OSError):
        return None
    return (time.perf_counter() - started) * 1000.0


def read_pool_counters(base_url: str, admin_key: str) -> dict[str, int] | None:
    """Scrape the DB pool counters, or None if ``/metrics`` is unavailable.

    ``timeout_total`` is the accurate starvation count; ``saturated_checkouts_total``
    is a lower bound on contention (a request that blocks and gives up never
    reaches the checkout event that would increment it).
    """
    wanted = (
        "shadow_agent_db_pool_saturated_checkouts_total",
        "shadow_agent_db_pool_timeout_total",
        "shadow_agent_db_pool_max_in_use_since_start",
    )
    request = urllib.request.Request(f"{base_url}/metrics", headers={"X-API-Key": admin_key})
    try:
        with urllib.request.urlopen(request, timeout=5.0) as response:
            if response.status != 200:
                return None
            body = response.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError):
        return None

    found: dict[str, int] = {}
    for line in body.splitlines():
        for name in wanted:
            if line.startswith(name + " ") or line.startswith(name + "{"):
                try:
                    found[name] = int(float(line.rsplit(" ", 1)[1]))
                except (IndexError, ValueError):
                    pass
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description="Shadow Agent concurrency gate")
    parser.add_argument("--base-url", default="", help="Test an already-running server instead of booting one")
    parser.add_argument("--client-key", default="")
    parser.add_argument("--admin-key", default="")
    parser.add_argument("--concurrency", type=int, default=8, help="Offered concurrency for the shape tier (default 8)")
    parser.add_argument("--duration", type=float, default=15.0, help="Seconds per scenario in the shape tier")
    parser.add_argument(
        "--stress-concurrency",
        type=int,
        default=32,
        help=(
            "Offered concurrency for the stress tier (default 32). Must exceed "
            "the pool ceiling for that ceiling to be exercised: peak demand was "
            "7 connections at c=8 but 23 at c=32, so c=8 cannot detect a "
            "15-connection ceiling."
        ),
    )
    parser.add_argument("--stress-duration", type=float, default=10.0)
    parser.add_argument(
        "--max-blocked-ratio",
        type=float,
        default=4.0,
        help=(
            "Worst allowed ratio of blocked-path p95 to allowed-path p95 "
            "(default 4.0). This is the coarsest criterion here and its own "
            "measured spread is wide: 2.66x and 3.59x on two passing runs of the "
            "same code, 4.34x on the saturated run. A 3.0 threshold would "
            "therefore flap. The sharp signals are the 5xx / timeout / "
            "pool-starvation criteria; this one only catches a change that makes "
            "the blocked path dramatically slower."
        ),
    )
    parser.add_argument(
        "--max-health-ms",
        type=float,
        default=2000.0,
        help="Post-load /health must answer within this many ms (default 2000)",
    )
    args = parser.parse_args()

    harness = load_harness()
    proc: subprocess.Popen | None = None
    tmpdir = tempfile.mkdtemp(prefix="shadow_perf_gate_")
    base_url = args.base_url
    client_key = args.client_key
    admin_key = args.admin_key

    try:
        if not base_url:
            port = free_port()
            base_url = f"http://127.0.0.1:{port}"
            env = build_env(os.path.join(tmpdir, "perf_gate.db"))
            client_key = client_key or env["SHADOW_AGENT_CLIENT_API_KEY"]
            admin_key = admin_key or env["SHADOW_AGENT_ADMIN_API_KEY"]
            print(f"Booting gateway on {base_url} (stdout/stderr -> DEVNULL)")
            # stdout/stderr MUST be consumed: an unread pipe fills at ~4 KB and
            # wedges the whole process, because the loop logs synchronously.
            proc = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "main:app",
                 "--host", "127.0.0.1", "--port", str(port)],
                cwd=str(BACKEND), env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if not wait_healthy(base_url, proc):
                print("GATE ERROR — 网关未能启动或未通过健康检查")
                return 2
        else:
            if not (client_key and admin_key):
                print("GATE ERROR — --base-url 需要同时提供 --client-key 与 --admin-key")
                return 2
            if probe_health(base_url, 3.0) is None:
                print("GATE ERROR — 目标网关无响应")
                return 2

        scenarios = harness.build_scenarios(client_key, admin_key)

        # --- Tier 1: concurrency stress ------------------------------------
        # This tier is why the gate has two of them. The 2026-09-20 pool defect
        # only appeared above ~20 concurrent clients: at c=8 the pool peak was
        # 7 connections out of 15, so a c=8-only gate would have reported green
        # for the whole duration of the bug. Offered concurrency has to exceed
        # the ceiling for the ceiling to be tested at all.
        print(
            f"=== 档 1 并发压力：{ALLOWED_PATH} @ c={args.stress_concurrency} "
            f"/ {args.stress_duration}s ==="
        )
        stress_started = time.perf_counter()
        stress_stats = asyncio.run(
            harness.run_load_test(
                base_url,
                scenarios[ALLOWED_PATH],
                concurrency=args.stress_concurrency,
                duration=args.stress_duration,
                max_requests_per_worker=100000,
            )
        )
        stress = stress_stats.summary(time.perf_counter() - stress_started)
        print(
            f"  {ALLOWED_PATH:<10} requests={stress['total']:<6} rps={stress['rps']:<8} "
            f"p50={stress['p50_ms']:<9} p95={stress['p95_ms']:<9} "
            f"codes={stress['status_codes']}"
        )

        # --- Tier 2: relative latency shape --------------------------------
        print(f"\n=== 档 2 相对延迟形状：c={args.concurrency} / {args.duration}s ===")
        results: dict[str, dict] = {}
        for name in SCENARIOS:
            started = time.perf_counter()
            stats = asyncio.run(
                harness.run_load_test(
                    base_url,
                    scenarios[name],
                    concurrency=args.concurrency,
                    duration=args.duration,
                    max_requests_per_worker=100000,
                )
            )
            elapsed = time.perf_counter() - started
            summary = stats.summary(elapsed)
            results[name] = summary
            print(
                f"  {name:<10} requests={summary['total']:<6} rps={summary['rps']:<8} "
                f"p50={summary['p50_ms']:<9} p95={summary['p95_ms']:<9} "
                f"codes={summary['status_codes']}"
            )

        print("\n=== 判据（相对，与硬件无关）===")

        def clean(summary: dict) -> bool:
            return summary["errors_5xx"] == 0 and summary["status_codes"].get(599, 0) == 0

        check(
            f"档 1（c={args.stress_concurrency}）无 5xx、无超时、且确实跑出流量",
            clean(stress) and stress["total"] > 0,
            f"-> {stress['status_codes']}",
        )
        check(
            "档 1 p95 未达客户端超时量级（30s）",
            stress["p95_ms"] < 30000,
            f"-> p95 {stress['p95_ms']}ms",
        )

        shape_ok = all(clean(summary) for summary in results.values())
        offending = {
            name: summary["status_codes"]
            for name, summary in results.items()
            if not clean(summary)
        }
        check("档 2 各场景无 5xx、无客户端超时(599)", shape_ok, f"-> {offending or 'clean'}")

        allowed = results[ALLOWED_PATH]
        blocked = results[BLOCKED_PATH]
        check(
            f"{ALLOWED_PATH} 场景确实跑出流量",
            allowed["total"] > 0 and allowed["p95_ms"] > 0,
            f"-> {allowed['total']} requests, p95 {allowed['p95_ms']}ms",
        )
        if allowed["p95_ms"] > 0:
            ratio = blocked["p95_ms"] / allowed["p95_ms"]
            check(
                f"阻断路径 p95 不劣化放行路径 {args.max_blocked_ratio:g} 倍以上",
                ratio <= args.max_blocked_ratio,
                f"-> {blocked['p95_ms']}ms / {allowed['p95_ms']}ms = {ratio:.2f}x",
            )

        health_ms = probe_health(base_url, args.max_health_ms / 1000.0)
        check(
            "压测后网关仍在服务（无静默停摆）",
            health_ms is not None and health_ms <= args.max_health_ms,
            f"-> /health {('%.1f ms' % health_ms) if health_ms is not None else 'TIMED OUT'}",
        )

        counters = read_pool_counters(base_url, admin_key)
        if counters is None:
            notes.append("池指标不可读（admin 凭证或 /metrics 不可用）——已跳过该项")
        else:
            starved = counters.get("shadow_agent_db_pool_timeout_total")
            saturated = counters.get("shadow_agent_db_pool_saturated_checkouts_total")
            peak = counters.get("shadow_agent_db_pool_max_in_use_since_start")
            check(
                "连接池未饿死任何请求",
                starved == 0,
                f"-> timeout_total={starved}, saturated_checkouts={saturated}, "
                f"max_in_use={peak}",
            )

        print()
        for note in notes:
            print(f"  NOTE {note}")
        if failures:
            print(f"PERF GATE FAILED ({len(failures)}): {json.dumps(failures, ensure_ascii=False)}")
            return 1
        print("PERF GATE OK — 全部判据通过")
        return 0
    finally:
        if proc is not None and proc.poll() is None:
            # TerminateProcess: `taskkill` reports failure for an already-gone PID,
            # so it cannot be used to decide whether this worked.
            ctypes.windll.kernel32.TerminateProcess(proc._handle, 1)  # noqa: SLF001
            proc.wait(timeout=10)
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
