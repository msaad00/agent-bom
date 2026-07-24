#!/usr/bin/env python3
"""Full-stack gateway relay latency / RSS benchmark harness.

Starts a mock MCP upstream and ``agent-bom gateway serve``, then drives
``POST /mcp/echo`` with JSON-RPC ``tools/call`` across a concurrency ladder.

Modes:
  baseline — stock asyncio + default httpx limits; gateway defaults
  tuned    — uvloop when installable, larger httpx pool/keepalive on the
             load generator. Gateway upstream pool size is not currently
             exposed via AGENT_BOM_* env vars (GatewaySettings fields only),
             so tuned mode documents that gap rather than inventing knobs.

``--relay-backend go`` starts ``runtime/gateway-relay`` and sets
``AGENT_BOM_GATEWAY_RELAY_BACKEND=go`` on the gateway child.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONCURRENCY = [1, 10, 50, 100, 250, 500]
DEFAULT_REQUESTS = 200
GATEWAY_BIND_HOST = "127.0.0.1"
GATEWAY_BIND_PORT = 8090
UPSTREAM_PORT = 8100
GO_RELAY_PORT = 8091
WARMUP_REQUESTS = 20
HEALTH_TIMEOUT_S = 45.0
REQUEST_TIMEOUT_S = 30.0
# Privacy: never record the operator machine hostname in committed artifacts.
BENCHMARK_HOSTNAME = "local-benchmark-host"


def _percentiles(values_ms: list[float]) -> dict[str, float | int]:
    if not values_ms:
        return {"p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "max_ms": 0.0, "mean_ms": 0.0, "samples": 0}
    ordered = sorted(values_ms)

    def pct(percent: float) -> float:
        idx = min(len(ordered) - 1, max(0, round((percent / 100.0) * (len(ordered) - 1))))
        return round(ordered[idx], 3)

    return {
        "p50_ms": pct(50),
        "p95_ms": pct(95),
        "p99_ms": pct(99),
        "max_ms": round(max(ordered), 3),
        "mean_ms": round(statistics.fmean(ordered), 3),
        "samples": len(ordered),
    }


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _rss_kb(pid: int) -> int | None:
    try:
        out = subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)], text=True).strip()
        if not out:
            return None
        return int(out.split()[0])
    except (subprocess.CalledProcessError, ValueError, FileNotFoundError, OSError):
        return None


def _descendant_pids(root_pid: int) -> list[int]:
    """Return root + descendants via repeated ``pgrep -P`` walks."""
    seen: set[int] = {root_pid}
    frontier = [root_pid]
    while frontier:
        parent = frontier.pop()
        try:
            out = subprocess.check_output(["pgrep", "-P", str(parent)], text=True).strip()
        except (subprocess.CalledProcessError, FileNotFoundError, OSError):
            continue
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                child = int(line)
            except ValueError:
                continue
            if child not in seen:
                seen.add(child)
                frontier.append(child)
    return sorted(seen)


def _peak_rss_kb_tree(root_pid: int) -> int | None:
    """Peak RSS across the process tree (uv wrapper + real gateway python)."""
    peak: int | None = None
    for pid in _descendant_pids(root_pid):
        rss = _rss_kb(pid)
        if rss is None:
            continue
        if peak is None or rss > peak:
            peak = rss
    return peak


def _agent_bom_version() -> str:
    try:
        from importlib.metadata import version

        return version("agent-bom")
    except Exception:
        try:
            from agent_bom import __version__

            return str(__version__)
        except Exception:
            return "unknown"


def _wait_http_ok(url: str, *, timeout_s: float = HEALTH_TIMEOUT_S) -> None:
    import urllib.error
    import urllib.request

    deadline = time.monotonic() + timeout_s
    last_err: str | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2.0) as resp:
                if 200 <= int(resp.status) < 300:
                    return
                last_err = f"status={resp.status}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_err = str(exc)
        time.sleep(0.15)
    raise RuntimeError(f"timed out waiting for {url}: {last_err}")


def _write_upstreams_yaml(path: Path, upstream_port: int) -> None:
    path.write_text(
        "upstreams:\n"
        "  - name: echo\n"
        f"    url: http://127.0.0.1:{upstream_port}/mcp\n"
        "    auth: none\n"
        "    transport: streamable-http\n",
        encoding="utf-8",
    )


def _spawn(cmd: list[str], *, env: dict[str, str] | None = None) -> subprocess.Popen[bytes]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        env=merged,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )


def _terminate(proc: subprocess.Popen[bytes] | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            proc.kill()
        proc.wait(timeout=5)


def _venv_python() -> str:
    candidate = ROOT / ".venv" / "bin" / "python"
    if candidate.exists():
        return str(candidate)
    return sys.executable


def _gateway_cmd(bind: str, upstreams: Path) -> list[str]:
    # Prefer the worktree venv binary so RSS belongs to the gateway process,
    # not an intermediate ``uv run`` wrapper.
    venv_cli = ROOT / ".venv" / "bin" / "agent-bom"
    if venv_cli.exists():
        base = [str(venv_cli), "gateway", "serve"]
    else:
        base = [_venv_python(), "-m", "agent_bom", "gateway", "serve"]
    return [
        *base,
        "--bind",
        bind,
        "--upstreams",
        str(upstreams),
        "--log-level",
        "warning",
        "--allow-anonymous-agents",
    ]


def _mock_cmd(port: int) -> list[str]:
    script = ROOT / "scripts" / "perf" / "mock_mcp_upstream.py"
    return [_venv_python(), str(script), "--port", str(port), "--host", "127.0.0.1"]


def _apply_uvloop_if_requested(mode: str) -> dict[str, Any]:
    note: dict[str, Any] = {"requested": mode == "tuned", "enabled": False, "detail": "not requested"}
    if mode != "tuned":
        return note
    if os.environ.get("UVLOOP", "").strip() in {"0", "false", "no"}:
        note["detail"] = "UVLOOP disabled via env"
        return note
    try:
        import uvloop

        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        note["enabled"] = True
        note["detail"] = f"uvloop {getattr(uvloop, '__version__', 'unknown')}"
    except Exception as exc:  # noqa: BLE001 — optional dep
        note["detail"] = f"uvloop unavailable: {type(exc).__name__}"
    return note


def _httpx_limits(mode: str) -> Any:
    import httpx

    if mode == "tuned":
        return httpx.Limits(max_connections=1000, max_keepalive_connections=500, keepalive_expiry=30.0)
    return httpx.Limits(max_connections=100, max_keepalive_connections=20)


def _gateway_env(mode: str, *, relay_backend: str = "python", go_relay_url: str | None = None) -> dict[str, str]:
    """Env for the gateway child process.

    ``GatewaySettings.upstream_http_max_connections`` / keepalive are dataclass
    fields wired only from the CLI constructor today — there is no
    ``AGENT_BOM_GATEWAY_UPSTREAM_*`` env. Tuned mode records that gap and still
    sets benign high-concurrency client hints where they exist.
    """
    env: dict[str, str] = {
        "AGENT_BOM_GATEWAY_ALLOW_ANONYMOUS_AGENTS": "1",
        # Empty policy + fail-open keeps the relay path free of DENY noise for
        # this microbenchmark (policy engine is not under test here).
        "AGENT_BOM_GATEWAY_FAIL_MODE": "open",
        "AGENT_BOM_GATEWAY_RELAY_BACKEND": relay_backend,
    }
    if relay_backend == "go":
        env["AGENT_BOM_GATEWAY_RELAY_GO_URL"] = go_relay_url or f"http://127.0.0.1:{GO_RELAY_PORT}"
    if mode == "tuned":
        env["UVLOOP"] = "1"
        # Documented non-knobs: pool size is not env-configurable yet.
        env["AGENT_BOM_GATEWAY_PERF_TUNE"] = "1"
    return env


def _go_relay_cmd(listen: str) -> list[str]:
    """Build the Go sidecar binary and return argv for ``-listen``."""
    module = ROOT / "runtime" / "gateway-relay"
    built = module / "bin" / "gateway-relay"
    built.parent.mkdir(parents=True, exist_ok=True)
    subprocess.check_call(
        ["go", "build", "-o", str(built), "./cmd/gateway-relay"],
        cwd=str(module),
    )
    return [str(built), "-listen", listen]


async def _one_call(client: Any, url: str, req_id: int) -> tuple[float, bool, str | None]:
    payload = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"n": req_id}},
    }
    started = time.perf_counter()
    try:
        resp = await client.post(url, json=payload)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if resp.status_code != 200:
            return elapsed_ms, False, f"http_{resp.status_code}"
        body = resp.json()
        if isinstance(body, dict) and body.get("error"):
            return elapsed_ms, False, "jsonrpc_error"
        if not isinstance(body, dict) or "result" not in body:
            return elapsed_ms, False, "missing_result"
        return elapsed_ms, True, None
    except Exception as exc:  # noqa: BLE001 — count as error sample
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return elapsed_ms, False, type(exc).__name__


async def _run_level(
    *,
    client: Any,
    url: str,
    concurrency: int,
    requests: int,
    gateway_pid: int,
) -> dict[str, Any]:
    sem = asyncio.Semaphore(concurrency)
    latencies: list[float] = []
    errors = 0
    error_kinds: dict[str, int] = {}
    peak_rss_kb: int | None = _peak_rss_kb_tree(gateway_pid)

    async def worker(req_id: int) -> None:
        nonlocal errors, peak_rss_kb
        async with sem:
            ms, ok, kind = await _one_call(client, url, req_id)
            latencies.append(ms)
            if not ok:
                errors += 1
                error_kinds[kind or "unknown"] = error_kinds.get(kind or "unknown", 0) + 1
            rss = _peak_rss_kb_tree(gateway_pid)
            if rss is not None and (peak_rss_kb is None or rss > peak_rss_kb):
                peak_rss_kb = rss

    await asyncio.gather(*(worker(i) for i in range(requests)))
    pct = _percentiles(latencies)
    error_rate = (errors / requests) if requests else 0.0
    peak_rss_mb = round((peak_rss_kb or 0) / 1024.0, 3) if peak_rss_kb is not None else None
    return {
        "concurrency": concurrency,
        "requests": requests,
        "error_count": errors,
        "error_rate": round(error_rate, 6),
        "error_kinds": error_kinds,
        "latency_ms": pct,
        "peak_rss_kb": peak_rss_kb,
        "peak_rss_mb": peak_rss_mb,
        "wall_s": None,  # filled by caller
    }


async def _drive(
    *,
    gateway_base: str,
    gateway_pid: int,
    mode: str,
    concurrency_levels: list[int],
    requests_per_level: int,
) -> list[dict[str, Any]]:
    import httpx

    url = f"{gateway_base}/mcp/echo"
    timeout = httpx.Timeout(REQUEST_TIMEOUT_S)
    limits = _httpx_limits(mode)
    results: list[dict[str, Any]] = []

    async with httpx.AsyncClient(timeout=timeout, limits=limits) as client:
        # Warmup
        for i in range(WARMUP_REQUESTS):
            await _one_call(client, url, i)

        for conc in concurrency_levels:
            started = time.perf_counter()
            level = await _run_level(
                client=client,
                url=url,
                concurrency=conc,
                requests=requests_per_level,
                gateway_pid=gateway_pid,
            )
            level["wall_s"] = round(time.perf_counter() - started, 3)
            results.append(level)
            # Soft cap: if a mid level already exceeds ~90s wall, still continue
            # to 500 (required for Go gate) but keep request count.
            print(
                f"concurrency={conc} p95_ms={level['latency_ms']['p95_ms']} "
                f"error_rate={level['error_rate']} peak_rss_mb={level['peak_rss_mb']} "
                f"wall_s={level['wall_s']}",
                flush=True,
            )
    return results


def _fetch_metrics(gateway_base: str) -> str | None:
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(f"{gateway_base}/metrics", timeout=5.0) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def run_benchmark(
    *,
    mode: str,
    output: Path,
    concurrency_levels: list[int],
    requests_per_level: int,
    gateway_port: int | None,
    upstream_port: int | None,
    relay_backend: str = "python",
    go_relay_port: int | None = None,
) -> dict[str, Any]:
    uvloop_note = _apply_uvloop_if_requested(mode)
    gport = gateway_port or _free_port()
    uport = upstream_port or _free_port()
    rport = go_relay_port or _free_port()
    # Prefer the documented default ports when free.
    if gateway_port is None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((GATEWAY_BIND_HOST, GATEWAY_BIND_PORT))
                gport = GATEWAY_BIND_PORT
        except OSError:
            pass
    if upstream_port is None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", UPSTREAM_PORT))
                uport = UPSTREAM_PORT
        except OSError:
            pass
    if relay_backend == "go" and go_relay_port is None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", GO_RELAY_PORT))
                rport = GO_RELAY_PORT
        except OSError:
            pass

    gateway_base = f"http://{GATEWAY_BIND_HOST}:{gport}"
    go_relay_url = f"http://127.0.0.1:{rport}"
    upstream_proc: subprocess.Popen[bytes] | None = None
    gateway_proc: subprocess.Popen[bytes] | None = None
    go_relay_proc: subprocess.Popen[bytes] | None = None

    with tempfile.TemporaryDirectory(prefix="abom-gateway-perf-") as tmp:
        upstreams = Path(tmp) / "upstreams.yaml"
        _write_upstreams_yaml(upstreams, uport)

        try:
            upstream_proc = _spawn(_mock_cmd(uport))
            _wait_http_ok(f"http://127.0.0.1:{uport}/healthz")

            if relay_backend == "go":
                go_relay_proc = _spawn(_go_relay_cmd(f"127.0.0.1:{rport}"))
                _wait_http_ok(f"{go_relay_url}/healthz", timeout_s=90.0)

            gateway_proc = _spawn(
                _gateway_cmd(f"{GATEWAY_BIND_HOST}:{gport}", upstreams),
                env=_gateway_env(mode, relay_backend=relay_backend, go_relay_url=go_relay_url),
            )
            _wait_http_ok(f"{gateway_base}/healthz")

            started = time.perf_counter()
            results = asyncio.run(
                _drive(
                    gateway_base=gateway_base,
                    gateway_pid=gateway_proc.pid,
                    mode=mode,
                    concurrency_levels=concurrency_levels,
                    requests_per_level=requests_per_level,
                )
            )
            total_wall_s = round(time.perf_counter() - started, 3)
            metrics_snippet = _fetch_metrics(gateway_base)
            final_rss_kb = _peak_rss_kb_tree(gateway_proc.pid)
        finally:
            _terminate(gateway_proc)
            _terminate(go_relay_proc)
            _terminate(upstream_proc)

    at_500 = next((r for r in results if r["concurrency"] == 500), None)
    artifact: dict[str, Any] = {
        "metadata": {
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "hostname": BENCHMARK_HOSTNAME,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "agent_bom_version": _agent_bom_version(),
            "mode": mode,
            "git_commit": _git_commit(),
            "uvloop": uvloop_note,
            "httpx_limits": {
                "mode": mode,
                "max_connections": 1000 if mode == "tuned" else 100,
                "max_keepalive_connections": 500 if mode == "tuned" else 20,
            },
            "gateway_pool_env": {
                "note": (
                    "GatewaySettings.upstream_http_max_connections defaults to 100 / "
                    "keepalive 20; not exposed via AGENT_BOM_* env today. Tuned mode "
                    "cannot enlarge the gateway pool without a code/CLI change."
                ),
                "upstream_http_max_connections_default": 100,
                "upstream_http_max_keepalive_connections_default": 20,
            },
            "bind": {
                "gateway": f"{GATEWAY_BIND_HOST}:{gport}",
                "upstream": f"127.0.0.1:{uport}",
                "go_relay": (go_relay_url if relay_backend == "go" else None),
            },
            "relay_backend": relay_backend,
            "requests_per_level": requests_per_level,
            "concurrency_levels": concurrency_levels,
            "warmup_requests": WARMUP_REQUESTS,
            "total_wall_s": total_wall_s,
        },
        "results": results,
        "gateway_metrics_tail": (metrics_snippet[-2000:] if metrics_snippet else None),
        "final_gateway_rss_kb": final_rss_kb,
        "final_gateway_rss_mb": round((final_rss_kb or 0) / 1024.0, 3) if final_rss_kb is not None else None,
        "go_gate_inputs_at_500": {
            "p95_ms": (at_500 or {}).get("latency_ms", {}).get("p95_ms"),
            "peak_rss_mb": (at_500 or {}).get("peak_rss_mb"),
            "error_rate": (at_500 or {}).get("error_rate"),
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {output}", flush=True)
    return artifact


def _git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=str(ROOT), text=True).strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        "--tune",
        dest="mode",
        choices=("baseline", "tuned", "python"),
        default="baseline",
        help="baseline (default) or tuned/python (uvloop + larger httpx limits)",
    )
    parser.add_argument("--output", type=Path, required=True, help="JSON result path")
    parser.add_argument(
        "--requests-per-level",
        type=int,
        default=DEFAULT_REQUESTS,
        help=f"Requests at each concurrency (default {DEFAULT_REQUESTS})",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        nargs="+",
        default=DEFAULT_CONCURRENCY,
        help="Concurrency ladder (must include 500 for Go gate)",
    )
    parser.add_argument("--gateway-port", type=int, default=None)
    parser.add_argument("--upstream-port", type=int, default=None)
    parser.add_argument(
        "--relay-backend",
        choices=("python", "go"),
        default="python",
        help="Pure-relay backend (default python; go starts the sidecar)",
    )
    parser.add_argument("--go-relay-port", type=int, default=None)
    args = parser.parse_args()
    mode = "tuned" if args.mode == "python" else args.mode
    if 500 not in args.concurrency:
        parser.error("concurrency ladder must include 500 (Go-gate measurement point)")
    run_benchmark(
        mode=mode,
        output=args.output,
        concurrency_levels=list(args.concurrency),
        requests_per_level=args.requests_per_level,
        gateway_port=args.gateway_port,
        upstream_port=args.upstream_port,
        relay_backend=args.relay_backend,
        go_relay_port=args.go_relay_port,
    )


if __name__ == "__main__":
    main()
