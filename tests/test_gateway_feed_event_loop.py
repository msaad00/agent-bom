"""The gateway feed must not stall the event loop while it reads its audit log.

`/v1/gateway/feed` and its KPI sibling answer from a JSONL audit log when the
in-process ring buffer is empty. That read is synchronous — open, iterate up to
_MAX_LOG_LINES, json.loads each line, redact each record — and it was called
directly from `async def` handlers. On a large log the whole process stops:
every other tenant's request, every health check, every background task.

AGENT_BOM_LOG is a shipped deployment surface (deploy/docker-compose.runtime-example.yml),
so this is reachable in a normal install, not a synthetic condition.
"""

from __future__ import annotations

import asyncio
import json
import time

import pytest


def _write_log(path, lines: int) -> None:
    with open(path, "w") as handle:
        for i in range(lines):
            handle.write(
                json.dumps(
                    {
                        "type": "runtime_alert",
                        "tenant_id": "default",
                        "timestamp": "2026-07-29T00:00:00Z",
                        "agent": f"agent-{i % 7}",
                        "action": "blocked",
                        "detail": "x" * 120,
                    }
                )
                + "\n"
            )


def test_jsonl_fallback_reads_the_newest_bounded_records(tmp_path) -> None:
    from agent_bom.api.routes.proxy import _MAX_FEED_LOG_LINES, _read_alerts_from_log

    log = tmp_path / "runtime.jsonl"
    with open(log, "w") as handle:
        for index in range(1_250):
            handle.write(
                json.dumps(
                    {
                        "type": "runtime_alert",
                        "tenant_id": "default",
                        "event_id": f"evt-{index}",
                    }
                )
                + "\n"
            )

    # The bound is now per caller; this asserts the feed's cap specifically.
    alerts = _read_alerts_from_log(log, limit=_MAX_FEED_LOG_LINES)

    assert len(alerts) == 1_000
    assert alerts[0]["event_id"] == "evt-250"
    assert alerts[-1]["event_id"] == "evt-1249"


async def _max_stall_while(coro, *, tick: float = 0.001) -> tuple[object, float]:
    """Run *coro*, sampling how long the loop ever went without servicing a tick."""
    worst = 0.0
    stop = False

    async def _heartbeat() -> None:
        nonlocal worst
        last = time.perf_counter()
        while not stop:
            await asyncio.sleep(tick)
            now = time.perf_counter()
            worst = max(worst, now - last)
            last = now

    beat = asyncio.create_task(_heartbeat())
    # Let the heartbeat actually start before the work begins. Without this the
    # task is merely scheduled, never runs, and a fully blocking call is
    # measured as zero stall -- the instrument would exonerate the bug.
    for _ in range(5):
        await asyncio.sleep(tick)
    try:
        result = await coro
    finally:
        stop = True
        await asyncio.sleep(0)
        beat.cancel()
    return result, worst


@pytest.mark.parametrize("route", ["feed", "kpis"])
def test_feed_routes_do_not_block_the_event_loop(tmp_path, monkeypatch, route):
    from agent_bom.api.routes import gateway_feed as feed_mod
    from agent_bom.api.routes import proxy as proxy_mod

    log = tmp_path / "runtime.jsonl"
    _write_log(log, 40_000)
    monkeypatch.setenv("AGENT_BOM_LOG", str(log))
    monkeypatch.setattr(proxy_mod, "_proxy_alerts", type(proxy_mod._proxy_alerts)(maxlen=1000))

    class _Req:
        state = type("S", (), {"tenant_id": "default"})()
        headers: dict[str, str] = {}

    handler = feed_mod.gateway_feed if route == "feed" else feed_mod.gateway_feed_kpis
    call = handler(_Req(), limit=100) if route == "feed" else handler(_Req())

    async def _drive():
        return await _max_stall_while(call)

    _result, worst_stall = asyncio.run(_drive())

    # Before the fix this measured ~3.6 s: the whole process frozen, not merely
    # a slow request. Off-loading brings it to ~0.19 s. The residue is GIL
    # contention -- parsing 40k JSON lines is CPU-bound, so a worker thread
    # interleaves with the loop rather than freeing it. Fully removing it needs
    # the work bounded (pagination / a smaller cap), not more threading.
    assert worst_stall < 0.35, f"event loop stalled {worst_stall * 1000:.0f} ms reading the audit log"
