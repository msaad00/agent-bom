"""Admit a bounded number of aggregate page reads at a time.

The dashboard's page reads already run on worker threads, but their work is
CPU-bound Python. Threads share one GIL with the event-loop thread, so ten of
them computing at once leave the loop waiting seconds for its turn: ``/health``
and ``/_next/static`` chunks queue behind them even though neither does any
work. Running two at a time completes the batch in about the same wall time,
since the GIL serializes them anyway, while the loop stays responsive and the
first pages finish sooner.

Only the listed read paths are gated; everything else, streams included, is
untouched. ``ForegroundActivityMiddleware`` calls :func:`admit`, so the gate
sits inside auth and rate limiting. A request holds its slot until its response
starts, not while the body drains to a slow client. Waiters past the
backpressure ceiling (``WORKER_THREAD_LIMIT``) are shed with 429 instead of
queueing without bound.
"""

from __future__ import annotations

import asyncio
import json
import weakref
from typing import Any

HEAVY_READ_PATHS = frozenset(
    {
        "/v1/overview",
        "/v1/posture",
        "/v1/posture/counts",
        "/v1/findings",
        "/v1/compliance",
        "/v1/compliance/summary",
        "/v1/graph",
    }
)


class _Gate:
    def __init__(self, limit: int, max_waiters: int) -> None:
        self.semaphore = asyncio.Semaphore(limit)
        self.max_waiters = max_waiters
        self.waiting = 0


_gates: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, _Gate] = weakref.WeakKeyDictionary()


DEFAULT_CONCURRENCY = 2


def concurrency() -> int:
    """Aggregate reads computed at once (``AGENT_BOM_HEAVY_READ_CONCURRENCY``)."""
    from agent_bom.core.settings import env_int

    return env_int("AGENT_BOM_HEAVY_READ_CONCURRENCY", DEFAULT_CONCURRENCY, minimum=1, maximum=64, on_invalid="default")


def _limits() -> tuple[int, int]:
    from agent_bom import config

    return concurrency(), max(1, int(config.WORKER_THREAD_LIMIT))


def _gate() -> _Gate:
    loop = asyncio.get_running_loop()
    gate = _gates.get(loop)
    if gate is None:
        gate = _gates[loop] = _Gate(*_limits())
    return gate


def reset() -> None:
    """Drop per-loop gates so the next request reads the current limits."""
    _gates.clear()


async def _reject(send: Any) -> None:
    body = json.dumps({"detail": "Too many concurrent dashboard reads; retry shortly."}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 429,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"retry-after", b"1"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


async def admit(app: Any, scope: Any, receive: Any, send: Any) -> None:
    """Run ``app`` for this HTTP request, holding a gate slot if it is a heavy read."""
    if scope.get("method") not in ("GET", "HEAD") or scope.get("path") not in HEAVY_READ_PATHS:
        await app(scope, receive, send)
        return

    gate = _gate()
    if gate.semaphore.locked():
        if gate.waiting >= gate.max_waiters:
            await _reject(send)
            return
        gate.waiting += 1
        try:
            await gate.semaphore.acquire()
        finally:
            gate.waiting -= 1
    else:
        await gate.semaphore.acquire()

    released = False

    def release() -> None:
        nonlocal released
        if not released:
            released = True
            gate.semaphore.release()

    async def send_releasing(message: Any) -> None:
        if message["type"] == "http.response.start":
            release()
        await send(message)

    try:
        await app(scope, receive, send_releasing)
    finally:
        release()
