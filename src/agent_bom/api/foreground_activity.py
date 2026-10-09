"""Let deferrable background CPU work yield to interactive requests.

Campaign reconciliation and the demo story prewarm are CPU-bound Python. Run
next to the first requests after a restart they hold the GIL and multiply those
requests' latency. Deferrable work waits until no request is in flight and none
ended within a quiet window. The wait is bounded, so constant traffic cannot
starve the work. State is per process, which matches the GIL it protects.
"""

from __future__ import annotations

import threading
import time
from typing import Any

QUIET_SECONDS = 5.0
MAX_DEFER_SECONDS = 60.0
_PROBE_PATHS = frozenset({"/health", "/healthz", "/livez", "/readyz", "/ping", "/metrics"})

_cond = threading.Condition()
_in_flight = 0
_last_activity = time.monotonic()


def _enter() -> None:
    global _in_flight, _last_activity
    with _cond:
        _in_flight += 1
        _last_activity = time.monotonic()


def reset() -> None:
    global _in_flight, _last_activity
    with _cond:
        _in_flight = 0
        _last_activity = time.monotonic() - QUIET_SECONDS
        _cond.notify_all()


def _leave() -> None:
    global _in_flight, _last_activity
    with _cond:
        _in_flight -= 1
        _last_activity = time.monotonic()
        _cond.notify_all()


def defer_until_idle(*, quiet: float | None = None, max_wait: float | None = None) -> bool:
    """Block until the foreground is quiet; return False if ``max_wait`` ran out first."""
    quiet = QUIET_SECONDS if quiet is None else quiet
    deadline = time.monotonic() + (MAX_DEFER_SECONDS if max_wait is None else max_wait)
    with _cond:
        while True:
            now = time.monotonic()
            if now >= deadline:
                return False
            if not _in_flight:
                idle_for = now - _last_activity
                if idle_for >= quiet:
                    return True
                _cond.wait(min(quiet - idle_for, deadline - now))
            else:
                _cond.wait(deadline - now)


class ForegroundActivityMiddleware:
    """Count in-flight HTTP requests, excluding orchestrator probes."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope.get("path") in _PROBE_PATHS:
            await self.app(scope, receive, send)
            return
        from agent_bom.api.heavy_read_gate import admit

        _enter()
        try:
            await admit(self.app, scope, receive, send)
        finally:
            _leave()
