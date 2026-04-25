"""Adaptive process-local backpressure controls for expensive runtime paths."""

from __future__ import annotations

import os
import time
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, AsyncIterator


class BackpressureRejectedError(RuntimeError):
    """Raised when a runtime path is shedding work under pressure."""

    def __init__(self, path: str, reason: str, retry_after_seconds: int) -> None:
        super().__init__(f"{path} backpressure active: {reason}")
        self.path = path
        self.reason = reason
        self.retry_after_seconds = retry_after_seconds

    def to_dict(self) -> dict[str, Any]:
        return {
            "message": "Backpressure active for runtime path",
            "path": self.path,
            "reason": self.reason,
            "retry_after_seconds": self.retry_after_seconds,
        }


@dataclass
class BackpressureController:
    """Small adaptive controller with concurrency and p99-triggered cooldown."""

    path: str
    max_concurrency: int
    p99_threshold_ms: float
    cooldown_seconds: int
    min_samples: int
    window_size: int = 128
    active: int = 0
    rejected: int = 0
    completed: int = 0
    open_until_monotonic: float = 0.0
    last_trigger_reason: str = ""
    _latencies_ms: deque[float] = field(default_factory=deque)
    _lock: Lock = field(default_factory=Lock)

    def try_enter(self) -> None:
        now = time.monotonic()
        with self._lock:
            if now < self.open_until_monotonic:
                self.rejected += 1
                raise BackpressureRejectedError(self.path, self.last_trigger_reason or "latency_degraded", self.retry_after_seconds(now))
            if self.open_until_monotonic:
                self.open_until_monotonic = 0.0
                self.last_trigger_reason = ""
                self._latencies_ms.clear()
            if self.active >= self.max_concurrency:
                self.rejected += 1
                raise BackpressureRejectedError(self.path, "concurrency_limit", 1)
            self.active += 1

    def exit(self, latency_ms: float) -> None:
        with self._lock:
            self.active = max(self.active - 1, 0)
            self.completed += 1
            self._latencies_ms.append(latency_ms)
            while len(self._latencies_ms) > self.window_size:
                self._latencies_ms.popleft()
            if len(self._latencies_ms) >= self.min_samples and self.p99_ms > self.p99_threshold_ms:
                self.open_until_monotonic = time.monotonic() + self.cooldown_seconds
                self.last_trigger_reason = "p99_latency_threshold"

    def retry_after_seconds(self, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        return max(1, int(self.open_until_monotonic - now + 0.999))

    @property
    def p95_ms(self) -> float:
        return _percentile(list(self._latencies_ms), 0.95)

    @property
    def p99_ms(self) -> float:
        return _percentile(list(self._latencies_ms), 0.99)

    def describe(self) -> dict[str, Any]:
        now = time.monotonic()
        open_state = now < self.open_until_monotonic
        return {
            "path": self.path,
            "state": "open" if open_state else "closed",
            "reason": self.last_trigger_reason if open_state else "",
            "active": self.active,
            "max_concurrency": self.max_concurrency,
            "completed": self.completed,
            "rejected": self.rejected,
            "latency_samples": len(self._latencies_ms),
            "p95_ms": round(self.p95_ms, 2),
            "p99_ms": round(self.p99_ms, 2),
            "p99_threshold_ms": self.p99_threshold_ms,
            "retry_after_seconds": self.retry_after_seconds(now) if open_state else 0,
        }


_CONTROLLERS: dict[str, BackpressureController] = {}
_CONTROLLERS_LOCK = Lock()


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * percentile))))
    return ordered[index]


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return min(max(value, minimum), maximum)


def _path_env_key(path: str, suffix: str) -> str:
    normalized = "".join(ch if ch.isalnum() else "_" for ch in path.upper()).strip("_")
    return f"AGENT_BOM_BACKPRESSURE_{normalized}_{suffix}"


def _controller_for(path: str) -> BackpressureController:
    with _CONTROLLERS_LOCK:
        controller = _CONTROLLERS.get(path)
        if controller is not None:
            return controller
        controller = BackpressureController(
            path=path,
            max_concurrency=_env_int(_path_env_key(path, "CONCURRENCY"), 8, minimum=1, maximum=1024),
            p99_threshold_ms=float(_env_int(_path_env_key(path, "P99_MS"), 2500, minimum=1, maximum=120_000)),
            cooldown_seconds=_env_int(_path_env_key(path, "COOLDOWN_SECONDS"), 10, minimum=1, maximum=3600),
            min_samples=_env_int(_path_env_key(path, "MIN_SAMPLES"), 20, minimum=1, maximum=10_000),
        )
        _CONTROLLERS[path] = controller
        return controller


@asynccontextmanager
async def adaptive_backpressure(path: str) -> AsyncIterator[None]:
    """Apply adaptive backpressure around a runtime operation."""
    if not _env_bool("AGENT_BOM_BACKPRESSURE_ENABLED", True):
        yield
        return
    controller = _controller_for(path)
    controller.try_enter()
    started = time.perf_counter()
    try:
        yield
    finally:
        controller.exit((time.perf_counter() - started) * 1000)


def describe_backpressure_posture() -> dict[str, Any]:
    """Return non-secret operator posture for adaptive backpressure."""
    enabled = _env_bool("AGENT_BOM_BACKPRESSURE_ENABLED", True)
    with _CONTROLLERS_LOCK:
        paths = [controller.describe() for controller in sorted(_CONTROLLERS.values(), key=lambda c: c.path)]
    return {
        "enabled": enabled,
        "status": "active" if any(path["state"] == "open" for path in paths) else "ready",
        "paths": paths,
        "notes": "Process-local adaptive backpressure. Static budgets and source circuit breakers still apply.",
    }


def reset_backpressure_for_tests() -> None:
    with _CONTROLLERS_LOCK:
        _CONTROLLERS.clear()
