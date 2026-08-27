"""Shared bounded delivery state for runtime audit events.

This module owns the retry controller and disk backlog used by the stdio proxy
and the HTTP gateway.  Transport-specific code remains responsible for the
actual network call; persistence, restart loading, circuit state, and health
reporting must not drift between runtime entry points.
"""

from __future__ import annotations

import json
import logging
import os
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Mapping

from agent_bom.security import sanitize_sensitive_payload, sanitize_text

logger = logging.getLogger(__name__)

AuditBacklogDestination = Literal["noop", "spillover", "dlq", "dropped"]
_DEFAULT_MIN_DLQ_BYTES = 1024 * 1024


@dataclass
class AuditDeliveryController:
    """Backoff and circuit-breaker state for runtime audit delivery."""

    base_interval_seconds: int = 10
    max_backoff_seconds: int = 300
    breaker_failure_threshold: int = 3
    breaker_cooldown_seconds: int = 60
    consecutive_failures: int = 0
    _next_delay_seconds: int = 10
    _circuit_open_until: float = 0.0

    def is_circuit_open(self, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        return now < self._circuit_open_until

    def current_backoff_seconds(self, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        if self.is_circuit_open(now):
            return max(int(self._circuit_open_until - now), 1)
        return self._next_delay_seconds

    def record_success(self) -> None:
        self.consecutive_failures = 0
        self._next_delay_seconds = self.base_interval_seconds
        self._circuit_open_until = 0.0

    def record_failure(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self.consecutive_failures += 1
        if self._next_delay_seconds <= self.base_interval_seconds:
            self._next_delay_seconds = min(self.base_interval_seconds * 2, self.max_backoff_seconds)
        else:
            self._next_delay_seconds = min(self._next_delay_seconds * 2, self.max_backoff_seconds)
        if self.consecutive_failures >= self.breaker_failure_threshold:
            self._circuit_open_until = now + self.breaker_cooldown_seconds


@dataclass
class AuditSpilloverStore:
    """Persist a bounded, secret-safe runtime audit backlog and DLQ."""

    spill_path: Path
    dlq_path: Path
    max_spillover_bytes: int
    max_dlq_bytes: int | None = None
    dropped_events: int = field(default=0, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.spill_path = Path(self.spill_path)
        self.dlq_path = Path(self.dlq_path)
        if self.max_spillover_bytes < 1:
            raise ValueError("max_spillover_bytes must be greater than zero")
        if self.max_dlq_bytes is None:
            # Keep the proxy's historical spill-to-DLQ behavior even for tiny
            # test/operator spill limits, while replacing its unbounded DLQ
            # with a finite ceiling.
            self.max_dlq_bytes = max(self.max_spillover_bytes * 8, _DEFAULT_MIN_DLQ_BYTES)
        if self.max_dlq_bytes < 1:
            raise ValueError("max_dlq_bytes must be greater than zero")

    @staticmethod
    def _size_bytes(path: Path) -> int:
        try:
            return path.stat().st_size
        except FileNotFoundError:
            return 0

    def spillover_size_bytes(self) -> int:
        return self._size_bytes(self.spill_path)

    def dlq_size_bytes(self) -> int:
        return self._size_bytes(self.dlq_path)

    @property
    def dlq_limit_bytes(self) -> int:
        """Return the normalized finite DLQ ceiling."""

        if self.max_dlq_bytes is None:  # pragma: no cover - normalized in __post_init__
            raise RuntimeError("max_dlq_bytes was not initialized")
        return self.max_dlq_bytes

    @staticmethod
    def _encode_events(events: list[Mapping[str, Any]]) -> list[str]:
        encoded: list[str] = []
        for event in events:
            sanitized = sanitize_sensitive_payload(dict(event))
            if not isinstance(sanitized, dict):  # pragma: no cover - defensive contract guard
                continue
            encoded.append(json.dumps(sanitized, separators=(",", ":"), sort_keys=True))
        return encoded

    def append_events(self, events: list[Mapping[str, Any]]) -> AuditBacklogDestination:
        if not events:
            return "noop"
        encoded = self._encode_events(events)
        if not encoded:
            return "noop"
        total_bytes = sum(len((line + "\n").encode("utf-8")) for line in encoded)
        with self._lock:
            if self.spillover_size_bytes() + total_bytes <= self.max_spillover_bytes:
                self._append_lines(self.spill_path, encoded)
                return "spillover"
            if self.dlq_size_bytes() + total_bytes <= self.dlq_limit_bytes:
                self._append_lines(self.dlq_path, encoded)
                return "dlq"
            self.dropped_events += len(encoded)
            return "dropped"

    def read_spillover(self) -> list[dict[str, Any]]:
        with self._lock:
            if not self.spill_path.exists():
                return []
            self._reject_symlink(self.spill_path)
            events: list[dict[str, Any]] = []
            with self.spill_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        logger.warning(
                            "Skipping malformed runtime audit spillover line from %s",
                            sanitize_text(self.spill_path),
                        )
                        continue
                    if isinstance(payload, dict):
                        events.append(payload)
            return events

    def clear_spillover(self) -> None:
        with self._lock:
            if self.spill_path.exists():
                self._reject_symlink(self.spill_path)
                self.spill_path.unlink()

    @staticmethod
    def _reject_symlink(path: Path) -> None:
        if path.is_symlink():
            raise ValueError("runtime audit backlog path must not be a symlink")

    def _append_lines(self, path: Path, lines: list[str]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._reject_symlink(path)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        try:
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                fd = -1
                for line in lines:
                    handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if fd >= 0:
                os.close(fd)


@dataclass(frozen=True)
class AuditDeliveryState:
    """One shared controller/backlog with a secret-free health contract."""

    controller: AuditDeliveryController
    store: AuditSpilloverStore

    def health(self, *, buffer_bytes: int = 0, now: float | None = None) -> dict[str, str | int | bool]:
        memory_bytes = max(0, int(buffer_bytes))
        spillover_bytes = self.store.spillover_size_bytes()
        dlq_bytes = self.store.dlq_size_bytes()
        circuit_open = self.controller.is_circuit_open(now)
        degraded = bool(
            memory_bytes
            or spillover_bytes
            or dlq_bytes
            or self.controller.consecutive_failures
            or circuit_open
            or self.store.dropped_events
        )
        return {
            "status": "degraded" if degraded else "healthy",
            "buffer_bytes": memory_bytes,
            "spillover_bytes": spillover_bytes,
            "dlq_bytes": dlq_bytes,
            "backlog_bytes": memory_bytes + spillover_bytes,
            "consecutive_failures": self.controller.consecutive_failures,
            "backoff_seconds": self.controller.current_backoff_seconds(now),
            "circuit_open": circuit_open,
            "dropped_events": self.store.dropped_events,
        }


__all__ = [
    "AuditBacklogDestination",
    "AuditDeliveryController",
    "AuditDeliveryState",
    "AuditSpilloverStore",
]
