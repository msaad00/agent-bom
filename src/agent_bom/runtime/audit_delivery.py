"""Shared bounded delivery state for runtime audit events.

This module owns the retry controller and disk backlog used by the stdio proxy
and the HTTP gateway.  Transport-specific code remains responsible for the
actual network call; persistence, restart loading, circuit state, and health
reporting must not drift between runtime entry points.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Literal, Mapping, Sequence

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows falls back to process locking
    fcntl = None  # type: ignore[assignment]

from agent_bom.security import sanitize_sensitive_payload

logger = logging.getLogger(__name__)

AuditBacklogDestination = Literal["noop", "spillover", "dlq", "dropped"]
_DEFAULT_MIN_DLQ_BYTES = 1024 * 1024
_STORE_LOCKS: dict[tuple[str, str], threading.RLock] = {}
_STORE_LOCKS_GUARD = threading.Lock()
_ACTIVE_CLAIMS: set[str] = set()


@dataclass(frozen=True)
class AuditDeliveryPaths:
    """Stable, secret-free paths for one runtime-delivery identity."""

    spill_path: Path
    dlq_path: Path


def audit_delivery_paths(state_dir: Path, *, surface: str, identity: str) -> AuditDeliveryPaths:
    """Derive restart-stable backlog paths without embedding credentials."""

    safe_surface = "".join(character for character in surface.lower() if character.isalnum() or character in {"-", "_"})
    if not safe_surface:
        raise ValueError("audit delivery surface must contain a safe character")
    identity_digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
    root = Path(state_dir) / "runtime-audit"
    stem = f"{safe_surface}-{identity_digest}"
    return AuditDeliveryPaths(
        spill_path=root / f"{stem}.spill.jsonl",
        dlq_path=root / f"{stem}.dlq.jsonl",
    )


@dataclass(frozen=True)
class AuditSpilloverClaim:
    """An atomically detached spill segment being delivered."""

    path: Path
    events: list[dict[str, Any]]


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

    def _shared_lock(self) -> threading.RLock:
        key = (os.path.abspath(self.spill_path), os.path.abspath(self.dlq_path))
        with _STORE_LOCKS_GUARD:
            return _STORE_LOCKS.setdefault(key, threading.RLock())

    @staticmethod
    def _safe_parent_fd(path: Path) -> int:
        parent = path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if parent.is_symlink():
            raise ValueError("runtime audit backlog parent directory must not be a symlink")
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        return os.open(parent, flags)

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        """Serialize bounds/rotation across store objects and processes."""

        with self._shared_lock(), self._lock:
            parent_fd = self._safe_parent_fd(self.spill_path)
            lock_name = f".{self.spill_path.name}.lock"
            lock_flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_NOFOLLOW"):
                lock_flags |= os.O_NOFOLLOW
            lock_fd = os.open(lock_name, lock_flags, 0o600, dir_fd=parent_fd)
            try:
                os.fchmod(lock_fd, stat.S_IRUSR | stat.S_IWUSR)
                if fcntl is not None:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX)
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
                os.close(parent_fd)

    @staticmethod
    def _size_bytes(path: Path) -> int:
        try:
            stat_result = path.lstat()
        except FileNotFoundError:
            return 0
        if stat.S_ISLNK(stat_result.st_mode):
            raise ValueError("runtime audit backlog path must not be a symlink")
        return stat_result.st_size

    def spillover_size_bytes(self) -> int:
        with self._exclusive():
            return self._spill_backlog_size_locked()

    def dlq_size_bytes(self) -> int:
        with self._exclusive():
            return self._size_bytes(self.dlq_path)

    @property
    def dlq_limit_bytes(self) -> int:
        """Return the normalized finite DLQ ceiling."""

        if self.max_dlq_bytes is None:  # pragma: no cover - normalized in __post_init__
            raise RuntimeError("max_dlq_bytes was not initialized")
        return self.max_dlq_bytes

    @staticmethod
    def _encode_events(events: Sequence[Mapping[str, Any]]) -> list[str]:
        encoded: list[str] = []
        for event in events:
            sanitized = sanitize_sensitive_payload(dict(event))
            if not isinstance(sanitized, dict):  # pragma: no cover - defensive contract guard
                continue
            encoded.append(json.dumps(sanitized, separators=(",", ":"), sort_keys=True))
        return encoded

    def append_events(self, events: Sequence[Mapping[str, Any]]) -> AuditBacklogDestination:
        if not events:
            return "noop"
        encoded = self._encode_events(events)
        if not encoded:
            return "noop"
        total_bytes = sum(len((line + "\n").encode("utf-8")) for line in encoded)
        with self._exclusive():
            if self._spill_backlog_size_locked() + total_bytes <= self.max_spillover_bytes:
                self._append_lines_locked(self.spill_path, encoded)
                return "spillover"
            if self._size_bytes(self.dlq_path) + total_bytes <= self.dlq_limit_bytes:
                self._append_lines_locked(self.dlq_path, encoded)
                return "dlq"
            self.dropped_events += len(encoded)
            return "dropped"

    def read_spillover(self) -> list[dict[str, Any]]:
        with self._exclusive():
            self._recover_orphan_claims_locked()
            if not self.spill_path.exists():
                return []
            return self._read_events_locked(self.spill_path)

    def claim_spillover(self) -> AuditSpilloverClaim | None:
        """Atomically detach the active spill so concurrent appends stay live."""

        with self._exclusive():
            self._recover_orphan_claims_locked()
            if self._size_bytes(self.spill_path) == 0:
                return None
            parent_fd = self._safe_parent_fd(self.spill_path)
            claim_path = self.spill_path.with_name(
                f"{self.spill_path.name}.claim-{time.time_ns():020d}-{os.getpid()}-{uuid.uuid4().hex}"
            )
            try:
                os.rename(
                    self.spill_path.name,
                    claim_path.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                os.fsync(parent_fd)
                _ACTIVE_CLAIMS.add(os.path.abspath(claim_path))
            finally:
                os.close(parent_fd)
            return AuditSpilloverClaim(path=claim_path, events=self._read_events_locked(claim_path))

    def acknowledge_claim(self, claim: AuditSpilloverClaim) -> None:
        """Delete only the segment a successful send actually delivered."""

        with self._exclusive():
            self._validate_claim_path(claim.path)
            self._reject_symlink(claim.path)
            if claim.path.exists():
                claim.path.unlink()
            _ACTIVE_CLAIMS.discard(os.path.abspath(claim.path))

    def acknowledge_claim_prefix(
        self,
        claim: AuditSpilloverClaim,
        event_count: int,
    ) -> AuditSpilloverClaim | None:
        """Durably acknowledge an ordered prefix and retain the unsent tail."""

        if event_count < 1 or event_count > len(claim.events):
            raise ValueError("acknowledged event count is outside the claimed batch")
        with self._exclusive():
            self._validate_claim_path(claim.path)
            self._reject_symlink(claim.path)
            if not claim.path.exists():
                _ACTIVE_CLAIMS.discard(os.path.abspath(claim.path))
                return None
            remaining = claim.events[event_count:]
            if not remaining:
                claim.path.unlink()
                _ACTIVE_CLAIMS.discard(os.path.abspath(claim.path))
                return None
            encoded = self._encode_events(remaining)
            payload = b"".join((line + "\n").encode("utf-8") for line in encoded)
            self._atomic_write_locked(claim.path, payload)
            return AuditSpilloverClaim(path=claim.path, events=[dict(event) for event in remaining])

    def restore_claim(
        self,
        claim: AuditSpilloverClaim,
        pending_events: Sequence[Mapping[str, Any]] | None = None,
    ) -> AuditBacklogDestination:
        """Restore a failed segment and persist the paired in-memory batch.

        Events appended while the transport awaits remain in the active spill.
        When the combined segment fits, the failed in-memory snapshot is placed
        before those newer events. If it does not fit, the claimed and active
        spill remains intact and the snapshot is diverted to the bounded DLQ.
        """

        with self._exclusive():
            self._validate_claim_path(claim.path)
            self._reject_symlink(claim.path)
            if not claim.path.exists():
                _ACTIVE_CLAIMS.discard(os.path.abspath(claim.path))
                return "noop"
            claimed = self._read_bytes_locked(claim.path)
            active = self._read_bytes_locked(self.spill_path)
            encoded = self._encode_events(pending_events or [])
            pending = b"".join((line + "\n").encode("utf-8") for line in encoded)
            if len(claimed) + len(pending) + len(active) <= self.max_spillover_bytes:
                self._atomic_write_locked(self.spill_path, claimed + pending + active)
                destination: AuditBacklogDestination = "spillover" if pending else "noop"
            else:
                self._atomic_write_locked(self.spill_path, claimed + active)
                if self._size_bytes(self.dlq_path) + len(pending) <= self.dlq_limit_bytes:
                    self._append_lines_locked(self.dlq_path, encoded)
                    destination = "dlq"
                else:
                    self.dropped_events += len(encoded)
                    destination = "dropped"
            claim.path.unlink()
            _ACTIVE_CLAIMS.discard(os.path.abspath(claim.path))
            return destination

    @staticmethod
    def _reject_symlink(path: Path) -> None:
        if path.is_symlink():
            raise ValueError("runtime audit backlog path must not be a symlink")

    def _claim_paths_locked(self) -> list[Path]:
        parent_fd = self._safe_parent_fd(self.spill_path)
        os.close(parent_fd)
        return sorted(self.spill_path.parent.glob(f"{self.spill_path.name}.claim-*"))

    def _spill_backlog_size_locked(self) -> int:
        return self._size_bytes(self.spill_path) + sum(self._size_bytes(path) for path in self._claim_paths_locked())

    def _validate_claim_path(self, path: Path) -> None:
        expected_prefix = f"{self.spill_path.name}.claim-"
        if path.parent != self.spill_path.parent or not path.name.startswith(expected_prefix):
            raise ValueError("runtime audit spillover claim does not belong to this store")

    def _read_events_locked(self, path: Path) -> list[dict[str, Any]]:
        self._reject_symlink(path)
        events: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning(
                        "Skipping malformed runtime audit spillover record",
                    )
                    continue
                if isinstance(payload, dict):
                    events.append(payload)
        return events

    def _read_bytes_locked(self, path: Path) -> bytes:
        self._reject_symlink(path)
        if not path.exists():
            return b""
        return path.read_bytes()

    def _recover_orphan_claims_locked(self) -> None:
        claims = [path for path in self._claim_paths_locked() if self._claim_is_orphaned(path)]
        if not claims:
            return
        recovered = b"".join(self._read_bytes_locked(path) for path in claims)
        active = self._read_bytes_locked(self.spill_path)
        self._atomic_write_locked(self.spill_path, recovered + active)
        for path in claims:
            path.unlink()

    @staticmethod
    def _claim_is_orphaned(path: Path) -> bool:
        if os.path.abspath(path) in _ACTIVE_CLAIMS:
            return False
        try:
            owner_pid = int(path.name.rsplit("-", 2)[1])
        except (IndexError, ValueError):
            return True
        if owner_pid == os.getpid():
            return True
        try:
            os.kill(owner_pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        return False

    def _append_lines_locked(self, path: Path, lines: list[str]) -> None:
        parent_fd = self._safe_parent_fd(path)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path.name, flags, 0o600, dir_fd=parent_fd)
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
            os.close(parent_fd)

    def _atomic_write_locked(self, path: Path, content: bytes) -> None:
        parent_fd = self._safe_parent_fd(path)
        temp_name = f".{path.name}.tmp-{uuid.uuid4().hex}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
        try:
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            os.close(parent_fd)


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
    "AuditDeliveryPaths",
    "AuditDeliveryState",
    "AuditSpilloverClaim",
    "AuditSpilloverStore",
    "audit_delivery_paths",
]
