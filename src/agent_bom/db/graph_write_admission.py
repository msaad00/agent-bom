"""Bounded FIFO admission for same-process SQLite graph writers.

SQLite still coordinates separate processes. This queue prevents a hot local
writer from repeatedly winning connection/bootstrap locks ahead of waiters.
Initialized WAL readers do not enter this queue.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from weakref import WeakValueDictionary


class _WriterQueue:
    def __init__(self) -> None:
        self.condition = threading.Condition()
        self.waiters: deque[object] = deque()
        self.owner: int | None = None
        self.depth = 0

    @contextmanager
    def enter(self, timeout: float) -> Iterator[None]:
        identity = threading.get_ident()
        deadline = time.monotonic() + timeout
        with self.condition:
            if self.owner == identity:
                self.depth += 1
            else:
                ticket = object()
                self.waiters.append(ticket)
                admitted = False
                try:
                    while self.owner is not None or self.waiters[0] is not ticket:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            error = sqlite3.OperationalError("Graph writer admission timed out")
                            error.sqlite_errorcode = sqlite3.SQLITE_BUSY
                            error.sqlite_errorname = "SQLITE_BUSY"
                            raise error
                        self.condition.wait(remaining)
                    self.waiters.popleft()
                    self.owner, self.depth = identity, 1
                    admitted = True
                finally:
                    if not admitted:
                        self.waiters.remove(ticket)
                        self.condition.notify_all()
        try:
            yield
        finally:
            with self.condition:
                self.depth -= 1
                if not self.depth:
                    self.owner = None
                    self.condition.notify_all()


_registry_lock = threading.Lock()
_queues: WeakValueDictionary[str, _WriterQueue] = WeakValueDictionary()


def _reset_after_fork() -> None:
    # A child must never inherit a queue owned by a vanished parent thread.
    global _registry_lock, _queues
    _registry_lock = threading.Lock()
    _queues = WeakValueDictionary()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_after_fork)


@contextmanager
def graph_writer_admission(db_path: str | Path, *, timeout: float = 10.0) -> Iterator[None]:
    """Queue by resolved file path; retain SQLite's bounded contention failure."""
    if str(db_path) == ":memory:":
        yield
        return
    key = str(Path(db_path).resolve())
    with _registry_lock:
        queue = _queues.get(key)
        if queue is None:
            queue = _WriterQueue()
            _queues[key] = queue
    with queue.enter(timeout):
        yield
