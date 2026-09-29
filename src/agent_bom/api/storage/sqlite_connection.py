"""Bounded WAL initialization shared by thread-local SQLite stores."""

from __future__ import annotations

import sqlite3
import time
from contextlib import ExitStack


def open_wal_connection(path: str, *, normal_sync: bool = False) -> sqlite3.Connection:
    """Wait up to 30 seconds for WAL startup; close failed connections.

    SQLite may return SQLITE_BUSY immediately when concurrent connections
    switch journal mode, even with a busy handler. Retry that specific startup
    contention within the normal write-lock budget; propagate every other error.
    """
    with ExitStack() as cleanup:
        conn = sqlite3.connect(path, timeout=0.05, check_same_thread=False)
        cleanup.callback(conn.close)
        deadline = time.monotonic() + 30
        while True:
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                break
            except sqlite3.OperationalError as exc:
                remaining = deadline - time.monotonic()
                if getattr(exc, "sqlite_errorcode", 0) & 0xFF != sqlite3.SQLITE_BUSY or remaining <= 0:
                    raise
                time.sleep(min(0.05, remaining))
        conn.execute("PRAGMA busy_timeout=30000")
        if normal_sync:
            conn.execute("PRAGMA synchronous=NORMAL")
        cleanup.pop_all()
        return conn
