"""Bounded SQLite journal-mode transitions shared by storage backends."""

from __future__ import annotations

import sqlite3
import time


def enable_wal(conn: sqlite3.Connection, *, wait_seconds: float = 30.0) -> None:
    """Retry only SQLITE_BUSY, preserving the caller's ordinary lock timeout.

    Journal-mode changes can bypass SQLite's busy handler. Use an explicit
    deadline, with a nonblocking busy handler so no attempt overruns the budget.
    Exhaustion and non-contention errors propagate to the connection owner.
    """
    busy_timeout = int(conn.execute("PRAGMA busy_timeout").fetchone()[0])
    conn.execute("PRAGMA busy_timeout=0")
    deadline = time.monotonic() + wait_seconds
    try:
        while True:
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                return
            except sqlite3.OperationalError as exc:
                remaining = deadline - time.monotonic()
                if getattr(exc, "sqlite_errorcode", 0) & 0xFF != sqlite3.SQLITE_BUSY or remaining <= 0:
                    raise
                time.sleep(min(0.05, remaining))
    finally:
        conn.execute(f"PRAGMA busy_timeout={busy_timeout}")
