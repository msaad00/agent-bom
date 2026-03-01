"""Schedule storage backends for recurring scans.

Follows the Protocol -> InMemory -> SQLite pattern.
"""

from __future__ import annotations

import sqlite3
import threading
from typing import Protocol

from pydantic import BaseModel


class ScanSchedule(BaseModel):
    """Recurring scan schedule."""

    schedule_id: str
    name: str
    cron_expression: str
    scan_config: dict
    enabled: bool = True
    last_run: str | None = None
    next_run: str | None = None
    last_job_id: str | None = None
    created_at: str = ""
    updated_at: str = ""
    tenant_id: str = "default"


class ScheduleStore(Protocol):
    """Protocol for schedule persistence."""

    def put(self, schedule: ScanSchedule) -> None: ...
    def get(self, schedule_id: str) -> ScanSchedule | None: ...
    def delete(self, schedule_id: str) -> bool: ...
    def list_all(self) -> list[ScanSchedule]: ...
    def list_due(self, now_iso: str) -> list[ScanSchedule]: ...


class InMemoryScheduleStore:
    """Dict-based in-memory schedule store."""

    def __init__(self) -> None:
        self._schedules: dict[str, ScanSchedule] = {}

    def put(self, schedule: ScanSchedule) -> None:
        self._schedules[schedule.schedule_id] = schedule

    def get(self, schedule_id: str) -> ScanSchedule | None:
        return self._schedules.get(schedule_id)

    def delete(self, schedule_id: str) -> bool:
        if schedule_id in self._schedules:
            del self._schedules[schedule_id]
            return True
        return False

    def list_all(self) -> list[ScanSchedule]:
        return list(self._schedules.values())

    def list_due(self, now_iso: str) -> list[ScanSchedule]:
        """Return enabled schedules where next_run <= now."""
        return [s for s in self._schedules.values() if s.enabled and s.next_run and s.next_run <= now_iso]


class SQLiteScheduleStore:
    """SQLite-backed persistent schedule store."""

    def __init__(self, db_path: str = "agent_bom_schedules.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

    def _init_db(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS schedules (
                schedule_id TEXT PRIMARY KEY,
                enabled INTEGER DEFAULT 1,
                next_run TEXT,
                data TEXT NOT NULL
            )
        """)
        self._conn.commit()

    def put(self, schedule: ScanSchedule) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO schedules (schedule_id, enabled, next_run, data)
               VALUES (?, ?, ?, ?)""",
            (schedule.schedule_id, int(schedule.enabled), schedule.next_run, schedule.model_dump_json()),
        )
        self._conn.commit()

    def get(self, schedule_id: str) -> ScanSchedule | None:
        row = self._conn.execute("SELECT data FROM schedules WHERE schedule_id = ?", (schedule_id,)).fetchone()
        if row is None:
            return None
        return ScanSchedule.model_validate_json(row[0])

    def delete(self, schedule_id: str) -> bool:
        cursor = self._conn.execute("DELETE FROM schedules WHERE schedule_id = ?", (schedule_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def list_all(self) -> list[ScanSchedule]:
        rows = self._conn.execute("SELECT data FROM schedules ORDER BY schedule_id").fetchall()
        return [ScanSchedule.model_validate_json(r[0]) for r in rows]

    def list_due(self, now_iso: str) -> list[ScanSchedule]:
        rows = self._conn.execute(
            "SELECT data FROM schedules WHERE enabled = 1 AND next_run IS NOT NULL AND next_run <= ?",
            (now_iso,),
        ).fetchall()
        return [ScanSchedule.model_validate_json(r[0]) for r in rows]
