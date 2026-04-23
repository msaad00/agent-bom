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
    def get(self, schedule_id: str, tenant_id: str | None = None) -> ScanSchedule | None: ...
    def delete(self, schedule_id: str, tenant_id: str | None = None) -> bool: ...
    def list_all(self, tenant_id: str | None = None) -> list[ScanSchedule]: ...
    def list_due(self, now_iso: str) -> list[ScanSchedule]: ...


class InMemoryScheduleStore:
    """Dict-based in-memory schedule store."""

    def __init__(self) -> None:
        self._schedules: dict[str, ScanSchedule] = {}

    def put(self, schedule: ScanSchedule) -> None:
        self._schedules[schedule.schedule_id] = schedule

    def get(self, schedule_id: str, tenant_id: str | None = None) -> ScanSchedule | None:
        schedule = self._schedules.get(schedule_id)
        if schedule is None:
            return None
        if tenant_id is not None and schedule.tenant_id != tenant_id:
            return None
        return schedule

    def delete(self, schedule_id: str, tenant_id: str | None = None) -> bool:
        schedule = self._schedules.get(schedule_id)
        if schedule is None:
            return False
        if tenant_id is not None and schedule.tenant_id != tenant_id:
            return False
        del self._schedules[schedule_id]
        return True
        return False

    def list_all(self, tenant_id: str | None = None) -> list[ScanSchedule]:
        schedules = list(self._schedules.values())
        if tenant_id is None:
            return schedules
        return [schedule for schedule in schedules if schedule.tenant_id == tenant_id]

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
                tenant_id TEXT NOT NULL DEFAULT 'default',
                data TEXT NOT NULL
            )
        """)
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(schedules)").fetchall()}
        if "tenant_id" not in cols:
            self._conn.execute("ALTER TABLE schedules ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_sched_due ON schedules(enabled, next_run)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_sched_tenant_due ON schedules(tenant_id, enabled, next_run)")
        self._conn.commit()

    def put(self, schedule: ScanSchedule) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO schedules (schedule_id, enabled, next_run, tenant_id, data)
               VALUES (?, ?, ?, ?, ?)""",
            (schedule.schedule_id, int(schedule.enabled), schedule.next_run, schedule.tenant_id, schedule.model_dump_json()),
        )
        self._conn.commit()

    def get(self, schedule_id: str, tenant_id: str | None = None) -> ScanSchedule | None:
        if tenant_id is None:
            row = self._conn.execute("SELECT data FROM schedules WHERE schedule_id = ?", (schedule_id,)).fetchone()
        else:
            row = self._conn.execute(
                "SELECT data FROM schedules WHERE schedule_id = ? AND tenant_id = ?",
                (schedule_id, tenant_id),
            ).fetchone()
        if row is None:
            return None
        return ScanSchedule.model_validate_json(row[0])

    def delete(self, schedule_id: str, tenant_id: str | None = None) -> bool:
        if tenant_id is None:
            cursor = self._conn.execute("DELETE FROM schedules WHERE schedule_id = ?", (schedule_id,))
        else:
            cursor = self._conn.execute(
                "DELETE FROM schedules WHERE schedule_id = ? AND tenant_id = ?",
                (schedule_id, tenant_id),
            )
        self._conn.commit()
        return cursor.rowcount > 0

    def list_all(self, tenant_id: str | None = None) -> list[ScanSchedule]:
        if tenant_id is None:
            rows = self._conn.execute("SELECT data FROM schedules ORDER BY schedule_id").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM schedules WHERE tenant_id = ? ORDER BY schedule_id",
                (tenant_id,),
            ).fetchall()
        return [ScanSchedule.model_validate_json(r[0]) for r in rows]

    def list_due(self, now_iso: str) -> list[ScanSchedule]:
        rows = self._conn.execute(
            "SELECT data FROM schedules WHERE enabled = 1 AND next_run IS NOT NULL AND next_run <= ?",
            (now_iso,),
        ).fetchall()
        return [ScanSchedule.model_validate_json(r[0]) for r in rows]
