"""Schedule storage backends for recurring scans.

Follows the Protocol -> InMemory -> SQLite pattern.
"""

from __future__ import annotations

import sqlite3
import threading
from typing import Any, Protocol

from pydantic import BaseModel

from agent_bom.api.storage_schema import ensure_sqlite_schema_version
from agent_bom.core.tenancy import require_explicit_tenant_id


class ScanSchedule(BaseModel):
    """Recurring scan schedule."""

    schedule_id: str
    name: str
    cron_expression: str
    scan_config: dict[str, Any]
    enabled: bool = True
    last_run: str | None = None
    next_run: str | None = None
    last_job_id: str | None = None
    created_at: str = ""
    updated_at: str = ""
    tenant_id: str = "default"


class ScheduleStore(Protocol):
    """Protocol for schedule persistence."""

    def put(self, schedule: ScanSchedule, *, tenant_id: str) -> None: ...
    def get(self, schedule_id: str, tenant_id: str) -> ScanSchedule | None: ...
    def delete(self, schedule_id: str, tenant_id: str) -> bool: ...
    def list_all(self, tenant_id: str) -> list[ScanSchedule]: ...
    def list_due(self, now_iso: str) -> list[ScanSchedule]: ...


def schedule_write_tenant(schedule: ScanSchedule, tenant_id: str) -> str:
    """A schedule record cannot choose a different tenant than its caller."""
    tenant = require_explicit_tenant_id(tenant_id)
    if schedule.tenant_id != tenant:
        raise ValueError("Schedule tenant does not match the authorized tenant")
    return tenant


def schedule_record_for_tenant(schedule: ScanSchedule, tenant_id: str) -> ScanSchedule:
    """Reject serialized schedule data whose tenant disagrees with its row scope."""
    tenant = require_explicit_tenant_id(tenant_id)
    if schedule.tenant_id != tenant:
        raise ValueError("Stored schedule tenant does not match its row tenant")
    return schedule


class InMemoryScheduleStore:
    """Dict-based in-memory schedule store."""

    def __init__(self) -> None:
        self._schedules: dict[str, ScanSchedule] = {}

    def put(self, schedule: ScanSchedule, *, tenant_id: str) -> None:
        tenant = schedule_write_tenant(schedule, tenant_id)
        previous = self._schedules.get(schedule.schedule_id)
        if previous is not None and previous.tenant_id != tenant:
            raise ValueError("Schedule identity belongs to a different tenant")
        self._schedules[schedule.schedule_id] = schedule.model_copy(deep=True)

    def get(self, schedule_id: str, tenant_id: str) -> ScanSchedule | None:
        tenant = require_explicit_tenant_id(tenant_id)
        schedule = self._schedules.get(schedule_id)
        if schedule is None:
            return None
        if schedule.tenant_id != tenant:
            return None
        return schedule.model_copy(deep=True)

    def delete(self, schedule_id: str, tenant_id: str) -> bool:
        tenant = require_explicit_tenant_id(tenant_id)
        schedule = self._schedules.get(schedule_id)
        if schedule is None:
            return False
        if schedule.tenant_id != tenant:
            return False
        del self._schedules[schedule_id]
        return True

    def list_all(self, tenant_id: str) -> list[ScanSchedule]:
        tenant = require_explicit_tenant_id(tenant_id)
        return [schedule.model_copy(deep=True) for schedule in self._schedules.values() if schedule.tenant_id == tenant]

    def list_due(self, now_iso: str) -> list[ScanSchedule]:
        """Return due rows for the privileged scheduler, which binds each tenant before work."""
        return [s.model_copy(deep=True) for s in self._schedules.values() if s.enabled and s.next_run and s.next_run <= now_iso]


class SQLiteScheduleStore:
    """SQLite-backed persistent schedule store."""

    _TABLE = "scan_schedules"
    _LEGACY_TABLE = "schedules"

    def __init__(self, db_path: str = "agent_bom_schedules.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        conn: sqlite3.Connection = self._local.conn
        return conn

    def _init_db(self) -> None:
        ensure_sqlite_schema_version(self._conn, "schedules")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_schedules (
                schedule_id TEXT PRIMARY KEY,
                enabled INTEGER DEFAULT 1,
                next_run TEXT,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                data TEXT NOT NULL
            )
        """)
        legacy_exists = self._conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (self._LEGACY_TABLE,),
        ).fetchone()
        if legacy_exists:
            cols = {r[1] for r in self._conn.execute("PRAGMA table_info(schedules)").fetchall()}
            if "tenant_id" not in cols:
                self._conn.execute("ALTER TABLE schedules ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'")
            self._conn.execute(
                """
                INSERT OR IGNORE INTO scan_schedules (schedule_id, enabled, next_run, tenant_id, data)
                SELECT schedule_id, enabled, next_run, tenant_id, data FROM schedules
                """
            )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_sched_due ON scan_schedules(enabled, next_run)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_sched_tenant_due ON scan_schedules(tenant_id, enabled, next_run)")
        self._conn.commit()

    def put(self, schedule: ScanSchedule, *, tenant_id: str) -> None:
        schedule_write_tenant(schedule, tenant_id)
        cursor = self._conn.execute(
            """INSERT INTO scan_schedules (schedule_id, enabled, next_run, tenant_id, data)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT (schedule_id) DO UPDATE SET enabled=excluded.enabled,
                 next_run=excluded.next_run, data=excluded.data
               WHERE scan_schedules.tenant_id=excluded.tenant_id""",
            (schedule.schedule_id, int(schedule.enabled), schedule.next_run, schedule.tenant_id, schedule.model_dump_json()),
        )
        self._conn.commit()
        if cursor.rowcount == 0:
            raise ValueError("Schedule identity belongs to a different tenant")

    def get(self, schedule_id: str, tenant_id: str) -> ScanSchedule | None:
        tenant = require_explicit_tenant_id(tenant_id)
        row = self._conn.execute(
            "SELECT data FROM scan_schedules WHERE schedule_id = ? AND tenant_id = ?",
            (schedule_id, tenant),
        ).fetchone()
        if row is None:
            return None
        schedule: ScanSchedule = ScanSchedule.model_validate_json(row[0])
        return schedule_record_for_tenant(schedule, tenant)

    def delete(self, schedule_id: str, tenant_id: str) -> bool:
        tenant = require_explicit_tenant_id(tenant_id)
        cursor = self._conn.execute(
            "DELETE FROM scan_schedules WHERE schedule_id = ? AND tenant_id = ?",
            (schedule_id, tenant),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def list_all(self, tenant_id: str) -> list[ScanSchedule]:
        tenant = require_explicit_tenant_id(tenant_id)
        rows = self._conn.execute(
            "SELECT data FROM scan_schedules WHERE tenant_id = ? ORDER BY schedule_id",
            (tenant,),
        ).fetchall()
        return [schedule_record_for_tenant(ScanSchedule.model_validate_json(r[0]), tenant) for r in rows]

    def list_due(self, now_iso: str) -> list[ScanSchedule]:
        rows = self._conn.execute(
            "SELECT tenant_id, data FROM scan_schedules WHERE enabled = 1 AND next_run IS NOT NULL AND next_run <= ?",
            (now_iso,),
        ).fetchall()
        return [schedule_record_for_tenant(ScanSchedule.model_validate_json(r[1]), r[0]) for r in rows]
