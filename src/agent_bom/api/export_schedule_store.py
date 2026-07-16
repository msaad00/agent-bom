"""Schedule persistence for recurring findings exports (#4040).

Mirrors the scan-schedule store but drives export delivery instead of scans: a
cron cadence plus the destination to deliver to and the finding filters to
snapshot. ``claim_due`` is an atomic compare-and-swap on ``next_run`` so that,
across control-plane replicas, exactly one replica fires a given due export.
"""

from __future__ import annotations

import sqlite3
import threading
from typing import Protocol

from pydantic import BaseModel

from agent_bom.api.storage_schema import ensure_sqlite_schema_version


class ExportSchedule(BaseModel):
    """Recurring findings-export schedule."""

    schedule_id: str
    name: str
    cron_expression: str
    destination_id: str
    tenant_id: str = "default"
    enabled: bool = True
    sort: str = "effective_reach"
    severity: str | None = None
    since_days: int | None = None
    last_run: str | None = None
    next_run: str | None = None
    last_run_status: str | None = None
    last_row_count: int | None = None
    created_at: str = ""
    updated_at: str = ""


class ExportScheduleStore(Protocol):
    """Protocol for export-schedule persistence."""

    def put(self, schedule: ExportSchedule) -> None: ...
    def get(self, schedule_id: str, tenant_id: str | None = None) -> ExportSchedule | None: ...
    def delete(self, schedule_id: str, tenant_id: str | None = None) -> bool: ...
    def list_all(self, tenant_id: str | None = None) -> list[ExportSchedule]: ...
    def list_due(self, now_iso: str) -> list[ExportSchedule]: ...
    def claim_due(self, schedule: ExportSchedule, next_run_iso: str | None) -> bool: ...


class InMemoryExportScheduleStore:
    """Dict-based in-memory export-schedule store."""

    def __init__(self) -> None:
        self._schedules: dict[str, ExportSchedule] = {}
        self._lock = threading.Lock()

    def put(self, schedule: ExportSchedule) -> None:
        with self._lock:
            self._schedules[schedule.schedule_id] = schedule.model_copy(deep=True)

    def get(self, schedule_id: str, tenant_id: str | None = None) -> ExportSchedule | None:
        with self._lock:
            schedule = self._schedules.get(schedule_id)
            if schedule is None or (tenant_id is not None and schedule.tenant_id != tenant_id):
                return None
            return schedule.model_copy(deep=True)

    def delete(self, schedule_id: str, tenant_id: str | None = None) -> bool:
        with self._lock:
            schedule = self._schedules.get(schedule_id)
            if schedule is None or (tenant_id is not None and schedule.tenant_id != tenant_id):
                return False
            del self._schedules[schedule_id]
            return True

    def list_all(self, tenant_id: str | None = None) -> list[ExportSchedule]:
        with self._lock:
            schedules = [s.model_copy(deep=True) for s in self._schedules.values()]
        if tenant_id is None:
            return schedules
        return [s for s in schedules if s.tenant_id == tenant_id]

    def list_due(self, now_iso: str) -> list[ExportSchedule]:
        with self._lock:
            return [s.model_copy(deep=True) for s in self._schedules.values() if s.enabled and s.next_run and s.next_run <= now_iso]

    def claim_due(self, schedule: ExportSchedule, next_run_iso: str | None) -> bool:
        """Advance ``next_run`` iff it still matches the observed value (CAS)."""
        with self._lock:
            current = self._schedules.get(schedule.schedule_id)
            if current is None or current.tenant_id != schedule.tenant_id:
                return False
            if current.next_run != schedule.next_run:
                return False
            current.next_run = next_run_iso
        return True


class SQLiteExportScheduleStore:
    """SQLite-backed persistent export-schedule store."""

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
        ensure_sqlite_schema_version(self._conn, "export_schedules")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS export_schedules ("
            "schedule_id TEXT PRIMARY KEY, enabled INTEGER DEFAULT 1, next_run TEXT, "
            "tenant_id TEXT NOT NULL DEFAULT 'default', data TEXT NOT NULL)"
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_export_sched_due ON export_schedules(enabled, next_run)")
        self._conn.commit()

    def put(self, schedule: ExportSchedule) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO export_schedules (schedule_id, enabled, next_run, tenant_id, data) VALUES (?, ?, ?, ?, ?)",
            (schedule.schedule_id, int(schedule.enabled), schedule.next_run, schedule.tenant_id, schedule.model_dump_json()),
        )
        self._conn.commit()

    def get(self, schedule_id: str, tenant_id: str | None = None) -> ExportSchedule | None:
        if tenant_id is None:
            row = self._conn.execute("SELECT data FROM export_schedules WHERE schedule_id = ?", (schedule_id,)).fetchone()
        else:
            row = self._conn.execute(
                "SELECT data FROM export_schedules WHERE schedule_id = ? AND tenant_id = ?",
                (schedule_id, tenant_id),
            ).fetchone()
        return ExportSchedule.model_validate_json(row[0]) if row else None

    def delete(self, schedule_id: str, tenant_id: str | None = None) -> bool:
        if tenant_id is None:
            cursor = self._conn.execute("DELETE FROM export_schedules WHERE schedule_id = ?", (schedule_id,))
        else:
            cursor = self._conn.execute(
                "DELETE FROM export_schedules WHERE schedule_id = ? AND tenant_id = ?",
                (schedule_id, tenant_id),
            )
        self._conn.commit()
        return cursor.rowcount > 0

    def list_all(self, tenant_id: str | None = None) -> list[ExportSchedule]:
        if tenant_id is None:
            rows = self._conn.execute("SELECT data FROM export_schedules ORDER BY schedule_id").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM export_schedules WHERE tenant_id = ? ORDER BY schedule_id",
                (tenant_id,),
            ).fetchall()
        return [ExportSchedule.model_validate_json(r[0]) for r in rows]

    def list_due(self, now_iso: str) -> list[ExportSchedule]:
        rows = self._conn.execute(
            "SELECT data FROM export_schedules WHERE enabled = 1 AND next_run IS NOT NULL AND next_run <= ?",
            (now_iso,),
        ).fetchall()
        return [ExportSchedule.model_validate_json(r[0]) for r in rows]

    def claim_due(self, schedule: ExportSchedule, next_run_iso: str | None) -> bool:
        """Advance ``next_run`` via a conditional UPDATE (compare-and-swap).

        Only the replica whose observed ``next_run`` still matches wins; a racing
        replica's WHERE no longer matches after the winner commits.
        """
        if schedule.next_run is None:
            cursor = self._conn.execute(
                "UPDATE export_schedules SET next_run = ? WHERE schedule_id = ? AND tenant_id = ? AND next_run IS NULL",
                (next_run_iso, schedule.schedule_id, schedule.tenant_id),
            )
        else:
            cursor = self._conn.execute(
                "UPDATE export_schedules SET next_run = ? WHERE schedule_id = ? AND tenant_id = ? AND next_run = ?",
                (next_run_iso, schedule.schedule_id, schedule.tenant_id, schedule.next_run),
            )
        self._conn.commit()
        return cursor.rowcount == 1


_EXPORT_SCHEDULE_STORE: ExportScheduleStore | None = None


def get_export_schedule_store() -> ExportScheduleStore:
    """Return the process export-schedule store, selecting backend via factory."""
    global _EXPORT_SCHEDULE_STORE
    if _EXPORT_SCHEDULE_STORE is not None:
        return _EXPORT_SCHEDULE_STORE
    import os

    from agent_bom.storage.base import BackendKind
    from agent_bom.storage.factory import resolve_backend

    selection = resolve_backend(mode="env")
    if selection.backend is BackendKind.SQLITE and selection.sqlite_path:
        _EXPORT_SCHEDULE_STORE = SQLiteExportScheduleStore(selection.sqlite_path)
    elif os.environ.get("AGENT_BOM_DB"):
        _EXPORT_SCHEDULE_STORE = SQLiteExportScheduleStore(os.environ["AGENT_BOM_DB"])
    else:
        _EXPORT_SCHEDULE_STORE = InMemoryExportScheduleStore()
    return _EXPORT_SCHEDULE_STORE


def set_export_schedule_store(store: ExportScheduleStore | None) -> None:
    """Swap the process export-schedule store (tests / explicit wiring)."""
    global _EXPORT_SCHEDULE_STORE
    _EXPORT_SCHEDULE_STORE = store
