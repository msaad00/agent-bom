"""Schedule persistence for recurring findings exports (#4040).

Mirrors the scan-schedule store but drives export delivery instead of scans: a
cron cadence plus the destination to deliver to and the finding filters to
snapshot. ``claim_due`` is an atomic compare-and-swap on ``next_run`` so that,
across control-plane replicas, exactly one replica fires a given due export.
"""

from __future__ import annotations

import heapq
import os
import sqlite3
import threading
from typing import Protocol

from pydantic import BaseModel

from agent_bom.api.storage_schema import ensure_sqlite_schema_version
from agent_bom.core.tenancy import require_explicit_tenant_id
from agent_bom.storage.base import BackendKind
from agent_bom.storage.factory import resolve_backend, validate_sqlite_path


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

    def record_run(self, observed: ExportSchedule, *, tenant_id: str, at: str, status: str, row_count: int | None) -> bool: ...
    def put(self, schedule: ExportSchedule, *, tenant_id: str) -> None: ...
    def get(self, schedule_id: str, tenant_id: str) -> ExportSchedule | None: ...
    def delete(self, schedule_id: str, tenant_id: str) -> bool: ...
    def list_all(self, tenant_id: str) -> list[ExportSchedule]: ...
    def list_due(self, now_iso: str, *, limit: int = 100) -> list[ExportSchedule]: ...
    def claim_due(self, schedule: ExportSchedule, next_run_iso: str | None, *, tenant_id: str) -> bool: ...


class InMemoryExportScheduleStore:
    """Dict-based in-memory export-schedule store."""

    def __init__(self) -> None:
        self._schedules: dict[str, ExportSchedule] = {}
        self._lock = threading.Lock()

    def put(self, schedule: ExportSchedule, *, tenant_id: str) -> None:
        tenant = schedule_write_tenant(schedule, tenant_id)
        with self._lock:
            previous = self._schedules.get(schedule.schedule_id)
            if previous is not None and previous.tenant_id != tenant:
                raise ValueError("Export schedule identity belongs to a different tenant")
            self._schedules[schedule.schedule_id] = schedule.model_copy(deep=True)

    def get(self, schedule_id: str, tenant_id: str) -> ExportSchedule | None:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._lock:
            schedule = self._schedules.get(schedule_id)
            if schedule is None or schedule.tenant_id != tenant:
                return None
            return schedule.model_copy(deep=True)

    def delete(self, schedule_id: str, tenant_id: str) -> bool:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._lock:
            schedule = self._schedules.get(schedule_id)
            if schedule is None or schedule.tenant_id != tenant:
                return False
            del self._schedules[schedule_id]
            return True

    def list_all(self, tenant_id: str) -> list[ExportSchedule]:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._lock:
            schedules = [s.model_copy(deep=True) for s in self._schedules.values() if s.tenant_id == tenant]
        return schedules

    def list_due(self, now_iso: str, *, limit: int = 100) -> list[ExportSchedule]:
        """Return due rows for the privileged scheduler, which binds each tenant before work."""
        with self._lock:
            due = (s for s in self._schedules.values() if s.enabled and s.next_run and s.next_run <= now_iso)
            return [s.model_copy(deep=True) for s in heapq.nsmallest(max(1, limit), due, key=lambda s: (s.next_run or "", s.schedule_id))]

    def claim_due(self, schedule: ExportSchedule, next_run_iso: str | None, *, tenant_id: str) -> bool:
        """Advance ``next_run`` iff it still matches the observed value (CAS)."""
        tenant = schedule_write_tenant(schedule, tenant_id)
        with self._lock:
            current = self._schedules.get(schedule.schedule_id)
            if current is None or current.tenant_id != tenant:
                return False
            if not current.enabled or current != schedule:
                return False
            current.next_run = next_run_iso
        return True

    def record_run(self, observed: ExportSchedule, *, tenant_id: str, at: str, status: str, row_count: int | None) -> bool:
        tenant = schedule_write_tenant(observed, tenant_id)
        with self._lock:
            current = self._schedules.get(observed.schedule_id)
            if current is None or current.tenant_id != tenant or current != observed:
                return False
            self._schedules[observed.schedule_id] = completed_schedule(observed, at, status, row_count)
            return True


class SQLiteExportScheduleStore:
    """SQLite-backed persistent export-schedule store."""

    def __init__(self, db_path: str = "agent_bom_schedules.db") -> None:
        self._db_path = validate_sqlite_path(db_path)
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

    def put(self, schedule: ExportSchedule, *, tenant_id: str) -> None:
        schedule_write_tenant(schedule, tenant_id)
        cursor = self._conn.execute(
            "INSERT INTO export_schedules (schedule_id, enabled, next_run, tenant_id, data) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT (schedule_id) DO UPDATE SET enabled=excluded.enabled, next_run=excluded.next_run, "
            "data=excluded.data WHERE export_schedules.tenant_id=excluded.tenant_id",
            (schedule.schedule_id, int(schedule.enabled), schedule.next_run, schedule.tenant_id, schedule.model_dump_json()),
        )
        self._conn.commit()
        if cursor.rowcount == 0:
            raise ValueError("Export schedule identity belongs to a different tenant")

    def get(self, schedule_id: str, tenant_id: str) -> ExportSchedule | None:
        tenant = require_explicit_tenant_id(tenant_id)
        row = self._conn.execute(
            "SELECT data, next_run, enabled FROM export_schedules WHERE schedule_id = ? AND tenant_id = ?",
            (schedule_id, tenant),
        ).fetchone()
        return _sqlite_schedule(row) if row else None

    def delete(self, schedule_id: str, tenant_id: str) -> bool:
        tenant = require_explicit_tenant_id(tenant_id)
        cursor = self._conn.execute(
            "DELETE FROM export_schedules WHERE schedule_id = ? AND tenant_id = ?",
            (schedule_id, tenant),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def list_all(self, tenant_id: str) -> list[ExportSchedule]:
        tenant = require_explicit_tenant_id(tenant_id)
        rows = self._conn.execute(
            "SELECT data, next_run, enabled FROM export_schedules WHERE tenant_id = ? ORDER BY schedule_id",
            (tenant,),
        ).fetchall()
        return [_sqlite_schedule(r) for r in rows]

    def list_due(self, now_iso: str, *, limit: int = 100) -> list[ExportSchedule]:
        """Return due rows for the privileged scheduler, which binds each tenant before work."""
        rows = self._conn.execute(
            "SELECT data, next_run, enabled FROM export_schedules WHERE enabled = 1 AND next_run IS NOT NULL AND next_run <= ? "
            "ORDER BY next_run, schedule_id LIMIT ?",
            (now_iso, max(1, limit)),
        ).fetchall()
        return [_sqlite_schedule(r) for r in rows]

    def claim_due(self, schedule: ExportSchedule, next_run_iso: str | None, *, tenant_id: str) -> bool:
        """Atomically advance the indexed time and record if configuration is unchanged."""
        schedule_write_tenant(schedule, tenant_id)
        if not schedule.enabled:
            return False
        return self._replace_observed(schedule, schedule.model_copy(update={"next_run": next_run_iso}))

    def record_run(self, observed: ExportSchedule, *, tenant_id: str, at: str, status: str, row_count: int | None) -> bool:
        schedule_write_tenant(observed, tenant_id)
        return self._replace_observed(observed, completed_schedule(observed, at, status, row_count))

    def _replace_observed(self, observed: ExportSchedule, updated: ExportSchedule) -> bool:
        # Reserve the write before reading so other processes cannot edit/delete
        # between the comparison and update. Exceptions roll back the transaction.
        with self._conn:
            self._conn.execute("BEGIN IMMEDIATE")
            current = self.get(observed.schedule_id, observed.tenant_id)
            if current != observed:
                return False
            self._conn.execute(
                "UPDATE export_schedules SET next_run=?, data=? WHERE schedule_id=? AND tenant_id=?",
                (updated.next_run, updated.model_dump_json(), observed.schedule_id, observed.tenant_id),
            )
        return True


def _sqlite_schedule(row: tuple) -> ExportSchedule:
    # Older replicas only updated the indexed columns during a claim. Those
    # columns are authoritative even before the next write repairs the payload.
    return ExportSchedule.model_validate_json(row[0]).model_copy(update={"next_run": row[1], "enabled": bool(row[2])})


def completed_schedule(observed: ExportSchedule, at: str, status: str, row_count: int | None) -> ExportSchedule:
    """Outcome metadata does not rewrite the configuration's update revision."""
    return observed.model_copy(update={"last_run": at, "last_run_status": status, "last_row_count": row_count})


def schedule_write_tenant(schedule: ExportSchedule, tenant_id: str) -> str:
    """A schedule record cannot choose a different tenant than its caller."""
    tenant = require_explicit_tenant_id(tenant_id)
    if schedule.tenant_id != tenant:
        raise ValueError("Export schedule tenant does not match the authorized tenant")
    return tenant


_EXPORT_SCHEDULE_STORE: ExportScheduleStore | None = None


def get_export_schedule_store() -> ExportScheduleStore:
    """Return the process export-schedule store, selecting backend via factory."""
    global _EXPORT_SCHEDULE_STORE
    if _EXPORT_SCHEDULE_STORE is not None:
        return _EXPORT_SCHEDULE_STORE
    from agent_bom.api.storage.export_schedules import PostgresExportScheduleStore

    selection = resolve_backend(mode="env")
    if selection.backend is BackendKind.SQLITE and selection.sqlite_path:
        _EXPORT_SCHEDULE_STORE = SQLiteExportScheduleStore(selection.sqlite_path)
    elif selection.backend is BackendKind.POSTGRES:
        _EXPORT_SCHEDULE_STORE = PostgresExportScheduleStore()
    elif os.environ.get("AGENT_BOM_DB"):
        _EXPORT_SCHEDULE_STORE = SQLiteExportScheduleStore(os.environ["AGENT_BOM_DB"])
    else:
        _EXPORT_SCHEDULE_STORE = InMemoryExportScheduleStore()
    return _EXPORT_SCHEDULE_STORE


def set_export_schedule_store(store: ExportScheduleStore | None) -> None:
    """Swap the process export-schedule store (tests / explicit wiring)."""
    global _EXPORT_SCHEDULE_STORE
    _EXPORT_SCHEDULE_STORE = store
