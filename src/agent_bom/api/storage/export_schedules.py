"""Postgres export schedules with tenant RLS and revision-fenced outcomes."""

from __future__ import annotations

from typing import Any

from agent_bom.api.export_schedule_store import ExportSchedule, completed_schedule, schedule_write_tenant
from agent_bom.api.postgres_common import _ensure_tenant_rls, _get_pool, _maintenance_connection, _tenant_connection, bypass_tenant_rls
from agent_bom.api.storage_schema import ensure_postgres_schema_version
from agent_bom.core.tenancy import require_explicit_tenant_id


class PostgresExportScheduleStore:
    """Application writes use tenant connections; due discovery requires maintenance."""

    def __init__(self, pool: Any = None, *, maintenance_pool: Any = None) -> None:
        self._pool = pool or _get_pool()
        self._maintenance_pool = maintenance_pool
        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, "export_schedules"):
                return
            conn.execute(
                "CREATE TABLE IF NOT EXISTS export_schedules ("
                "schedule_id TEXT NOT NULL, tenant_id TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE, "
                "next_run TEXT, data JSONB NOT NULL, PRIMARY KEY (tenant_id, schedule_id))"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_export_sched_due ON export_schedules(enabled, next_run, schedule_id)")
            _ensure_tenant_rls(conn, "export_schedules", "tenant_id")
            conn.commit()

    def put(self, schedule: ExportSchedule, *, tenant_id: str) -> None:
        tenant = schedule_write_tenant(schedule, tenant_id)
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                "INSERT INTO export_schedules (schedule_id, tenant_id, enabled, next_run, data) VALUES (%s, %s, %s, %s, %s::jsonb) "
                "ON CONFLICT (tenant_id, schedule_id) DO UPDATE SET enabled=excluded.enabled, "
                "next_run=excluded.next_run, data=excluded.data",
                (schedule.schedule_id, tenant, schedule.enabled, schedule.next_run, schedule.model_dump_json()),
            )
            conn.commit()

    def get(self, schedule_id: str, tenant_id: str) -> ExportSchedule | None:
        tenant = require_explicit_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            row = conn.execute("SELECT data FROM export_schedules WHERE schedule_id=%s AND tenant_id=%s", (schedule_id, tenant)).fetchone()
        return ExportSchedule.model_validate(row[0]) if row else None

    def delete(self, schedule_id: str, tenant_id: str) -> bool:
        tenant = require_explicit_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute("DELETE FROM export_schedules WHERE schedule_id=%s AND tenant_id=%s", (schedule_id, tenant))
            conn.commit()
            return bool(cursor.rowcount > 0)

    def list_all(self, tenant_id: str) -> list[ExportSchedule]:
        tenant = require_explicit_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute("SELECT data FROM export_schedules WHERE tenant_id=%s ORDER BY schedule_id", (tenant,)).fetchall()
        return [ExportSchedule.model_validate(row[0]) for row in rows]

    def list_due(self, now_iso: str, *, limit: int = 100) -> list[ExportSchedule]:
        with bypass_tenant_rls(), _maintenance_connection(self._maintenance_pool) as conn:
            rows = conn.execute(
                "SELECT data FROM export_schedules WHERE enabled AND next_run IS NOT NULL AND next_run<=%s "
                "ORDER BY next_run, schedule_id LIMIT %s",
                (now_iso, max(1, limit)),
            ).fetchall()
        return [ExportSchedule.model_validate(row[0]) for row in rows]

    def claim_due(self, schedule: ExportSchedule, next_run_iso: str | None, *, tenant_id: str) -> bool:
        schedule_write_tenant(schedule, tenant_id)
        if not schedule.enabled:
            return False
        return self._replace_observed(schedule, schedule.model_copy(update={"next_run": next_run_iso}))

    def record_run(self, observed: ExportSchedule, *, tenant_id: str, at: str, status: str, row_count: int | None) -> bool:
        schedule_write_tenant(observed, tenant_id)
        return self._replace_observed(observed, completed_schedule(observed, at, status, row_count))

    def _replace_observed(self, observed: ExportSchedule, updated: ExportSchedule) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                "UPDATE export_schedules SET next_run=%s, data=%s::jsonb WHERE schedule_id=%s AND tenant_id=%s AND data=%s::jsonb",
                (updated.next_run, updated.model_dump_json(), observed.schedule_id, observed.tenant_id, observed.model_dump_json()),
            )
            conn.commit()
            return bool(cursor.rowcount == 1)
