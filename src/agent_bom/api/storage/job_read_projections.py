"""Existence queries that never materialize persisted scan reports."""

from typing import Any

from agent_bom.api.storage.jobs import require_job_tenant

DEMO_ESTATE_TRIGGERED_BY = "demo-estate-bootstrap"


def sqlite_demo_exists(self: Any, tenant_id: str) -> bool:
    require_job_tenant(tenant_id)
    try:
        return (
            self._conn.execute(
                """SELECT 1 FROM jobs WHERE tenant_id = ? AND status = 'done'
            AND (triggered_by = ? OR EXISTS (
                SELECT 1 FROM json_each(data, '$.result.scan_sources')
                WHERE LOWER(CAST(value AS TEXT)) LIKE '%demo%'))
            AND (COALESCE(json_array_length(data, '$.result.findings'), 0) > 0
                OR COALESCE(json_array_length(data, '$.result.vulnerabilities'), 0) > 0)
            LIMIT 1""",
                (tenant_id, DEMO_ESTATE_TRIGGERED_BY),
            ).fetchone()
            is not None
        )
    finally:
        self._shrink_connection_memory()
        self._close_thread_connection()


def postgres_demo_exists(self: Any, tenant_id: str) -> bool:
    from agent_bom.api.postgres_common import _tenant_connection

    require_job_tenant(tenant_id)
    with _tenant_connection(self._pool) as conn:
        return (
            conn.execute(
                """SELECT 1 FROM scan_jobs WHERE team_id = %s AND status = 'done'
            AND (triggered_by = 'demo-estate-bootstrap' OR EXISTS (
                SELECT 1 FROM jsonb_array_elements_text(
                    CASE WHEN jsonb_typeof(data->'result'->'scan_sources') = 'array'
                    THEN data->'result'->'scan_sources' ELSE '[]'::jsonb END) AS source(value)
                WHERE LOWER(value) LIKE '%%demo%%'))
            AND (jsonb_array_length(CASE WHEN jsonb_typeof(data->'result'->'findings') = 'array'
                    THEN data->'result'->'findings' ELSE '[]'::jsonb END) > 0
                OR jsonb_array_length(CASE WHEN jsonb_typeof(data->'result'->'vulnerabilities') = 'array'
                    THEN data->'result'->'vulnerabilities' ELSE '[]'::jsonb END) > 0)
            LIMIT 1""",
                (tenant_id,),
            ).fetchone()
            is not None
        )
