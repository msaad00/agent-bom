"""Postgres-backed scan finding snapshots with forced tenant RLS (ADR-015).

``POSTGRES_SCAN_SNAPSHOTS_V1`` is the migration-owned DDL: Alembic revision
``20261010_01`` executes it and ``runtime-schema.sql`` carries it verbatim, so a
configured deployment never runs store DDL. The bootstrap path below only runs
for isolated development pools without a deployment URL.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from agent_bom.api.postgres_common import (
    _ensure_tenant_rls,
    _get_pool,
    _maintenance_connection,
    _tenant_connection,
    bypass_tenant_rls,
    reset_current_tenant,
    set_current_tenant,
)
from agent_bom.api.scan_snapshot_store import (
    META_COLUMNS_SQL,
    meta_columns,
    meta_from_columns,
    require_tenant,
    row_columns,
    row_from_columns,
)
from agent_bom.api.storage_schema import ensure_postgres_schema_version

if TYPE_CHECKING:
    from psycopg import Connection
    from psycopg_pool import ConnectionPool

_TABLE_DDL = (
    """CREATE TABLE IF NOT EXISTS scan_snapshot_jobs (
    tenant_id TEXT NOT NULL CHECK (length(btrim(tenant_id)) > 0),
    job_id TEXT NOT NULL,
    scope_key TEXT NOT NULL,
    authority_evidence_at TEXT NOT NULL,
    authority_completed_at TEXT NOT NULL,
    authoritative BOOLEAN NOT NULL,
    incomplete_reasons TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    row_schema_version INTEGER NOT NULL,
    row_count INTEGER NOT NULL,
    materialized_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, job_id)
);""",
    "CREATE INDEX IF NOT EXISTS idx_scan_snapshot_jobs_completed ON scan_snapshot_jobs (completed_at);",
    """CREATE TABLE IF NOT EXISTS scan_snapshot_rows (
    tenant_id TEXT NOT NULL CHECK (length(btrim(tenant_id)) > 0),
    job_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    finding_identity TEXT NOT NULL,
    canonical_id TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',
    payload TEXT NOT NULL,
    PRIMARY KEY (tenant_id, job_id, ordinal)
);""",
    "CREATE INDEX IF NOT EXISTS idx_scan_snapshot_rows_job ON scan_snapshot_rows (tenant_id, job_id);",
    "CREATE INDEX IF NOT EXISTS idx_scan_snapshot_rows_canonical ON scan_snapshot_rows (tenant_id, canonical_id) WHERE canonical_id <> '';",
)
_TABLES = ("scan_snapshot_jobs", "scan_snapshot_rows")


def _rls_ddl(table: str) -> str:
    predicate = "public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant()"
    return (
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;\n"
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;\n"
        f"DROP POLICY IF EXISTS {table}_tenant_isolation ON {table};\n"
        f"CREATE POLICY {table}_tenant_isolation ON {table} USING ({predicate}) WITH CHECK ({predicate});\n"
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO agent_bom_app, agent_bom_rls_maintenance;"
    )


POSTGRES_SCAN_SNAPSHOTS_V1 = "\n".join(
    (
        "-- Materialized scan finding snapshots (ADR-015, migration 20261010_01).",
        *_TABLE_DDL,
        *(_rls_ddl(table) for table in _TABLES),
        "INSERT INTO control_plane_schema_versions(component,version,updated_at) VALUES ('scan_snapshots',1,now()) "
        "ON CONFLICT(component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,1);",
    )
)


@contextmanager
def _tenant_bound(pool: ConnectionPool, tenant_id: str) -> Iterator[Connection]:
    """Bind the RLS tenant to the snapshot owner for this one connection."""
    token = set_current_tenant(require_tenant(tenant_id))
    try:
        with _tenant_connection(pool) as conn:
            yield conn
    finally:
        reset_current_tenant(token)


class PostgresScanSnapshotStore:
    """Persistent scan snapshots; every query is tenant-bound under forced RLS."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, "scan_snapshots"):
                return
            for statement in _TABLE_DDL:
                conn.execute(statement)
            for table in _TABLES:
                _ensure_tenant_rls(conn, table, "tenant_id")
            conn.commit()

    def put_snapshot(self, tenant_id: str, job_id: str, meta: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> None:
        values = meta_columns(meta)
        # One transaction: the tenant session settings, the delete and the
        # inserts commit together, so a reader never sees a partial snapshot.
        with _tenant_bound(self._pool, tenant_id) as conn:
            conn.execute("DELETE FROM scan_snapshot_rows WHERE tenant_id = %s AND job_id = %s", (tenant_id, job_id))
            conn.execute("DELETE FROM scan_snapshot_jobs WHERE tenant_id = %s AND job_id = %s", (tenant_id, job_id))
            conn.execute(
                f"INSERT INTO scan_snapshot_jobs (tenant_id, job_id, {META_COLUMNS_SQL}) "  # nosec B608
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (tenant_id, job_id, *values),
            )
            with conn.cursor() as cursor:
                cursor.executemany(
                    "INSERT INTO scan_snapshot_rows (tenant_id, job_id, ordinal, finding_identity, canonical_id, severity, payload) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    [(tenant_id, job_id, *row_columns(index, row)) for index, row in enumerate(rows)],
                )
            conn.commit()

    def get_meta(self, tenant_id: str, job_ids: Iterable[str] | None = None) -> dict[str, dict[str, Any]]:
        wanted = None if job_ids is None else sorted(set(job_ids))
        if wanted == []:
            return {}
        sql = f"SELECT job_id, {META_COLUMNS_SQL} FROM scan_snapshot_jobs WHERE tenant_id = %s"  # nosec B608
        params: tuple[Any, ...] = (tenant_id,)
        if wanted is not None:
            sql += " AND job_id = ANY(%s)"
            params = (tenant_id, wanted)
        with _tenant_bound(self._pool, tenant_id) as conn:
            rows = conn.execute(sql, params).fetchall()
        return {str(row[0]): meta_from_columns(str(row[0]), row[1:]) for row in rows}

    def get_rows(self, tenant_id: str, job_id: str) -> list[dict[str, Any]]:
        with _tenant_bound(self._pool, tenant_id) as conn:
            rows = conn.execute(
                "SELECT ordinal, finding_identity, canonical_id, severity, payload FROM scan_snapshot_rows "
                "WHERE tenant_id = %s AND job_id = %s ORDER BY ordinal",
                (tenant_id, job_id),
            ).fetchall()
        return [row_from_columns(row) for row in rows]

    def delete_job(self, tenant_id: str, job_id: str) -> bool:
        with _tenant_bound(self._pool, tenant_id) as conn:
            conn.execute("DELETE FROM scan_snapshot_rows WHERE tenant_id = %s AND job_id = %s", (tenant_id, job_id))
            cursor = conn.execute("DELETE FROM scan_snapshot_jobs WHERE tenant_id = %s AND job_id = %s", (tenant_id, job_id))
            conn.commit()
        return bool(cursor.rowcount > 0)

    def delete_older_than(self, tenant_id: str | None, cutoff_iso: str) -> int:
        if tenant_id is not None:
            with _tenant_bound(self._pool, tenant_id) as conn:
                conn.execute(
                    "DELETE FROM scan_snapshot_rows AS r USING scan_snapshot_jobs AS j WHERE r.tenant_id = j.tenant_id "
                    "AND r.job_id = j.job_id AND j.completed_at < %s AND j.tenant_id = %s",
                    (cutoff_iso, tenant_id),
                )
                cursor = conn.execute(
                    "DELETE FROM scan_snapshot_jobs WHERE completed_at < %s AND tenant_id = %s",
                    (cutoff_iso, tenant_id),
                )
                conn.commit()
            return int(cursor.rowcount)
        # The global TTL sweep spans tenants. Like job expiry it runs on every
        # maintenance tick, so it uses the maintenance role without emitting a
        # signed bypass event per sweep.
        with bypass_tenant_rls(audit=False, warn=False):
            with _maintenance_connection() as conn:
                conn.execute(
                    "DELETE FROM scan_snapshot_rows AS r USING scan_snapshot_jobs AS j WHERE r.tenant_id = j.tenant_id "
                    "AND r.job_id = j.job_id AND j.completed_at < %s",
                    (cutoff_iso,),
                )
                cursor = conn.execute("DELETE FROM scan_snapshot_jobs WHERE completed_at < %s", (cutoff_iso,))
                conn.commit()
        return int(cursor.rowcount)

    def delete_tenant(self, tenant_id: str) -> int:
        with _tenant_bound(self._pool, tenant_id) as conn:
            conn.execute("DELETE FROM scan_snapshot_rows WHERE tenant_id = %s", (tenant_id,))
            cursor = conn.execute("DELETE FROM scan_snapshot_jobs WHERE tenant_id = %s", (tenant_id,))
            conn.commit()
        return int(cursor.rowcount)
