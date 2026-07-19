"""Postgres-backed per-tenant graph retention overrides."""

from __future__ import annotations

from agent_bom.api.postgres_common import ConnectionPool, _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.storage_schema import ensure_postgres_schema_version


class PostgresTenantGraphRetentionStore:
    """Persistent tenant graph retention overrides with tenant-aware access."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, "tenant_graph_retention"):
                return
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tenant_graph_retention_overrides (
                    tenant_id TEXT PRIMARY KEY,
                    updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                    retention_days INTEGER NOT NULL
                )
                """
            )
            _ensure_tenant_rls(conn, "tenant_graph_retention_overrides", "tenant_id")
            conn.commit()

    def get(self, tenant_id: str) -> int | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT retention_days FROM tenant_graph_retention_overrides WHERE tenant_id = %s",
                (tenant_id,),
            ).fetchone()
            if row is None:
                return None
            return max(1, int(row[0]))

    def put(self, tenant_id: str, retention_days: int) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO tenant_graph_retention_overrides (tenant_id, retention_days)
                VALUES (%s, %s)
                ON CONFLICT (tenant_id) DO UPDATE SET
                    updated_at = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                    retention_days = EXCLUDED.retention_days
                """,
                (tenant_id, max(1, int(retention_days))),
            )
            conn.commit()

    def delete(self, tenant_id: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                "DELETE FROM tenant_graph_retention_overrides WHERE tenant_id = %s",
                (tenant_id,),
            )
            conn.commit()
            return bool(cursor.rowcount > 0)
