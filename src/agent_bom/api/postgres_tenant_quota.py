"""Postgres-backed tenant quota overrides."""

from __future__ import annotations

import json
from collections.abc import Mapping

from agent_bom.api.postgres_common import _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.storage_schema import ensure_postgres_schema_version


class PostgresTenantQuotaStore:
    """Persistent tenant quota overrides with tenant-aware access."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "tenant_quotas")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tenant_quota_overrides (
                    tenant_id TEXT PRIMARY KEY,
                    updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                    data JSONB NOT NULL
                )
            """)
            _ensure_tenant_rls(conn, "tenant_quota_overrides", "tenant_id")
            conn.commit()

    def get(self, tenant_id: str) -> dict[str, int] | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT data FROM tenant_quota_overrides WHERE tenant_id = %s",
                (tenant_id,),
            ).fetchone()
            if row is None:
                return None
            loaded = row[0] if isinstance(row[0], dict) else json.loads(row[0])
            return {str(key): int(value) for key, value in loaded.items()}

    def put(self, tenant_id: str, overrides: Mapping[str, int]) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO tenant_quota_overrides (tenant_id, data)
                VALUES (%s, %s)
                ON CONFLICT (tenant_id) DO UPDATE SET
                    updated_at = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                    data = EXCLUDED.data
                """,
                (tenant_id, json.dumps(overrides, sort_keys=True)),
            )
            conn.commit()

    def delete(self, tenant_id: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                "DELETE FROM tenant_quota_overrides WHERE tenant_id = %s",
                (tenant_id,),
            )
            conn.commit()
            return cursor.rowcount > 0
