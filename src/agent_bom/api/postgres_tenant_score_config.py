"""Postgres-backed per-tenant exec-score config overrides (#3940)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from agent_bom.api.postgres_common import ConnectionPool, _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.storage_schema import ensure_postgres_schema_version


class PostgresTenantScoreConfigStore:
    """Persistent tenant exec-score config overrides with tenant-aware access."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, "tenant_score_config"):
                return
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tenant_score_config_overrides (
                    tenant_id TEXT PRIMARY KEY,
                    updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                    data TEXT NOT NULL
                )
                """
            )
            _ensure_tenant_rls(conn, "tenant_score_config_overrides", "tenant_id")
            conn.commit()

    def get(self, tenant_id: str) -> dict[str, Any] | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT data FROM tenant_score_config_overrides WHERE tenant_id = %s",
                (tenant_id,),
            ).fetchone()
            if row is None:
                return None
            loaded = json.loads(row[0])
            return loaded if isinstance(loaded, dict) else None

    def put(self, tenant_id: str, config: Mapping[str, Any]) -> None:
        payload = json.dumps(dict(config), sort_keys=True)
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO tenant_score_config_overrides (tenant_id, data)
                VALUES (%s, %s)
                ON CONFLICT (tenant_id) DO UPDATE SET
                    updated_at = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                    data = EXCLUDED.data
                """,
                (tenant_id, payload),
            )
            conn.commit()

    def delete(self, tenant_id: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                "DELETE FROM tenant_score_config_overrides WHERE tenant_id = %s",
                (tenant_id,),
            )
            conn.commit()
            return bool(cursor.rowcount > 0)
