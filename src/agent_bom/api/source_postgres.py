"""Tenant-explicit Postgres source registry; database RLS remains enforced."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from agent_bom.api.postgres_common import _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.source_store import source_write_tenant
from agent_bom.api.storage_schema import ensure_postgres_schema_version
from agent_bom.core.tenancy import require_explicit_tenant_id

if TYPE_CHECKING:
    from psycopg_pool import ConnectionPool

    from agent_bom.api.models import SourceRecord


class PostgresSourceStore:
    """PostgreSQL-backed hosted product source registry."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, "sources"):
                return
            conn.execute("""
                CREATE TABLE IF NOT EXISTS control_plane_sources (
                    source_id TEXT PRIMARY KEY,
                    enabled INTEGER DEFAULT 1,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    updated_at TEXT NOT NULL,
                    data JSONB NOT NULL
                )
            """)
            conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'control_plane_sources' AND column_name = 'tenant_id'
                    ) THEN
                        ALTER TABLE control_plane_sources ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'control_plane_sources' AND column_name = 'updated_at'
                    ) THEN
                        ALTER TABLE control_plane_sources ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';
                    END IF;
                END
                $$;
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_control_plane_sources_tenant_updated ON control_plane_sources(tenant_id, updated_at DESC)"
            )
            _ensure_tenant_rls(conn, "control_plane_sources", "tenant_id")
            conn.commit()

    def put(self, source: SourceRecord, *, tenant_id: str) -> None:
        source_write_tenant(source, tenant_id)
        data = source.model_dump_json()
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                """INSERT INTO control_plane_sources (source_id, enabled, tenant_id, updated_at, data)
                   VALUES (%s, %s, %s, %s, %s)
                   ON CONFLICT (source_id) DO UPDATE SET
                     enabled = EXCLUDED.enabled,
                     updated_at = EXCLUDED.updated_at,
                     data = EXCLUDED.data
                   WHERE control_plane_sources.tenant_id = EXCLUDED.tenant_id""",
                (source.source_id, int(source.enabled), source.tenant_id, source.updated_at, data),
            )
            conn.commit()
            if cursor.rowcount == 0:
                raise ValueError("Source identity belongs to a different tenant")

    def get(self, source_id: str, *, tenant_id: str) -> SourceRecord | None:
        from agent_bom.api.models import SourceRecord

        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT data FROM control_plane_sources WHERE source_id = %s AND tenant_id = %s",
                (source_id, require_explicit_tenant_id(tenant_id)),
            ).fetchone()
            if row is None:
                return None
            raw = row[0] if isinstance(row[0], str) else json.dumps(row[0])
            return SourceRecord.model_validate_json(raw)

    def delete(self, source_id: str, *, tenant_id: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                "DELETE FROM control_plane_sources WHERE source_id = %s AND tenant_id = %s",
                (source_id, require_explicit_tenant_id(tenant_id)),
            )
            conn.commit()
            return int(cursor.rowcount) > 0

    def list_all(self, tenant_id: str) -> list:
        from agent_bom.api.models import SourceRecord

        tenant = require_explicit_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT data FROM control_plane_sources WHERE tenant_id = %s ORDER BY updated_at DESC, source_id", (tenant,)
            ).fetchall()
            return [SourceRecord.model_validate_json(row[0] if isinstance(row[0], str) else json.dumps(row[0])) for row in rows]
