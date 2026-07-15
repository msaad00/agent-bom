"""Postgres-backed MCP-client-config distribution store (#3908).

Mirrors :class:`agent_bom.api.mcp_config_store.SQLiteMcpConfigStore` but persists
assignments in shared Postgres with tenant RLS, so a served MCP-client-config
URL resolves consistently across every control-plane replica. Tenant isolation
is enforced by Postgres FORCE ROW LEVEL SECURITY, not application filtering
alone.
"""

from __future__ import annotations

import builtins
import json
from dataclasses import asdict

from agent_bom.api.mcp_config_store import McpClientConfigAssignment
from agent_bom.api.postgres_common import (
    ConnectionPool,
    _ensure_tenant_rls,
    _get_pool,
    _tenant_connection,
)
from agent_bom.api.storage_schema import ensure_postgres_schema_version


class PostgresMcpConfigStore:
    """Shared MCP-client-config assignment store backed by Postgres (tenant RLS)."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "mcp_client_configs")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS mcp_client_configs (
                    config_id  TEXT PRIMARY KEY,
                    tenant_id  TEXT NOT NULL,
                    name       TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    revoked    BOOLEAN NOT NULL DEFAULT FALSE,
                    data       TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_mcp_client_configs_tenant ON mcp_client_configs(tenant_id, created_at)")
            _ensure_tenant_rls(conn, "mcp_client_configs", "tenant_id")
            conn.commit()

    def put(self, assignment: McpClientConfigAssignment) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO mcp_client_configs (config_id, tenant_id, name, profile_id, created_at, revoked, data)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (config_id) DO UPDATE SET
                    name = EXCLUDED.name,
                    profile_id = EXCLUDED.profile_id,
                    revoked = EXCLUDED.revoked,
                    data = EXCLUDED.data
                """,
                (
                    assignment.config_id,
                    assignment.tenant_id,
                    assignment.name,
                    assignment.profile_id,
                    assignment.created_at,
                    bool(assignment.revoked),
                    json.dumps(asdict(assignment), sort_keys=True),
                ),
            )
            conn.commit()

    def get(self, tenant_id: str, config_id: str) -> McpClientConfigAssignment | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT data FROM mcp_client_configs WHERE config_id = %s AND tenant_id = %s", (config_id, tenant_id)
            ).fetchone()
        return McpClientConfigAssignment(**json.loads(row[0])) if row else None

    def list_for_tenant(
        self, tenant_id: str, *, include_revoked: bool = False, limit: int = 200
    ) -> builtins.list[McpClientConfigAssignment]:
        with _tenant_connection(self._pool) as conn:
            if include_revoked:
                rows = conn.execute(
                    "SELECT data FROM mcp_client_configs WHERE tenant_id = %s ORDER BY created_at DESC LIMIT %s",
                    (tenant_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT data FROM mcp_client_configs WHERE tenant_id = %s AND revoked = FALSE ORDER BY created_at DESC LIMIT %s",
                    (tenant_id, limit),
                ).fetchall()
        return [McpClientConfigAssignment(**json.loads(r[0])) for r in rows]
