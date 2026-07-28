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
from dataclasses import asdict, replace

from agent_bom.api.mcp_config_store import (
    McpClientConfigAssignment,
    McpConfigConflictError,
    McpConfigRevisionConflictError,
    _assignment_from_storage_row,
    _bounded_identity_history_limit,
    _now_iso,
)
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
            if not ensure_postgres_schema_version(conn, "mcp_client_configs", version=2):
                return
            conn.execute("""
                CREATE TABLE IF NOT EXISTS mcp_client_configs (
                    config_id  TEXT PRIMARY KEY,
                    tenant_id  TEXT NOT NULL,
                    name       TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    identity_id TEXT NOT NULL DEFAULT '',
                    issuer TEXT NOT NULL DEFAULT '',
                    environment TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'active',
                    revision INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT '',
                    revoked    BOOLEAN NOT NULL DEFAULT FALSE,
                    data       TEXT NOT NULL
                )
            """)
            for ddl in (
                "ALTER TABLE mcp_client_configs ADD COLUMN IF NOT EXISTS identity_id TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE mcp_client_configs ADD COLUMN IF NOT EXISTS issuer TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE mcp_client_configs ADD COLUMN IF NOT EXISTS environment TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE mcp_client_configs ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'",
                "ALTER TABLE mcp_client_configs ADD COLUMN IF NOT EXISTS revision INTEGER NOT NULL DEFAULT 1",
                "ALTER TABLE mcp_client_configs ADD COLUMN IF NOT EXISTS updated_at TEXT NOT NULL DEFAULT ''",
            ):
                conn.execute(ddl)
            conn.execute("UPDATE mcp_client_configs SET identity_id = COALESCE(identity_id, '')")
            conn.execute("ALTER TABLE mcp_client_configs ALTER COLUMN identity_id SET DEFAULT ''")
            conn.execute("ALTER TABLE mcp_client_configs ALTER COLUMN identity_id SET NOT NULL")
            conn.execute("UPDATE mcp_client_configs SET status = 'revoked' WHERE revoked = TRUE AND status = 'active'")
            conn.execute("UPDATE mcp_client_configs SET updated_at = created_at WHERE updated_at = ''")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_mcp_client_configs_tenant ON mcp_client_configs(tenant_id, created_at)")
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_client_configs_active_identity "
                "ON mcp_client_configs(tenant_id, identity_id) "
                "WHERE btrim(identity_id) <> '' AND revoked = FALSE AND status = 'active'"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_mcp_client_configs_identity_history "
                "ON mcp_client_configs(tenant_id, identity_id, updated_at DESC) WHERE btrim(identity_id) <> ''"
            )
            _ensure_tenant_rls(conn, "mcp_client_configs", "tenant_id")
            conn.commit()

    def put(self, assignment: McpClientConfigAssignment) -> None:
        with _tenant_connection(self._pool) as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO mcp_client_configs (
                        config_id, tenant_id, name, profile_id, identity_id, issuer,
                        environment, status, revision, created_at, updated_at, revoked, data
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    self._values(assignment),
                )
                conn.commit()
            except Exception as exc:
                conn.rollback()
                if exc.__class__.__name__ == "UniqueViolation":
                    raise McpConfigConflictError("MCP client profile conflicts with an existing assignment") from exc
                raise

    @staticmethod
    def _values(assignment: McpClientConfigAssignment) -> tuple[object, ...]:
        return (
            assignment.config_id,
            assignment.tenant_id,
            assignment.name,
            assignment.profile_id,
            assignment.identity_id,
            assignment.issuer,
            assignment.environment,
            assignment.status,
            int(assignment.revision),
            assignment.created_at,
            assignment.updated_at,
            bool(assignment.revoked),
            json.dumps(asdict(assignment), sort_keys=True),
        )

    def get(self, tenant_id: str, config_id: str) -> McpClientConfigAssignment | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT data, config_id, tenant_id, identity_id, issuer, environment, status, revision, updated_at, revoked "
                "FROM mcp_client_configs WHERE config_id = %s AND tenant_id = %s",
                (config_id, tenant_id),
            ).fetchone()
        return _assignment_from_storage_row(row) if row else None

    def get_active_for_identity(self, tenant_id: str, identity_id: str) -> McpClientConfigAssignment | None:
        if not identity_id:
            return None
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT data, config_id, tenant_id, identity_id, issuer, environment, status, revision, updated_at, revoked "
                "FROM mcp_client_configs "
                "WHERE tenant_id = %s AND identity_id = %s AND btrim(identity_id) <> '' "
                "AND revoked = FALSE AND status = 'active'",
                (tenant_id, identity_id),
            ).fetchone()
        return _assignment_from_storage_row(row) if row else None

    def list_for_identity(
        self,
        tenant_id: str,
        identity_id: str,
        *,
        limit: int = 200,
    ) -> builtins.list[McpClientConfigAssignment]:
        if not identity_id:
            return []
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT data, config_id, tenant_id, identity_id, issuer, environment, status, revision, updated_at, revoked "
                "FROM mcp_client_configs WHERE tenant_id = %s AND identity_id = %s AND btrim(identity_id) <> '' "
                "ORDER BY updated_at DESC, config_id DESC LIMIT %s",
                (tenant_id, identity_id, _bounded_identity_history_limit(limit)),
            ).fetchall()
        return [_assignment_from_storage_row(row) for row in rows]

    def compare_and_swap(
        self,
        assignment: McpClientConfigAssignment,
        *,
        expected_revision: int,
    ) -> McpClientConfigAssignment:
        candidate = replace(assignment, revision=expected_revision + 1)
        with _tenant_connection(self._pool) as conn:
            try:
                row = conn.execute(
                    """
                    UPDATE mcp_client_configs SET
                        name = %s, profile_id = %s, issuer = %s, environment = %s,
                        status = %s, revision = %s, updated_at = %s, revoked = %s, data = %s
                    WHERE config_id = %s AND tenant_id = %s AND identity_id = %s AND revision = %s
                    RETURNING data
                    """,
                    (
                        candidate.name,
                        candidate.profile_id,
                        candidate.issuer,
                        candidate.environment,
                        candidate.status,
                        candidate.revision,
                        candidate.updated_at,
                        bool(candidate.revoked),
                        json.dumps(asdict(candidate), sort_keys=True),
                        candidate.config_id,
                        candidate.tenant_id,
                        candidate.identity_id,
                        expected_revision,
                    ),
                ).fetchone()
                if row is None:
                    raise McpConfigRevisionConflictError("MCP client profile revision is stale")
                conn.commit()
                return McpClientConfigAssignment(**json.loads(row[0]))
            except Exception as exc:
                conn.rollback()
                if exc.__class__.__name__ == "UniqueViolation":
                    raise McpConfigConflictError("The managed identity already has an active client profile") from exc
                raise

    def revoke(self, tenant_id: str, config_id: str) -> McpClientConfigAssignment | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT data, config_id, tenant_id, identity_id, issuer, environment, status, revision, updated_at, revoked "
                "FROM mcp_client_configs WHERE config_id = %s AND tenant_id = %s FOR UPDATE",
                (config_id, tenant_id),
            ).fetchone()
            if row is None:
                conn.rollback()
                return None
            current = _assignment_from_storage_row(row)
            if current.revoked:
                conn.commit()
                return current
            revoked = replace(
                current,
                revoked=True,
                status="revoked",
                revision=current.revision + 1,
                updated_at=_now_iso(),
            )
            updated = conn.execute(
                "UPDATE mcp_client_configs SET status = %s, revision = %s, updated_at = %s, "
                "revoked = TRUE, data = %s WHERE config_id = %s AND tenant_id = %s AND revision = %s RETURNING data",
                (
                    revoked.status,
                    revoked.revision,
                    revoked.updated_at,
                    json.dumps(asdict(revoked), sort_keys=True),
                    config_id,
                    tenant_id,
                    current.revision,
                ),
            ).fetchone()
            if updated is None:
                conn.rollback()
                raise McpConfigRevisionConflictError("MCP client profile revision is stale")
            conn.commit()
            return McpClientConfigAssignment(**json.loads(updated[0]))

    def list_for_tenant(
        self, tenant_id: str, *, include_revoked: bool = False, limit: int = 200
    ) -> builtins.list[McpClientConfigAssignment]:
        with _tenant_connection(self._pool) as conn:
            if include_revoked:
                rows = conn.execute(
                    "SELECT data, config_id, tenant_id, identity_id, issuer, environment, status, revision, updated_at, revoked "
                    "FROM mcp_client_configs WHERE tenant_id = %s ORDER BY created_at DESC LIMIT %s",
                    (tenant_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT data, config_id, tenant_id, identity_id, issuer, environment, status, revision, updated_at, revoked "
                    "FROM mcp_client_configs WHERE tenant_id = %s AND revoked = FALSE ORDER BY created_at DESC LIMIT %s",
                    (tenant_id, limit),
                ).fetchall()
        return [_assignment_from_storage_row(row) for row in rows]
