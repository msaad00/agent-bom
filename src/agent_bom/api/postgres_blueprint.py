"""Postgres-backed AI-system blueprint store for horizontal scaling.

Mirrors :class:`agent_bom.api.blueprint_store.SQLiteBlueprintStore` but stores
blueprints and their immutable versions in shared Postgres with tenant RLS, so
approved blueprints and pending-approval versions stay consistent across every
control-plane replica instead of diverging on node-local SQLite (or vanishing on
an in-memory restart). This is the multi-replica tier of the durable-by-default
blueprint store.

Tenant isolation is enforced by Postgres FORCE ROW LEVEL SECURITY; the workflow
invariants (draft → pending → approved/rejected, mandatory approver, approved
immutability) live in the shared dataclass/lifecycle logic, not in SQL.
"""

from __future__ import annotations

import json

from agent_bom.api.blueprint_store import (
    Blueprint,
    BlueprintPage,
    BlueprintVersion,
)
from agent_bom.api.postgres_common import (
    ConnectionPool,
    _ensure_tenant_rls,
    _get_pool,
    _tenant_connection,
)
from agent_bom.api.storage_schema import ensure_postgres_schema_version


class PostgresBlueprintStore:
    """Shared AI-system blueprint + version store backed by Postgres."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, "ai_system_blueprints"):
                return
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ai_system_blueprints (
                    tenant_id    TEXT NOT NULL,
                    blueprint_id TEXT NOT NULL,
                    name         TEXT NOT NULL,
                    updated_at   TEXT NOT NULL,
                    data         TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, blueprint_id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ai_system_blueprint_versions (
                    tenant_id    TEXT NOT NULL,
                    blueprint_id TEXT NOT NULL,
                    version      INTEGER NOT NULL,
                    version_id   TEXT NOT NULL,
                    status       TEXT NOT NULL,
                    created_at   TEXT NOT NULL,
                    data         TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, blueprint_id, version)
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ai_system_blueprints_tenant "
                "ON ai_system_blueprints(tenant_id, updated_at DESC, blueprint_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ai_system_blueprint_versions_lookup "
                "ON ai_system_blueprint_versions(tenant_id, blueprint_id, version DESC)"
            )
            _ensure_tenant_rls(conn, "ai_system_blueprints", "tenant_id")
            _ensure_tenant_rls(conn, "ai_system_blueprint_versions", "tenant_id")
            conn.commit()

    def put_blueprint(self, blueprint: Blueprint) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO ai_system_blueprints (tenant_id, blueprint_id, name, updated_at, data)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, blueprint_id) DO UPDATE SET
                    name = EXCLUDED.name,
                    updated_at = EXCLUDED.updated_at,
                    data = EXCLUDED.data
                """,
                (
                    blueprint.tenant_id,
                    blueprint.blueprint_id,
                    blueprint.name,
                    blueprint.updated_at,
                    json.dumps(blueprint.to_dict(), sort_keys=True),
                ),
            )
            conn.commit()

    def get_blueprint(self, tenant_id: str, blueprint_id: str) -> Blueprint | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT data FROM ai_system_blueprints WHERE tenant_id = %s AND blueprint_id = %s",
                (tenant_id, blueprint_id),
            ).fetchone()
        return Blueprint.from_dict(json.loads(row[0])) if row else None

    def list_blueprints(self, tenant_id: str, *, limit: int = 50, offset: int = 0) -> BlueprintPage:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT data FROM ai_system_blueprints WHERE tenant_id = %s "
                "ORDER BY updated_at DESC, blueprint_id DESC LIMIT %s OFFSET %s",
                (tenant_id, limit + 1, offset),
            ).fetchall()
        blueprints = [Blueprint.from_dict(json.loads(r[0])) for r in rows[:limit]]
        next_offset = offset + limit if len(rows) > limit else None
        return BlueprintPage(blueprints=blueprints, next_offset=next_offset)

    def iter_tenant_blueprints(self, tenant_id: str, *, limit: int = 10000) -> list[Blueprint]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT data FROM ai_system_blueprints WHERE tenant_id = %s ORDER BY updated_at ASC LIMIT %s",
                (tenant_id, limit),
            ).fetchall()
        return [Blueprint.from_dict(json.loads(r[0])) for r in rows]

    def put_version(self, version: BlueprintVersion) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO ai_system_blueprint_versions
                    (tenant_id, blueprint_id, version, version_id, status, created_at, data)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, blueprint_id, version) DO UPDATE SET
                    status = EXCLUDED.status,
                    data = EXCLUDED.data
                """,
                (
                    version.tenant_id,
                    version.blueprint_id,
                    version.version,
                    version.version_id,
                    version.status,
                    version.created_at,
                    json.dumps(version.to_dict(), sort_keys=True),
                ),
            )
            conn.commit()

    def get_version(self, tenant_id: str, blueprint_id: str, version: int) -> BlueprintVersion | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT data FROM ai_system_blueprint_versions WHERE tenant_id = %s AND blueprint_id = %s AND version = %s",
                (tenant_id, blueprint_id, version),
            ).fetchone()
        return BlueprintVersion.from_dict(json.loads(row[0])) if row else None

    def list_versions(self, tenant_id: str, blueprint_id: str, *, limit: int = 200) -> list[BlueprintVersion]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT data FROM ai_system_blueprint_versions WHERE tenant_id = %s AND blueprint_id = %s "
                "ORDER BY version DESC LIMIT %s",
                (tenant_id, blueprint_id, limit),
            ).fetchall()
        return [BlueprintVersion.from_dict(json.loads(r[0])) for r in rows]
