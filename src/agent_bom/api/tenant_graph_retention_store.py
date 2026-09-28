"""Per-tenant graph retention override persistence: one port, one SQL store, one test fake."""

from __future__ import annotations

from typing import Protocol

from agent_bom.api.postgres_common import ConnectionPool
from agent_bom.api.storage.sql import (
    Dialect,
    PostgresBackend,
    SqlBackend,
    SQLiteBackend,
    require_tenant_id,
    require_tenant_scope,
    utc_timestamp,
)


class TenantGraphRetentionStore(Protocol):
    """Protocol for per-tenant graph retention day overrides."""

    def get(self, tenant_id: str) -> int | None: ...
    def put(self, tenant_id: str, retention_days: int) -> None: ...
    def delete(self, tenant_id: str) -> bool: ...
    def list_overrides(self, tenant_id: str | None = None, *, all_tenants: bool = False) -> dict[str, int]:
        """Overrides for one tenant, or for every tenant when ``all_tenants=True`` (background retention sweeps)."""
        ...


def _days(value: int | str) -> int:
    return max(1, int(value))


class InMemoryTenantGraphRetentionStore:
    """Process-local retention override store for development and tests."""

    def __init__(self) -> None:
        self._overrides: dict[str, int] = {}

    def get(self, tenant_id: str) -> int | None:
        value = self._overrides.get(require_tenant_id(tenant_id))
        return _days(value) if value is not None else None

    def put(self, tenant_id: str, retention_days: int) -> None:
        self._overrides[require_tenant_id(tenant_id)] = _days(retention_days)

    def delete(self, tenant_id: str) -> bool:
        return self._overrides.pop(require_tenant_id(tenant_id), None) is not None

    def list_overrides(self, tenant_id: str | None = None, *, all_tenants: bool = False) -> dict[str, int]:
        tenant = require_tenant_scope(tenant_id, all_tenants=all_tenants)
        return {key: _days(value) for key, value in self._overrides.items() if tenant is None or key == tenant}


_DDL: dict[Dialect, tuple[str, ...]] = {
    "sqlite": (
        """
        CREATE TABLE IF NOT EXISTS tenant_graph_retention_overrides (
            tenant_id TEXT PRIMARY KEY,
            updated_at TEXT NOT NULL DEFAULT '',
            retention_days INTEGER NOT NULL
        )
        """,
    ),
    "postgres": (
        """
        CREATE TABLE IF NOT EXISTS tenant_graph_retention_overrides (
            tenant_id TEXT PRIMARY KEY,
            updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
            retention_days INTEGER NOT NULL
        )
        """,
    ),
}


class SqlTenantGraphRetentionStore:
    """Tenant graph retention overrides on SQLite or Postgres through one set of statements.

    Tenant calls run in a tenant-bound transaction (RLS on Postgres). Only
    ``list_overrides(all_tenants=True)`` reads every tenant, through the
    backend's maintenance path, in a read-only snapshot.
    """

    def __init__(self, backend: SqlBackend) -> None:
        self._backend = backend
        backend.bootstrap("tenant_graph_retention", _DDL, rls_table="tenant_graph_retention_overrides")

    @classmethod
    def sqlite(cls, db_path: str = "agent_bom.db") -> SqlTenantGraphRetentionStore:
        return cls(SQLiteBackend(db_path))

    @classmethod
    def postgres(
        cls, pool: ConnectionPool | None = None, *, maintenance_pool: ConnectionPool | None = None
    ) -> SqlTenantGraphRetentionStore:
        return cls(PostgresBackend(pool, maintenance_pool=maintenance_pool))

    def get(self, tenant_id: str) -> int | None:
        tenant = require_tenant_id(tenant_id)
        with self._backend.transaction(read_only=True) as tx:
            row = tx.execute("SELECT retention_days FROM tenant_graph_retention_overrides WHERE tenant_id = ?", (tenant,)).fetchone()
        return None if row is None else _days(row[0])

    def put(self, tenant_id: str, retention_days: int) -> None:
        tenant = require_tenant_id(tenant_id)
        with self._backend.transaction() as tx:
            tx.execute(
                """
                INSERT INTO tenant_graph_retention_overrides (tenant_id, updated_at, retention_days)
                VALUES (?, ?, ?)
                ON CONFLICT (tenant_id) DO UPDATE SET updated_at = excluded.updated_at, retention_days = excluded.retention_days
                """,
                (tenant, utc_timestamp(), _days(retention_days)),
            )

    def delete(self, tenant_id: str) -> bool:
        tenant = require_tenant_id(tenant_id)
        with self._backend.transaction() as tx:
            cursor = tx.execute("DELETE FROM tenant_graph_retention_overrides WHERE tenant_id = ?", (tenant,))
            return bool(cursor.rowcount > 0)

    def list_overrides(self, tenant_id: str | None = None, *, all_tenants: bool = False) -> dict[str, int]:
        tenant = require_tenant_scope(tenant_id, all_tenants=all_tenants)
        sql = "SELECT tenant_id, retention_days FROM tenant_graph_retention_overrides"
        params: tuple[str, ...] = ()
        if tenant is not None:
            sql += " WHERE tenant_id = ?"
            params = (tenant,)
        with self._backend.transaction(read_only=True, all_tenants=tenant is None) as tx:
            rows = tx.execute(sql, params).fetchall()
        return {str(row[0]): _days(row[1]) for row in rows}


SQLiteTenantGraphRetentionStore = SqlTenantGraphRetentionStore.sqlite
PostgresTenantGraphRetentionStore = SqlTenantGraphRetentionStore.postgres
