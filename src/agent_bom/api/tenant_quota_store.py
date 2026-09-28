"""Tenant quota override persistence: one port, one SQL store, one test fake."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Protocol

from agent_bom.api.postgres_common import ConnectionPool
from agent_bom.api.storage.sql import (
    Dialect,
    PostgresBackend,
    SqlBackend,
    SQLiteBackend,
    load_json,
    require_tenant_id,
    utc_timestamp,
)


class TenantQuotaStore(Protocol):
    """Protocol for tenant quota override persistence."""

    def get(self, tenant_id: str) -> dict[str, int] | None: ...
    def put(self, tenant_id: str, overrides: Mapping[str, int]) -> None: ...
    def delete(self, tenant_id: str) -> bool: ...


class InMemoryTenantQuotaStore:
    """Process-local quota override store for development and tests."""

    def __init__(self) -> None:
        self._overrides: dict[str, dict[str, int]] = {}

    def get(self, tenant_id: str) -> dict[str, int] | None:
        record = self._overrides.get(require_tenant_id(tenant_id))
        return dict(record) if record is not None else None

    def put(self, tenant_id: str, overrides: Mapping[str, int]) -> None:
        self._overrides[require_tenant_id(tenant_id)] = dict(overrides)

    def delete(self, tenant_id: str) -> bool:
        return self._overrides.pop(require_tenant_id(tenant_id), None) is not None


_DDL: dict[Dialect, tuple[str, ...]] = {
    "sqlite": (
        """
        CREATE TABLE IF NOT EXISTS tenant_quota_overrides (
            tenant_id TEXT PRIMARY KEY,
            updated_at TEXT NOT NULL DEFAULT '',
            data TEXT NOT NULL
        )
        """,
    ),
    "postgres": (
        """
        CREATE TABLE IF NOT EXISTS tenant_quota_overrides (
            tenant_id TEXT PRIMARY KEY,
            updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
            data JSONB NOT NULL
        )
        """,
    ),
}


class SqlTenantQuotaStore:
    """Tenant quota overrides on SQLite or Postgres through one set of statements."""

    def __init__(self, backend: SqlBackend) -> None:
        self._backend = backend
        backend.bootstrap("tenant_quotas", _DDL, rls_table="tenant_quota_overrides")

    @classmethod
    def sqlite(cls, db_path: str = "agent_bom.db") -> SqlTenantQuotaStore:
        return cls(SQLiteBackend(db_path))

    @classmethod
    def postgres(cls, pool: ConnectionPool | None = None) -> SqlTenantQuotaStore:
        return cls(PostgresBackend(pool))

    def get(self, tenant_id: str) -> dict[str, int] | None:
        tenant = require_tenant_id(tenant_id)
        with self._backend.transaction() as tx:
            row = tx.execute("SELECT data FROM tenant_quota_overrides WHERE tenant_id = ?", (tenant,)).fetchone()
        if row is None:
            return None
        return {str(key): int(value) for key, value in load_json(row[0]).items()}

    def put(self, tenant_id: str, overrides: Mapping[str, int]) -> None:
        tenant = require_tenant_id(tenant_id)
        with self._backend.transaction() as tx:
            tx.execute(
                """
                INSERT INTO tenant_quota_overrides (tenant_id, updated_at, data)
                VALUES (?, ?, ?)
                ON CONFLICT (tenant_id) DO UPDATE SET updated_at = excluded.updated_at, data = excluded.data
                """,
                (tenant, utc_timestamp(), json.dumps(dict(overrides), sort_keys=True)),
            )

    def delete(self, tenant_id: str) -> bool:
        tenant = require_tenant_id(tenant_id)
        with self._backend.transaction() as tx:
            cursor = tx.execute("DELETE FROM tenant_quota_overrides WHERE tenant_id = ?", (tenant,))
            return bool(cursor.rowcount > 0)


SQLiteTenantQuotaStore = SqlTenantQuotaStore.sqlite
PostgresTenantQuotaStore = SqlTenantQuotaStore.postgres
