"""Store backends for tenant-specific quota overrides."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Mapping
from typing import Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version


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
        record = self._overrides.get(tenant_id)
        return dict(record) if record is not None else None

    def put(self, tenant_id: str, overrides: Mapping[str, int]) -> None:
        self._overrides[tenant_id] = dict(overrides)

    def delete(self, tenant_id: str) -> bool:
        return self._overrides.pop(tenant_id, None) is not None


class SQLiteTenantQuotaStore:
    """SQLite-backed tenant quota override store."""

    def __init__(self, db_path: str = "agent_bom.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

    def _init_db(self) -> None:
        ensure_sqlite_schema_version(self._conn, "tenant_quotas")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS tenant_quota_overrides (
                tenant_id TEXT PRIMARY KEY,
                updated_at TEXT NOT NULL DEFAULT '',
                data TEXT NOT NULL
            )
        """)
        self._conn.commit()

    def get(self, tenant_id: str) -> dict[str, int] | None:
        row = self._conn.execute(
            "SELECT data FROM tenant_quota_overrides WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        if row is None:
            return None
        loaded = json.loads(row[0])
        return {str(key): int(value) for key, value in loaded.items()}

    def put(self, tenant_id: str, overrides: Mapping[str, int]) -> None:
        payload = json.dumps(overrides, sort_keys=True)
        self._conn.execute(
            """
            INSERT OR REPLACE INTO tenant_quota_overrides (tenant_id, updated_at, data)
            VALUES (?, datetime('now'), ?)
            """,
            (tenant_id, payload),
        )
        self._conn.commit()

    def delete(self, tenant_id: str) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM tenant_quota_overrides WHERE tenant_id = ?",
            (tenant_id,),
        )
        self._conn.commit()
        return cursor.rowcount > 0
