"""Store backends for per-tenant graph snapshot retention overrides."""

from __future__ import annotations

import sqlite3
import threading
from typing import Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version


class TenantGraphRetentionStore(Protocol):
    """Protocol for per-tenant graph retention day overrides."""

    def get(self, tenant_id: str) -> int | None: ...
    def put(self, tenant_id: str, retention_days: int) -> None: ...
    def delete(self, tenant_id: str) -> bool: ...


class InMemoryTenantGraphRetentionStore:
    """Process-local retention override store for development and tests."""

    def __init__(self) -> None:
        self._overrides: dict[str, int] = {}

    def get(self, tenant_id: str) -> int | None:
        value = self._overrides.get(tenant_id)
        return int(value) if value is not None else None

    def put(self, tenant_id: str, retention_days: int) -> None:
        self._overrides[tenant_id] = max(1, int(retention_days))

    def delete(self, tenant_id: str) -> bool:
        return self._overrides.pop(tenant_id, None) is not None


class SQLiteTenantGraphRetentionStore:
    """SQLite-backed tenant graph retention override store."""

    def __init__(self, db_path: str = "agent_bom.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        conn: sqlite3.Connection = self._local.conn
        return conn

    def _init_db(self) -> None:
        ensure_sqlite_schema_version(self._conn, "tenant_graph_retention")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tenant_graph_retention_overrides (
                tenant_id TEXT PRIMARY KEY,
                updated_at TEXT NOT NULL DEFAULT '',
                retention_days INTEGER NOT NULL
            )
            """
        )
        self._conn.commit()

    def get(self, tenant_id: str) -> int | None:
        row = self._conn.execute(
            "SELECT retention_days FROM tenant_graph_retention_overrides WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        if row is None:
            return None
        return max(1, int(row[0]))

    def put(self, tenant_id: str, retention_days: int) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO tenant_graph_retention_overrides (tenant_id, updated_at, retention_days)
            VALUES (?, datetime('now'), ?)
            """,
            (tenant_id, max(1, int(retention_days))),
        )
        self._conn.commit()

    def delete(self, tenant_id: str) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM tenant_graph_retention_overrides WHERE tenant_id = ?",
            (tenant_id,),
        )
        self._conn.commit()
        return cursor.rowcount > 0
