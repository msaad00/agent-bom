"""Store backends for per-tenant executive risk-score config overrides (#3940).

Mirrors the ``tenant_graph_retention`` / ``tenant_quota`` override stores: a
per-tenant JSON blob holding the (partial) exec-score config a tenant admin has
customized. In-memory for tests, SQLite for single-node durability, Postgres for
multi-replica with tenant RLS (see ``postgres_tenant_score_config``).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Mapping
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version


class TenantScoreConfigStore(Protocol):
    """Protocol for per-tenant exec-score config override persistence."""

    def get(self, tenant_id: str) -> dict[str, Any] | None: ...
    def put(self, tenant_id: str, config: Mapping[str, Any]) -> None: ...
    def delete(self, tenant_id: str) -> bool: ...


class InMemoryTenantScoreConfigStore:
    """Process-local exec-score config store for development and tests."""

    def __init__(self) -> None:
        self._configs: dict[str, dict[str, Any]] = {}

    def get(self, tenant_id: str) -> dict[str, Any] | None:
        record = self._configs.get(tenant_id)
        return json.loads(json.dumps(record)) if record is not None else None

    def put(self, tenant_id: str, config: Mapping[str, Any]) -> None:
        self._configs[tenant_id] = json.loads(json.dumps(dict(config)))

    def delete(self, tenant_id: str) -> bool:
        return self._configs.pop(tenant_id, None) is not None


class SQLiteTenantScoreConfigStore:
    """SQLite-backed exec-score config override store."""

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
        ensure_sqlite_schema_version(self._conn, "tenant_score_config")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tenant_score_config_overrides (
                tenant_id TEXT PRIMARY KEY,
                updated_at TEXT NOT NULL DEFAULT '',
                data TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def get(self, tenant_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT data FROM tenant_score_config_overrides WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        if row is None:
            return None
        loaded = json.loads(row[0])
        return loaded if isinstance(loaded, dict) else None

    def put(self, tenant_id: str, config: Mapping[str, Any]) -> None:
        payload = json.dumps(dict(config), sort_keys=True)
        self._conn.execute(
            """
            INSERT OR REPLACE INTO tenant_score_config_overrides (tenant_id, updated_at, data)
            VALUES (?, datetime('now'), ?)
            """,
            (tenant_id, payload),
        )
        self._conn.commit()

    def delete(self, tenant_id: str) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM tenant_score_config_overrides WHERE tenant_id = ?",
            (tenant_id,),
        )
        self._conn.commit()
        return cursor.rowcount > 0
