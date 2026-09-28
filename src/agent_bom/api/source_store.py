"""Source registry storage backends for hosted control-plane data sources."""

from __future__ import annotations

import sqlite3
import threading
from typing import Protocol

from agent_bom.api.models import SourceRecord
from agent_bom.api.storage_schema import ensure_sqlite_schema_version
from agent_bom.core.tenancy import require_explicit_tenant_id


class SourceStore(Protocol):
    """Protocol for source registry persistence."""

    def put(self, source: SourceRecord, *, tenant_id: str) -> None: ...
    def get(self, source_id: str, *, tenant_id: str) -> SourceRecord | None: ...
    def delete(self, source_id: str, *, tenant_id: str) -> bool: ...
    def list_all(self, tenant_id: str) -> list[SourceRecord]: ...


def source_write_tenant(source: SourceRecord, tenant_id: str) -> str:
    """A supplied record cannot choose a different tenant than its caller."""
    tenant = require_explicit_tenant_id(tenant_id)
    if source.tenant_id != tenant:
        raise ValueError("Source tenant does not match the authorized tenant")
    return tenant


class InMemorySourceStore:
    """Thread-safe source registry with copied records and explicit ownership."""

    def __init__(self) -> None:
        self._sources: dict[str, SourceRecord] = {}
        self._lock = threading.RLock()

    def put(self, source: SourceRecord, *, tenant_id: str) -> None:
        tenant = source_write_tenant(source, tenant_id)
        with self._lock:
            previous = self._sources.get(source.source_id)
            if previous is not None and previous.tenant_id != tenant:
                raise ValueError("Source identity belongs to a different tenant")
            self._sources[source.source_id] = source.model_copy(deep=True)

    def get(self, source_id: str, *, tenant_id: str) -> SourceRecord | None:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._lock:
            source = self._sources.get(source_id)
            return source.model_copy(deep=True) if source is not None and source.tenant_id == tenant else None

    def delete(self, source_id: str, *, tenant_id: str) -> bool:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._lock:
            source = self._sources.get(source_id)
            if source is None or source.tenant_id != tenant:
                return False
            del self._sources[source_id]
            return True

    def list_all(self, tenant_id: str) -> list[SourceRecord]:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._lock:
            sources = [source.model_copy(deep=True) for source in self._sources.values() if source.tenant_id == tenant]
        return sorted(sources, key=lambda source: source.display_name.lower())


class SQLiteSourceStore:
    """SQLite-backed persistent source registry."""

    def __init__(self, db_path: str = "agent_bom_sources.db") -> None:
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
        ensure_sqlite_schema_version(self._conn, "sources")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS sources (
                source_id TEXT PRIMARY KEY,
                enabled INTEGER DEFAULT 1,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                updated_at TEXT NOT NULL,
                data TEXT NOT NULL
            )
        """)
        cols = {row[1] for row in self._conn.execute("PRAGMA table_info(sources)").fetchall()}
        if "tenant_id" not in cols:
            self._conn.execute("ALTER TABLE sources ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'")
        if "updated_at" not in cols:
            self._conn.execute("ALTER TABLE sources ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_sources_tenant_name ON sources(tenant_id, updated_at)")
        self._conn.commit()

    def put(self, source: SourceRecord, *, tenant_id: str) -> None:
        source_write_tenant(source, tenant_id)
        cursor = self._conn.execute(
            """INSERT INTO sources (source_id, enabled, tenant_id, updated_at, data)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT (source_id) DO UPDATE SET enabled = excluded.enabled,
                 updated_at = excluded.updated_at, data = excluded.data
               WHERE sources.tenant_id = excluded.tenant_id""",
            (
                source.source_id,
                int(source.enabled),
                source.tenant_id,
                source.updated_at,
                source.model_dump_json(),
            ),
        )
        self._conn.commit()
        if cursor.rowcount == 0:
            raise ValueError("Source identity belongs to a different tenant")

    def get(self, source_id: str, *, tenant_id: str) -> SourceRecord | None:
        tenant = require_explicit_tenant_id(tenant_id)
        row = self._conn.execute("SELECT data FROM sources WHERE source_id = ? AND tenant_id = ?", (source_id, tenant)).fetchone()
        if row is None:
            return None
        record: SourceRecord = SourceRecord.model_validate_json(row[0])
        return record

    def delete(self, source_id: str, *, tenant_id: str) -> bool:
        tenant = require_explicit_tenant_id(tenant_id)
        cursor = self._conn.execute("DELETE FROM sources WHERE source_id = ? AND tenant_id = ?", (source_id, tenant))
        self._conn.commit()
        return cursor.rowcount > 0

    def list_all(self, tenant_id: str) -> list[SourceRecord]:
        tenant = require_explicit_tenant_id(tenant_id)
        rows = self._conn.execute("SELECT data FROM sources WHERE tenant_id = ? ORDER BY updated_at DESC, source_id", (tenant,)).fetchall()
        return [SourceRecord.model_validate_json(row[0]) for row in rows]
