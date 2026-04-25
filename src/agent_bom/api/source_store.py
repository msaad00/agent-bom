"""Source registry storage backends for hosted control-plane data sources."""

from __future__ import annotations

import sqlite3
import threading
from typing import Protocol

from agent_bom.api.models import SourceRecord
from agent_bom.api.storage_schema import ensure_sqlite_schema_version


class SourceStore(Protocol):
    """Protocol for source registry persistence."""

    def put(self, source: SourceRecord) -> None: ...
    def get(self, source_id: str) -> SourceRecord | None: ...
    def delete(self, source_id: str) -> bool: ...
    def list_all(self, tenant_id: str | None = None) -> list[SourceRecord]: ...


class InMemorySourceStore:
    """Dict-based source registry store."""

    def __init__(self) -> None:
        self._sources: dict[str, SourceRecord] = {}

    def put(self, source: SourceRecord) -> None:
        self._sources[source.source_id] = source

    def get(self, source_id: str) -> SourceRecord | None:
        return self._sources.get(source_id)

    def delete(self, source_id: str) -> bool:
        return self._sources.pop(source_id, None) is not None

    def list_all(self, tenant_id: str | None = None) -> list[SourceRecord]:
        sources = list(self._sources.values())
        if tenant_id is None:
            return sorted(sources, key=lambda source: source.display_name.lower())
        return sorted(
            [source for source in sources if source.tenant_id == tenant_id],
            key=lambda source: source.display_name.lower(),
        )


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
        return self._local.conn

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

    def put(self, source: SourceRecord) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO sources (source_id, enabled, tenant_id, updated_at, data)
               VALUES (?, ?, ?, ?, ?)""",
            (
                source.source_id,
                int(source.enabled),
                source.tenant_id,
                source.updated_at,
                source.model_dump_json(),
            ),
        )
        self._conn.commit()

    def get(self, source_id: str) -> SourceRecord | None:
        row = self._conn.execute("SELECT data FROM sources WHERE source_id = ?", (source_id,)).fetchone()
        if row is None:
            return None
        return SourceRecord.model_validate_json(row[0])

    def delete(self, source_id: str) -> bool:
        cursor = self._conn.execute("DELETE FROM sources WHERE source_id = ?", (source_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def list_all(self, tenant_id: str | None = None) -> list[SourceRecord]:
        if tenant_id is None:
            rows = self._conn.execute("SELECT data FROM sources ORDER BY updated_at DESC, source_id").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM sources WHERE tenant_id = ? ORDER BY updated_at DESC, source_id",
                (tenant_id,),
            ).fetchall()
        return [SourceRecord.model_validate_json(row[0]) for row in rows]
