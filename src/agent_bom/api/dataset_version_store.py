"""Tenant-scoped dataset version registry for headless API clients."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version


@dataclass(frozen=True)
class DatasetVersionRecord:
    tenant_id: str
    dataset_id: str
    version_id: str
    created_at: str
    source: str
    artifact_uri: str | None = None
    digest: str | None = None
    digest_algorithm: str = "sha256"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DatasetVersionStore(Protocol):
    def put(self, record: DatasetVersionRecord) -> None: ...
    def get(self, tenant_id: str, dataset_id: str, version_id: str) -> DatasetVersionRecord | None: ...
    def list(self, tenant_id: str, dataset_id: str) -> list[DatasetVersionRecord]: ...


class InMemoryDatasetVersionStore:
    def __init__(self) -> None:
        self._records: dict[tuple[str, str, str], DatasetVersionRecord] = {}
        self._lock = threading.Lock()

    def put(self, record: DatasetVersionRecord) -> None:
        with self._lock:
            self._records[(record.tenant_id, record.dataset_id, record.version_id)] = record

    def get(self, tenant_id: str, dataset_id: str, version_id: str) -> DatasetVersionRecord | None:
        with self._lock:
            return self._records.get((tenant_id, dataset_id, version_id))

    def list(self, tenant_id: str, dataset_id: str) -> list[DatasetVersionRecord]:
        with self._lock:
            records = [record for record in self._records.values() if record.tenant_id == tenant_id and record.dataset_id == dataset_id]
        return sorted(records, key=lambda record: record.created_at, reverse=True)


class SQLiteDatasetVersionStore:
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
        ensure_sqlite_schema_version(self._conn, "dataset_versions")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dataset_versions (
                tenant_id TEXT NOT NULL,
                dataset_id TEXT NOT NULL,
                version_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (tenant_id, dataset_id, version_id)
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_dataset_versions_tenant_dataset_created "
            "ON dataset_versions(tenant_id, dataset_id, created_at DESC)"
        )
        self._conn.commit()

    def put(self, record: DatasetVersionRecord) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO dataset_versions
                (tenant_id, dataset_id, version_id, created_at, data)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                record.tenant_id,
                record.dataset_id,
                record.version_id,
                record.created_at,
                json.dumps(record.to_dict(), sort_keys=True),
            ),
        )
        self._conn.commit()

    def get(self, tenant_id: str, dataset_id: str, version_id: str) -> DatasetVersionRecord | None:
        row = self._conn.execute(
            "SELECT data FROM dataset_versions WHERE tenant_id = ? AND dataset_id = ? AND version_id = ?",
            (tenant_id, dataset_id, version_id),
        ).fetchone()
        return _record_from_json(row[0]) if row else None

    def list(self, tenant_id: str, dataset_id: str) -> list[DatasetVersionRecord]:
        rows = self._conn.execute(
            """
            SELECT data FROM dataset_versions
            WHERE tenant_id = ? AND dataset_id = ?
            ORDER BY created_at DESC
            """,
            (tenant_id, dataset_id),
        ).fetchall()
        return [_record_from_json(row[0]) for row in rows]


def _record_from_json(raw: str) -> DatasetVersionRecord:
    payload = json.loads(raw)
    return DatasetVersionRecord(
        tenant_id=str(payload["tenant_id"]),
        dataset_id=str(payload["dataset_id"]),
        version_id=str(payload["version_id"]),
        created_at=str(payload["created_at"]),
        source=str(payload["source"]),
        artifact_uri=payload.get("artifact_uri"),
        digest=payload.get("digest"),
        digest_algorithm=str(payload.get("digest_algorithm") or "sha256"),
        metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {},
    )


_DATASET_VERSION_STORE: DatasetVersionStore | None = None


def get_dataset_version_store() -> DatasetVersionStore:
    global _DATASET_VERSION_STORE
    if _DATASET_VERSION_STORE is not None:
        return _DATASET_VERSION_STORE
    if os.environ.get("AGENT_BOM_DB"):
        _DATASET_VERSION_STORE = SQLiteDatasetVersionStore(os.environ["AGENT_BOM_DB"])
    else:
        _DATASET_VERSION_STORE = InMemoryDatasetVersionStore()
    return _DATASET_VERSION_STORE


def set_dataset_version_store(store: DatasetVersionStore | None) -> None:
    global _DATASET_VERSION_STORE
    _DATASET_VERSION_STORE = store


def reset_dataset_version_store() -> None:
    set_dataset_version_store(None)
