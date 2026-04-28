"""Idempotency key storage for retry-safe write endpoints."""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version


@dataclass
class IdempotencyRecord:
    endpoint: str
    tenant_id: str
    source_id: str
    idempotency_key: str
    response_json: str
    created_at: str


class IdempotencyStore(Protocol):
    def get(self, endpoint: str, tenant_id: str, source_id: str, idempotency_key: str) -> dict[str, Any] | None: ...
    def put(self, endpoint: str, tenant_id: str, source_id: str, idempotency_key: str, response: dict[str, Any]) -> None: ...


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class InMemoryIdempotencyStore:
    def __init__(self, ttl_hours: int = 24) -> None:
        self._records: dict[tuple[str, str, str, str], IdempotencyRecord] = {}
        self._ttl = timedelta(hours=ttl_hours)
        self._lock = threading.Lock()

    def _prune(self) -> None:
        cutoff = datetime.now(timezone.utc) - self._ttl
        stale = [key for key, record in self._records.items() if datetime.fromisoformat(record.created_at) < cutoff]
        for key in stale:
            self._records.pop(key, None)

    def get(self, endpoint: str, tenant_id: str, source_id: str, idempotency_key: str) -> dict[str, Any] | None:
        with self._lock:
            self._prune()
            record = self._records.get((endpoint, tenant_id, source_id, idempotency_key))
            return json.loads(record.response_json) if record else None

    def put(self, endpoint: str, tenant_id: str, source_id: str, idempotency_key: str, response: dict[str, Any]) -> None:
        with self._lock:
            self._prune()
            self._records[(endpoint, tenant_id, source_id, idempotency_key)] = IdempotencyRecord(
                endpoint=endpoint,
                tenant_id=tenant_id,
                source_id=source_id,
                idempotency_key=idempotency_key,
                response_json=json.dumps(response, sort_keys=True),
                created_at=_utcnow(),
            )


class SQLiteIdempotencyStore:
    def __init__(self, db_path: str = "agent_bom_jobs.db") -> None:
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
        ensure_sqlite_schema_version(self._conn, "idempotency")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS idempotency_keys (
                endpoint TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                source_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (endpoint, tenant_id, source_id, idempotency_key)
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_idempotency_created_at ON idempotency_keys(created_at)")
        self._conn.commit()

    def get(self, endpoint: str, tenant_id: str, source_id: str, idempotency_key: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            """SELECT response_json FROM idempotency_keys
               WHERE endpoint = ? AND tenant_id = ? AND source_id = ? AND idempotency_key = ?""",
            (endpoint, tenant_id, source_id, idempotency_key),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, endpoint: str, tenant_id: str, source_id: str, idempotency_key: str, response: dict[str, Any]) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO idempotency_keys
               (endpoint, tenant_id, source_id, idempotency_key, response_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (endpoint, tenant_id, source_id, idempotency_key, json.dumps(response, sort_keys=True), _utcnow()),
        )
        self._conn.commit()
