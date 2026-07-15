"""Idempotency key storage for retry-safe write endpoints."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version

# Fixed namespace for content-derived batch ids so an identical write resent
# without an ``Idempotency-Key`` header still collapses onto one logical batch
# (stable observation dedup key) instead of minting a fresh random batch id.
_BATCH_ID_NAMESPACE = uuid.UUID("6f6b4b2e-2c1a-4d9e-9d3b-8a1f0c5e7d42")
_DEFAULT_IDEMPOTENCY_TTL_HOURS = 24


def deterministic_batch_id(seed: str) -> str:
    """Return a stable batch id derived from *seed* (idempotency key or hash).

    A pure function of the seed: the same request content (or the same explicit
    ``Idempotency-Key``) always yields the same batch id, so replays dedup rather
    than inflate per-batch observation counts.
    """
    return str(uuid.uuid5(_BATCH_ID_NAMESPACE, seed or ""))


def _idempotency_ttl_hours() -> int:
    raw = os.environ.get("AGENT_BOM_IDEMPOTENCY_TTL_HOURS")
    if raw is None:
        return _DEFAULT_IDEMPOTENCY_TTL_HOURS
    try:
        return max(1, int(raw))
    except ValueError:
        return _DEFAULT_IDEMPOTENCY_TTL_HOURS


@dataclass
class IdempotencyRecord:
    endpoint: str
    tenant_id: str
    source_id: str
    idempotency_key: str
    request_hash: str
    response_json: str
    created_at: str


class IdempotencyConflictError(RuntimeError):
    """Raised when a key is reused for a different request payload."""


class IdempotencyStore(Protocol):
    def get(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        request_hash: str = "",
    ) -> dict[str, Any] | None: ...
    def put(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        response: dict[str, Any],
        *,
        request_hash: str = "",
    ) -> None: ...


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_request_payload(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if isinstance(value, dict):
        return {
            str(key): _normalize_request_payload(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(key) != "idempotency_key"
        }
    if isinstance(value, list | tuple):
        return [_normalize_request_payload(item) for item in value]
    return value


def idempotency_request_fingerprint(payload: Any) -> str:
    """Return a stable fingerprint for comparing idempotent write retries."""
    normalized = _normalize_request_payload(payload or {})
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _ensure_request_hash_matches(stored_hash: str, request_hash: str) -> None:
    if stored_hash and request_hash and stored_hash != request_hash:
        raise IdempotencyConflictError("Idempotency key was reused with a different request payload")


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

    def get(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        request_hash: str = "",
    ) -> dict[str, Any] | None:
        with self._lock:
            self._prune()
            record = self._records.get((endpoint, tenant_id, source_id, idempotency_key))
            if record:
                _ensure_request_hash_matches(record.request_hash, request_hash)
            return json.loads(record.response_json) if record else None

    def put(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        response: dict[str, Any],
        *,
        request_hash: str = "",
    ) -> None:
        with self._lock:
            self._prune()
            self._records[(endpoint, tenant_id, source_id, idempotency_key)] = IdempotencyRecord(
                endpoint=endpoint,
                tenant_id=tenant_id,
                source_id=source_id,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                response_json=json.dumps(response, sort_keys=True),
                created_at=_utcnow(),
            )


class SQLiteIdempotencyStore:
    def __init__(self, db_path: str = "agent_bom_jobs.db", ttl_hours: int | None = None) -> None:
        self._db_path = db_path
        self._ttl_hours = ttl_hours
        self._local = threading.local()
        self._init_db()

    def _prune(self) -> None:
        """Delete idempotency keys past the TTL (keyed on ``idx_idempotency_created_at``)."""
        ttl = self._ttl_hours if self._ttl_hours is not None else _idempotency_ttl_hours()
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=max(1, int(ttl)))).isoformat()
        self._conn.execute("DELETE FROM idempotency_keys WHERE created_at < ?", (cutoff,))

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
                request_hash TEXT NOT NULL DEFAULT '',
                response_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (endpoint, tenant_id, source_id, idempotency_key)
            )
            """
        )
        columns = {str(row[1]) for row in self._conn.execute("PRAGMA table_info(idempotency_keys)").fetchall()}
        if "request_hash" not in columns:
            self._conn.execute("ALTER TABLE idempotency_keys ADD COLUMN request_hash TEXT NOT NULL DEFAULT ''")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_idempotency_created_at ON idempotency_keys(created_at)")
        self._conn.commit()

    def get(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        request_hash: str = "",
    ) -> dict[str, Any] | None:
        row = self._conn.execute(
            """SELECT response_json, request_hash FROM idempotency_keys
               WHERE endpoint = ? AND tenant_id = ? AND source_id = ? AND idempotency_key = ?""",
            (endpoint, tenant_id, source_id, idempotency_key),
        ).fetchone()
        if row:
            _ensure_request_hash_matches(str(row[1] or ""), request_hash)
        return json.loads(row[0]) if row else None

    def put(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        response: dict[str, Any],
        *,
        request_hash: str = "",
    ) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO idempotency_keys
               (endpoint, tenant_id, source_id, idempotency_key, request_hash, response_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                endpoint,
                tenant_id,
                source_id,
                idempotency_key,
                request_hash,
                json.dumps(response, sort_keys=True),
                _utcnow(),
            ),
        )
        # Prune expired keys on write so the table cannot grow without bound.
        self._prune()
        self._conn.commit()
