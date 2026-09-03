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

from agent_bom.api.postgres_common import ConnectionPool, _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.storage_schema import ensure_postgres_schema_version, ensure_sqlite_schema_version

# Fixed namespace for content-derived batch ids so an identical write resent
# without an ``Idempotency-Key`` header still collapses onto one logical batch
# (stable observation dedup key) instead of minting a fresh random batch id.
_BATCH_ID_NAMESPACE = uuid.UUID("6f6b4b2e-2c1a-4d9e-9d3b-8a1f0c5e7d42")
_DEFAULT_IDEMPOTENCY_TTL_HOURS = 24
_DEFAULT_IDEMPOTENCY_RESERVATION_LEASE_SECONDS = 30
_MAX_IDEMPOTENCY_RESERVATION_LEASE_SECONDS = 300
_SQLITE_IDEMPOTENCY_INIT_LOCK = threading.Lock()


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


def idempotency_reservation_lease_seconds() -> int:
    """Return the short lease used only for in-progress write reservations."""

    raw = os.environ.get("AGENT_BOM_IDEMPOTENCY_RESERVATION_LEASE_SECONDS")
    if raw is None:
        return _DEFAULT_IDEMPOTENCY_RESERVATION_LEASE_SECONDS
    try:
        return min(_MAX_IDEMPOTENCY_RESERVATION_LEASE_SECONDS, max(1, int(raw)))
    except ValueError:
        return _DEFAULT_IDEMPOTENCY_RESERVATION_LEASE_SECONDS


@dataclass
class IdempotencyRecord:
    endpoint: str
    tenant_id: str
    source_id: str
    idempotency_key: str
    request_hash: str
    response_json: str
    created_at: str
    reservation_owner: str = ""
    lease_expires_at: str = ""


class IdempotencyConflictError(RuntimeError):
    """Raised when a key is reused for a different request payload."""


class IdempotencyPayloadError(ValueError):
    """Raised when a request payload cannot be fingerprinted.

    Pydantic's serializer aborts with ``ValueError: Circular reference detected
    (depth exceeded)`` on a deeply nested body, and ``json.dumps`` can hit the
    interpreter recursion limit on the same input. Both are caller-controlled,
    so they must land as a 422 instead of escaping as an unhandled 500.
    """


class IdempotencyReservationHeartbeat:
    """Keep a reservation live and expose owner loss before durable commit."""

    def __init__(
        self,
        store: IdempotencyStore,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        request_hash: str,
        owner_token: str,
        lease_seconds: int,
    ) -> None:
        self._store = store
        self._args = (endpoint, tenant_id, source_id, idempotency_key)
        self._request_hash = request_hash
        self._owner_token = owner_token
        self._lease_seconds = lease_seconds
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def lost(self) -> bool:
        return self._lost.is_set()

    def ensure_owned(self) -> None:
        owned = self._store.heartbeat(
            *self._args,
            request_hash=self._request_hash,
            owner_token=self._owner_token,
            reservation_lease_seconds=self._lease_seconds,
        )
        if not owned:
            self._lost.set()
            raise IdempotencyConflictError("idempotency reservation ownership was lost")

    def __enter__(self) -> IdempotencyReservationHeartbeat:
        def beat() -> None:
            interval = max(0.25, self._lease_seconds / 3)
            while not self._stop.wait(interval):
                try:
                    self.ensure_owned()
                except Exception:  # noqa: BLE001 - ownership loss is observed by the request thread
                    self._lost.set()
                    return

        self._thread = threading.Thread(target=beat, name="idempotency-reservation-heartbeat", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type: object = None, *_args: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)
        if exc_type is not None:
            self._store.release(
                *self._args,
                request_hash=self._request_hash,
                owner_token=self._owner_token,
            )


def idempotency_owner_token() -> str:
    return uuid.uuid4().hex


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
        owner_token: str = "",
    ) -> bool: ...
    def claim(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        response: dict[str, Any],
        *,
        request_hash: str = "",
        reservation_lease_seconds: int | None = None,
        owner_token: str = "",
    ) -> tuple[dict[str, Any], bool]: ...
    def heartbeat(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        request_hash: str,
        owner_token: str,
        reservation_lease_seconds: int,
    ) -> bool: ...
    def release(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        request_hash: str = "",
        owner_token: str = "",
    ) -> bool: ...


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _reservation_is_expired(response_json: str, created_at: str, lease_seconds: int | None) -> bool:
    """Return whether an explicitly uncommitted reservation can be reclaimed."""

    if lease_seconds is None:
        return False
    try:
        response = json.loads(response_json)
        created = datetime.fromisoformat(created_at)
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    if not isinstance(response, dict) or response.get("committed") is not False:
        return False
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=max(1, int(lease_seconds)))
    return created <= cutoff


def _lease_expiry(lease_seconds: int | None) -> str:
    if lease_seconds is None:
        return ""
    return (datetime.now(timezone.utc) + timedelta(seconds=max(1, int(lease_seconds)))).isoformat()


def _reservation_lease_is_expired(
    response_json: str,
    created_at: str,
    lease_expires_at: str,
    lease_seconds: int | None,
) -> bool:
    if lease_seconds is None:
        return False
    try:
        response = json.loads(response_json)
    except json.JSONDecodeError:
        return False
    if not isinstance(response, dict) or response.get("committed") is not False:
        return False
    if lease_expires_at:
        try:
            expires = datetime.fromisoformat(lease_expires_at)
        except ValueError:
            return False
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires <= datetime.now(timezone.utc)
    return _reservation_is_expired(response_json, created_at, lease_seconds)


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
    """Return a stable fingerprint for comparing idempotent write retries.

    Raises:
        IdempotencyPayloadError: when the caller's payload is too deeply nested
            (or otherwise cyclic) to normalize. Callers surface this as 422.
    """
    try:
        normalized = _normalize_request_payload(payload or {})
        encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":"), default=str)
    except (ValueError, TypeError, RecursionError) as exc:
        raise IdempotencyPayloadError("Request payload is too deeply nested to process") from exc
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
        owner_token: str = "",
    ) -> bool:
        with self._lock:
            self._prune()
            key = (endpoint, tenant_id, source_id, idempotency_key)
            existing = self._records.get(key)
            if owner_token and (existing is None or existing.reservation_owner != owner_token):
                return False
            self._records[key] = IdempotencyRecord(
                endpoint=endpoint,
                tenant_id=tenant_id,
                source_id=source_id,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                response_json=json.dumps(response, sort_keys=True),
                created_at=_utcnow(),
                reservation_owner=(
                    "" if response.get("committed") is True else owner_token or (existing.reservation_owner if existing else "")
                ),
                lease_expires_at="",
            )
            return True

    def claim(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        response: dict[str, Any],
        *,
        request_hash: str = "",
        reservation_lease_seconds: int | None = None,
        owner_token: str = "",
    ) -> tuple[dict[str, Any], bool]:
        """Atomically reserve one logical write and return its stable receipt."""
        key = (endpoint, tenant_id, source_id, idempotency_key)
        with self._lock:
            self._prune()
            existing = self._records.get(key)
            if existing is not None:
                _ensure_request_hash_matches(existing.request_hash, request_hash)
                if _reservation_lease_is_expired(
                    existing.response_json,
                    existing.created_at,
                    existing.lease_expires_at,
                    reservation_lease_seconds,
                ):
                    existing.created_at = _utcnow()
                    existing.reservation_owner = owner_token
                    existing.lease_expires_at = _lease_expiry(reservation_lease_seconds)
                    return json.loads(existing.response_json), True
                return json.loads(existing.response_json), False
            self._records[key] = IdempotencyRecord(
                endpoint=endpoint,
                tenant_id=tenant_id,
                source_id=source_id,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                response_json=json.dumps(response, sort_keys=True),
                created_at=_utcnow(),
                reservation_owner=owner_token,
                lease_expires_at=_lease_expiry(reservation_lease_seconds) if owner_token else "",
            )
            return json.loads(json.dumps(response)), True

    def heartbeat(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        request_hash: str,
        owner_token: str,
        reservation_lease_seconds: int,
    ) -> bool:
        key = (endpoint, tenant_id, source_id, idempotency_key)
        with self._lock:
            existing = self._records.get(key)
            if existing is None:
                return False
            _ensure_request_hash_matches(existing.request_hash, request_hash)
            if not owner_token or existing.reservation_owner != owner_token:
                return False
            existing.lease_expires_at = _lease_expiry(reservation_lease_seconds)
            return True

    def release(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        request_hash: str = "",
        owner_token: str = "",
    ) -> bool:
        key = (endpoint, tenant_id, source_id, idempotency_key)
        with self._lock:
            existing = self._records.get(key)
            if existing is None:
                return False
            _ensure_request_hash_matches(existing.request_hash, request_hash)
            if owner_token and existing.reservation_owner != owner_token:
                return False
            self._records.pop(key, None)
            return True


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
            self._local.conn = sqlite3.connect(self._db_path, timeout=10, check_same_thread=False)
            self._local.conn.execute("PRAGMA busy_timeout=10000")
        conn: sqlite3.Connection = self._local.conn
        return conn

    def _init_db(self) -> None:
        # WAL mode and schema DDL both take SQLite write locks. Multiple API
        # replicas/threads can construct this store together during startup, so
        # serialize that one-time setup instead of racing PRAGMA journal_mode on
        # every thread-local connection.
        with _SQLITE_IDEMPOTENCY_INIT_LOCK:
            self._conn.execute("PRAGMA journal_mode=WAL")
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
                    reservation_owner TEXT NOT NULL DEFAULT '',
                    lease_expires_at TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (endpoint, tenant_id, source_id, idempotency_key)
                )
                """
            )
            columns = {str(row[1]) for row in self._conn.execute("PRAGMA table_info(idempotency_keys)").fetchall()}
            if "request_hash" not in columns:
                self._conn.execute("ALTER TABLE idempotency_keys ADD COLUMN request_hash TEXT NOT NULL DEFAULT ''")
            if "reservation_owner" not in columns:
                self._conn.execute("ALTER TABLE idempotency_keys ADD COLUMN reservation_owner TEXT NOT NULL DEFAULT ''")
            if "lease_expires_at" not in columns:
                self._conn.execute("ALTER TABLE idempotency_keys ADD COLUMN lease_expires_at TEXT NOT NULL DEFAULT ''")
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
        owner_token: str = "",
    ) -> bool:
        if owner_token:
            cursor = self._conn.execute(
                """UPDATE idempotency_keys
                   SET request_hash = ?, response_json = ?, created_at = ?, lease_expires_at = '', reservation_owner = ?
                   WHERE endpoint = ? AND tenant_id = ? AND source_id = ? AND idempotency_key = ?
                     AND reservation_owner = ?""",
                (
                    request_hash,
                    json.dumps(response, sort_keys=True),
                    _utcnow(),
                    "" if response.get("committed") is True else owner_token,
                    endpoint,
                    tenant_id,
                    source_id,
                    idempotency_key,
                    owner_token,
                ),
            )
            self._prune()
            self._conn.commit()
            return cursor.rowcount == 1
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
        return True

    def claim(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        response: dict[str, Any],
        *,
        request_hash: str = "",
        reservation_lease_seconds: int | None = None,
        owner_token: str = "",
    ) -> tuple[dict[str, Any], bool]:
        """Atomically insert a reservation across threads and API processes."""
        response_json = json.dumps(response, sort_keys=True)
        cursor = self._conn.execute(
            """INSERT OR IGNORE INTO idempotency_keys
               (endpoint, tenant_id, source_id, idempotency_key, request_hash, response_json, created_at,
                reservation_owner, lease_expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                endpoint,
                tenant_id,
                source_id,
                idempotency_key,
                request_hash,
                response_json,
                _utcnow(),
                owner_token,
                _lease_expiry(reservation_lease_seconds) if owner_token else "",
            ),
        )
        acquired = cursor.rowcount == 1
        row = self._conn.execute(
            """SELECT response_json, request_hash, created_at, reservation_owner, lease_expires_at FROM idempotency_keys
               WHERE endpoint = ? AND tenant_id = ? AND source_id = ? AND idempotency_key = ?""",
            (endpoint, tenant_id, source_id, idempotency_key),
        ).fetchone()
        if row is None:  # pragma: no cover - protected by same transaction
            self._conn.rollback()
            raise RuntimeError("Idempotency reservation was not persisted")
        try:
            _ensure_request_hash_matches(str(row[1] or ""), request_hash)
        except IdempotencyConflictError:
            self._conn.rollback()
            raise
        if not acquired and _reservation_lease_is_expired(str(row[0]), str(row[2]), str(row[4] or ""), reservation_lease_seconds):
            cursor = self._conn.execute(
                """UPDATE idempotency_keys SET created_at = ?, reservation_owner = ?, lease_expires_at = ?
                   WHERE endpoint = ? AND tenant_id = ? AND source_id = ? AND idempotency_key = ?
                     AND reservation_owner = ? AND lease_expires_at = ?""",
                (
                    _utcnow(),
                    owner_token,
                    _lease_expiry(reservation_lease_seconds) if owner_token else "",
                    endpoint,
                    tenant_id,
                    source_id,
                    idempotency_key,
                    str(row[3] or ""),
                    str(row[4] or ""),
                ),
            )
            acquired = cursor.rowcount == 1
        self._prune()
        self._conn.commit()
        return json.loads(row[0]), acquired

    def heartbeat(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        request_hash: str,
        owner_token: str,
        reservation_lease_seconds: int,
    ) -> bool:
        cursor = self._conn.execute(
            """UPDATE idempotency_keys SET lease_expires_at = ?
               WHERE endpoint = ? AND tenant_id = ? AND source_id = ? AND idempotency_key = ?
                 AND request_hash = ? AND reservation_owner = ?""",
            (
                _lease_expiry(reservation_lease_seconds),
                endpoint,
                tenant_id,
                source_id,
                idempotency_key,
                request_hash,
                owner_token,
            ),
        )
        self._conn.commit()
        return cursor.rowcount == 1

    def release(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        request_hash: str = "",
        owner_token: str = "",
    ) -> bool:
        cursor = self._conn.execute(
            """DELETE FROM idempotency_keys
               WHERE endpoint = ? AND tenant_id = ? AND source_id = ? AND idempotency_key = ?
                 AND (? = '' OR request_hash = ?)
                 AND (? = '' OR reservation_owner = ?)""",
            (endpoint, tenant_id, source_id, idempotency_key, request_hash, request_hash, owner_token, owner_token),
        )
        self._conn.commit()
        return cursor.rowcount == 1


class PostgresIdempotencyStore:
    """PostgreSQL-backed idempotency store for multi-replica deployments.

    Mirrors :class:`SQLiteIdempotencyStore` semantics — replay the cached
    response for a repeated ``Idempotency-Key``, raise
    :class:`IdempotencyConflictError` (surfaced as HTTP 409) when the same key
    is reused with a different request body, and prune past-TTL rows on write —
    but shares state across every API replica through Postgres. The per-process
    :class:`InMemoryIdempotencyStore` fallback silently dropped that guarantee
    on clustered Postgres deployments: a retried ``POST /v1/findings/bulk`` that
    landed on a different replica (or after a restart) was not recognized.

    The table is tenant-scoped and registered under ``FORCE ROW LEVEL SECURITY``
    via the shared :func:`_ensure_tenant_rls` helper, exactly like every other
    control-plane table, so it never bypasses the tenancy backstop.
    """

    def __init__(self, pool: ConnectionPool | None = None, ttl_hours: int | None = None) -> None:
        self._pool = pool or _get_pool()
        self._ttl_hours = ttl_hours
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, "idempotency"):
                return
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS idempotency_keys (
                    endpoint TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_hash TEXT NOT NULL DEFAULT '',
                    response_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    reservation_owner TEXT NOT NULL DEFAULT '',
                    lease_expires_at TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (endpoint, tenant_id, source_id, idempotency_key)
                )
                """
            )
            conn.execute("ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS reservation_owner TEXT NOT NULL DEFAULT ''")
            conn.execute("ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS lease_expires_at TEXT NOT NULL DEFAULT ''")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_idempotency_created_at ON idempotency_keys(created_at)")
            _ensure_tenant_rls(conn, "idempotency_keys", "tenant_id")
            conn.commit()

    def _prune(self, conn: Any) -> None:
        """Delete idempotency keys past the TTL (keyed on ``idx_idempotency_created_at``)."""
        ttl = self._ttl_hours if self._ttl_hours is not None else _idempotency_ttl_hours()
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=max(1, int(ttl)))).isoformat()
        conn.execute("DELETE FROM idempotency_keys WHERE created_at < %s", (cutoff,))

    def get(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        request_hash: str = "",
    ) -> dict[str, Any] | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                """SELECT response_json, request_hash FROM idempotency_keys
                   WHERE endpoint = %s AND tenant_id = %s AND source_id = %s AND idempotency_key = %s""",
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
        owner_token: str = "",
    ) -> bool:
        with _tenant_connection(self._pool) as conn:
            if owner_token:
                cursor = conn.execute(
                    """UPDATE idempotency_keys
                       SET request_hash = %s, response_json = %s, created_at = %s, lease_expires_at = '', reservation_owner = %s
                       WHERE endpoint = %s AND tenant_id = %s AND source_id = %s AND idempotency_key = %s
                         AND reservation_owner = %s""",
                    (
                        request_hash,
                        json.dumps(response, sort_keys=True),
                        _utcnow(),
                        "" if response.get("committed") is True else owner_token,
                        endpoint,
                        tenant_id,
                        source_id,
                        idempotency_key,
                        owner_token,
                    ),
                )
            else:
                cursor = conn.execute(
                    """INSERT INTO idempotency_keys
                   (endpoint, tenant_id, source_id, idempotency_key, request_hash, response_json, created_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (endpoint, tenant_id, source_id, idempotency_key) DO UPDATE SET
                       request_hash = EXCLUDED.request_hash,
                       response_json = EXCLUDED.response_json,
                       created_at = EXCLUDED.created_at""",
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
            self._prune(conn)
            conn.commit()
            return int(cursor.rowcount or 0) == 1

    def claim(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        response: dict[str, Any],
        *,
        request_hash: str = "",
        reservation_lease_seconds: int | None = None,
        owner_token: str = "",
    ) -> tuple[dict[str, Any], bool]:
        """Atomically reserve a write across every Postgres-backed replica."""
        response_json = json.dumps(response, sort_keys=True)
        with _tenant_connection(self._pool) as conn:
            inserted = conn.execute(
                """INSERT INTO idempotency_keys
                   (endpoint, tenant_id, source_id, idempotency_key, request_hash, response_json, created_at,
                    reservation_owner, lease_expires_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (endpoint, tenant_id, source_id, idempotency_key) DO NOTHING
                   RETURNING response_json, request_hash""",
                (
                    endpoint,
                    tenant_id,
                    source_id,
                    idempotency_key,
                    request_hash,
                    response_json,
                    _utcnow(),
                    owner_token,
                    _lease_expiry(reservation_lease_seconds) if owner_token else "",
                ),
            ).fetchone()
            row = inserted
            if row is None:
                row = conn.execute(
                    """SELECT response_json, request_hash, created_at, reservation_owner, lease_expires_at FROM idempotency_keys
                       WHERE endpoint = %s AND tenant_id = %s AND source_id = %s AND idempotency_key = %s
                       FOR UPDATE""",
                    (endpoint, tenant_id, source_id, idempotency_key),
                ).fetchone()
                if row is not None:
                    _ensure_request_hash_matches(str(row[1] or ""), request_hash)
                    if _reservation_lease_is_expired(str(row[0]), str(row[2]), str(row[4] or ""), reservation_lease_seconds):
                        cursor = conn.execute(
                            """UPDATE idempotency_keys
                               SET created_at = %s, reservation_owner = %s, lease_expires_at = %s
                               WHERE endpoint = %s AND tenant_id = %s AND source_id = %s AND idempotency_key = %s
                                 AND reservation_owner = %s AND lease_expires_at = %s""",
                            (
                                _utcnow(),
                                owner_token,
                                _lease_expiry(reservation_lease_seconds) if owner_token else "",
                                endpoint,
                                tenant_id,
                                source_id,
                                idempotency_key,
                                str(row[3] or ""),
                                str(row[4] or ""),
                            ),
                        )
                        if int(cursor.rowcount or 0) == 1:
                            inserted = row
            self._prune(conn)
            conn.commit()
        if row is None:  # pragma: no cover - protected by the unique key transaction
            raise RuntimeError("Idempotency reservation was not persisted")
        _ensure_request_hash_matches(str(row[1] or ""), request_hash)
        return json.loads(row[0]), inserted is not None

    def heartbeat(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        request_hash: str,
        owner_token: str,
        reservation_lease_seconds: int,
    ) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                """UPDATE idempotency_keys SET lease_expires_at = %s
                   WHERE endpoint = %s AND tenant_id = %s AND source_id = %s AND idempotency_key = %s
                     AND request_hash = %s AND reservation_owner = %s""",
                (
                    _lease_expiry(reservation_lease_seconds),
                    endpoint,
                    tenant_id,
                    source_id,
                    idempotency_key,
                    request_hash,
                    owner_token,
                ),
            )
            conn.commit()
            return int(cursor.rowcount or 0) == 1

    def release(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        request_hash: str = "",
        owner_token: str = "",
    ) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                """DELETE FROM idempotency_keys
                   WHERE endpoint = %s AND tenant_id = %s AND source_id = %s AND idempotency_key = %s
                     AND (%s = '' OR request_hash = %s)
                     AND (%s = '' OR reservation_owner = %s)""",
                (endpoint, tenant_id, source_id, idempotency_key, request_hash, request_hash, owner_token, owner_token),
            )
            conn.commit()
            return int(cursor.rowcount) == 1
