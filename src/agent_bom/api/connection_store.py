"""Tenant-scoped persistence for read-only cloud connections.

A *connection* is a stored, encrypted record of how the control plane reaches a
customer's cloud account in read-only mode: the role reference it assumes
(``role_ref``) plus the encrypted ``ExternalId`` (or provider equivalent) the
credential broker presents. The plaintext secret is encrypted at rest by
:mod:`agent_bom.api.connection_crypto` and is the only sensitive column; it is
never returned by the API (see :meth:`CloudConnectionRecord.to_public_dict`).

Backend parity mirrors the cost / credential stores: in-memory for tests,
SQLite as the durable single-node default, and Postgres (tenant RLS) for
multi-replica deployments — selected by the shared storage factory.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version
from agent_bom.storage.base import StorageSchema, TableSchema

# Providers a connection can target. AWS is broker-enabled in Phase A; the
# others are accepted/stored and reported as "planned" by the broker.
SUPPORTED_PROVIDERS: tuple[str, ...] = ("aws", "azure", "gcp", "snowflake")

# Connection lifecycle status vocabulary.
STATUS_PENDING = "pending"
STATUS_ACTIVE = "active"
STATUS_ERROR = "error"
VALID_STATUSES: tuple[str, ...] = (STATUS_PENDING, STATUS_ACTIVE, STATUS_ERROR)


@dataclass
class CloudConnectionRecord:
    """One read-only cloud connection for a tenant.

    ``external_id_encrypted`` holds the Fernet ciphertext of the connection
    secret — never the plaintext. :meth:`to_public_dict` is the only shape that
    leaves the process over the API and it omits that column entirely.
    """

    id: str
    tenant_id: str
    provider: str
    display_name: str
    role_ref: str
    external_id_encrypted: str
    regions: list[str] = field(default_factory=list)
    status: str = STATUS_PENDING
    status_detail: str = ""
    created_at: str = ""
    updated_at: str = ""
    last_scan_at: str | None = None
    last_scan_id: str | None = None
    scan_interval_minutes: int | None = None
    # Timestamp of the most recent event-driven (CloudTrail/EventBridge) posture
    # re-evaluation, distinct from ``last_scan_at`` (the last full polling scan).
    # Lets the UI surface an event-driven-vs-polling freshness signal: a
    # connection reacting to change events stays fresh between scheduled scans.
    last_event_at: str | None = None
    # Non-secret, provider-specific connection parameters (e.g. Azure
    # tenant_id/subscription_id, GCP project_id, Snowflake user/role/warehouse).
    # The single reversible secret per connection lives in
    # ``external_id_encrypted``; these are deliberately NOT secret and are safe to
    # return in API responses.
    auth_params: dict[str, Any] = field(default_factory=dict)

    def to_public_dict(self) -> dict[str, Any]:
        """Non-secret representation for API responses.

        Deliberately excludes ``external_id_encrypted`` (and never carries the
        plaintext) so no secret material can leak through a response body. Also
        surfaces ``has_external_id`` so a client can tell a secret is configured
        without ever seeing it. ``auth_params`` is non-secret and is included.
        """
        data = asdict(self)
        data.pop("external_id_encrypted", None)
        data["has_external_id"] = bool(self.external_id_encrypted)
        return data


class ConnectionStore(Protocol):
    """Tenant-scoped CRUD contract for cloud connections."""

    def init_schema(self) -> None: ...
    def put(self, record: CloudConnectionRecord) -> None: ...
    def get(self, tenant_id: str, connection_id: str) -> CloudConnectionRecord | None: ...
    def list_for_tenant(self, tenant_id: str) -> list[CloudConnectionRecord]: ...
    def delete(self, tenant_id: str, connection_id: str) -> bool: ...
    def list_schedulable(self) -> list[CloudConnectionRecord]: ...
    def claim_due_scan(self, record: CloudConnectionRecord, claimed_at: str) -> bool: ...


# ── Portable schema seam ──────────────────────────────────────────────────────
# Single source-of-truth table contract shared across backends. The SQLite and
# Postgres ``_init_*`` paths below remain the executed DDL; this declaration
# mirrors them so a parity test can assert both backends cover the same logical
# columns and a new backend is a registration here rather than a fork.
CONNECTION_STORAGE_SCHEMA = StorageSchema(
    component="cloud_connections",
    tables=(
        TableSchema(
            name="cloud_connections",
            columns=(
                "id",
                "tenant_id",
                "provider",
                "display_name",
                "role_ref",
                "external_id_encrypted",
                "regions",
                "status",
                "status_detail",
                "created_at",
                "updated_at",
                "last_scan_at",
                "last_scan_id",
                "scan_interval_minutes",
                "auth_params",
                "last_event_at",
            ),
            ddl_by_backend={
                "sqlite": (
                    "CREATE TABLE IF NOT EXISTS cloud_connections (id TEXT PRIMARY KEY, "
                    "tenant_id TEXT NOT NULL, provider TEXT NOT NULL, display_name TEXT NOT NULL, "
                    "role_ref TEXT NOT NULL, external_id_encrypted TEXT NOT NULL DEFAULT '', "
                    "regions TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'pending', "
                    "status_detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, "
                    "updated_at TEXT NOT NULL, last_scan_at TEXT, last_scan_id TEXT, "
                    "scan_interval_minutes INTEGER, auth_params TEXT NOT NULL DEFAULT '{}', "
                    "last_event_at TEXT)"
                ),
                "postgres": (
                    "CREATE TABLE IF NOT EXISTS cloud_connections (id TEXT PRIMARY KEY, "
                    "tenant_id TEXT NOT NULL, provider TEXT NOT NULL, display_name TEXT NOT NULL, "
                    "role_ref TEXT NOT NULL, external_id_encrypted TEXT NOT NULL DEFAULT '', "
                    "regions TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'pending', "
                    "status_detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, "
                    "updated_at TEXT NOT NULL, last_scan_at TEXT, last_scan_id TEXT, "
                    "scan_interval_minutes INTEGER, auth_params TEXT NOT NULL DEFAULT '{}', "
                    "last_event_at TEXT)"
                ),
            },
        ),
    ),
)


def _decode_regions(raw: Any) -> list[str]:
    """Parse a stored regions JSON blob into a list of strings (tolerant)."""
    if not raw:
        return []
    try:
        parsed = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
    except (ValueError, TypeError):
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed]


def _decode_interval(raw: Any) -> int | None:
    """Parse a stored ``scan_interval_minutes`` value into an int (tolerant)."""
    if raw is None:
        return None
    try:
        return int(raw)
    except (ValueError, TypeError):
        return None


def _decode_auth_params(raw: Any) -> dict[str, Any]:
    """Parse a stored ``auth_params`` JSON blob into a dict (tolerant).

    Non-secret provider-specific params. Defaults to an empty dict on any
    malformed / missing value so a legacy row (pre-migration) reads cleanly.
    """
    if not raw:
        return {}
    try:
        parsed = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
    except (ValueError, TypeError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {str(k): v for k, v in parsed.items()}


def _row_to_record(row: Sequence[Any]) -> CloudConnectionRecord:
    """Map a ``cloud_connections`` row tuple to a record (shared by backends).

    The two durable backends select slightly different column shapes: the SQLite
    SELECT carries ``last_scan_id`` (16 columns) while the Postgres SELECT omits
    it (15 columns). ``last_scan_id`` therefore only exists in the wider SQLite
    shape; every other column keeps the same relative order in both, so a single
    length check distinguishes them and the trailing columns are read positionally
    from the correct index in each shape.
    """
    has_last_scan_id = len(row) >= 16
    interval_idx = 13 if has_last_scan_id else 12
    auth_idx = 14 if has_last_scan_id else 13
    event_idx = 15 if has_last_scan_id else 14
    return CloudConnectionRecord(
        id=row[0],
        tenant_id=row[1],
        provider=row[2],
        display_name=row[3],
        role_ref=row[4],
        external_id_encrypted=row[5] or "",
        regions=_decode_regions(row[6]),
        status=row[7] or STATUS_PENDING,
        status_detail=row[8] or "",
        created_at=row[9] or "",
        updated_at=row[10] or "",
        last_scan_at=row[11] if len(row) > 11 else None,
        last_scan_id=row[12] if has_last_scan_id else None,
        scan_interval_minutes=(_decode_interval(row[interval_idx]) if len(row) > interval_idx else None),
        auth_params=_decode_auth_params(row[auth_idx]) if len(row) > auth_idx else {},
        last_event_at=row[event_idx] if len(row) > event_idx else None,
    )


def _copy_record(record: CloudConnectionRecord) -> CloudConnectionRecord:
    """Return an independent copy so callers cannot mutate stored state in place.

    Mirrors the durable backends, which deserialize a fresh object on every read.
    Without this the in-memory store would hand out the live reference and the
    compare-and-swap claim could never observe a concurrent change.
    """
    return replace(record, regions=list(record.regions), auth_params=dict(record.auth_params))


class InMemoryConnectionStore:
    """Dict-backed connection store for tests and ephemeral runs."""

    def __init__(self) -> None:
        self._rows: dict[str, CloudConnectionRecord] = {}
        self._lock = threading.Lock()

    def init_schema(self) -> None:
        """No-op: the in-memory backend has no persistent schema."""

    def put(self, record: CloudConnectionRecord) -> None:
        with self._lock:
            self._rows[record.id] = _copy_record(record)

    def get(self, tenant_id: str, connection_id: str) -> CloudConnectionRecord | None:
        with self._lock:
            record = self._rows.get(connection_id)
            if record is None or record.tenant_id != tenant_id:
                return None
            return _copy_record(record)

    def list_for_tenant(self, tenant_id: str) -> list[CloudConnectionRecord]:
        with self._lock:
            records = [_copy_record(r) for r in self._rows.values() if r.tenant_id == tenant_id]
        return sorted(records, key=lambda r: (r.created_at, r.id))

    def delete(self, tenant_id: str, connection_id: str) -> bool:
        with self._lock:
            record = self._rows.get(connection_id)
            if record is None or record.tenant_id != tenant_id:
                return False
            del self._rows[connection_id]
            return True

    def list_schedulable(self) -> list[CloudConnectionRecord]:
        with self._lock:
            return [_copy_record(r) for r in self._rows.values() if r.scan_interval_minutes is not None]

    def claim_due_scan(self, record: CloudConnectionRecord, claimed_at: str) -> bool:
        """Atomically claim a due scan, gated on the last-seen ``last_scan_at``.

        Returns True only if the stored row still carries the ``last_scan_at``
        the caller observed — a compare-and-swap so exactly one replica wins a
        given due scan even when several poll the same connection concurrently.
        """
        with self._lock:
            current = self._rows.get(record.id)
            if current is None or current.tenant_id != record.tenant_id:
                return False
            if current.last_scan_at != record.last_scan_at:
                return False
            current.last_scan_at = claimed_at
            current.updated_at = claimed_at
        record.last_scan_at = claimed_at
        return True


class SQLiteConnectionStore:
    """SQLite-backed connection store (durable single-node default)."""

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

    def init_schema(self) -> None:
        self._init_db()

    def _init_db(self) -> None:
        ensure_sqlite_schema_version(self._conn, "cloud_connections")
        ddl = CONNECTION_STORAGE_SCHEMA.tables[0].ddl_for("sqlite")
        if ddl:
            self._conn.execute(ddl)
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(cloud_connections)").fetchall()}
        if "last_scan_id" not in columns:
            self._conn.execute("ALTER TABLE cloud_connections ADD COLUMN last_scan_id TEXT")
        if "scan_interval_minutes" not in columns:
            self._conn.execute("ALTER TABLE cloud_connections ADD COLUMN scan_interval_minutes INTEGER")
        if "auth_params" not in columns:
            # Idempotent migration: backfill existing rows with an empty object so
            # the column stays NOT NULL and legacy connections read as no-params.
            self._conn.execute("ALTER TABLE cloud_connections ADD COLUMN auth_params TEXT NOT NULL DEFAULT '{}'")
        if "last_event_at" not in columns:
            self._conn.execute("ALTER TABLE cloud_connections ADD COLUMN last_event_at TEXT")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_cloud_connections_tenant ON cloud_connections(tenant_id, created_at)")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cloud_connections_schedulable ON cloud_connections(scan_interval_minutes, last_scan_at)"
        )
        self._conn.commit()

    def put(self, record: CloudConnectionRecord) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO cloud_connections
                (id, tenant_id, provider, display_name, role_ref, external_id_encrypted,
                 regions, status, status_detail, created_at, updated_at, last_scan_at,
                 last_scan_id, scan_interval_minutes, auth_params, last_event_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.id,
                record.tenant_id,
                record.provider,
                record.display_name,
                record.role_ref,
                record.external_id_encrypted,
                json.dumps(record.regions),
                record.status,
                record.status_detail,
                record.created_at,
                record.updated_at,
                record.last_scan_at,
                record.last_scan_id,
                record.scan_interval_minutes,
                json.dumps(record.auth_params),
                record.last_event_at,
            ),
        )
        self._conn.commit()

    def get(self, tenant_id: str, connection_id: str) -> CloudConnectionRecord | None:
        row = self._conn.execute(
            "SELECT id, tenant_id, provider, display_name, role_ref, external_id_encrypted, "
            "regions, status, status_detail, created_at, updated_at, last_scan_at, "
            "last_scan_id, scan_interval_minutes, auth_params, last_event_at "
            "FROM cloud_connections WHERE tenant_id = ? AND id = ?",
            (tenant_id, connection_id),
        ).fetchone()
        return _row_to_record(row) if row else None

    def list_for_tenant(self, tenant_id: str) -> list[CloudConnectionRecord]:
        rows = self._conn.execute(
            "SELECT id, tenant_id, provider, display_name, role_ref, external_id_encrypted, "
            "regions, status, status_detail, created_at, updated_at, last_scan_at, "
            "last_scan_id, scan_interval_minutes, auth_params, last_event_at "
            "FROM cloud_connections WHERE tenant_id = ? ORDER BY created_at, id",
            (tenant_id,),
        ).fetchall()
        return [_row_to_record(row) for row in rows]

    def delete(self, tenant_id: str, connection_id: str) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM cloud_connections WHERE tenant_id = ? AND id = ?",
            (tenant_id, connection_id),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def list_schedulable(self) -> list[CloudConnectionRecord]:
        rows = self._conn.execute(
            "SELECT id, tenant_id, provider, display_name, role_ref, external_id_encrypted, "
            "regions, status, status_detail, created_at, updated_at, last_scan_at, "
            "last_scan_id, scan_interval_minutes, auth_params, last_event_at "
            "FROM cloud_connections WHERE scan_interval_minutes IS NOT NULL ORDER BY created_at, id"
        ).fetchall()
        return [_row_to_record(row) for row in rows]

    def claim_due_scan(self, record: CloudConnectionRecord, claimed_at: str) -> bool:
        """Atomically claim a due scan via a compare-and-swap on ``last_scan_at``.

        The conditional UPDATE only matches while the stored ``last_scan_at``
        equals the value the caller observed, so two replicas racing the same
        due connection cannot both win — the loser's WHERE no longer matches
        after the winner commits the new claim timestamp.
        """
        if record.last_scan_at is None:
            cursor = self._conn.execute(
                "UPDATE cloud_connections SET last_scan_at = ?, updated_at = ? WHERE id = ? AND tenant_id = ? AND last_scan_at IS NULL",
                (claimed_at, claimed_at, record.id, record.tenant_id),
            )
        else:
            cursor = self._conn.execute(
                "UPDATE cloud_connections SET last_scan_at = ?, updated_at = ? WHERE id = ? AND tenant_id = ? AND last_scan_at = ?",
                (claimed_at, claimed_at, record.id, record.tenant_id, record.last_scan_at),
            )
        self._conn.commit()
        won = cursor.rowcount == 1
        if won:
            record.last_scan_at = claimed_at
        return won


_CONNECTION_STORE: ConnectionStore | None = None


def get_connection_store() -> ConnectionStore:
    """Return the process connection store, selecting the backend via the factory.

    Mirrors ``cost_store.get_cost_store``: Postgres → shared SQLite → in-memory,
    so connections land on the same tier as every other env-ladder store.
    """
    global _CONNECTION_STORE
    if _CONNECTION_STORE is not None:
        return _CONNECTION_STORE
    from agent_bom.storage.base import BackendKind
    from agent_bom.storage.factory import resolve_backend

    selection = resolve_backend(mode="env")
    if selection.backend is BackendKind.POSTGRES:
        from agent_bom.api.postgres_connection import PostgresConnectionStore

        _CONNECTION_STORE = PostgresConnectionStore()
    elif selection.backend is BackendKind.SQLITE and selection.sqlite_path:
        _CONNECTION_STORE = SQLiteConnectionStore(selection.sqlite_path)
    else:
        _CONNECTION_STORE = InMemoryConnectionStore()
    return _CONNECTION_STORE


def set_connection_store(store: ConnectionStore | None) -> None:
    """Swap the process connection store (tests / explicit backend wiring)."""
    global _CONNECTION_STORE
    _CONNECTION_STORE = store
