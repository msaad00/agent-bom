"""Tenant-scoped persistence for scheduled-export destinations (#4040).

An *export destination* is a connect-once record of where a tenant's findings
feed is delivered: an object store (``s3``) or a warehouse (``clickhouse``). It
mirrors the cloud-connection model — the single sensitive value (the warehouse
access token) is encrypted at rest by
:mod:`agent_bom.api.connection_crypto` and is the only column never returned by
the API (see :meth:`ExportDestinationRecord.to_public_dict`). The non-secret
``config`` (bucket/prefix/region, or url/user/database/table) is safe to return.

Backends mirror the connection store: in-memory for tests, SQLite as the durable
single-node default, and Postgres with tenant RLS for shared deployments.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Sequence
from copy import deepcopy
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version
from agent_bom.core.tenancy import require_explicit_tenant_id
from agent_bom.export.destinations import SUPPORTED_EXPORT_KINDS

STATUS_PENDING = "pending"
STATUS_ACTIVE = "active"
STATUS_ERROR = "error"
STATUS_INDETERMINATE = "indeterminate"
VALID_STATUSES: tuple[str, ...] = (STATUS_PENDING, STATUS_ACTIVE, STATUS_ERROR, STATUS_INDETERMINATE)


@dataclass
class ExportDestinationRecord:
    """One connect-once export destination for a tenant.

    ``secret_encrypted`` holds the Fernet ciphertext of the destination secret
    (the warehouse access token) — never plaintext. :meth:`to_public_dict` omits
    it. ``config`` is non-secret and is returned in API responses.
    """

    id: str
    tenant_id: str
    kind: str
    display_name: str
    config: dict[str, Any] = field(default_factory=dict)
    secret_encrypted: str = ""
    status: str = STATUS_PENDING
    status_detail: str = ""
    created_at: str = ""
    updated_at: str = ""
    last_run_at: str | None = None
    last_run_status: str | None = None

    def to_public_dict(self) -> dict[str, Any]:
        """Non-secret representation for API responses (omits the ciphertext)."""
        data = asdict(self)
        data.pop("secret_encrypted", None)
        data["has_secret"] = bool(self.secret_encrypted)
        return data


class ExportDestinationStore(Protocol):
    """Tenant-scoped CRUD contract for export destinations."""

    def init_schema(self) -> None: ...
    def put(self, record: ExportDestinationRecord, *, tenant_id: str) -> None: ...
    def get(self, tenant_id: str, destination_id: str) -> ExportDestinationRecord | None: ...
    def list_for_tenant(self, tenant_id: str) -> list[ExportDestinationRecord]: ...
    def delete(self, tenant_id: str, destination_id: str) -> bool: ...


def is_supported_kind(kind: str) -> bool:
    return (kind or "").strip().lower() in SUPPORTED_EXPORT_KINDS


def _copy(record: ExportDestinationRecord) -> ExportDestinationRecord:
    return replace(record, config=deepcopy(record.config))


def destination_write_tenant(record: ExportDestinationRecord, tenant_id: str) -> str:
    """Require the record owner to match the tenant authorized by its caller."""
    tenant = require_explicit_tenant_id(tenant_id)
    if record.tenant_id != tenant:
        raise ValueError("Export destination tenant does not match the authorized tenant")
    return tenant


def _decode_config(raw: Any) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
    except (ValueError, TypeError):
        return {}
    return {str(k): v for k, v in parsed.items()} if isinstance(parsed, dict) else {}


_COLUMNS = (
    "id",
    "tenant_id",
    "kind",
    "display_name",
    "config",
    "secret_encrypted",
    "status",
    "status_detail",
    "created_at",
    "updated_at",
    "last_run_at",
    "last_run_status",
)
_SELECT = f"SELECT {', '.join(_COLUMNS)} FROM export_destinations"  # nosec B608 — _COLUMNS is a static constant tuple, no user input


def _row_to_record(row: Sequence[Any]) -> ExportDestinationRecord:
    return ExportDestinationRecord(
        id=row[0],
        tenant_id=row[1],
        kind=row[2],
        display_name=row[3],
        config=_decode_config(row[4]),
        secret_encrypted=row[5] or "",
        status=row[6] or STATUS_PENDING,
        status_detail=row[7] or "",
        created_at=row[8] or "",
        updated_at=row[9] or "",
        last_run_at=row[10],
        last_run_status=row[11],
    )


class InMemoryExportDestinationStore:
    """Dict-backed export-destination store for tests and ephemeral runs."""

    def __init__(self) -> None:
        self._rows: dict[str, ExportDestinationRecord] = {}
        self._lock = threading.Lock()

    def init_schema(self) -> None:
        """No-op: the in-memory backend has no persistent schema."""

    def put(self, record: ExportDestinationRecord, *, tenant_id: str) -> None:
        tenant = destination_write_tenant(record, tenant_id)
        with self._lock:
            previous = self._rows.get(record.id)
            if previous is not None and previous.tenant_id != tenant:
                raise ValueError("Export destination identity belongs to a different tenant")
            self._rows[record.id] = _copy(record)

    def get(self, tenant_id: str, destination_id: str) -> ExportDestinationRecord | None:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._lock:
            record = self._rows.get(destination_id)
            if record is None or record.tenant_id != tenant:
                return None
            return _copy(record)

    def list_for_tenant(self, tenant_id: str) -> list[ExportDestinationRecord]:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._lock:
            records = [_copy(r) for r in self._rows.values() if r.tenant_id == tenant]
        return sorted(records, key=lambda r: (r.created_at, r.id))

    def delete(self, tenant_id: str, destination_id: str) -> bool:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._lock:
            record = self._rows.get(destination_id)
            if record is None or record.tenant_id != tenant:
                return False
            del self._rows[destination_id]
            return True


class SQLiteExportDestinationStore:
    """SQLite-backed export-destination store (durable single-node default)."""

    _DDL = (
        "CREATE TABLE IF NOT EXISTS export_destinations ("
        "id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, kind TEXT NOT NULL, "
        "display_name TEXT NOT NULL, config TEXT NOT NULL DEFAULT '{}', "
        "secret_encrypted TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', "
        "status_detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "
        "last_run_at TEXT, last_run_status TEXT)"
    )

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
        ensure_sqlite_schema_version(self._conn, "export_destinations")
        self._conn.execute(self._DDL)
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_export_dest_tenant ON export_destinations(tenant_id, created_at)")
        self._conn.commit()

    def put(self, record: ExportDestinationRecord, *, tenant_id: str) -> None:
        destination_write_tenant(record, tenant_id)
        cursor = self._conn.execute(
            f"INSERT INTO export_destinations ({', '.join(_COLUMNS)}) VALUES ({', '.join('?' for _ in _COLUMNS)}) "  # nosec B608 — columns are static and values are bound parameters
            "ON CONFLICT (id) DO UPDATE SET tenant_id=excluded.tenant_id, kind=excluded.kind, "
            "display_name=excluded.display_name, config=excluded.config, secret_encrypted=excluded.secret_encrypted, "
            "status=excluded.status, status_detail=excluded.status_detail, created_at=excluded.created_at, "
            "updated_at=excluded.updated_at, last_run_at=excluded.last_run_at, last_run_status=excluded.last_run_status "
            "WHERE export_destinations.tenant_id=excluded.tenant_id",
            (
                record.id,
                record.tenant_id,
                record.kind,
                record.display_name,
                json.dumps(record.config),
                record.secret_encrypted,
                record.status,
                record.status_detail,
                record.created_at,
                record.updated_at,
                record.last_run_at,
                record.last_run_status,
            ),
        )
        self._conn.commit()
        if cursor.rowcount == 0:
            raise ValueError("Export destination identity belongs to a different tenant")

    def get(self, tenant_id: str, destination_id: str) -> ExportDestinationRecord | None:
        tenant = require_explicit_tenant_id(tenant_id)
        row = self._conn.execute(
            f"{_SELECT} WHERE tenant_id = ? AND id = ?",
            (tenant, destination_id),
        ).fetchone()
        return _row_to_record(row) if row else None

    def list_for_tenant(self, tenant_id: str) -> list[ExportDestinationRecord]:
        tenant = require_explicit_tenant_id(tenant_id)
        rows = self._conn.execute(
            f"{_SELECT} WHERE tenant_id = ? ORDER BY created_at, id",
            (tenant,),
        ).fetchall()
        return [_row_to_record(row) for row in rows]

    def delete(self, tenant_id: str, destination_id: str) -> bool:
        tenant = require_explicit_tenant_id(tenant_id)
        cursor = self._conn.execute(
            "DELETE FROM export_destinations WHERE tenant_id = ? AND id = ?",
            (tenant, destination_id),
        )
        self._conn.commit()
        return cursor.rowcount > 0


class PostgresExportDestinationStore:
    """Durable shared destinations; tenant context and SQL predicates both apply."""

    def __init__(self, pool: Any = None) -> None:
        from agent_bom.api.postgres_common import _get_pool

        self._pool = pool or _get_pool()
        self.init_schema()

    def init_schema(self) -> None:
        from agent_bom.api.postgres_common import _ensure_tenant_rls
        from agent_bom.api.storage_schema import ensure_postgres_schema_version

        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, "export_destinations"):
                return
            conn.execute(
                "CREATE TABLE IF NOT EXISTS export_destinations ("
                "id TEXT NOT NULL, tenant_id TEXT NOT NULL, kind TEXT NOT NULL, "
                "display_name TEXT NOT NULL, config JSONB NOT NULL DEFAULT '{}'::jsonb, "
                "secret_encrypted TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', "
                "status_detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "
                "last_run_at TEXT, last_run_status TEXT, PRIMARY KEY (tenant_id, id))"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_export_dest_tenant ON export_destinations(tenant_id, created_at)")
            _ensure_tenant_rls(conn, "export_destinations", "tenant_id")
            conn.commit()

    def put(self, record: ExportDestinationRecord, *, tenant_id: str) -> None:
        from agent_bom.api.postgres_common import _tenant_connection

        destination_write_tenant(record, tenant_id)
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                "INSERT INTO export_destinations (id, tenant_id, kind, display_name, config, secret_encrypted, "
                "status, status_detail, created_at, updated_at, last_run_at, last_run_status) "
                "VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (tenant_id, id) DO UPDATE SET kind=excluded.kind, display_name=excluded.display_name, "
                "config=excluded.config, secret_encrypted=excluded.secret_encrypted, status=excluded.status, "
                "status_detail=excluded.status_detail, created_at=excluded.created_at, updated_at=excluded.updated_at, "
                "last_run_at=excluded.last_run_at, last_run_status=excluded.last_run_status",
                (
                    record.id,
                    record.tenant_id,
                    record.kind,
                    record.display_name,
                    json.dumps(record.config),
                    record.secret_encrypted,
                    record.status,
                    record.status_detail,
                    record.created_at,
                    record.updated_at,
                    record.last_run_at,
                    record.last_run_status,
                ),
            )
            conn.commit()

    def get(self, tenant_id: str, destination_id: str) -> ExportDestinationRecord | None:
        from agent_bom.api.postgres_common import _tenant_connection

        tenant = require_explicit_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(f"{_SELECT} WHERE tenant_id = %s AND id = %s", (tenant, destination_id)).fetchone()
        return _row_to_record(row) if row else None

    def list_for_tenant(self, tenant_id: str) -> list[ExportDestinationRecord]:
        from agent_bom.api.postgres_common import _tenant_connection

        tenant = require_explicit_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(f"{_SELECT} WHERE tenant_id = %s ORDER BY created_at, id", (tenant,)).fetchall()
        return [_row_to_record(row) for row in rows]

    def delete(self, tenant_id: str, destination_id: str) -> bool:
        from agent_bom.api.postgres_common import _tenant_connection

        tenant = require_explicit_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            deleted = conn.execute("DELETE FROM export_destinations WHERE tenant_id = %s AND id = %s", (tenant, destination_id))
            conn.commit()
            return bool(deleted.rowcount > 0)


_DESTINATION_STORE: ExportDestinationStore | None = None


def get_export_destination_store() -> ExportDestinationStore:
    """Return the process export-destination store, selecting backend via factory."""
    global _DESTINATION_STORE
    if _DESTINATION_STORE is not None:
        return _DESTINATION_STORE
    from agent_bom.storage.base import BackendKind
    from agent_bom.storage.factory import resolve_backend

    selection = resolve_backend(mode="env")
    if selection.backend is BackendKind.SQLITE and selection.sqlite_path:
        _DESTINATION_STORE = SQLiteExportDestinationStore(selection.sqlite_path)
    elif selection.backend is BackendKind.POSTGRES:
        _DESTINATION_STORE = PostgresExportDestinationStore()
    else:
        _DESTINATION_STORE = InMemoryExportDestinationStore()
    return _DESTINATION_STORE


def set_export_destination_store(store: ExportDestinationStore | None) -> None:
    """Swap the process export-destination store (tests / explicit wiring)."""
    global _DESTINATION_STORE
    _DESTINATION_STORE = store
