"""Tenant-scoped persistence for ITSM ticketing connections + ticket links.

Two logical entities, one store (parity with the cloud-connection store's
backend tiering: in-memory for tests, SQLite for the single-node durable
default, Postgres with tenant RLS for multi-replica):

* ``ticketing_connections`` — the stored, encrypted, revocable connection
  (``secret_encrypted`` is the only sensitive column; never returned).
* ``ticket_links`` — the bidirectional link from a finding to its filed ticket.
  Its ``UNIQUE (tenant_id, connection_id, dedupe_key)`` is the idempotency guard:
  a second create for the same finding *claims* the same row instead of filing a
  duplicate ticket. The tenant_id is part of the key so two tenants filing the
  same logical finding never collide.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version
from agent_bom.ticketing.models import TicketingConnectionRecord


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TicketLink:
    """A finding→ticket link (also the idempotency ledger row)."""

    id: str
    tenant_id: str
    connection_id: str
    dedupe_key: str
    provider: str
    status: str = "open"
    external_id: str = ""
    key: str = ""
    url: str = ""
    created_at: str = ""
    updated_at: str = ""

    def to_public_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Store contract ────────────────────────────────────────────────────────────


class TicketingStore(Protocol):
    def init_schema(self) -> None: ...
    def put_connection(self, record: TicketingConnectionRecord) -> None: ...
    def get_connection(self, tenant_id: str, connection_id: str) -> TicketingConnectionRecord | None: ...
    def list_connections(self, tenant_id: str) -> list[TicketingConnectionRecord]: ...
    def delete_connection(self, tenant_id: str, connection_id: str) -> bool: ...
    def claim_ticket_link(self, link: TicketLink) -> tuple[bool, TicketLink]: ...
    def update_ticket_link(self, link: TicketLink) -> None: ...
    def get_ticket_link(self, tenant_id: str, ticket_id: str) -> TicketLink | None: ...
    def get_ticket_link_by_dedupe(self, tenant_id: str, connection_id: str, dedupe_key: str) -> TicketLink | None: ...
    def list_ticket_links(self, tenant_id: str) -> list[TicketLink]: ...
    def list_ticket_links_for_findings(self, tenant_id: str, finding_ids: set[str], *, limit: int) -> list[TicketLink]: ...
    def delete_ticket_link(self, tenant_id: str, ticket_id: str) -> bool: ...


def _copy_conn(record: TicketingConnectionRecord) -> TicketingConnectionRecord:
    return replace(record, auth_params=dict(record.auth_params))


# ── In-memory backend ─────────────────────────────────────────────────────────


class InMemoryTicketingStore:
    """Dict-backed store for tests and ephemeral runs (tenant-scoped)."""

    def __init__(self) -> None:
        self._conns: dict[str, TicketingConnectionRecord] = {}
        self._links: dict[str, TicketLink] = {}
        self._lock = threading.Lock()

    def init_schema(self) -> None:  # no persistent schema
        return None

    def put_connection(self, record: TicketingConnectionRecord) -> None:
        with self._lock:
            self._conns[record.id] = _copy_conn(record)

    def get_connection(self, tenant_id: str, connection_id: str) -> TicketingConnectionRecord | None:
        with self._lock:
            record = self._conns.get(connection_id)
            if record is None or record.tenant_id != tenant_id:
                return None
            return _copy_conn(record)

    def list_connections(self, tenant_id: str) -> list[TicketingConnectionRecord]:
        with self._lock:
            rows = [_copy_conn(r) for r in self._conns.values() if r.tenant_id == tenant_id]
        return sorted(rows, key=lambda r: (r.created_at, r.id))

    def delete_connection(self, tenant_id: str, connection_id: str) -> bool:
        with self._lock:
            record = self._conns.get(connection_id)
            if record is None or record.tenant_id != tenant_id:
                return False
            del self._conns[connection_id]
            return True

    def claim_ticket_link(self, link: TicketLink) -> tuple[bool, TicketLink]:
        with self._lock:
            for existing in self._links.values():
                if (
                    existing.tenant_id == link.tenant_id
                    and existing.connection_id == link.connection_id
                    and existing.dedupe_key == link.dedupe_key
                ):
                    return False, replace(existing)
            self._links[link.id] = replace(link)
            return True, replace(link)

    def update_ticket_link(self, link: TicketLink) -> None:
        with self._lock:
            self._links[link.id] = replace(link)

    def get_ticket_link(self, tenant_id: str, ticket_id: str) -> TicketLink | None:
        with self._lock:
            link = self._links.get(ticket_id)
            if link is None or link.tenant_id != tenant_id:
                return None
            return replace(link)

    def get_ticket_link_by_dedupe(self, tenant_id: str, connection_id: str, dedupe_key: str) -> TicketLink | None:
        with self._lock:
            for link in self._links.values():
                if link.tenant_id == tenant_id and link.connection_id == connection_id and link.dedupe_key == dedupe_key:
                    return replace(link)
            return None

    def list_ticket_links(self, tenant_id: str) -> list[TicketLink]:
        with self._lock:
            rows = [replace(link) for link in self._links.values() if link.tenant_id == tenant_id]
        return sorted(rows, key=lambda r: (r.created_at, r.id))

    def list_ticket_links_for_findings(self, tenant_id: str, finding_ids: set[str], *, limit: int) -> list[TicketLink]:
        if not finding_ids or limit < 1:
            return []
        with self._lock:
            rows = [
                replace(link)
                for link in self._links.values()
                if link.tenant_id == tenant_id and link.dedupe_key in finding_ids
            ]
        return sorted(rows, key=lambda row: (row.created_at, row.id))[:limit]

    def delete_ticket_link(self, tenant_id: str, ticket_id: str) -> bool:
        with self._lock:
            link = self._links.get(ticket_id)
            if link is None or link.tenant_id != tenant_id:
                return False
            del self._links[ticket_id]
            return True


# ── SQLite backend ────────────────────────────────────────────────────────────

_CONN_COLS = (
    "id, tenant_id, provider, transport, auth_method, display_name, endpoint, "
    "secret_encrypted, auth_params, status, status_detail, created_at, updated_at"
)
_LINK_COLS = "id, tenant_id, connection_id, dedupe_key, provider, status, external_id, key, url, created_at, updated_at"


def _row_to_conn(row: Any) -> TicketingConnectionRecord:
    return TicketingConnectionRecord(
        id=row[0],
        tenant_id=row[1],
        provider=row[2],
        transport=row[3],
        auth_method=row[4],
        display_name=row[5],
        endpoint=row[6],
        secret_encrypted=row[7],
        auth_params=json.loads(row[8]) if row[8] else {},
        status=row[9],
        status_detail=row[10],
        created_at=row[11],
        updated_at=row[12],
    )


def _row_to_link(row: Any) -> TicketLink:
    return TicketLink(
        id=row[0],
        tenant_id=row[1],
        connection_id=row[2],
        dedupe_key=row[3],
        provider=row[4],
        status=row[5],
        external_id=row[6],
        key=row[7],
        url=row[8],
        created_at=row[9],
        updated_at=row[10],
    )


class SQLiteTicketingStore:
    """SQLite-backed store (durable single-node default)."""

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
        ensure_sqlite_schema_version(self._conn, "ticketing_connections")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ticketing_connections (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                transport TEXT NOT NULL,
                auth_method TEXT NOT NULL,
                display_name TEXT NOT NULL,
                endpoint TEXT NOT NULL DEFAULT '',
                secret_encrypted TEXT NOT NULL DEFAULT '',
                auth_params TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'pending',
                status_detail TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_ticketing_connections_tenant ON ticketing_connections(tenant_id, created_at)")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ticket_links (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                connection_id TEXT NOT NULL,
                dedupe_key TEXT NOT NULL,
                provider TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                external_id TEXT NOT NULL DEFAULT '',
                key TEXT NOT NULL DEFAULT '',
                url TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (tenant_id, connection_id, dedupe_key)
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_ticket_links_tenant ON ticket_links(tenant_id, created_at)")
        self._conn.commit()

    def put_connection(self, record: TicketingConnectionRecord) -> None:
        self._conn.execute(
            f"INSERT OR REPLACE INTO ticketing_connections ({_CONN_COLS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                record.id,
                record.tenant_id,
                record.provider,
                record.transport,
                record.auth_method,
                record.display_name,
                record.endpoint,
                record.secret_encrypted,
                json.dumps(record.auth_params),
                record.status,
                record.status_detail,
                record.created_at,
                record.updated_at,
            ),
        )
        self._conn.commit()

    def get_connection(self, tenant_id: str, connection_id: str) -> TicketingConnectionRecord | None:
        row = self._conn.execute(
            f"SELECT {_CONN_COLS} FROM ticketing_connections WHERE tenant_id = ? AND id = ?",  # nosec B608 -- fixed internal columns
            (tenant_id, connection_id),
        ).fetchone()
        return _row_to_conn(row) if row else None

    def list_connections(self, tenant_id: str) -> list[TicketingConnectionRecord]:
        rows = self._conn.execute(
            f"SELECT {_CONN_COLS} FROM ticketing_connections WHERE tenant_id = ? ORDER BY created_at, id",  # nosec B608 -- fixed internal columns
            (tenant_id,),
        ).fetchall()
        return [_row_to_conn(r) for r in rows]

    def delete_connection(self, tenant_id: str, connection_id: str) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM ticketing_connections WHERE tenant_id = ? AND id = ?",
            (tenant_id, connection_id),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def claim_ticket_link(self, link: TicketLink) -> tuple[bool, TicketLink]:
        try:
            self._conn.execute(
                f"INSERT INTO ticket_links ({_LINK_COLS}) VALUES (?,?,?,?,?,?,?,?,?,?,?)",  # nosec B608 -- fixed internal columns
                (
                    link.id,
                    link.tenant_id,
                    link.connection_id,
                    link.dedupe_key,
                    link.provider,
                    link.status,
                    link.external_id,
                    link.key,
                    link.url,
                    link.created_at,
                    link.updated_at,
                ),
            )
            self._conn.commit()
            return True, link
        except sqlite3.IntegrityError:
            self._conn.rollback()
            existing = self.get_ticket_link_by_dedupe(link.tenant_id, link.connection_id, link.dedupe_key)
            if existing is None:  # pragma: no cover - lost row after conflict
                raise
            return False, existing

    def update_ticket_link(self, link: TicketLink) -> None:
        self._conn.execute(
            "UPDATE ticket_links SET status=?, external_id=?, key=?, url=?, updated_at=? WHERE tenant_id=? AND id=?",
            (link.status, link.external_id, link.key, link.url, link.updated_at, link.tenant_id, link.id),
        )
        self._conn.commit()

    def get_ticket_link(self, tenant_id: str, ticket_id: str) -> TicketLink | None:
        row = self._conn.execute(
            f"SELECT {_LINK_COLS} FROM ticket_links WHERE tenant_id = ? AND id = ?",  # nosec B608 -- fixed internal columns
            (tenant_id, ticket_id),
        ).fetchone()
        return _row_to_link(row) if row else None

    def get_ticket_link_by_dedupe(self, tenant_id: str, connection_id: str, dedupe_key: str) -> TicketLink | None:
        row = self._conn.execute(
            f"SELECT {_LINK_COLS} FROM ticket_links WHERE tenant_id = ? AND connection_id = ? AND dedupe_key = ?",  # nosec B608 -- fixed internal columns
            (tenant_id, connection_id, dedupe_key),
        ).fetchone()
        return _row_to_link(row) if row else None

    def list_ticket_links(self, tenant_id: str) -> list[TicketLink]:
        rows = self._conn.execute(
            f"SELECT {_LINK_COLS} FROM ticket_links WHERE tenant_id = ? ORDER BY created_at, id",  # nosec B608 -- fixed internal columns
            (tenant_id,),
        ).fetchall()
        return [_row_to_link(r) for r in rows]

    def list_ticket_links_for_findings(self, tenant_id: str, finding_ids: set[str], *, limit: int) -> list[TicketLink]:
        keys = sorted(finding_ids)[:1000]
        if not keys or limit < 1:
            return []
        placeholders = ",".join("?" for _ in keys)
        rows = self._conn.execute(
            f"SELECT {_LINK_COLS} FROM ticket_links WHERE tenant_id = ? AND dedupe_key IN ({placeholders}) "  # nosec B608
            "ORDER BY created_at, id LIMIT ?",
            (tenant_id, *keys, min(limit, 1001)),
        ).fetchall()
        return [_row_to_link(row) for row in rows]

    def delete_ticket_link(self, tenant_id: str, ticket_id: str) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM ticket_links WHERE tenant_id = ? AND id = ?",
            (tenant_id, ticket_id),
        )
        self._conn.commit()
        return cursor.rowcount > 0


# ── Factory (mirrors get_connection_store) ────────────────────────────────────

_TICKETING_STORE: TicketingStore | None = None


def get_ticketing_store() -> TicketingStore:
    """Return the process ticketing store, selecting the backend via the factory.

    Postgres → shared SQLite → in-memory, matching every other env-ladder store.
    """
    global _TICKETING_STORE
    if _TICKETING_STORE is not None:
        return _TICKETING_STORE
    from agent_bom.storage.base import BackendKind
    from agent_bom.storage.factory import resolve_backend

    selection = resolve_backend(mode="env")
    if selection.backend is BackendKind.POSTGRES:
        from agent_bom.ticketing.postgres_store import PostgresTicketingStore

        _TICKETING_STORE = PostgresTicketingStore()
    elif selection.backend is BackendKind.SQLITE and selection.sqlite_path:
        _TICKETING_STORE = SQLiteTicketingStore(selection.sqlite_path)
    else:
        _TICKETING_STORE = InMemoryTicketingStore()
    return _TICKETING_STORE


def set_ticketing_store(store: TicketingStore | None) -> None:
    """Swap the process ticketing store (tests / explicit backend wiring)."""
    global _TICKETING_STORE
    _TICKETING_STORE = store
