"""Postgres-backed ticketing store for multi-replica deployments.

Mirrors :class:`agent_bom.ticketing.connection_store.SQLiteTicketingStore` but on
shared Postgres with tenant RLS, so the connect-once connection and the ticket
dedupe ledger stay consistent across control-plane replicas. The
``secret_encrypted`` column is opaque ciphertext here exactly as in SQLite —
Postgres never sees the plaintext secret. The ``ticket_links`` unique key does the
cross-process idempotency claim via ``INSERT ... ON CONFLICT DO NOTHING``.
"""

from __future__ import annotations

import json

from agent_bom.api.postgres_common import (
    ConnectionPool,
    _ensure_tenant_rls,
    _get_pool,
    _tenant_connection,
)
from agent_bom.api.storage_schema import ensure_postgres_schema_version
from agent_bom.ticketing.connection_store import (
    _CONN_COLS,
    _LINK_COLS,
    TicketLink,
    _row_to_conn,
    _row_to_link,
)
from agent_bom.ticketing.models import TicketingConnectionRecord


class PostgresTicketingStore:
    """Shared ticketing store backed by Postgres with tenant RLS."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def init_schema(self) -> None:
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "ticketing_connections")
            conn.execute(
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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ticketing_connections_tenant ON ticketing_connections(tenant_id, created_at)")
            conn.execute(
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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ticket_links_tenant ON ticket_links(tenant_id, created_at)")
            _ensure_tenant_rls(conn, "ticketing_connections", "tenant_id")
            _ensure_tenant_rls(conn, "ticket_links", "tenant_id")
            conn.commit()

    def put_connection(self, record: TicketingConnectionRecord) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                (
                    f"INSERT INTO ticketing_connections ({_CONN_COLS}) "  # nosec B608 -- fixed internal columns
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                    "ON CONFLICT (id) DO UPDATE SET provider = EXCLUDED.provider, transport = EXCLUDED.transport, "
                    "auth_method = EXCLUDED.auth_method, display_name = EXCLUDED.display_name, endpoint = EXCLUDED.endpoint, "
                    "secret_encrypted = EXCLUDED.secret_encrypted, auth_params = EXCLUDED.auth_params, status = EXCLUDED.status, "
                    "status_detail = EXCLUDED.status_detail, updated_at = EXCLUDED.updated_at"
                ),
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
            conn.commit()

    def get_connection(self, tenant_id: str, connection_id: str) -> TicketingConnectionRecord | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                f"SELECT {_CONN_COLS} FROM ticketing_connections WHERE tenant_id = %s AND id = %s",  # nosec B608 -- fixed internal columns
                (tenant_id, connection_id),
            ).fetchone()
        return _row_to_conn(row) if row else None

    def list_connections(self, tenant_id: str) -> list[TicketingConnectionRecord]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                f"SELECT {_CONN_COLS} FROM ticketing_connections WHERE tenant_id = %s ORDER BY created_at, id",  # nosec B608 -- fixed internal columns
                (tenant_id,),
            ).fetchall()
        return [_row_to_conn(r) for r in rows]

    def delete_connection(self, tenant_id: str, connection_id: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                "DELETE FROM ticketing_connections WHERE tenant_id = %s AND id = %s",
                (tenant_id, connection_id),
            )
            conn.commit()
            return bool(cursor.rowcount > 0)

    def claim_ticket_link(self, link: TicketLink) -> tuple[bool, TicketLink]:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                (
                    f"INSERT INTO ticket_links ({_LINK_COLS}) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "  # nosec B608 -- fixed internal columns
                    "ON CONFLICT (tenant_id, connection_id, dedupe_key) DO NOTHING"
                ),
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
            conn.commit()
            won = bool(cursor.rowcount == 1)
        if won:
            return True, link
        existing = self.get_ticket_link_by_dedupe(link.tenant_id, link.connection_id, link.dedupe_key)
        if existing is None:  # pragma: no cover - lost row after conflict
            return True, link
        return False, existing

    def update_ticket_link(self, link: TicketLink) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                "UPDATE ticket_links SET status=%s, external_id=%s, key=%s, url=%s, updated_at=%s WHERE tenant_id=%s AND id=%s",
                (link.status, link.external_id, link.key, link.url, link.updated_at, link.tenant_id, link.id),
            )
            conn.commit()

    def get_ticket_link(self, tenant_id: str, ticket_id: str) -> TicketLink | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                f"SELECT {_LINK_COLS} FROM ticket_links WHERE tenant_id = %s AND id = %s",  # nosec B608 -- fixed internal columns
                (tenant_id, ticket_id),
            ).fetchone()
        return _row_to_link(row) if row else None

    def get_ticket_link_by_dedupe(self, tenant_id: str, connection_id: str, dedupe_key: str) -> TicketLink | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                f"SELECT {_LINK_COLS} FROM ticket_links WHERE tenant_id = %s AND connection_id = %s AND dedupe_key = %s",  # nosec B608 -- fixed internal columns
                (tenant_id, connection_id, dedupe_key),
            ).fetchone()
        return _row_to_link(row) if row else None

    def list_ticket_links(self, tenant_id: str) -> list[TicketLink]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                f"SELECT {_LINK_COLS} FROM ticket_links WHERE tenant_id = %s ORDER BY created_at, id",  # nosec B608 -- fixed internal columns
                (tenant_id,),
            ).fetchall()
        return [_row_to_link(r) for r in rows]

    def list_ticket_links_for_findings(self, tenant_id: str, finding_ids: set[str], *, limit: int) -> list[TicketLink]:
        keys = sorted(finding_ids)[:1000]
        if not keys or limit < 1:
            return []
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                f"SELECT {_LINK_COLS} FROM ticket_links WHERE tenant_id = %s AND dedupe_key = ANY(%s) "  # nosec B608
                "ORDER BY created_at, id LIMIT %s",
                (tenant_id, keys, min(limit, 1001)),
            ).fetchall()
        return [_row_to_link(row) for row in rows]

    def delete_ticket_link(self, tenant_id: str, ticket_id: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                "DELETE FROM ticket_links WHERE tenant_id = %s AND id = %s",
                (tenant_id, ticket_id),
            )
            conn.commit()
            return bool(cursor.rowcount > 0)
