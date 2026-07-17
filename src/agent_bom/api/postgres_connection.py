"""Postgres-backed cloud-connection persistence for horizontal scaling.

Mirrors :class:`agent_bom.api.connection_store.SQLiteConnectionStore` but stores
connections in shared Postgres with tenant RLS, so the connections plane stays
consistent across control-plane replicas. The encrypted ``ExternalId`` column is
opaque ciphertext here exactly as it is in SQLite — Postgres never sees the
plaintext secret.
"""

from __future__ import annotations

import json

from agent_bom.api.connection_store import CloudConnectionRecord, _row_to_record
from agent_bom.api.postgres_common import (
    ConnectionPool,
    _ensure_tenant_rls,
    _get_pool,
    _tenant_connection,
    bypass_tenant_rls,
)
from agent_bom.api.storage_schema import ensure_postgres_schema_version


class PostgresConnectionStore:
    """Shared cloud-connection store backed by Postgres with tenant RLS."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def init_schema(self) -> None:
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "cloud_connections")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cloud_connections (
                    id                    TEXT PRIMARY KEY,
                    tenant_id             TEXT NOT NULL,
                    provider              TEXT NOT NULL,
                    display_name          TEXT NOT NULL,
                    role_ref              TEXT NOT NULL,
                    external_id_encrypted TEXT NOT NULL DEFAULT '',
                    regions               TEXT NOT NULL DEFAULT '[]',
                    status                TEXT NOT NULL DEFAULT 'pending',
                    status_detail         TEXT NOT NULL DEFAULT '',
                    created_at            TEXT NOT NULL,
                    updated_at            TEXT NOT NULL,
                    last_scan_at          TEXT,
                    last_scan_id          TEXT,
                    scan_interval_minutes INTEGER,
                    auth_params           TEXT NOT NULL DEFAULT '{}',
                    last_event_at         TEXT
                )
            """)
            conn.execute("ALTER TABLE cloud_connections ADD COLUMN IF NOT EXISTS scan_interval_minutes INTEGER")
            conn.execute("ALTER TABLE cloud_connections ADD COLUMN IF NOT EXISTS last_scan_id TEXT")
            # Idempotent migration: backfill existing rows with an empty object so
            # the column stays NOT NULL and legacy connections read as no-params.
            conn.execute("ALTER TABLE cloud_connections ADD COLUMN IF NOT EXISTS auth_params TEXT NOT NULL DEFAULT '{}'")
            conn.execute("ALTER TABLE cloud_connections ADD COLUMN IF NOT EXISTS last_event_at TEXT")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cloud_connections_tenant ON cloud_connections(tenant_id, created_at)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cloud_connections_schedulable ON cloud_connections(scan_interval_minutes, last_scan_at)"
            )
            _ensure_tenant_rls(conn, "cloud_connections", "tenant_id")
            conn.commit()

    def put(self, record: CloudConnectionRecord) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO cloud_connections
                    (id, tenant_id, provider, display_name, role_ref, external_id_encrypted,
                     regions, status, status_detail, created_at, updated_at, last_scan_at,
                     last_scan_id, scan_interval_minutes, auth_params, last_event_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    provider = EXCLUDED.provider,
                    display_name = EXCLUDED.display_name,
                    role_ref = EXCLUDED.role_ref,
                    external_id_encrypted = EXCLUDED.external_id_encrypted,
                    regions = EXCLUDED.regions,
                    status = EXCLUDED.status,
                    status_detail = EXCLUDED.status_detail,
                    updated_at = EXCLUDED.updated_at,
                    last_scan_at = EXCLUDED.last_scan_at,
                    last_scan_id = EXCLUDED.last_scan_id,
                    scan_interval_minutes = EXCLUDED.scan_interval_minutes,
                    auth_params = EXCLUDED.auth_params,
                    last_event_at = EXCLUDED.last_event_at
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
            conn.commit()

    def get(self, tenant_id: str, connection_id: str) -> CloudConnectionRecord | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT id, tenant_id, provider, display_name, role_ref, external_id_encrypted, "
                "regions, status, status_detail, created_at, updated_at, last_scan_at, last_scan_id, "
                "scan_interval_minutes, auth_params, last_event_at "
                "FROM cloud_connections WHERE tenant_id = %s AND id = %s",
                (tenant_id, connection_id),
            ).fetchone()
        return _row_to_record(row) if row else None

    def list_for_tenant(self, tenant_id: str) -> list[CloudConnectionRecord]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT id, tenant_id, provider, display_name, role_ref, external_id_encrypted, "
                "regions, status, status_detail, created_at, updated_at, last_scan_at, last_scan_id, "
                "scan_interval_minutes, auth_params, last_event_at "
                "FROM cloud_connections WHERE tenant_id = %s ORDER BY created_at, id",
                (tenant_id,),
            ).fetchall()
        return [_row_to_record(row) for row in rows]

    def delete(self, tenant_id: str, connection_id: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                "DELETE FROM cloud_connections WHERE tenant_id = %s AND id = %s",
                (tenant_id, connection_id),
            )
            conn.commit()
            return bool(cursor.rowcount > 0)

    def list_schedulable(self) -> list[CloudConnectionRecord]:
        """Cross-tenant fetch of connections with an interval set (scheduler use).

        Runs with tenant RLS bypassed because the background scheduler is a
        trusted internal task that must see every tenant's schedulable
        connections; tenant identity is preserved on each returned record.
        """
        with bypass_tenant_rls(), _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT id, tenant_id, provider, display_name, role_ref, external_id_encrypted, "
                "regions, status, status_detail, created_at, updated_at, last_scan_at, last_scan_id, "
                "scan_interval_minutes, auth_params, last_event_at "
                "FROM cloud_connections WHERE scan_interval_minutes IS NOT NULL ORDER BY created_at, id"
            ).fetchall()
        return [_row_to_record(row) for row in rows]

    def claim_due_scan(self, record: CloudConnectionRecord, claimed_at: str) -> bool:
        """Atomically claim a due scan via a compare-and-swap on ``last_scan_at``.

        The conditional UPDATE only matches while the stored ``last_scan_at``
        equals the value the caller observed. Postgres row locking serializes
        two replicas racing the same due connection: the first to commit
        advances ``last_scan_at`` so the second's WHERE no longer matches and it
        loses the claim. Runs RLS-bypassed (trusted scheduler) with the explicit
        tenant id retained in the predicate.
        """
        with bypass_tenant_rls(), _tenant_connection(self._pool) as conn:
            if record.last_scan_at is None:
                cursor = conn.execute(
                    "UPDATE cloud_connections SET last_scan_at = %s, updated_at = %s "
                    "WHERE id = %s AND tenant_id = %s AND last_scan_at IS NULL",
                    (claimed_at, claimed_at, record.id, record.tenant_id),
                )
            else:
                cursor = conn.execute(
                    "UPDATE cloud_connections SET last_scan_at = %s, updated_at = %s "
                    "WHERE id = %s AND tenant_id = %s AND last_scan_at = %s",
                    (claimed_at, claimed_at, record.id, record.tenant_id, record.last_scan_at),
                )
            conn.commit()
        won = bool(cursor.rowcount == 1)
        if won:
            record.last_scan_at = claimed_at
        return won
