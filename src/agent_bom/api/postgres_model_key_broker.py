"""Postgres-backed model-provider key broker store for horizontal scaling.

Mirrors :class:`agent_bom.api.model_key_broker.SQLiteModelKeyBrokerStore` but
stores sealed provider keys and minted virtual keys in shared Postgres with
tenant RLS, so registrations and virtual keys stay consistent across every
control-plane replica instead of diverging on node-local SQLite (or vanishing on
an in-memory restart).

Security properties carried over verbatim from the SQLite store:
- the real provider key is stored only as Fernet ciphertext inside the JSON
  ``data`` blob (``secret_encrypted``); the plaintext is never persisted,
- virtual keys are stored only by SHA-256 ``token_hash``; the raw ``abvk_`` token
  is never persisted,
- tenant isolation is enforced by Postgres FORCE ROW LEVEL SECURITY *and* every
  query additionally filters ``tenant_id`` so resolution is fail-closed across
  tenants.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from agent_bom.api.model_key_broker import (
    STATUS_ACTIVE,
    ModelProviderKey,
    VirtualModelKey,
)
from agent_bom.api.postgres_common import (
    ConnectionPool,
    _ensure_tenant_rls,
    _get_pool,
    _tenant_connection,
)
from agent_bom.api.storage_schema import ensure_postgres_schema_version


class PostgresModelKeyBrokerStore:
    """Shared provider-key + virtual-key broker store backed by Postgres."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def init_schema(self) -> None:
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "model_provider_keys")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS model_provider_keys (
                    provider_key_id TEXT PRIMARY KEY,
                    tenant_id       TEXT NOT NULL,
                    provider        TEXT NOT NULL,
                    status          TEXT NOT NULL,
                    created_at      TEXT NOT NULL,
                    data            TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS model_virtual_keys (
                    virtual_key_id  TEXT PRIMARY KEY,
                    tenant_id       TEXT NOT NULL,
                    provider_key_id TEXT NOT NULL,
                    token_hash      TEXT NOT NULL UNIQUE,
                    status          TEXT NOT NULL,
                    issued_at       TEXT NOT NULL,
                    data            TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_model_provider_keys_tenant ON model_provider_keys(tenant_id, created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_model_virtual_keys_tenant ON model_virtual_keys(tenant_id, issued_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_model_virtual_keys_hash ON model_virtual_keys(token_hash)")
            _ensure_tenant_rls(conn, "model_provider_keys", "tenant_id")
            _ensure_tenant_rls(conn, "model_virtual_keys", "tenant_id")
            conn.commit()

    # ── provider keys ─────────────────────────────────────────────────────────

    def put_provider_key(self, record: ModelProviderKey) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO model_provider_keys (provider_key_id, tenant_id, provider, status, created_at, data)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (provider_key_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    data = EXCLUDED.data
                """,
                (
                    record.provider_key_id,
                    record.tenant_id,
                    record.provider,
                    record.status,
                    record.created_at,
                    json.dumps(asdict(record), sort_keys=True),
                ),
            )
            conn.commit()

    def get_provider_key(self, provider_key_id: str, *, tenant_id: str) -> ModelProviderKey | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT data FROM model_provider_keys WHERE provider_key_id = %s AND tenant_id = %s",
                (provider_key_id, tenant_id),
            ).fetchone()
        return ModelProviderKey(**json.loads(row[0])) if row else None

    def list_provider_keys(self, tenant_id: str) -> list[ModelProviderKey]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT data FROM model_provider_keys WHERE tenant_id = %s ORDER BY created_at, provider_key_id",
                (tenant_id,),
            ).fetchall()
        return [ModelProviderKey(**json.loads(r[0])) for r in rows]

    def delete_provider_key(self, provider_key_id: str, *, tenant_id: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                "DELETE FROM model_provider_keys WHERE provider_key_id = %s AND tenant_id = %s",
                (provider_key_id, tenant_id),
            )
            conn.commit()
            return bool(cursor.rowcount)

    # ── virtual keys ──────────────────────────────────────────────────────────

    def put_virtual_key(self, record: VirtualModelKey) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO model_virtual_keys
                    (virtual_key_id, tenant_id, provider_key_id, token_hash, status, issued_at, data)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (virtual_key_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    data = EXCLUDED.data
                """,
                (
                    record.virtual_key_id,
                    record.tenant_id,
                    record.provider_key_id,
                    record.token_hash,
                    record.status,
                    record.issued_at,
                    json.dumps(asdict(record), sort_keys=True),
                ),
            )
            conn.commit()

    def get_virtual_key(self, virtual_key_id: str, *, tenant_id: str) -> VirtualModelKey | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT data FROM model_virtual_keys WHERE virtual_key_id = %s AND tenant_id = %s",
                (virtual_key_id, tenant_id),
            ).fetchone()
        return VirtualModelKey(**json.loads(row[0])) if row else None

    def get_virtual_key_by_hash(self, token_hash: str, *, tenant_id: str) -> VirtualModelKey | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT data FROM model_virtual_keys WHERE token_hash = %s AND tenant_id = %s",
                (token_hash, tenant_id),
            ).fetchone()
        return VirtualModelKey(**json.loads(row[0])) if row else None

    def list_virtual_keys(
        self,
        tenant_id: str,
        *,
        provider_key_id: str | None = None,
        include_inactive: bool = False,
    ) -> list[VirtualModelKey]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT data FROM model_virtual_keys WHERE tenant_id = %s ORDER BY issued_at DESC, virtual_key_id DESC",
                (tenant_id,),
            ).fetchall()
        records = [VirtualModelKey(**json.loads(r[0])) for r in rows]
        if provider_key_id is not None:
            records = [r for r in records if r.provider_key_id == provider_key_id]
        if not include_inactive:
            records = [r for r in records if r.status == STATUS_ACTIVE]
        return records
