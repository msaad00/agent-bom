"""Postgres-backed durable governance audit chain for horizontal scaling.

Mirrors :class:`agent_bom.api.governance_audit_log.SQLiteGovernanceAuditLog`
but stores the NHI lifecycle-enforcement chain in shared Postgres with tenant
RLS, so on a clustered (multi-replica) control plane the tamper-evident audit
trail is ONE durable, append-only chain per tenant instead of splitting into a
node-local SQLite chain per replica.

Design (mirrors :class:`agent_bom.api.postgres_audit.PostgresAuditLog`):

* **Per-tenant hash chain.** Each tenant's records form an independent
  HMAC-linked chain: ``append`` seals a record against that tenant's current
  head (the max-``seq`` ``record_hash`` visible under the tenant's RLS session),
  matching the SQLite/in-memory tamper-evidence contract. This keeps chain
  integrity tenant-scoped, so a tenant can verify its own chain without seeing
  any other tenant's rows.
* **Tenant isolation via FORCE ROW LEVEL SECURITY.** Reads and the head lookup
  run under the record's tenant session, so a cross-tenant ``get`` returns
  ``None`` even for a valid ``action_id`` from another tenant.
* **Idempotent append.** The ``action_id`` is ``UNIQUE``; a second append of the
  same deterministic action is a no-op (``ON CONFLICT DO NOTHING``) and returns
  the already-stored canonical record, even across replicas.

This store never holds secret material — only identity ids, statuses, reasons.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from agent_bom.api.governance_audit_log import (
    GovernanceAuditRecord,
    _seal_record,
    _verify_rows,
)
from agent_bom.api.postgres_common import (
    ConnectionPool,
    _current_tenant,
    _ensure_tenant_rls,
    _get_pool,
    _tenant_connection,
    bypass_tenant_rls,
)
from agent_bom.api.storage_schema import ensure_postgres_schema_version


class PostgresGovernanceAuditLog:
    """Shared, tenant-scoped, append-only governance audit chain on Postgres."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "governance_audit_log")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS governance_audit_log (
                    seq         BIGSERIAL PRIMARY KEY,
                    action_id   TEXT NOT NULL UNIQUE,
                    tenant_id   TEXT NOT NULL,
                    action      TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    record_hash TEXT NOT NULL,
                    data        TEXT NOT NULL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_governance_audit_tenant "
                "ON governance_audit_log(tenant_id, seq)"
            )
            _ensure_tenant_rls(conn, "governance_audit_log", "tenant_id")
            conn.commit()

    def _get_within_tenant(self, conn: Any, action_id: str) -> GovernanceAuditRecord | None:
        row = conn.execute(
            "SELECT data FROM governance_audit_log WHERE action_id = %s",
            (action_id,),
        ).fetchone()
        return GovernanceAuditRecord(**json.loads(row[0])) if row else None

    def append(self, record: GovernanceAuditRecord) -> GovernanceAuditRecord:
        # Bind the record's own tenant so the head lookup and RLS WITH CHECK
        # resolve to that tenant's chain — never the ambient request tenant.
        token = _current_tenant.set(record.tenant_id)
        try:
            with _tenant_connection(self._pool) as conn:
                existing = self._get_within_tenant(conn, record.action_id)
                if existing is not None:
                    return existing
                head_row = conn.execute(
                    "SELECT record_hash FROM governance_audit_log "
                    "WHERE tenant_id = %s ORDER BY seq DESC LIMIT 1",
                    (record.tenant_id,),
                ).fetchone()
                head = str(head_row[0]) if head_row else ""
                sealed = _seal_record(record, head)
                conn.execute(
                    "INSERT INTO governance_audit_log "
                    "(action_id, tenant_id, action, observed_at, record_hash, data) "
                    "VALUES (%s, %s, %s, %s, %s, %s) "
                    "ON CONFLICT (action_id) DO NOTHING",
                    (
                        sealed.action_id,
                        sealed.tenant_id,
                        sealed.action,
                        sealed.observed_at,
                        sealed.record_hash,
                        json.dumps(asdict(sealed), sort_keys=True),
                    ),
                )
                conn.commit()
                # A concurrent replica may have won the UNIQUE race between our
                # existence check and insert; re-read so the canonical row wins.
                stored = self._get_within_tenant(conn, sealed.action_id)
                return stored if stored is not None else sealed
        finally:
            _current_tenant.reset(token)

    def get(self, action_id: str) -> GovernanceAuditRecord | None:
        # Scoped to the ambient tenant session: a cross-tenant action_id is
        # invisible under FORCE ROW LEVEL SECURITY and returns None.
        with _tenant_connection(self._pool) as conn:
            return self._get_within_tenant(conn, action_id)

    def list(self, *, tenant_id: str | None = None, limit: int = 500) -> list[GovernanceAuditRecord]:
        if tenant_id is not None:
            token = _current_tenant.set(tenant_id)
            try:
                with _tenant_connection(self._pool) as conn:
                    rows = conn.execute(
                        "SELECT data FROM governance_audit_log WHERE tenant_id = %s "
                        "ORDER BY seq DESC LIMIT %s",
                        (tenant_id, limit),
                    ).fetchall()
            finally:
                _current_tenant.reset(token)
        else:
            # Cross-tenant listing is a trusted control-plane read; the bypass
            # activation is itself audit-logged in postgres_common.
            with bypass_tenant_rls(), _tenant_connection(self._pool) as conn:
                rows = conn.execute(
                    "SELECT data FROM governance_audit_log ORDER BY seq DESC LIMIT %s",
                    (limit,),
                ).fetchall()
        return [GovernanceAuditRecord(**json.loads(r[0])) for r in rows]

    def head_hash(self) -> str:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT record_hash FROM governance_audit_log "
                "WHERE tenant_id = %s ORDER BY seq DESC LIMIT 1",
                (_current_tenant.get(),),
            ).fetchone()
        return str(row[0]) if row else ""

    def verify_chain(self, *, max_rows: int = 50_000) -> dict[str, Any]:
        # Full-estate integrity sweep: read every tenant's rows (trusted bypass),
        # then verify each tenant's chain independently — a tenant's records link
        # only to that tenant's prior record, so mixing tenants would false-flag.
        with bypass_tenant_rls(), _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT data FROM governance_audit_log ORDER BY tenant_id ASC, seq ASC LIMIT %s",
                (max_rows,),
            ).fetchall()
        by_tenant: dict[str, list[GovernanceAuditRecord]] = {}
        for r in rows:
            record = GovernanceAuditRecord(**json.loads(r[0]))
            by_tenant.setdefault(record.tenant_id, []).append(record)
        verified = tampered = 0
        for chain in by_tenant.values():
            result = _verify_rows(chain)
            verified += result["verified"]
            tampered += result["tampered"]
        return {"verified": verified, "tampered": tampered, "checked": verified + tampered}


__all__ = ["PostgresGovernanceAuditLog"]
