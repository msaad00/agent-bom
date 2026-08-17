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
* **Idempotent append.** ``(tenant_id, action_id)`` is ``UNIQUE``; a second
  append of the same deterministic action is a no-op (``ON CONFLICT (tenant_id,
  action_id) DO NOTHING``) and returns the already-stored canonical record, even
  across replicas. The composite (rather than a global ``UNIQUE(action_id)``)
  means two tenants' independent actions can never collide, so no tenant's row is
  silently dropped.

This store never holds secret material — only identity ids, statuses, reasons.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from agent_bom.api.governance_audit_log import (
    GovernanceAuditRecord,
    _combined_head,
    _seal_record,
    _verify_rows_grouped,
)
from agent_bom.api.postgres_common import (
    ConnectionPool,
    _current_tenant,
    _ensure_tenant_rls,
    _get_pool,
    _maintenance_connection,
    _tenant_connection,
    bypass_tenant_rls,
)
from agent_bom.api.storage_schema import ensure_postgres_schema_version

# The fork-guard index this store relies on. Named so a unique violation can be
# attributed to a chain race rather than to the (tenant_id, action_id) dedupe.
_GOVERNANCE_FORK_GUARD_INDEX = "governance_audit_log_tenant_prevhash_uniq"
# Bounded: a genuine fork race resolves in one or two rounds. An unbounded loop
# would turn a persistent constraint problem into a hang on the request path.
_MAX_APPEND_RETRIES = 5


def _is_chain_fork_conflict(exc: Exception) -> bool:
    """True when ``exc`` is a unique violation on the chain fork-guard index.

    Deliberately narrow: the same INSERT also carries
    ``ON CONFLICT (tenant_id, action_id) DO NOTHING``, so a dedupe collision
    never raises. Anything that is not this index is a real error and must not
    be retried into a loop.
    """
    if getattr(exc, "sqlstate", None) != "23505":
        return False
    diag = getattr(exc, "diag", None)
    constraint = getattr(diag, "constraint_name", None) if diag else None
    return constraint in (None, "", _GOVERNANCE_FORK_GUARD_INDEX)


class PostgresGovernanceAuditLog:
    """Shared, tenant-scoped, append-only governance audit chain on Postgres."""

    def __init__(
        self,
        pool: ConnectionPool | None = None,
        maintenance_pool: ConnectionPool | None = None,
    ) -> None:
        self._pool = pool or _get_pool()
        self._maintenance_pool = maintenance_pool
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            if ensure_postgres_schema_version(conn, "governance_audit_log"):
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS governance_audit_log (
                        seq         BIGSERIAL PRIMARY KEY,
                        action_id   TEXT NOT NULL,
                        tenant_id   TEXT NOT NULL,
                        action      TEXT NOT NULL,
                        observed_at TEXT NOT NULL,
                        record_hash TEXT NOT NULL,
                        prev_hash   TEXT NOT NULL DEFAULT '',
                        data        TEXT NOT NULL
                    )
                """)
                conn.execute("ALTER TABLE governance_audit_log DROP CONSTRAINT IF EXISTS governance_audit_log_action_id_key")
                conn.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_governance_audit_tenant_action ON governance_audit_log(tenant_id, action_id)"
                )
                conn.execute(
                    f"CREATE UNIQUE INDEX IF NOT EXISTS {_GOVERNANCE_FORK_GUARD_INDEX} ON governance_audit_log(tenant_id, prev_hash)"
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_governance_audit_tenant ON governance_audit_log(tenant_id, seq)")
                _ensure_tenant_rls(conn, "governance_audit_log", "tenant_id")
                conn.commit()

    def _get_within_tenant(self, conn: Any, action_id: str) -> GovernanceAuditRecord | None:
        row = conn.execute(
            "SELECT data FROM governance_audit_log WHERE action_id = %s",
            (action_id,),
        ).fetchone()
        return GovernanceAuditRecord(**json.loads(row[0])) if row else None

    def append(self, record: GovernanceAuditRecord) -> GovernanceAuditRecord:
        """Append one record under a tenant-scoped transaction lock.

        The advisory lock serializes head-read, sealing, and insert across
        workers and replicas. The unique predecessor guard and bounded retry
        remain as rolling-upgrade protection while older replicas may still
        use the pre-lock append protocol.
        """
        # Bind the record's own tenant so the head lookup and RLS WITH CHECK
        # resolve to that tenant's chain — never the ambient request tenant.
        token = _current_tenant.set(record.tenant_id)
        attempts = 0
        try:
            while True:
                attempts += 1
                with _tenant_connection(self._pool) as conn:
                    conn.execute(
                        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                        (f"governance_audit:{record.tenant_id}",),
                    )
                    existing = self._get_within_tenant(conn, record.action_id)
                    if existing is not None:
                        conn.commit()
                        return existing
                    head_row = conn.execute(
                        "SELECT record_hash FROM governance_audit_log WHERE tenant_id = %s ORDER BY seq DESC LIMIT 1",
                        (record.tenant_id,),
                    ).fetchone()
                    head = str(head_row[0]) if head_row else ""
                    sealed = _seal_record(record, head)
                    try:
                        conn.execute(
                            "INSERT INTO governance_audit_log "
                            "(action_id, tenant_id, action, observed_at, record_hash, prev_hash, data) "
                            "VALUES (%s, %s, %s, %s, %s, %s, %s) "
                            "ON CONFLICT (tenant_id, action_id) DO NOTHING",
                            (
                                sealed.action_id,
                                sealed.tenant_id,
                                sealed.action,
                                sealed.observed_at,
                                sealed.record_hash,
                                sealed.prev_hash,
                                json.dumps(asdict(sealed), sort_keys=True),
                            ),
                        )
                        stored = self._get_within_tenant(conn, sealed.action_id)
                        conn.commit()
                    except Exception as exc:  # noqa: BLE001 - narrowed by _is_chain_fork_conflict
                        conn.rollback()
                        if _is_chain_fork_conflict(exc) and attempts <= _MAX_APPEND_RETRIES:
                            continue
                        raise
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
                        "SELECT data FROM governance_audit_log WHERE tenant_id = %s ORDER BY seq DESC LIMIT %s",
                        (tenant_id, limit),
                    ).fetchall()
            finally:
                _current_tenant.reset(token)
        else:
            # Cross-tenant listing is a trusted control-plane read; the bypass
            # activation is itself audit-logged in postgres_common.
            with bypass_tenant_rls(), _maintenance_connection(self._maintenance_pool) as conn:
                rows = conn.execute(
                    "SELECT data FROM governance_audit_log ORDER BY seq DESC LIMIT %s",
                    (limit,),
                ).fetchall()
        return [GovernanceAuditRecord(**json.loads(r[0])) for r in rows]

    def head_hash(self, tenant_id: str | None = None) -> str:
        if tenant_id is not None:
            token = _current_tenant.set(tenant_id)
            try:
                with _tenant_connection(self._pool) as conn:
                    row = conn.execute(
                        "SELECT record_hash FROM governance_audit_log WHERE tenant_id = %s ORDER BY seq DESC LIMIT 1",
                        (tenant_id,),
                    ).fetchone()
            finally:
                _current_tenant.reset(token)
            return str(row[0]) if row else ""
        # No tenant → a combined fingerprint over every tenant's head, so callers
        # can cheaply detect "did any chain move" without conflating tenants
        # (trusted control-plane read via the audited RLS bypass).
        with bypass_tenant_rls(), _maintenance_connection(self._maintenance_pool) as conn:
            rows = conn.execute(
                "SELECT g.tenant_id, g.record_hash FROM governance_audit_log g "
                "JOIN (SELECT tenant_id, MAX(seq) AS m FROM governance_audit_log GROUP BY tenant_id) t "
                "ON g.tenant_id = t.tenant_id AND g.seq = t.m"
            ).fetchall()
        return _combined_head({str(r[0]): str(r[1]) for r in rows})

    def verify_chain(self, *, tenant_id: str | None = None, max_rows: int = 50_000) -> dict[str, Any]:
        # A tenant's records link only to that tenant's prior record, so each
        # chain is verified in isolation; mixing tenants would false-flag.
        if tenant_id is not None:
            token = _current_tenant.set(tenant_id)
            try:
                with _tenant_connection(self._pool) as conn:
                    rows = conn.execute(
                        "SELECT data FROM governance_audit_log WHERE tenant_id = %s ORDER BY seq ASC LIMIT %s",
                        (tenant_id, max_rows),
                    ).fetchall()
            finally:
                _current_tenant.reset(token)
        else:
            # Full-estate sweep: read every tenant's rows under the audited bypass,
            # ordered so each tenant's rows stay in seq order for the grouped walk.
            with bypass_tenant_rls(), _maintenance_connection(self._maintenance_pool) as conn:
                rows = conn.execute(
                    "SELECT data FROM governance_audit_log ORDER BY tenant_id ASC, seq ASC LIMIT %s",
                    (max_rows,),
                ).fetchall()
        records = [GovernanceAuditRecord(**json.loads(r[0])) for r in rows]
        return _verify_rows_grouped(records, tenant_id=tenant_id)


__all__ = ["PostgresGovernanceAuditLog"]
