"""Postgres-backed agent-identity lifecycle store for horizontal scaling.

Mirrors :class:`agent_bom.api.agent_identity_store.SQLiteAgentIdentityStore`
but stores managed identities, JIT grants, and conditional-access policies in
shared Postgres with tenant RLS, so issued tokens, time-bound grants, and
context-aware access rules stay consistent across every control-plane replica
instead of diverging on node-local SQLite (or vanishing on an in-memory
restart). This is the multi-replica tier of the durable-by-default identity
store; the SQLite tier is single-node durable and the in-memory tier is an
explicit ephemeral opt-out.

Security properties carried over verbatim from the SQLite store:
- tokens are stored only as SHA-256 hashes (``token_hash``); the raw token is
  never persisted,
- tenant isolation is enforced by Postgres FORCE ROW LEVEL SECURITY,
- identity liveness (revoked / expired / rotation overlap) is computed from the
  same dataclass logic, not re-implemented in SQL.
"""

from __future__ import annotations

import builtins
import json
from dataclasses import asdict
from datetime import datetime

from agent_bom.api.agent_identity_store import (
    AgentIdentity,
    AgentJITGrant,
    ConditionalAccessPolicy,
)
from agent_bom.api.postgres_common import (
    ConnectionPool,
    _ensure_tenant_rls,
    _get_pool,
    _tenant_connection,
    bypass_tenant_rls,
)
from agent_bom.api.storage_schema import ensure_postgres_schema_version


class PostgresAgentIdentityStore:
    """Shared agent-identity + JIT + conditional-access store backed by Postgres."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "agent_identities")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_identities (
                    identity_id TEXT PRIMARY KEY,
                    tenant_id   TEXT NOT NULL,
                    token_hash  TEXT NOT NULL UNIQUE,
                    status      TEXT NOT NULL,
                    issued_at   TEXT NOT NULL,
                    data        TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_identity_jit_grants (
                    grant_id     TEXT PRIMARY KEY,
                    tenant_id    TEXT NOT NULL,
                    identity_id  TEXT NOT NULL,
                    tool_name    TEXT NOT NULL,
                    status       TEXT NOT NULL,
                    requested_at TEXT NOT NULL,
                    expires_at   TEXT NOT NULL,
                    data         TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_conditional_access_policies (
                    policy_id  TEXT PRIMARY KEY,
                    tenant_id  TEXT NOT NULL,
                    status     TEXT NOT NULL,
                    priority   INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    data       TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_identities_tenant ON agent_identities(tenant_id, status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_identities_hash ON agent_identities(token_hash)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_agent_identity_jit_lookup "
                "ON agent_identity_jit_grants(tenant_id, identity_id, tool_name, status, expires_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_agent_conditional_access_tenant "
                "ON agent_conditional_access_policies(tenant_id, status, priority)"
            )
            _ensure_tenant_rls(conn, "agent_identities", "tenant_id")
            _ensure_tenant_rls(conn, "agent_identity_jit_grants", "tenant_id")
            _ensure_tenant_rls(conn, "agent_conditional_access_policies", "tenant_id")
            conn.commit()

    # ── identities ──────────────────────────────────────────────────────────

    def put(self, identity: AgentIdentity) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO agent_identities (identity_id, tenant_id, token_hash, status, issued_at, data)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (identity_id) DO UPDATE SET
                    token_hash = EXCLUDED.token_hash,
                    status = EXCLUDED.status,
                    issued_at = EXCLUDED.issued_at,
                    data = EXCLUDED.data
                """,
                (
                    identity.identity_id,
                    identity.tenant_id,
                    identity.token_hash,
                    identity.status,
                    identity.issued_at,
                    json.dumps(asdict(identity), sort_keys=True),
                ),
            )
            conn.commit()

    def get(self, identity_id: str) -> AgentIdentity | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute("SELECT data FROM agent_identities WHERE identity_id = %s", (identity_id,)).fetchone()
        return AgentIdentity(**json.loads(row[0])) if row else None

    def get_by_token_hash(self, token_hash: str) -> AgentIdentity | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute("SELECT data FROM agent_identities WHERE token_hash = %s", (token_hash,)).fetchone()
        return AgentIdentity(**json.loads(row[0])) if row else None

    def list(self, tenant_id: str, *, include_inactive: bool = False, limit: int = 200) -> list[AgentIdentity]:
        with _tenant_connection(self._pool) as conn:
            if include_inactive:
                rows = conn.execute(
                    "SELECT data FROM agent_identities WHERE tenant_id = %s ORDER BY issued_at DESC LIMIT %s",
                    (tenant_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT data FROM agent_identities WHERE tenant_id = %s AND status IN ('active', 'rotating') "
                    "ORDER BY issued_at DESC LIMIT %s",
                    (tenant_id, limit),
                ).fetchall()
        return [AgentIdentity(**json.loads(r[0])) for r in rows]

    # ── JIT grants ──────────────────────────────────────────────────────────

    def put_jit_grant(self, grant: AgentJITGrant) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO agent_identity_jit_grants
                    (grant_id, tenant_id, identity_id, tool_name, status, requested_at, expires_at, data)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (grant_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    expires_at = EXCLUDED.expires_at,
                    data = EXCLUDED.data
                """,
                (
                    grant.grant_id,
                    grant.tenant_id,
                    grant.identity_id,
                    grant.tool_name,
                    grant.status,
                    grant.requested_at,
                    grant.expires_at,
                    json.dumps(asdict(grant), sort_keys=True),
                ),
            )
            conn.commit()

    def get_jit_grant(self, grant_id: str) -> AgentJITGrant | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute("SELECT data FROM agent_identity_jit_grants WHERE grant_id = %s", (grant_id,)).fetchone()
        return AgentJITGrant(**json.loads(row[0])) if row else None

    def list_jit_grants(
        self,
        tenant_id: str,
        *,
        identity_id: str | None = None,
        include_inactive: bool = False,
        limit: int = 200,
    ) -> builtins.list[AgentJITGrant]:
        with _tenant_connection(self._pool) as conn:
            if identity_id is not None:
                rows = conn.execute(
                    "SELECT data FROM agent_identity_jit_grants WHERE tenant_id = %s AND identity_id = %s "
                    "ORDER BY requested_at DESC LIMIT %s",
                    (tenant_id, identity_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT data FROM agent_identity_jit_grants WHERE tenant_id = %s ORDER BY requested_at DESC LIMIT %s",
                    (tenant_id, limit),
                ).fetchall()
        grants = [AgentJITGrant(**json.loads(r[0])) for r in rows]
        if not include_inactive:
            grants = [g for g in grants if g.is_live()]
        return grants[:limit]

    def active_jit_grant(
        self,
        tenant_id: str,
        identity_id: str,
        tool_name: str,
        *,
        at: datetime | None = None,
    ) -> AgentJITGrant | None:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT data FROM agent_identity_jit_grants "
                "WHERE tenant_id = %s AND identity_id = %s AND tool_name = %s AND status = 'active' "
                "ORDER BY expires_at DESC LIMIT 20",
                (tenant_id, identity_id, tool_name),
            ).fetchall()
        grants = [AgentJITGrant(**json.loads(r[0])) for r in rows]
        live = [g for g in grants if g.is_live(at=at)]
        return live[0] if live else None

    # ── cross-tenant maintenance sweeps ─────────────────────────────────────

    def iter_all_identities(self, *, limit: int = 10000) -> builtins.list[AgentIdentity]:
        """Return identities across every tenant for the cleanup loop.

        Runs under a trusted RLS bypass: the lifecycle cleanup is a control-plane
        maintenance task that must see all tenants' identities, not just the
        ambient one. The bypass activation is itself audit-logged in
        ``postgres_common``.
        """
        with bypass_tenant_rls(), _tenant_connection(self._pool) as conn:
            rows = conn.execute("SELECT data FROM agent_identities ORDER BY issued_at ASC LIMIT %s", (limit,)).fetchall()
        return [AgentIdentity(**json.loads(r[0])) for r in rows]

    def iter_all_jit_grants(self, *, limit: int = 10000) -> builtins.list[AgentJITGrant]:
        with bypass_tenant_rls(), _tenant_connection(self._pool) as conn:
            rows = conn.execute("SELECT data FROM agent_identity_jit_grants ORDER BY requested_at ASC LIMIT %s", (limit,)).fetchall()
        return [AgentJITGrant(**json.loads(r[0])) for r in rows]

    # ── conditional-access policies ─────────────────────────────────────────

    def put_conditional_policy(self, policy: ConditionalAccessPolicy) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO agent_conditional_access_policies
                    (policy_id, tenant_id, status, priority, created_at, data)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (policy_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    priority = EXCLUDED.priority,
                    data = EXCLUDED.data
                """,
                (
                    policy.policy_id,
                    policy.tenant_id,
                    policy.status,
                    int(policy.priority),
                    policy.created_at,
                    json.dumps(asdict(policy), sort_keys=True),
                ),
            )
            conn.commit()

    def get_conditional_policy(self, policy_id: str) -> ConditionalAccessPolicy | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute("SELECT data FROM agent_conditional_access_policies WHERE policy_id = %s", (policy_id,)).fetchone()
        return ConditionalAccessPolicy(**json.loads(row[0])) if row else None

    def list_conditional_policies(
        self,
        tenant_id: str,
        *,
        include_disabled: bool = False,
        limit: int = 200,
    ) -> builtins.list[ConditionalAccessPolicy]:
        with _tenant_connection(self._pool) as conn:
            if include_disabled:
                rows = conn.execute(
                    "SELECT data FROM agent_conditional_access_policies WHERE tenant_id = %s "
                    "ORDER BY priority ASC, created_at ASC LIMIT %s",
                    (tenant_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT data FROM agent_conditional_access_policies WHERE tenant_id = %s AND status = 'active' "
                    "ORDER BY priority ASC, created_at ASC LIMIT %s",
                    (tenant_id, limit),
                ).fetchall()
        return [ConditionalAccessPolicy(**json.loads(r[0])) for r in rows]
