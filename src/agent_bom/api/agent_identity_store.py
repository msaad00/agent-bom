"""Agent identity lifecycle: issue, rotate, revoke, and verify.

``agent_bom.agent_identity`` verifies identity tokens an external IdP issues but
never managed their lifecycle. This store lets agent-bom issue time-scoped
identities for agents that have no IdP, rotate them with an overlap window, and
revoke them — the provisioning/rotation/revocation layer an agent-identity
control plane needs. Issued tokens (``abi_<prefix>_<secret>``) are stored only
as SHA-256 hashes; the raw token is returned exactly once at issue/rotate time.
"""

from __future__ import annotations

import builtins
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import threading
from copy import deepcopy
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Protocol

from agent_bom.api.identity_grants import (
    AgentJITGrant as AgentJITGrant,
)
from agent_bom.api.identity_grants import (
    approve_jit_grant as approve_jit_grant,
)
from agent_bom.api.identity_grants import (
    deny_jit_grant as deny_jit_grant,
)
from agent_bom.api.identity_grants import (
    identity_expiry as _ttl_to_expiry,
)
from agent_bom.api.identity_grants import (
    issue_jit_grant as issue_jit_grant,
)
from agent_bom.api.identity_grants import (
    request_jit_grant as request_jit_grant,
)
from agent_bom.api.identity_grants import (
    require_grant_tenant,
)
from agent_bom.api.identity_grants import (
    revoke_jit_grant as revoke_jit_grant,
)
from agent_bom.api.identity_policies import (
    AccessContext as AccessContext,
)
from agent_bom.api.identity_policies import (
    ConditionalAccessPolicy as ConditionalAccessPolicy,
)
from agent_bom.api.identity_policies import (
    create_conditional_policy as create_conditional_policy,
)
from agent_bom.api.identity_policies import (
    evaluate_conditional_access as evaluate_conditional_access,
)
from agent_bom.api.identity_policies import (
    evaluate_conditional_access_for_request as evaluate_conditional_access_for_request,
)
from agent_bom.api.identity_policies import (
    require_policy_tenant,
)
from agent_bom.api.identity_policies import (
    set_conditional_policy_status as set_conditional_policy_status,
)
from agent_bom.api.storage_schema import ensure_sqlite_schema_version
from agent_bom.core.tenancy import require_explicit_tenant_id

TOKEN_PREFIX = "abi"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> tuple[str, str, str]:
    """Return ``(raw_token, public_prefix, token_hash)``. Raw token is shown once."""
    public = secrets.token_hex(4)
    secret = secrets.token_urlsafe(32)
    raw = f"{TOKEN_PREFIX}_{public}_{secret}"
    return raw, public, hash_token(raw)


@dataclass
class AgentIdentity:
    """A managed agent identity and its lifecycle state."""

    identity_id: str
    agent_id: str
    tenant_id: str
    token_hash: str
    token_prefix: str
    role: str
    blueprint_id: str
    status: str  # active | rotating | revoked | expired
    issued_at: str
    expires_at: str
    # Per-tool scope allowlist. Empty = the identity may call any tool the
    # policy permits; non-empty = the identity is bounded to these tool names
    # ("*" allows all). Enforced at the gateway/proxy decision point so the
    # identity itself constrains authorization, not just the policy.
    allowed_tools: list[str] = field(default_factory=list)
    # Accountable owner of this ISSUED identity — the human / team / service that
    # provisioned it and is answerable for it. New identities are always
    # owner-bound at issue time (the issuing actor when no explicit owner is
    # given), so an agent-bom-issued identity carries the same attribution as a
    # discovered cloud NHI. Empty only for rows persisted before owner-binding
    # existed; ``owner_type`` is advisory (user | team | service).
    #
    # Migration: persisted JSON rows written before this field existed simply
    # lack the key and deserialize back to "" (no schema change needed — the
    # SQLite/Postgres stores keep the full dataclass as JSON ``data``).
    owner: str = ""
    owner_type: str = ""
    rotated_to_id: str = ""
    revoked_at: str = ""
    revoked_reason: str = ""
    # Last observed authentication time for this identity (ISO-8601, injected by
    # the runtime verifier). Drives dormant auto-deprovision; empty means the
    # identity has never been observed authenticating.
    last_used_at: str = ""
    # Advisory rotation flag. The cleanup loop sets this True when the token's
    # age exceeds the configured rotation window; the secret is never rotated
    # silently — an operator/automation rotates it explicitly via rotate_identity.
    rotation_due: bool = False
    rotation_due_at: str = ""
    # Per-identity quota DATA. These are surfaced via ``quota_state`` for the
    # gateway to enforce in a later PR; this store records them but does not
    # itself meter requests. 0 / unset means "no limit".
    max_requests_per_window: int = 0
    max_cost_usd_per_window: float = 0.0
    quota_window_seconds: int = 0

    def tool_allowed(self, tool_name: str) -> bool:
        """True when this identity may call ``tool_name`` (empty allowlist = any)."""
        if not self.allowed_tools:
            return True
        return "*" in self.allowed_tools or tool_name in self.allowed_tools

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize without the token hash."""
        d = asdict(self)
        d.pop("token_hash", None)
        return d

    def is_live(self, *, at: datetime | None = None) -> bool:
        """True when the identity may still authenticate (active or in rotation
        overlap, and not past expiry)."""
        if self.status in ("revoked", "expired"):
            return False
        now = at or _now()
        try:
            if self.expires_at and now > datetime.fromisoformat(self.expires_at):
                return False
        except ValueError:
            return False
        return self.status in ("active", "rotating")


class AgentIdentityStore(Protocol):
    def put(self, identity: AgentIdentity) -> None: ...

    def get(self, identity_id: str, *, tenant_id: str) -> AgentIdentity | None: ...

    def get_by_token_hash(self, token_hash: str) -> AgentIdentity | None: ...

    def list(self, tenant_id: str, *, include_inactive: bool = False, limit: int = 200) -> list[AgentIdentity]: ...

    def count(self, tenant_id: str, *, include_inactive: bool = False) -> int: ...

    def list_by_agent(self, tenant_id: str, agent_id: str, *, limit: int = 200) -> builtins.list[AgentIdentity]: ...

    def put_jit_grant(self, grant: AgentJITGrant, *, tenant_id: str) -> None: ...

    def get_jit_grant(self, grant_id: str, *, tenant_id: str) -> AgentJITGrant | None: ...

    def list_jit_grants(
        self,
        tenant_id: str,
        *,
        identity_id: str | None = None,
        include_inactive: bool = False,
        limit: int = 200,
    ) -> builtins.list[AgentJITGrant]: ...

    def active_jit_grant(
        self,
        tenant_id: str,
        identity_id: str,
        tool_name: str,
        *,
        at: datetime | None = None,
    ) -> AgentJITGrant | None: ...

    def iter_all_identities(self, *, limit: int = 10000) -> builtins.list[AgentIdentity]: ...

    def iter_all_jit_grants(self, *, limit: int = 10000) -> builtins.list[AgentJITGrant]: ...

    def put_conditional_policy(self, policy: ConditionalAccessPolicy, *, tenant_id: str) -> None: ...

    def get_conditional_policy(self, policy_id: str, *, tenant_id: str) -> ConditionalAccessPolicy | None: ...

    def list_conditional_policies(
        self,
        tenant_id: str,
        *,
        include_disabled: bool = False,
        limit: int = 200,
    ) -> builtins.list[ConditionalAccessPolicy]: ...


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}  # nosec B608 - table is static


class InMemoryAgentIdentityStore:
    def __init__(self) -> None:
        self._by_id: dict[str, AgentIdentity] = {}
        self._by_hash: dict[str, str] = {}
        self._jit_by_id: dict[str, AgentJITGrant] = {}
        self._cond_by_id: dict[str, ConditionalAccessPolicy] = {}
        self._lock = threading.Lock()

    def put(self, identity: AgentIdentity) -> None:
        with self._lock:
            self._by_id[identity.identity_id] = identity
            self._by_hash[identity.token_hash] = identity.identity_id

    def get(self, identity_id: str, *, tenant_id: str) -> AgentIdentity | None:
        with self._lock:
            identity = self._by_id.get(identity_id)
            if identity is None or identity.tenant_id != tenant_id:
                return None
            return identity

    def get_by_token_hash(self, token_hash: str) -> AgentIdentity | None:
        with self._lock:
            iid = self._by_hash.get(token_hash)
            return self._by_id.get(iid) if iid else None

    def list(self, tenant_id: str, *, include_inactive: bool = False, limit: int = 200) -> list[AgentIdentity]:
        with self._lock:
            rows = [
                i for i in self._by_id.values() if i.tenant_id == tenant_id and (include_inactive or i.status in ("active", "rotating"))
            ]
            return sorted(rows, key=lambda i: i.issued_at, reverse=True)[:limit]

    def count(self, tenant_id: str, *, include_inactive: bool = False) -> int:
        """Count records without list pagination; lifecycle status is not authority."""
        with self._lock:
            return sum(
                identity.tenant_id == tenant_id and (include_inactive or identity.status in ("active", "rotating"))
                for identity in self._by_id.values()
            )

    def list_by_agent(self, tenant_id: str, agent_id: str, *, limit: int = 200) -> builtins.list[AgentIdentity]:
        with self._lock:
            rows = [i for i in self._by_id.values() if i.tenant_id == tenant_id and (i.agent_id or "").strip() == agent_id]
            return sorted(rows, key=lambda i: i.issued_at, reverse=True)[:limit]

    def put_jit_grant(self, grant: AgentJITGrant, *, tenant_id: str) -> None:
        tenant = require_grant_tenant(grant, tenant_id)
        with self._lock:
            previous = self._jit_by_id.get(grant.grant_id)
            if previous is not None and previous.tenant_id != tenant:
                raise ValueError("JIT grant identity belongs to another tenant")
            self._jit_by_id[grant.grant_id] = replace(grant)

    def get_jit_grant(self, grant_id: str, *, tenant_id: str) -> AgentJITGrant | None:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._lock:
            grant = self._jit_by_id.get(grant_id)
            return replace(grant) if grant is not None and grant.tenant_id == tenant else None

    def list_jit_grants(
        self,
        tenant_id: str,
        *,
        identity_id: str | None = None,
        include_inactive: bool = False,
        limit: int = 200,
    ) -> builtins.list[AgentJITGrant]:
        with self._lock:
            rows = [g for g in self._jit_by_id.values() if g.tenant_id == tenant_id]
            if identity_id is not None:
                rows = [g for g in rows if g.identity_id == identity_id]
            if not include_inactive:
                rows = [g for g in rows if g.is_live()]
            return [replace(g) for g in sorted(rows, key=lambda g: g.requested_at, reverse=True)[:limit]]

    def active_jit_grant(
        self,
        tenant_id: str,
        identity_id: str,
        tool_name: str,
        *,
        at: datetime | None = None,
    ) -> AgentJITGrant | None:
        with self._lock:
            candidates = [
                g
                for g in self._jit_by_id.values()
                if g.tenant_id == tenant_id and g.identity_id == identity_id and g.tool_name == tool_name and g.is_live(at=at)
            ]
            return replace(sorted(candidates, key=lambda g: g.expires_at, reverse=True)[0]) if candidates else None

    def iter_all_identities(self, *, limit: int = 10000) -> builtins.list[AgentIdentity]:
        with self._lock:
            return list(self._by_id.values())[:limit]

    def iter_all_jit_grants(self, *, limit: int = 10000) -> builtins.list[AgentJITGrant]:
        with self._lock:
            return [replace(g) for g in list(self._jit_by_id.values())[:limit]]

    def put_conditional_policy(self, policy: ConditionalAccessPolicy, *, tenant_id: str) -> None:
        tenant = require_policy_tenant(policy, tenant_id)
        with self._lock:
            current = self._cond_by_id.get(policy.policy_id)
            if current is not None and current.tenant_id != tenant:
                raise ValueError("Conditional policy identity belongs to another tenant")
            self._cond_by_id[policy.policy_id] = deepcopy(policy)

    def get_conditional_policy(self, policy_id: str, *, tenant_id: str) -> ConditionalAccessPolicy | None:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._lock:
            policy = self._cond_by_id.get(policy_id)
            return deepcopy(policy) if policy is not None and policy.tenant_id == tenant else None

    def list_conditional_policies(
        self,
        tenant_id: str,
        *,
        include_disabled: bool = False,
        limit: int = 200,
    ) -> builtins.list[ConditionalAccessPolicy]:
        tenant_id = require_explicit_tenant_id(tenant_id)
        with self._lock:
            rows = [p for p in self._cond_by_id.values() if p.tenant_id == tenant_id]
            if not include_disabled:
                rows = [p for p in rows if p.status == "active"]
            return deepcopy(sorted(rows, key=lambda p: (p.priority, p.created_at))[:limit])


class SQLiteAgentIdentityStore:
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

    def _init_db(self) -> None:
        ensure_sqlite_schema_version(self._conn, "agent_identities", version=2)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_identities (
                identity_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                agent_id TEXT NOT NULL DEFAULT '',
                data TEXT NOT NULL
            )
            """
        )
        # Revocation is looked up per agent, not per tenant. Without this column
        # the check had to page the tenant's whole roster and could miss an old
        # revoked row behind the page cap.
        if "agent_id" not in _table_columns(self._conn, "agent_identities"):
            self._conn.execute("ALTER TABLE agent_identities ADD COLUMN agent_id TEXT NOT NULL DEFAULT ''")
            self._backfill_agent_ids()
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_identities_tenant ON agent_identities(tenant_id, status)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_identities_hash ON agent_identities(token_hash)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_identities_agent ON agent_identities(tenant_id, agent_id)")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_identity_jit_grants (
                grant_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                identity_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                status TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                data TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_agent_identity_jit_lookup "
            "ON agent_identity_jit_grants(tenant_id, identity_id, tool_name, status, expires_at)"
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_conditional_access_policies (
                policy_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                status TEXT NOT NULL,
                priority INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                data TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_agent_conditional_access_tenant "
            "ON agent_conditional_access_policies(tenant_id, status, priority)"
        )
        self._conn.commit()

    def _backfill_agent_ids(self) -> None:
        rows = self._conn.execute("SELECT identity_id, data FROM agent_identities WHERE agent_id = ''").fetchall()
        for identity_id, data in rows:
            try:
                agent_id = str(json.loads(data).get("agent_id") or "").strip()
            except (json.JSONDecodeError, AttributeError):
                continue
            if agent_id:
                self._conn.execute(
                    "UPDATE agent_identities SET agent_id = ? WHERE identity_id = ?",
                    (agent_id, identity_id),
                )

    def put(self, identity: AgentIdentity) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO agent_identities "
            "(identity_id, tenant_id, token_hash, status, issued_at, agent_id, data) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                identity.identity_id,
                identity.tenant_id,
                identity.token_hash,
                identity.status,
                identity.issued_at,
                (identity.agent_id or "").strip(),
                json.dumps(asdict(identity), sort_keys=True),
            ),
        )
        self._conn.commit()

    def get(self, identity_id: str, *, tenant_id: str) -> AgentIdentity | None:
        row = self._conn.execute(
            "SELECT data FROM agent_identities WHERE identity_id = ? AND tenant_id = ?",
            (identity_id, tenant_id),
        ).fetchone()
        return AgentIdentity(**json.loads(row[0])) if row else None

    def get_by_token_hash(self, token_hash: str) -> AgentIdentity | None:
        row = self._conn.execute("SELECT data FROM agent_identities WHERE token_hash = ?", (token_hash,)).fetchone()
        return AgentIdentity(**json.loads(row[0])) if row else None

    def list(self, tenant_id: str, *, include_inactive: bool = False, limit: int = 200) -> list[AgentIdentity]:
        if include_inactive:
            rows = self._conn.execute(
                "SELECT data FROM agent_identities WHERE tenant_id = ? ORDER BY issued_at DESC LIMIT ?", (tenant_id, limit)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM agent_identities WHERE tenant_id = ? AND status IN ('active', 'rotating') "
                "ORDER BY issued_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [AgentIdentity(**json.loads(r[0])) for r in rows]

    def count(self, tenant_id: str, *, include_inactive: bool = False) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM agent_identities WHERE tenant_id = ? AND (? OR status IN ('active', 'rotating'))",
            (tenant_id, include_inactive),
        ).fetchone()
        return int(row[0])

    def list_by_agent(self, tenant_id: str, agent_id: str, *, limit: int = 200) -> builtins.list[AgentIdentity]:
        rows = self._conn.execute(
            "SELECT data FROM agent_identities WHERE tenant_id = ? AND agent_id = ? ORDER BY issued_at DESC LIMIT ?",
            (tenant_id, agent_id, limit),
        ).fetchall()
        return [AgentIdentity(**json.loads(r[0])) for r in rows]

    def put_jit_grant(self, grant: AgentJITGrant, *, tenant_id: str) -> None:
        tenant = require_grant_tenant(grant, tenant_id)
        with self._conn:
            cursor = self._conn.execute(
                "INSERT INTO agent_identity_jit_grants "
                "(grant_id, tenant_id, identity_id, tool_name, status, requested_at, expires_at, data) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (grant_id) DO UPDATE SET "
                "identity_id = excluded.identity_id, tool_name = excluded.tool_name, requested_at = excluded.requested_at, "
                "status = excluded.status, expires_at = excluded.expires_at, data = excluded.data "
                "WHERE agent_identity_jit_grants.tenant_id = excluded.tenant_id",
                (
                    grant.grant_id,
                    tenant,
                    grant.identity_id,
                    grant.tool_name,
                    grant.status,
                    grant.requested_at,
                    grant.expires_at,
                    json.dumps(asdict(grant), sort_keys=True),
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("JIT grant identity belongs to another tenant")

    def get_jit_grant(self, grant_id: str, *, tenant_id: str) -> AgentJITGrant | None:
        tenant = require_explicit_tenant_id(tenant_id)
        row = self._conn.execute(
            "SELECT data FROM agent_identity_jit_grants WHERE grant_id = ? AND tenant_id = ?", (grant_id, tenant)
        ).fetchone()
        grant = AgentJITGrant(**json.loads(row[0])) if row else None
        if grant is not None:
            require_grant_tenant(grant, tenant)
            if grant.grant_id != grant_id:
                raise ValueError("JIT grant record identity does not match")
        return grant

    def list_jit_grants(
        self,
        tenant_id: str,
        *,
        identity_id: str | None = None,
        include_inactive: bool = False,
        limit: int = 200,
    ) -> builtins.list[AgentJITGrant]:
        if identity_id is not None:
            rows = self._conn.execute(
                "SELECT data FROM agent_identity_jit_grants WHERE tenant_id = ? AND identity_id = ? ORDER BY requested_at DESC LIMIT ?",
                (tenant_id, identity_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM agent_identity_jit_grants WHERE tenant_id = ? ORDER BY requested_at DESC LIMIT ?",
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
        rows = self._conn.execute(
            "SELECT data FROM agent_identity_jit_grants "
            "WHERE tenant_id = ? AND identity_id = ? AND tool_name = ? AND status = 'active' "
            "ORDER BY expires_at DESC LIMIT 20",
            (tenant_id, identity_id, tool_name),
        ).fetchall()
        grants = [AgentJITGrant(**json.loads(r[0])) for r in rows]
        live = [g for g in grants if g.is_live(at=at)]
        return live[0] if live else None

    def iter_all_identities(self, *, limit: int = 10000) -> builtins.list[AgentIdentity]:
        rows = self._conn.execute("SELECT data FROM agent_identities ORDER BY issued_at ASC LIMIT ?", (limit,)).fetchall()
        return [AgentIdentity(**json.loads(r[0])) for r in rows]

    def iter_all_jit_grants(self, *, limit: int = 10000) -> builtins.list[AgentJITGrant]:
        rows = self._conn.execute("SELECT data FROM agent_identity_jit_grants ORDER BY requested_at ASC LIMIT ?", (limit,)).fetchall()
        return [AgentJITGrant(**json.loads(r[0])) for r in rows]

    def put_conditional_policy(self, policy: ConditionalAccessPolicy, *, tenant_id: str) -> None:
        tenant = require_policy_tenant(policy, tenant_id)
        with self._conn:
            cursor = self._conn.execute(
                "INSERT INTO agent_conditional_access_policies "
                "(policy_id, tenant_id, status, priority, created_at, data) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (policy_id) DO UPDATE SET status = excluded.status, priority = excluded.priority, "
                "created_at = excluded.created_at, data = excluded.data "
                "WHERE agent_conditional_access_policies.tenant_id = excluded.tenant_id",
                (
                    policy.policy_id,
                    tenant,
                    policy.status,
                    int(policy.priority),
                    policy.created_at,
                    json.dumps(asdict(policy), sort_keys=True),
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("Conditional policy identity belongs to another tenant")

    def get_conditional_policy(self, policy_id: str, *, tenant_id: str) -> ConditionalAccessPolicy | None:
        tenant = require_explicit_tenant_id(tenant_id)
        row = self._conn.execute(
            "SELECT data FROM agent_conditional_access_policies WHERE policy_id = ? AND tenant_id = ?", (policy_id, tenant)
        ).fetchone()
        policy = ConditionalAccessPolicy(**json.loads(row[0])) if row else None
        if policy is not None:
            require_policy_tenant(policy, tenant)
            if policy.policy_id != policy_id:
                raise ValueError("Conditional policy record identity does not match")
        return policy

    def list_conditional_policies(
        self,
        tenant_id: str,
        *,
        include_disabled: bool = False,
        limit: int = 200,
    ) -> builtins.list[ConditionalAccessPolicy]:
        tenant_id = require_explicit_tenant_id(tenant_id)
        if include_disabled:
            rows = self._conn.execute(
                "SELECT data FROM agent_conditional_access_policies WHERE tenant_id = ? ORDER BY priority ASC, created_at ASC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM agent_conditional_access_policies WHERE tenant_id = ? AND status = 'active' "
                "ORDER BY priority ASC, created_at ASC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [ConditionalAccessPolicy(**json.loads(r[0])) for r in rows]


# ── Lifecycle operations ────────────────────────────────────────────────────────


def issue_identity(
    store: AgentIdentityStore,
    *,
    agent_id: str,
    tenant_id: str,
    role: str = "agent",
    blueprint_id: str = "",
    ttl_seconds: int = 90 * 86400,
    allowed_tools: list[str] | None = None,
    owner: str = "",
    owner_type: str = "",
) -> tuple[AgentIdentity, str]:
    """Issue a new identity. Returns ``(identity, raw_token)``; the raw token is
    only available here and at rotation.

    ``owner`` records the accountable principal (human / team / service) for the
    issued identity and is preserved across rotation; pass it so the identity is
    owner-bound at birth rather than orphaned.
    """
    raw, prefix, token_hash = generate_token()
    now = _now()
    identity = AgentIdentity(
        identity_id=f"id_{secrets.token_hex(8)}",
        agent_id=agent_id,
        tenant_id=tenant_id,
        token_hash=token_hash,
        token_prefix=prefix,
        role=role,
        blueprint_id=blueprint_id,
        status="active",
        issued_at=_iso(now),
        expires_at=_ttl_to_expiry(ttl_seconds, at=now),
        allowed_tools=list(allowed_tools or []),
        owner=str(owner or "").strip()[:200],
        owner_type=str(owner_type or "").strip()[:60],
    )
    store.put(identity)
    return identity, raw


def identity_for_token(store: AgentIdentityStore, token: str) -> AgentIdentity | None:
    """Resolve a raw token to its live managed identity, or None.

    Used by the runtime relay to enforce per-tool scopes; returns None for
    unknown or non-live (revoked/expired) tokens.
    """
    identity = store.get_by_token_hash(hash_token(token))
    if identity is None or not identity.is_live():
        return None
    return identity


def rotate_identity(
    store: AgentIdentityStore,
    identity_id: str,
    *,
    tenant_id: str,
    overlap_seconds: int = 3600,
    ttl_seconds: int = 90 * 86400,
) -> tuple[AgentIdentity, str] | None:
    """Issue a replacement identity and keep the old one live for ``overlap_seconds``
    so in-flight callers are not cut off. Returns ``(new_identity, raw_token)``."""
    old = store.get(identity_id, tenant_id=tenant_id)
    # Don't rotate a revoked identity, or one already mid-rotation (that would
    # orphan the first replacement and break the rotated_to chain).
    if old is None or old.status in ("revoked", "rotating"):
        return None
    new_identity, raw = issue_identity(
        store,
        agent_id=old.agent_id,
        tenant_id=old.tenant_id,
        role=old.role,
        blueprint_id=old.blueprint_id,
        ttl_seconds=ttl_seconds,
        allowed_tools=old.allowed_tools,
        owner=old.owner,
        owner_type=old.owner_type,
    )
    now = _now()
    old.status = "rotating"
    old.rotated_to_id = new_identity.identity_id
    old.expires_at = _ttl_to_expiry(overlap_seconds, at=now)
    store.put(old)
    return new_identity, raw


def revoke_identity(store: AgentIdentityStore, identity_id: str, *, tenant_id: str, reason: str = "") -> AgentIdentity | None:
    """Immediately revoke an identity; it can no longer authenticate."""
    identity = store.get(identity_id, tenant_id=tenant_id)
    if identity is None:
        return None
    identity.status = "revoked"
    identity.revoked_at = _iso(_now())
    identity.revoked_reason = reason[:500]
    store.put(identity)
    return identity


# Upper bound on identities fetched per revocation check. The agent-keyed
# lookup bounds one agent's own rotation history, which no deployment approaches,
# so the cap is not reachable in practice. A store that predates
# ``list_by_agent`` still has to page the tenant roster by recency; there the cap
# IS reachable, and hitting it means an older revoked row may sit in the
# untraversed tail. That case reports the lookup as incomplete — an honest
# partial signal the caller fails closed on — rather than a confident "not
# revoked". Mirrors ``_DRIFT_INCIDENT_LOOKUP_CAP`` in the gateway.
_IDENTITY_LOOKUP_CAP = 5000


def identities_for_agent(store: AgentIdentityStore, tenant_id: str, agent_id: str) -> tuple[list[AgentIdentity], bool]:
    """Return ``(identities_for_agent, lookup_was_incomplete)`` for one tenant.

    Reads the agent's own identities through an indexed lookup so the tenant's
    roster size cannot hide a revoked row. Falls back to the recency-capped
    roster scan only for a store that does not implement ``list_by_agent``.
    """
    key = (agent_id or "").strip()
    if not key:
        return [], False
    by_agent = getattr(store, "list_by_agent", None)
    if by_agent is not None:
        rows = by_agent(tenant_id, key, limit=_IDENTITY_LOOKUP_CAP)
        return [i for i in rows if (i.agent_id or "").strip() == key], False
    rows = store.list(tenant_id, include_inactive=True, limit=_IDENTITY_LOOKUP_CAP)
    capped = len(rows) >= _IDENTITY_LOOKUP_CAP
    return [i for i in rows if (i.agent_id or "").strip() == key], capped


def live_identity_for_agent(store: AgentIdentityStore, tenant_id: str, agent_id: str) -> AgentIdentity | None:
    """Return one live identity for ``agent_id``, or ``None`` if every one is dead.

    ``identity_for_token`` resolves by token hash, which only matches an
    agent-bom-issued ``abi_`` token. A caller presenting a JWKS/OIDC JWT or an
    opaque ``policy.agent_tokens`` mapping never reaches the identity store, so
    the gateway needs an agent-keyed lookup to honour revocation for them too.
    """
    identities, _capped = identities_for_agent(store, tenant_id, agent_id)
    for identity in identities:
        if identity.is_live():
            return identity
    return None


def agent_identity_revoked(store: AgentIdentityStore, tenant_id: str, agent_id: str) -> tuple[bool, bool]:
    """Return ``(revoked, lookup_incomplete)`` for ``agent_id`` in one tenant.

    An agent with no managed identity at all is *not* revoked — deployments that
    never issued one must keep working. Rotation also leaves revoked rows behind,
    so a single live identity is enough to keep the agent alive.

    ``lookup_incomplete`` is True when the roster hit the lookup cap and this
    agent had no matching identity: absence is then unproven, not evidence of
    absence, and the caller must not read it as "authorized".
    """
    identities, capped = identities_for_agent(store, tenant_id, agent_id)
    if not identities:
        return False, capped
    return not any(i.is_live() for i in identities), False


def active_jit_grant_for_tool(
    store: AgentIdentityStore,
    *,
    tenant_id: str,
    identity_id: str,
    tool_name: str,
    at: datetime | None = None,
) -> AgentJITGrant | None:
    return store.active_jit_grant(tenant_id, identity_id, tool_name, at=at)


# ── Lifecycle-enforcement sweeps (driven by the API cleanup loop) ─────────────
#
# These transition lingering JIT grants and dormant agent-bom identities to a
# terminal state and surface rotation-due tokens, emitting one append-only,
# hash-chained governance-audit record per action. Every function:
#   • takes an INJECTED ``now`` (never calls datetime.now itself) so results are
#     deterministic and consistent across replicas,
#   • derives a DETERMINISTIC action id from stable target state (so a re-run
#     over identical state produces no duplicate audit row and no double
#     transition — idempotent), and
#   • catches store/DB errors per-row and continues, so a single bad record or a
#     backend hiccup never aborts the sweep (fail-open for cleanup).

_lifecycle_logger = logging.getLogger("agent_bom.api.nhi_lifecycle")

# Quotas/rotation defaults. 0 = disabled for the deprovision window so dormant
# auto-revoke is strictly opt-in; rotation defaults to a 90-day advisory flag.
DEFAULT_TOKEN_ROTATION_DAYS = 90


def _env_int(name: str, default: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        parsed = int(raw)
    except ValueError:
        return default
    return parsed if parsed >= 0 else default


def nhi_deprovision_days() -> int:
    """Dormant agent-identity auto-deprovision window in days.

    Default 0 = DISABLED (opt-in). Operators set
    ``AGENT_BOM_NHI_DEPROVISION_DAYS`` to a positive value to enable automatic
    revocation of agent-bom's own dormant identities. Cloud NHIs are never
    written to — this governs issued ``abi_`` identities only.
    """
    return _env_int("AGENT_BOM_NHI_DEPROVISION_DAYS", 0)


def token_rotation_days() -> int:
    """Token age (days) beyond which an identity is flagged ``rotation_due``."""
    return _env_int("AGENT_BOM_TOKEN_ROTATION_DAYS", DEFAULT_TOKEN_ROTATION_DAYS)


def quota_state(identity: AgentIdentity) -> dict[str, Any]:
    """Return the per-identity quota envelope the gateway will later enforce.

    Pure DATA getter: it reports the configured limits and whether any are set,
    but does not meter usage — request/cost accounting lives in the gateway
    (separate PR). ``enforced`` is True when at least one positive limit exists.
    """
    max_requests = max(0, int(identity.max_requests_per_window or 0))
    max_cost = max(0.0, float(identity.max_cost_usd_per_window or 0.0))
    window = max(0, int(identity.quota_window_seconds or 0))
    return {
        "identity_id": identity.identity_id,
        "tenant_id": identity.tenant_id,
        "max_requests_per_window": max_requests,
        "max_cost_usd_per_window": max_cost,
        "window_seconds": window,
        "enforced": bool((max_requests or max_cost) and window),
    }


def set_identity_quota(
    store: AgentIdentityStore,
    identity_id: str,
    *,
    tenant_id: str,
    max_requests_per_window: int = 0,
    max_cost_usd_per_window: float = 0.0,
    window_seconds: int = 0,
) -> AgentIdentity | None:
    """Record per-identity quota limits (data only; gateway enforces later)."""
    identity = store.get(identity_id, tenant_id=tenant_id)
    if identity is None:
        return None
    identity.max_requests_per_window = max(0, int(max_requests_per_window))
    identity.max_cost_usd_per_window = max(0.0, float(max_cost_usd_per_window))
    identity.quota_window_seconds = max(0, int(window_seconds))
    store.put(identity)
    return identity


def _is_postgres_store(store: AgentIdentityStore) -> bool:
    return type(store).__name__ == "PostgresAgentIdentityStore"


def _put_identity_any_tenant(store: AgentIdentityStore, identity: AgentIdentity) -> None:
    """Persist an identity write that may target a non-ambient tenant.

    The cleanup loop sweeps every tenant, so a write-back for tenant X must
    satisfy that tenant's RLS WITH CHECK. For Postgres we bind X explicitly and
    keep the write on the ordinary app connection; other backends ignore
    tenant scoping on write.
    """
    if _is_postgres_store(store):
        from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

        token = set_current_tenant(identity.tenant_id)
        try:
            store.put(identity)
        finally:
            reset_current_tenant(token)
        return
    store.put(identity)


def _put_grant_any_tenant(store: AgentIdentityStore, grant: AgentJITGrant) -> None:
    if _is_postgres_store(store):
        from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

        token = set_current_tenant(grant.tenant_id)
        try:
            store.put_jit_grant(grant, tenant_id=grant.tenant_id)
        finally:
            reset_current_tenant(token)
        return
    store.put_jit_grant(grant, tenant_id=grant.tenant_id)


def _export_audit_to_otlp(record: Any) -> None:
    """Fire-and-forget OTLP-log export of a sealed audit record.

    Batched + non-blocking (the OTLP batch processor flushes off-thread) and a
    strict no-op unless ``AGENT_BOM_OTEL_LOGS_ENDPOINT`` is configured, so the
    cleanup loop is never blocked or aborted by observability export.
    """
    try:
        from agent_bom.siem.otlp_logs import export_governance_audit_record

        export_governance_audit_record(record)
    except Exception:  # noqa: BLE001 — export must never abort cleanup
        _lifecycle_logger.debug("governance audit OTLP export skipped", exc_info=False)


def _emit_audit(record_kwargs: dict[str, Any], audit_log: Any) -> None:
    """Append one governance-audit record, tolerating a sink failure."""
    if audit_log is None:
        return
    try:
        from agent_bom.api.governance_audit_log import make_governance_audit_record

        record = make_governance_audit_record(**record_kwargs)
        sealed = audit_log.append(record)
        _export_audit_to_otlp(sealed)
    except Exception:  # noqa: BLE001 — an audit-sink hiccup must not abort cleanup
        _lifecycle_logger.warning(
            "governance audit append failed for action=%s target=%s; "
            "check the governance_audit_log backend (SQLite path writable / disk space)",
            record_kwargs.get("action"),
            record_kwargs.get("target_id"),
            exc_info=False,
        )


def cleanup_expired_grants(
    store: AgentIdentityStore,
    *,
    now: datetime,
    audit_log: Any = None,
    actor: str = "system:nhi-cleanup",
    limit: int = 10000,
) -> dict[str, int]:
    """Transition expired ``active`` and lingering ``denied`` JIT grants to terminal.

    An ``active`` grant whose ``expires_at`` has passed becomes ``revoked`` with
    reason ``expired``; a ``denied`` grant becomes ``revoked`` (pruned) so it no
    longer lingers in the active set. The transition is idempotent: a grant
    already ``revoked`` is skipped, and the audit id is derived from the grant id
    + its terminal timestamp, so a second sweep over the same state writes no new
    rows. Never raises; per-grant errors are logged and skipped.
    """
    expired = pruned = errors = 0
    try:
        grants = store.iter_all_jit_grants(limit=limit)
    except Exception:  # noqa: BLE001
        _lifecycle_logger.warning(
            "JIT-grant cleanup could not list grants; the identity store may be "
            "unreachable (check AGENT_BOM_POSTGRES_URL / DB connectivity). Skipping this tick.",
            exc_info=False,
        )
        return {"expired": 0, "pruned": 0, "errors": 1}

    for grant in grants:
        try:
            if grant.status == "active" and grant.expires_at and now > datetime.fromisoformat(grant.expires_at):
                before = grant.status
                grant.status = "revoked"
                grant.revoked_at = _iso(now)
                grant.revoked_reason = "expired"
                _put_grant_any_tenant(store, grant)
                expired += 1
                _emit_audit(
                    {
                        "tenant_id": grant.tenant_id,
                        "actor": actor,
                        "action": "jit_grant_expired",
                        "target_type": "jit_grant",
                        "target_id": grant.grant_id,
                        "reason": "expired",
                        "before_state": before,
                        "after_state": "revoked",
                        "observed_at": _iso(now),
                        "window_key": grant.expires_at,
                        "detail": {"identity_id": grant.identity_id, "tool_name": grant.tool_name},
                    },
                    audit_log,
                )
            elif grant.status == "denied":
                before = grant.status
                window_key = grant.denied_at or grant.requested_at
                grant.status = "revoked"
                grant.revoked_at = _iso(now)
                grant.revoked_reason = "denied_pruned"
                _put_grant_any_tenant(store, grant)
                pruned += 1
                _emit_audit(
                    {
                        "tenant_id": grant.tenant_id,
                        "actor": actor,
                        "action": "jit_grant_denied_pruned",
                        "target_type": "jit_grant",
                        "target_id": grant.grant_id,
                        "reason": "denied_pruned",
                        "before_state": before,
                        "after_state": "revoked",
                        "observed_at": _iso(now),
                        "window_key": window_key,
                        "detail": {"identity_id": grant.identity_id, "tool_name": grant.tool_name},
                    },
                    audit_log,
                )
        except (ValueError, TypeError):
            errors += 1
            _lifecycle_logger.warning("skipping JIT grant %s with unparseable timestamps", grant.grant_id)
        except Exception:  # noqa: BLE001 — one bad write must not abort the sweep
            errors += 1
            _lifecycle_logger.warning("failed to clean up JIT grant %s; continuing", grant.grant_id, exc_info=False)

    return {"expired": expired, "pruned": pruned, "errors": errors}


def deprovision_dormant_identities(
    store: AgentIdentityStore,
    *,
    now: datetime,
    dormant_days: int | None = None,
    audit_log: Any = None,
    actor: str = "system:nhi-cleanup",
    limit: int = 10000,
) -> dict[str, int]:
    """Revoke agent-bom's OWN identities dormant beyond the configured window.

    DISABLED by default (``dormant_days`` 0 / ``AGENT_BOM_NHI_DEPROVISION_DAYS``
    unset): operators opt in. Only ``active``/``rotating`` issued identities with
    a ``last_used_at`` older than the window are revoked, with reason
    ``dormant_auto_revoke``. Cloud principals are not touched — this store only
    holds agent-bom-issued identities. Idempotent + injected ``now``; never
    raises into the loop.
    """
    window = dormant_days if dormant_days is not None else nhi_deprovision_days()
    if window <= 0:
        return {"revoked": 0, "errors": 0, "disabled": 1}

    revoked = errors = 0
    try:
        identities = store.iter_all_identities(limit=limit)
    except Exception:  # noqa: BLE001
        _lifecycle_logger.warning(
            "dormant-identity sweep could not list identities; the identity store may be "
            "unreachable (check DB connectivity). Skipping this tick.",
            exc_info=False,
        )
        return {"revoked": 0, "errors": 1, "disabled": 0}

    for identity in identities:
        try:
            if identity.status not in ("active", "rotating"):
                continue
            last_used = identity.last_used_at.strip() if identity.last_used_at else ""
            if not last_used:
                # Never-observed identities are not auto-revoked here: lack of a
                # usage marker can mean a freshly issued token, not dormancy. The
                # graph governance overlay still surfaces them as findings.
                continue
            last_used_dt = datetime.fromisoformat(last_used)
            age_days = (now - last_used_dt).total_seconds() / 86400.0
            if age_days < window:
                continue
            before = identity.status
            identity.status = "revoked"
            identity.revoked_at = _iso(now)
            identity.revoked_reason = "dormant_auto_revoke"
            _put_identity_any_tenant(store, identity)
            revoked += 1
            _emit_audit(
                {
                    "tenant_id": identity.tenant_id,
                    "actor": actor,
                    "action": "identity_dormant_auto_revoke",
                    "target_type": "agent_identity",
                    "target_id": identity.identity_id,
                    "reason": "dormant_auto_revoke",
                    "before_state": before,
                    "after_state": "revoked",
                    "observed_at": _iso(now),
                    "window_key": identity.revoked_at,
                    "detail": {
                        "agent_id": identity.agent_id,
                        "owner": identity.owner,
                        "owner_type": identity.owner_type,
                        "last_used_at": last_used,
                        "window_days": window,
                    },
                },
                audit_log,
            )
        except (ValueError, TypeError):
            errors += 1
            _lifecycle_logger.warning("skipping identity %s with unparseable last_used_at", identity.identity_id)
        except Exception:  # noqa: BLE001
            errors += 1
            _lifecycle_logger.warning("failed to deprovision identity %s; continuing", identity.identity_id, exc_info=False)

    return {"revoked": revoked, "errors": errors, "disabled": 0}


def flag_rotation_due_identities(
    store: AgentIdentityStore,
    *,
    now: datetime,
    rotation_days: int | None = None,
    audit_log: Any = None,
    actor: str = "system:nhi-cleanup",
    limit: int = 10000,
) -> dict[str, int]:
    """Advisory: flag identities whose token age exceeds the rotation window.

    Sets ``rotation_due=True`` (and ``rotation_due_at``) on live identities whose
    ``issued_at`` is older than the window. The secret is NOT rotated — an
    operator/automation rotates it explicitly. Idempotent: an identity already
    flagged is skipped (no second audit row); injected ``now``; never raises.
    """
    window = rotation_days if rotation_days is not None else token_rotation_days()
    flagged = errors = 0
    if window <= 0:
        return {"flagged": 0, "errors": 0}
    try:
        identities = store.iter_all_identities(limit=limit)
    except Exception:  # noqa: BLE001
        _lifecycle_logger.warning(
            "rotation-due sweep could not list identities; the identity store may be unreachable. Skipping this tick.",
            exc_info=False,
        )
        return {"flagged": 0, "errors": 1}

    for identity in identities:
        try:
            if identity.status not in ("active", "rotating") or identity.rotation_due:
                continue
            if not identity.issued_at:
                continue
            issued_dt = datetime.fromisoformat(identity.issued_at)
            age_days = (now - issued_dt).total_seconds() / 86400.0
            if age_days < window:
                continue
            identity.rotation_due = True
            identity.rotation_due_at = _iso(now)
            _put_identity_any_tenant(store, identity)
            flagged += 1
            _emit_audit(
                {
                    "tenant_id": identity.tenant_id,
                    "actor": actor,
                    "action": "token_rotation_due",
                    "target_type": "agent_identity",
                    "target_id": identity.identity_id,
                    "reason": f"token age exceeds {window}d rotation window",
                    "before_state": "rotation_current",
                    "after_state": "rotation_due",
                    "observed_at": _iso(now),
                    "window_key": identity.issued_at,
                    "detail": {
                        "agent_id": identity.agent_id,
                        "owner": identity.owner,
                        "owner_type": identity.owner_type,
                        "issued_at": identity.issued_at,
                        "window_days": window,
                    },
                },
                audit_log,
            )
        except (ValueError, TypeError):
            errors += 1
            _lifecycle_logger.warning("skipping identity %s with unparseable issued_at", identity.identity_id)
        except Exception:  # noqa: BLE001
            errors += 1
            _lifecycle_logger.warning("failed to flag identity %s for rotation; continuing", identity.identity_id, exc_info=False)

    return {"flagged": flagged, "errors": errors}


def run_nhi_lifecycle_cleanup(
    store: AgentIdentityStore,
    *,
    now: datetime,
    audit_log: Any = None,
    dormant_days: int | None = None,
    rotation_days: int | None = None,
) -> dict[str, dict[str, int]]:
    """Run all NHI lifecycle sweeps once. Backend-agnostic; never raises.

    Returns per-sweep counters. Safe to call repeatedly: each sweep is
    idempotent over identical store state, so two consecutive calls produce the
    same end-state and no duplicate audit rows.
    """
    result: dict[str, dict[str, int]] = {}
    try:
        result["grants"] = cleanup_expired_grants(store, now=now, audit_log=audit_log)
    except Exception:  # noqa: BLE001
        _lifecycle_logger.warning("JIT-grant cleanup sweep failed wholesale; continuing", exc_info=False)
        result["grants"] = {"expired": 0, "pruned": 0, "errors": 1}
    try:
        result["dormant"] = deprovision_dormant_identities(store, now=now, dormant_days=dormant_days, audit_log=audit_log)
    except Exception:  # noqa: BLE001
        _lifecycle_logger.warning("dormant-identity sweep failed wholesale; continuing", exc_info=False)
        result["dormant"] = {"revoked": 0, "errors": 1, "disabled": 0}
    try:
        result["rotation"] = flag_rotation_due_identities(store, now=now, rotation_days=rotation_days, audit_log=audit_log)
    except Exception:  # noqa: BLE001
        _lifecycle_logger.warning("rotation-due sweep failed wholesale; continuing", exc_info=False)
        result["rotation"] = {"flagged": 0, "errors": 1}
    return result


def verify_token(store: AgentIdentityStore, token: str) -> tuple[str, str | None]:
    """Resolve an agent-bom-issued token to ``(agent_id, error)``.

    Returns a non-None error for revoked, expired, or unknown tokens so the
    gateway/proxy identity check fails closed.
    """
    identity = store.get_by_token_hash(hash_token(token))
    if identity is None:
        return "anonymous", "Unknown agent identity token"
    if identity.status == "revoked":
        return "anonymous", "Agent identity has been revoked"
    if not identity.is_live():
        return "anonymous", "Agent identity has expired"
    return identity.agent_id, None


_AGENT_IDENTITY_STORE: AgentIdentityStore | None = None


def get_agent_identity_store() -> AgentIdentityStore:
    """Return the process agent-identity store, durable by default.

    Selection (highest precedence first), via :mod:`agent_bom.api.durable_store`:
    - Postgres (``AGENT_BOM_POSTGRES_URL`` / ``AGENT_BOM_DB`` Postgres URL):
      multi-replica, tenant RLS — issued tokens, JIT grants, and conditional
      policies stay consistent across every replica.
    - in-memory (``AGENT_BOM_EPHEMERAL_STORE=1``): explicit opt-out; issued
      identities and grants are lost on restart.
    - SQLite (default, or ``AGENT_BOM_DB`` file path): single-node durable —
      identities and grants survive a restart. This is the default; a control
      plane must not drop issued tokens on a single-replica restart.
    """
    global _AGENT_IDENTITY_STORE
    if _AGENT_IDENTITY_STORE is not None:
        return _AGENT_IDENTITY_STORE
    from agent_bom.api.durable_store import select_backend, sqlite_path

    backend = select_backend()
    if backend == "postgres":
        from agent_bom.api.postgres_agent_identity import PostgresAgentIdentityStore

        _AGENT_IDENTITY_STORE = PostgresAgentIdentityStore()
    elif backend == "memory":
        _AGENT_IDENTITY_STORE = InMemoryAgentIdentityStore()
    else:
        _AGENT_IDENTITY_STORE = SQLiteAgentIdentityStore(sqlite_path())
    return _AGENT_IDENTITY_STORE


def set_agent_identity_store(store: AgentIdentityStore | None) -> None:
    global _AGENT_IDENTITY_STORE
    _AGENT_IDENTITY_STORE = store


def register_local_identity_verifier() -> None:
    """Wire the lifecycle store into agent_bom.agent_identity so issued tokens
    resolve (and revoked/expired ones fail closed) in the proxy/gateway."""
    from agent_bom import agent_identity as _ai

    _ai.set_local_identity_verifier(lambda token: verify_token(get_agent_identity_store(), token))
