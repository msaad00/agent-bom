"""Agent identity lifecycle: issue, rotate, revoke, and verify.

``agent_bom.agent_identity`` verifies identity tokens an external IdP issues but
never managed their lifecycle. This store lets agent-bom issue time-scoped
identities for agents that have no IdP, rotate them with an overlap window, and
revoke them — the provisioning/rotation/revocation layer an agent-identity
control plane needs. Issued tokens (``abi_<prefix>_<secret>``) are stored only
as SHA-256 hashes; the raw token is returned exactly once at issue/rotate time.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version

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
    rotated_to_id: str = ""
    revoked_at: str = ""
    revoked_reason: str = ""

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

    def get(self, identity_id: str) -> AgentIdentity | None: ...

    def get_by_token_hash(self, token_hash: str) -> AgentIdentity | None: ...

    def list(self, tenant_id: str, *, include_inactive: bool = False, limit: int = 200) -> list[AgentIdentity]: ...


def _ttl_to_expiry(ttl_seconds: int, *, at: datetime | None = None) -> str:
    base = at or _now()
    return _iso(base + timedelta(seconds=max(60, int(ttl_seconds))))


class InMemoryAgentIdentityStore:
    def __init__(self) -> None:
        self._by_id: dict[str, AgentIdentity] = {}
        self._by_hash: dict[str, str] = {}
        self._lock = threading.Lock()

    def put(self, identity: AgentIdentity) -> None:
        with self._lock:
            self._by_id[identity.identity_id] = identity
            self._by_hash[identity.token_hash] = identity.identity_id

    def get(self, identity_id: str) -> AgentIdentity | None:
        with self._lock:
            return self._by_id.get(identity_id)

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
        ensure_sqlite_schema_version(self._conn, "agent_identities")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_identities (
                identity_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                data TEXT NOT NULL
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_identities_tenant ON agent_identities(tenant_id, status)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_identities_hash ON agent_identities(token_hash)")
        self._conn.commit()

    def put(self, identity: AgentIdentity) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO agent_identities "
            "(identity_id, tenant_id, token_hash, status, issued_at, data) VALUES (?, ?, ?, ?, ?, ?)",
            (
                identity.identity_id,
                identity.tenant_id,
                identity.token_hash,
                identity.status,
                identity.issued_at,
                json.dumps(asdict(identity), sort_keys=True),
            ),
        )
        self._conn.commit()

    def get(self, identity_id: str) -> AgentIdentity | None:
        row = self._conn.execute("SELECT data FROM agent_identities WHERE identity_id = ?", (identity_id,)).fetchone()
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


# ── Lifecycle operations ────────────────────────────────────────────────────────


def issue_identity(
    store: AgentIdentityStore,
    *,
    agent_id: str,
    tenant_id: str,
    role: str = "agent",
    blueprint_id: str = "",
    ttl_seconds: int = 90 * 86400,
) -> tuple[AgentIdentity, str]:
    """Issue a new identity. Returns ``(identity, raw_token)``; the raw token is
    only available here and at rotation."""
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
    )
    store.put(identity)
    return identity, raw


def rotate_identity(
    store: AgentIdentityStore,
    identity_id: str,
    *,
    overlap_seconds: int = 3600,
    ttl_seconds: int = 90 * 86400,
) -> tuple[AgentIdentity, str] | None:
    """Issue a replacement identity and keep the old one live for ``overlap_seconds``
    so in-flight callers are not cut off. Returns ``(new_identity, raw_token)``."""
    old = store.get(identity_id)
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
    )
    now = _now()
    old.status = "rotating"
    old.rotated_to_id = new_identity.identity_id
    old.expires_at = _ttl_to_expiry(overlap_seconds, at=now)
    store.put(old)
    return new_identity, raw


def revoke_identity(store: AgentIdentityStore, identity_id: str, *, reason: str = "") -> AgentIdentity | None:
    """Immediately revoke an identity; it can no longer authenticate."""
    identity = store.get(identity_id)
    if identity is None:
        return None
    identity.status = "revoked"
    identity.revoked_at = _iso(_now())
    identity.revoked_reason = reason[:500]
    store.put(identity)
    return identity


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
    global _AGENT_IDENTITY_STORE
    if _AGENT_IDENTITY_STORE is not None:
        return _AGENT_IDENTITY_STORE
    if os.environ.get("AGENT_BOM_DB"):
        _AGENT_IDENTITY_STORE = SQLiteAgentIdentityStore(os.environ["AGENT_BOM_DB"])
    else:
        _AGENT_IDENTITY_STORE = InMemoryAgentIdentityStore()
    return _AGENT_IDENTITY_STORE


def set_agent_identity_store(store: AgentIdentityStore | None) -> None:
    global _AGENT_IDENTITY_STORE
    _AGENT_IDENTITY_STORE = store


def register_local_identity_verifier() -> None:
    """Wire the lifecycle store into agent_bom.agent_identity so issued tokens
    resolve (and revoked/expired ones fail closed) in the proxy/gateway."""
    from agent_bom import agent_identity as _ai

    _ai.set_local_identity_verifier(lambda token: verify_token(get_agent_identity_store(), token))
