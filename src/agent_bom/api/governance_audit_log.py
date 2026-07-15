"""Append-only audit log for NHI lifecycle-enforcement actions.

Every automated lifecycle transition the cleanup loop performs — JIT-grant
cleanup, dormant agent-identity auto-deprovision, token rotation-due flips — is
recorded here as an immutable, hash-chained row. The design mirrors the runtime
proxy audit chain (:mod:`agent_bom.audit_integrity`): each record carries the
previous record's MAC plus its own, so a tamper of any row breaks the chain and
is detectable by ``verify_chain``.

Three properties are load-bearing for determinism and replay-safety:

1. **Deterministic, tenant-scoped record id.** ``action_id`` is derived from
   stable inputs (``tenant_id`` + ``target identity`` + ``action`` + ``window
   key``), never a fresh ``uuid4()``. Re-running the same cleanup over the same
   state yields the same id, so an idempotent ``append`` is a no-op rather than
   a duplicate row. Folding ``tenant_id`` into the id means two tenants acting
   on a same-named target never derive the same id.

2. **Injected timestamp.** The acting time is always passed in by the caller
   (``observed_at``); this module never calls ``time.time()`` / ``datetime.now``
   inside its logic, matching the runtime incident-feedback convention.

3. **Idempotent append.** ``append`` dedups on the composite
   ``(tenant_id, action_id)``: a second append of the same action returns the
   already-stored record and does not extend the chain, so the cleanup loop is
   safe to run twice over identical state.

4. **Per-tenant hash chains.** Each tenant owns an independent chain: a new
   record's ``prev_hash`` links to that tenant's head only, and ``verify_chain``
   walks each tenant's rows in isolation. One tenant's appends can never extend,
   fork, or invalidate another tenant's chain, and a dropped/collided row in one
   tenant cannot mask itself behind another tenant's "verified" count.

This store never holds secret material — it records identity ids, statuses, and
reasons only, never token hashes or secrets.

**Concurrency & scope (honest).** The SQLite/in-memory backends serialize
seal+insert with an in-process lock, and the composite ``UNIQUE(tenant_id,
action_id)`` makes a lost in-process race collapse to the stored row rather than
a duplicate — so a single process (any number of threads) never forks a chain.
Cross-*process* serialization for those backends relies on that unique
constraint plus single-writer operation, so they are **not** safe for multiple
concurrent writers against one shared chain (multi-replica). The Postgres
backend (:class:`agent_bom.api.postgres_governance_audit.PostgresGovernanceAuditLog`)
IS the multi-replica tier: it keeps one shared, tenant-RLS-scoped chain per
tenant and gets cross-writer idempotency from the same composite
``UNIQUE(tenant_id, action_id)`` plus ``ON CONFLICT (tenant_id, action_id) DO
NOTHING`` — a replica that loses the insert race re-reads the canonical row. It
does not take a cross-node lock, so two replicas can still seal against the same
head and land two rows for one tenant; that is caught (reported ``tampered``) by
``verify_chain`` rather than silently corrupting another tenant's chain.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version
from agent_bom.audit_integrity import compute_audit_record_mac, verify_audit_record_mac

# Lifecycle action verbs recorded in the chain. Kept small and explicit so the
# governance posture can group on them without parsing free text.
ACTION_JIT_GRANT_EXPIRED = "jit_grant_expired"
ACTION_JIT_GRANT_DENIED_PRUNED = "jit_grant_denied_pruned"
ACTION_IDENTITY_DORMANT_REVOKE = "identity_dormant_auto_revoke"
ACTION_TOKEN_ROTATION_DUE = "token_rotation_due"

_VALID_ACTIONS = frozenset(
    {
        ACTION_JIT_GRANT_EXPIRED,
        ACTION_JIT_GRANT_DENIED_PRUNED,
        ACTION_IDENTITY_DORMANT_REVOKE,
        ACTION_TOKEN_ROTATION_DUE,
    }
)


def derive_action_id(*, tenant_id: str, target_id: str, action: str, window_key: str) -> str:
    """Return a deterministic, collision-resistant, tenant-scoped action id.

    The id is a SHA-256 over the stable tuple ``(tenant_id, action, target_id,
    window_key)``. ``window_key`` is a caller-chosen stable token for the
    enforcement occasion — typically the target's terminal state timestamp (an
    expired grant's ``expires_at``, a revoked identity's ``revoked_at``) — so the
    same transition over the same state always derives the same id, and a *new*
    transition (a later re-deprovision after re-activation) derives a new one.

    ``tenant_id`` is folded into the digest so two tenants performing the same
    logical action on a same-named target derive *different* ids and can never
    collide on the composite ``UNIQUE(tenant_id, action_id)`` constraint.
    """
    digest = hashlib.sha256(
        f"{tenant_id}\x1f{action}\x1f{target_id}\x1f{window_key}".encode("utf-8")
    ).hexdigest()
    return f"gov_{digest[:32]}"


@dataclass
class GovernanceAuditRecord:
    """One append-only NHI lifecycle-action record (no secret material)."""

    action_id: str
    tenant_id: str
    actor: str
    action: str
    target_type: str  # jit_grant | agent_identity
    target_id: str
    reason: str
    before_state: str
    after_state: str
    observed_at: str  # ISO-8601, injected by the caller
    prev_hash: str = ""
    record_hash: str = ""
    record_hash_algorithm: str = "aes-cmac-128"
    detail: dict[str, Any] = field(default_factory=dict)

    def payload_for_mac(self) -> dict[str, Any]:
        """Return the redacted payload the chain MAC is computed over."""
        body = asdict(self)
        body.pop("prev_hash", None)
        body.pop("record_hash", None)
        return body

    def to_public_dict(self) -> dict[str, Any]:
        return asdict(self)


class GovernanceAuditLog(Protocol):
    def append(self, record: GovernanceAuditRecord) -> GovernanceAuditRecord: ...

    def get(self, action_id: str) -> GovernanceAuditRecord | None: ...

    def list(self, *, tenant_id: str | None = None, limit: int = 500) -> list[GovernanceAuditRecord]: ...

    def head_hash(self, tenant_id: str | None = None) -> str: ...

    def verify_chain(self, *, tenant_id: str | None = None, max_rows: int = 50_000) -> dict[str, Any]: ...


def _seal_record(record: GovernanceAuditRecord, prev_hash: str) -> GovernanceAuditRecord:
    """Stamp ``prev_hash`` + computed ``record_hash`` onto a record."""
    record.prev_hash = prev_hash
    record.record_hash = compute_audit_record_mac(record.payload_for_mac(), prev_hash)
    return record


class InMemoryGovernanceAuditLog:
    """Process-local per-tenant append-only chains. Lost on restart; ephemeral."""

    def __init__(self) -> None:
        # Dedup key is the composite (tenant_id, action_id) so a caller-supplied
        # pre-built id can never cross tenants.
        self._by_key: dict[tuple[str, str], GovernanceAuditRecord] = {}
        self._order: list[GovernanceAuditRecord] = []  # global insertion order
        self._heads: dict[str, str] = {}  # tenant_id -> that tenant's chain head
        self._lock = threading.Lock()

    def append(self, record: GovernanceAuditRecord) -> GovernanceAuditRecord:
        with self._lock:
            key = (record.tenant_id, record.action_id)
            existing = self._by_key.get(key)
            if existing is not None:
                return existing
            prev = self._heads.get(record.tenant_id, "")
            sealed = _seal_record(record, prev)
            self._by_key[key] = sealed
            self._order.append(sealed)
            self._heads[sealed.tenant_id] = sealed.record_hash
            return sealed

    def get(self, action_id: str) -> GovernanceAuditRecord | None:
        with self._lock:
            for record in self._order:
                if record.action_id == action_id:
                    return record
            return None

    def list(self, *, tenant_id: str | None = None, limit: int = 500) -> list[GovernanceAuditRecord]:
        with self._lock:
            rows = list(self._order)
        if tenant_id is not None:
            rows = [r for r in rows if r.tenant_id == tenant_id]
        return list(reversed(rows))[:limit]

    def head_hash(self, tenant_id: str | None = None) -> str:
        with self._lock:
            if tenant_id is not None:
                return self._heads.get(tenant_id, "")
            return _combined_head(self._heads)

    def verify_chain(self, *, tenant_id: str | None = None, max_rows: int = 50_000) -> dict[str, Any]:
        with self._lock:
            rows = list(self._order[:max_rows])
        return _verify_rows_grouped(rows, tenant_id=tenant_id)


class SQLiteGovernanceAuditLog:
    """Single-node durable append-only chain backed by SQLite."""

    def __init__(self, db_path: str = "agent_bom.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._lock = threading.Lock()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        conn: sqlite3.Connection = self._local.conn
        return conn

    _TABLE_DDL = """
        CREATE TABLE IF NOT EXISTS governance_audit_log (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            action_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            action TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            record_hash TEXT NOT NULL,
            data TEXT NOT NULL,
            UNIQUE(tenant_id, action_id)
        )
    """

    def _init_db(self) -> None:
        ensure_sqlite_schema_version(self._conn, "governance_audit_log")
        self._migrate_unique_constraint()
        self._conn.execute(self._TABLE_DDL)
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_governance_audit_tenant ON governance_audit_log(tenant_id, seq)")
        self._conn.commit()

    def _migrate_unique_constraint(self) -> None:
        """Idempotently rebuild an old single-column ``UNIQUE(action_id)`` table.

        Earlier schema declared ``action_id TEXT NOT NULL UNIQUE`` — a *global*
        uniqueness that silently dropped a second tenant's legitimately distinct
        row. Rebuild it to composite ``UNIQUE(tenant_id, action_id)`` in place,
        preserving ``seq`` (chain order) and every row's original bytes. A no-op
        when the table is absent or already migrated.
        """
        row = self._conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='governance_audit_log'"
        ).fetchone()
        if row is None:
            return  # fresh install — CREATE TABLE below builds the new shape
        normalized = (row[0] or "").replace(" ", "").lower()
        if "unique(tenant_id,action_id)" in normalized:
            return  # already migrated
        if "action_idtextnotnullunique" not in normalized:
            return  # unrecognized shape — leave it untouched rather than guess
        # Rebuild preserving seq so per-tenant chain order is stable.
        self._conn.execute("ALTER TABLE governance_audit_log RENAME TO governance_audit_log_legacy")
        self._conn.execute(self._TABLE_DDL)
        self._conn.execute(
            "INSERT INTO governance_audit_log (seq, action_id, tenant_id, action, observed_at, record_hash, data) "
            "SELECT seq, action_id, tenant_id, action, observed_at, record_hash, data FROM governance_audit_log_legacy"
        )
        self._conn.execute("DROP TABLE governance_audit_log_legacy")
        self._conn.commit()

    def append(self, record: GovernanceAuditRecord) -> GovernanceAuditRecord:
        # Serialize seal+insert so two threads can't read the same tenant head
        # and fork that tenant's chain (read-modify-write race). The composite
        # UNIQUE(tenant_id, action_id) makes a lost race collapse to the stored
        # row rather than a duplicate.
        with self._lock:
            existing = self._get_scoped(record.tenant_id, record.action_id)
            if existing is not None:
                return existing
            head = self.head_hash(record.tenant_id)
            sealed = _seal_record(record, head)
            try:
                self._conn.execute(
                    "INSERT INTO governance_audit_log (action_id, tenant_id, action, observed_at, record_hash, data) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        sealed.action_id,
                        sealed.tenant_id,
                        sealed.action,
                        sealed.observed_at,
                        sealed.record_hash,
                        json.dumps(asdict(sealed), sort_keys=True),
                    ),
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                # Lost a race on UNIQUE(tenant_id, action_id) — the other writer's
                # row is canonical; return it rather than duplicating.
                self._conn.rollback()
                stored = self._get_scoped(record.tenant_id, record.action_id)
                return stored if stored is not None else sealed
            return sealed

    def _get_scoped(self, tenant_id: str, action_id: str) -> GovernanceAuditRecord | None:
        row = self._conn.execute(
            "SELECT data FROM governance_audit_log WHERE tenant_id = ? AND action_id = ?",
            (tenant_id, action_id),
        ).fetchone()
        return GovernanceAuditRecord(**json.loads(row[0])) if row else None

    def get(self, action_id: str) -> GovernanceAuditRecord | None:
        row = self._conn.execute(
            "SELECT data FROM governance_audit_log WHERE action_id = ? ORDER BY seq ASC LIMIT 1",
            (action_id,),
        ).fetchone()
        return GovernanceAuditRecord(**json.loads(row[0])) if row else None

    def list(self, *, tenant_id: str | None = None, limit: int = 500) -> list[GovernanceAuditRecord]:
        if tenant_id is not None:
            rows = self._conn.execute(
                "SELECT data FROM governance_audit_log WHERE tenant_id = ? ORDER BY seq DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM governance_audit_log ORDER BY seq DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [GovernanceAuditRecord(**json.loads(r[0])) for r in rows]

    def head_hash(self, tenant_id: str | None = None) -> str:
        if tenant_id is not None:
            row = self._conn.execute(
                "SELECT record_hash FROM governance_audit_log WHERE tenant_id = ? ORDER BY seq DESC LIMIT 1",
                (tenant_id,),
            ).fetchone()
            return str(row[0]) if row else ""
        # No tenant → a combined fingerprint over every tenant's head, so callers
        # can cheaply detect "did any chain move" without conflating tenants.
        rows = self._conn.execute(
            "SELECT g.tenant_id, g.record_hash FROM governance_audit_log g "
            "JOIN (SELECT tenant_id, MAX(seq) AS m FROM governance_audit_log GROUP BY tenant_id) t "
            "ON g.tenant_id = t.tenant_id AND g.seq = t.m"
        ).fetchall()
        return _combined_head({str(r[0]): str(r[1]) for r in rows})

    def verify_chain(self, *, tenant_id: str | None = None, max_rows: int = 50_000) -> dict[str, Any]:
        if tenant_id is not None:
            rows = self._conn.execute(
                "SELECT data FROM governance_audit_log WHERE tenant_id = ? ORDER BY seq ASC LIMIT ?",
                (tenant_id, max_rows),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM governance_audit_log ORDER BY seq ASC LIMIT ?",
                (max_rows,),
            ).fetchall()
        records = [GovernanceAuditRecord(**json.loads(r[0])) for r in rows]
        return _verify_rows_grouped(records, tenant_id=tenant_id)


def _verify_rows(rows: list[GovernanceAuditRecord]) -> dict[str, Any]:
    """Walk one tenant's chain in order, re-deriving each MAC. Never raises."""
    verified = 0
    tampered = 0
    prev = ""
    for record in rows:
        # Signed with the primary key; verify against any key in the rotation list.
        mac_ok = verify_audit_record_mac(record.payload_for_mac(), record.prev_hash, record.record_hash)
        if record.prev_hash == prev and mac_ok:
            verified += 1
        else:
            tampered += 1
        prev = record.record_hash or prev
    return {"verified": verified, "tampered": tampered, "checked": verified + tampered}


def _verify_rows_grouped(
    rows: list[GovernanceAuditRecord], *, tenant_id: str | None = None
) -> dict[str, Any]:
    """Verify each tenant's chain independently and sum the results.

    ``rows`` must be in global ``seq`` order; grouping preserves that order per
    tenant so every chain is walked from its own genesis (``prev_hash == ""``).
    With ``tenant_id`` set, only that tenant's chain is verified.
    """
    by_tenant: dict[str, list[GovernanceAuditRecord]] = {}
    for record in rows:
        if tenant_id is not None and record.tenant_id != tenant_id:
            continue
        by_tenant.setdefault(record.tenant_id, []).append(record)
    verified = 0
    tampered = 0
    for tenant_rows in by_tenant.values():
        result = _verify_rows(tenant_rows)
        verified += result["verified"]
        tampered += result["tampered"]
    return {"verified": verified, "tampered": tampered, "checked": verified + tampered}


def _combined_head(heads: dict[str, str]) -> str:
    """Deterministic fingerprint over every tenant's chain head.

    Returns ``""`` when no chain exists. Any tenant's head advancing changes the
    fingerprint, so a no-op sweep leaves it unchanged — without pretending the
    tenants share one chain.
    """
    if not heads:
        return ""
    joined = "\x1f".join(f"{tenant}={head}" for tenant, head in sorted(heads.items()))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


_GOVERNANCE_AUDIT_LOG: GovernanceAuditLog | None = None


def make_governance_audit_record(
    *,
    tenant_id: str,
    actor: str,
    action: str,
    target_type: str,
    target_id: str,
    reason: str,
    before_state: str,
    after_state: str,
    observed_at: str,
    window_key: str,
    detail: dict[str, Any] | None = None,
) -> GovernanceAuditRecord:
    """Build a record with a deterministic id (no chain hashes yet)."""
    if action not in _VALID_ACTIONS:
        raise ValueError(f"unknown governance action {action!r}; expected one of {sorted(_VALID_ACTIONS)}")
    return GovernanceAuditRecord(
        action_id=derive_action_id(
            tenant_id=tenant_id, target_id=target_id, action=action, window_key=window_key
        ),
        tenant_id=tenant_id,
        actor=actor[:120],
        action=action,
        target_type=target_type,
        target_id=target_id,
        reason=reason[:500],
        before_state=before_state,
        after_state=after_state,
        observed_at=observed_at,
        detail=dict(detail or {}),
    )


def get_governance_audit_log() -> GovernanceAuditLog:
    """Return the process governance audit log, durable by default.

    Selection mirrors the agent-identity store: Postgres (multi-replica, tenant
    RLS) when configured, node-local durable SQLite otherwise, and in-memory only
    on an explicit ephemeral opt-out. On a clustered Postgres deployment this
    keeps the tamper-evident chain a single durable per-tenant chain shared
    across every replica rather than splitting per-node.
    """
    global _GOVERNANCE_AUDIT_LOG
    if _GOVERNANCE_AUDIT_LOG is not None:
        return _GOVERNANCE_AUDIT_LOG
    from agent_bom.api.durable_store import select_backend, sqlite_path

    backend = select_backend()
    if backend == "memory":
        _GOVERNANCE_AUDIT_LOG = InMemoryGovernanceAuditLog()
    elif backend == "postgres":
        from agent_bom.api.postgres_governance_audit import PostgresGovernanceAuditLog

        _GOVERNANCE_AUDIT_LOG = PostgresGovernanceAuditLog()
    else:
        _GOVERNANCE_AUDIT_LOG = SQLiteGovernanceAuditLog(sqlite_path())
    return _GOVERNANCE_AUDIT_LOG


def set_governance_audit_log(log: GovernanceAuditLog | None) -> None:
    global _GOVERNANCE_AUDIT_LOG
    _GOVERNANCE_AUDIT_LOG = log


__all__ = [
    "ACTION_IDENTITY_DORMANT_REVOKE",
    "ACTION_JIT_GRANT_DENIED_PRUNED",
    "ACTION_JIT_GRANT_EXPIRED",
    "ACTION_TOKEN_ROTATION_DUE",
    "GovernanceAuditLog",
    "GovernanceAuditRecord",
    "InMemoryGovernanceAuditLog",
    "SQLiteGovernanceAuditLog",
    "derive_action_id",
    "get_governance_audit_log",
    "make_governance_audit_record",
    "set_governance_audit_log",
]
