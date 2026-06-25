"""Append-only audit log for NHI lifecycle-enforcement actions.

Every automated lifecycle transition the cleanup loop performs — JIT-grant
cleanup, dormant agent-identity auto-deprovision, token rotation-due flips — is
recorded here as an immutable, hash-chained row. The design mirrors the runtime
proxy audit chain (:mod:`agent_bom.audit_integrity`): each record carries the
previous record's MAC plus its own, so a tamper of any row breaks the chain and
is detectable by ``verify_chain``.

Three properties are load-bearing for determinism and replay-safety:

1. **Deterministic record id.** ``action_id`` is derived from stable inputs
   (``target identity`` + ``action`` + ``window key``), never a fresh
   ``uuid4()``. Re-running the same cleanup over the same state yields the same
   id, so an idempotent ``append`` is a no-op rather than a duplicate row.

2. **Injected timestamp.** The acting time is always passed in by the caller
   (``observed_at``); this module never calls ``time.time()`` / ``datetime.now``
   inside its logic, matching the runtime incident-feedback convention.

3. **Idempotent append.** ``append`` is keyed on ``action_id``: a second append
   of the same action returns the already-stored record and does not extend the
   chain, so the cleanup loop is safe to run twice over identical state.

This store never holds secret material — it records identity ids, statuses, and
reasons only, never token hashes or secrets.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version
from agent_bom.audit_integrity import compute_audit_record_mac

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


def derive_action_id(*, target_id: str, action: str, window_key: str) -> str:
    """Return a deterministic, collision-resistant id for one lifecycle action.

    The id is a SHA-256 over the stable triple ``(target_id, action,
    window_key)``. ``window_key`` is a caller-chosen stable token for the
    enforcement occasion — typically the target's terminal state timestamp (an
    expired grant's ``expires_at``, a revoked identity's ``revoked_at``) — so the
    same transition over the same state always derives the same id, and a *new*
    transition (a later re-deprovision after re-activation) derives a new one.
    """
    digest = hashlib.sha256(f"{action}\x1f{target_id}\x1f{window_key}".encode("utf-8")).hexdigest()
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

    def head_hash(self) -> str: ...

    def verify_chain(self, *, max_rows: int = 50_000) -> dict[str, Any]: ...


def _seal_record(record: GovernanceAuditRecord, prev_hash: str) -> GovernanceAuditRecord:
    """Stamp ``prev_hash`` + computed ``record_hash`` onto a record."""
    record.prev_hash = prev_hash
    record.record_hash = compute_audit_record_mac(record.payload_for_mac(), prev_hash)
    return record


class InMemoryGovernanceAuditLog:
    """Process-local append-only chain. Lost on restart; used for tests/ephemeral."""

    def __init__(self) -> None:
        self._by_id: dict[str, GovernanceAuditRecord] = {}
        self._order: list[str] = []
        self._head: str = ""
        self._lock = threading.Lock()

    def append(self, record: GovernanceAuditRecord) -> GovernanceAuditRecord:
        with self._lock:
            existing = self._by_id.get(record.action_id)
            if existing is not None:
                return existing
            sealed = _seal_record(record, self._head)
            self._by_id[sealed.action_id] = sealed
            self._order.append(sealed.action_id)
            self._head = sealed.record_hash
            return sealed

    def get(self, action_id: str) -> GovernanceAuditRecord | None:
        with self._lock:
            return self._by_id.get(action_id)

    def list(self, *, tenant_id: str | None = None, limit: int = 500) -> list[GovernanceAuditRecord]:
        with self._lock:
            rows = [self._by_id[aid] for aid in self._order]
        if tenant_id is not None:
            rows = [r for r in rows if r.tenant_id == tenant_id]
        return list(reversed(rows))[:limit]

    def head_hash(self) -> str:
        with self._lock:
            return self._head

    def verify_chain(self, *, max_rows: int = 50_000) -> dict[str, Any]:
        with self._lock:
            rows = [self._by_id[aid] for aid in self._order[:max_rows]]
        return _verify_rows(rows)


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

    def _init_db(self) -> None:
        ensure_sqlite_schema_version(self._conn, "governance_audit_log")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS governance_audit_log (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id TEXT NOT NULL UNIQUE,
                tenant_id TEXT NOT NULL,
                action TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                record_hash TEXT NOT NULL,
                data TEXT NOT NULL
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_governance_audit_tenant ON governance_audit_log(tenant_id, seq)")
        self._conn.commit()

    def append(self, record: GovernanceAuditRecord) -> GovernanceAuditRecord:
        # Serialize seal+insert so two threads can't read the same head and fork
        # the chain (read-modify-write race). The UNIQUE action_id makes a second
        # append of the same action a no-op even across processes/replicas.
        with self._lock:
            existing = self.get(record.action_id)
            if existing is not None:
                return existing
            head = self.head_hash()
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
                # Lost a race on the UNIQUE action_id — the other writer's row is
                # canonical; return it rather than duplicating.
                self._conn.rollback()
                stored = self.get(record.action_id)
                return stored if stored is not None else sealed
            return sealed

    def get(self, action_id: str) -> GovernanceAuditRecord | None:
        row = self._conn.execute("SELECT data FROM governance_audit_log WHERE action_id = ?", (action_id,)).fetchone()
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

    def head_hash(self) -> str:
        row = self._conn.execute("SELECT record_hash FROM governance_audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        return str(row[0]) if row else ""

    def verify_chain(self, *, max_rows: int = 50_000) -> dict[str, Any]:
        rows = self._conn.execute("SELECT data FROM governance_audit_log ORDER BY seq ASC LIMIT ?", (max_rows,)).fetchall()
        records = [GovernanceAuditRecord(**json.loads(r[0])) for r in rows]
        return _verify_rows(records)


def _verify_rows(rows: list[GovernanceAuditRecord]) -> dict[str, Any]:
    """Walk the chain in order, re-deriving each MAC. Never raises."""
    verified = 0
    tampered = 0
    prev = ""
    for record in rows:
        expected = compute_audit_record_mac(record.payload_for_mac(), record.prev_hash)
        if record.prev_hash == prev and record.record_hash == expected:
            verified += 1
        else:
            tampered += 1
        prev = record.record_hash or prev
    return {"verified": verified, "tampered": tampered, "checked": verified + tampered}


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
        action_id=derive_action_id(target_id=target_id, action=action, window_key=window_key),
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

    Selection mirrors the agent-identity store: Postgres is not yet a backend
    here (a future PR adds the shared-replica chain), so the durable tier is
    SQLite and the ephemeral opt-out is in-memory.
    """
    global _GOVERNANCE_AUDIT_LOG
    if _GOVERNANCE_AUDIT_LOG is not None:
        return _GOVERNANCE_AUDIT_LOG
    from agent_bom.api.durable_store import select_backend, sqlite_path

    backend = select_backend()
    if backend == "memory":
        _GOVERNANCE_AUDIT_LOG = InMemoryGovernanceAuditLog()
    else:
        # Postgres backend has no dedicated chain table yet; fall back to the
        # node-local durable SQLite chain rather than dropping the audit trail.
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
