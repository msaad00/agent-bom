"""PostgresGovernanceAuditLog — clustered, tenant-scoped, tamper-evident chain.

Uses a functional in-memory fake pool that persists the ``governance_audit_log``
table and honours the exact SQL + FORCE ROW LEVEL SECURITY session the store
issues (``set_config('app.tenant_id' / 'app.bypass_rls')``). The tests prove the
properties that matter for a multi-replica control plane:

* the HMAC-linked chain appends, reads, and integrity-verifies on Postgres;
* tenant isolation holds — a cross-tenant ``get`` is denied and each tenant has
  its own verifiable chain;
* two store instances over one backend see each other's writes (no per-node
  divergence);
* append is idempotent on the deterministic ``action_id``;
* backend selection follows the configured store.
"""

from __future__ import annotations

import pytest

import json
from typing import Any

from agent_bom.api.governance_audit_log import (
    ACTION_IDENTITY_DORMANT_REVOKE,
    InMemoryGovernanceAuditLog,
    SQLiteGovernanceAuditLog,
    make_governance_audit_record,
    set_governance_audit_log,
)
from agent_bom.api.postgres_governance_audit import PostgresGovernanceAuditLog

# ─── Functional fake Postgres with RLS ───────────────────────────────────────


class _FakeCursor:
    def __init__(self, rows=None):
        self.rows = rows or []

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class _FakeUniqueViolation(Exception):
    """Shaped like psycopg's UniqueViolation: sqlstate 23505 + a named constraint."""

    def __init__(self, constraint: str) -> None:
        super().__init__(f'duplicate key value violates unique constraint "{constraint}"')
        self.sqlstate = "23505"

        class _Diag:
            constraint_name = constraint

        self.diag = _Diag()


class _FakeConnection:
    """Minimal Postgres-shaped engine for one governance_audit_log table.

    Enforces tenant RLS the way FORCE ROW LEVEL SECURITY does: a normally-scoped
    session only sees its own tenant's rows; a bypass session sees all rows.
    """

    def __init__(self, state):
        self._state = state  # shared across connections from one pool
        self.tenant = "default"
        self.bypass = False

    def _visible(self):
        rows = self._state["rows"]
        if self.bypass:
            return list(rows)
        return [r for r in rows if r["tenant_id"] == self.tenant]

    def execute(self, sql, params=None):
        s = " ".join(sql.lower().split())
        params = params or ()

        if "select version from control_plane_schema_versions" in s:
            return _FakeCursor([(1,)])
        if "set_config('app.tenant_id'" in s:
            self.tenant = params[0]
            return _FakeCursor()
        if "set_config('app.bypass_rls'" in s:
            self.bypass = params[0] == "1"
            return _FakeCursor()
        if "set_config('statement_timeout'" in s:
            return _FakeCursor()

        if s.startswith("insert into governance_audit_log"):
            action_id, tenant_id, action, observed_at, record_hash, prev_hash, data = params
            rows = self._state["rows"]
            # ON CONFLICT (tenant_id, action_id) DO NOTHING — composite arbiter.
            if any(r["action_id"] == action_id and r["tenant_id"] == tenant_id for r in rows):
                return _FakeCursor()
            # UNIQUE (tenant_id, prev_hash) — the fork guard. Two records may
            # never claim the same predecessor within one tenant. Modelled here
            # because it is the constraint the store's retry loop exists for.
            if any(r["tenant_id"] == tenant_id and r["prev_hash"] == prev_hash for r in rows):
                raise _FakeUniqueViolation("governance_audit_log_tenant_prevhash_uniq")
            self._state["seq"] += 1
            rows.append(
                {
                    "seq": self._state["seq"],
                    "action_id": action_id,
                    "tenant_id": tenant_id,
                    "action": action,
                    "observed_at": observed_at,
                    "record_hash": record_hash,
                    "prev_hash": prev_hash,
                    "data": data,
                }
            )
            return _FakeCursor()

        if "from governance_audit_log where action_id" in s:
            match = [r for r in self._visible() if r["action_id"] == params[0]]
            return _FakeCursor([(match[0]["data"],)] if match else [])

        if "select record_hash from governance_audit_log where tenant_id" in s:
            rows = sorted(
                (r for r in self._visible() if r["tenant_id"] == params[0]),
                key=lambda r: r["seq"],
                reverse=True,
            )
            return _FakeCursor([(rows[0]["record_hash"],)] if rows else [])

        if "select data from governance_audit_log where tenant_id" in s:
            # list() reads DESC; verify_chain(tenant_id=...) reads ASC.
            rows = sorted(
                (r for r in self._visible() if r["tenant_id"] == params[0]),
                key=lambda r: r["seq"],
                reverse="desc" in s,
            )[: params[1]]
            return _FakeCursor([(r["data"],) for r in rows])

        if "group by tenant_id" in s and "max(seq)" in s:
            # Combined head: the last record_hash per tenant (head_hash() no-arg).
            latest: dict[str, str] = {}
            for r in sorted(self._visible(), key=lambda r: r["seq"]):
                latest[r["tenant_id"]] = r["record_hash"]
            return _FakeCursor([(t, h) for t, h in latest.items()])

        if "order by tenant_id asc, seq asc" in s:
            rows = sorted(self._visible(), key=lambda r: (r["tenant_id"], r["seq"]))[: params[0]]
            return _FakeCursor([(r["data"],) for r in rows])

        if s.startswith("select data from governance_audit_log order by seq desc"):
            rows = sorted(self._visible(), key=lambda r: r["seq"], reverse=True)[: params[0]]
            return _FakeCursor([(r["data"],) for r in rows])

        # DDL, RLS helpers, schema-version bookkeeping → no-op.
        return _FakeCursor()

    def commit(self):
        pass

    def rollback(self):
        # The store rolls back before re-sealing on a fork race. Nothing to undo
        # here (the failed INSERT never mutated state), but the method must
        # exist or the retry path raises AttributeError instead of retrying.
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


class _FakePool:
    def __init__(self, *, state: dict[str, Any] | None = None):
        self._state: dict[str, Any] = state if state is not None else {"rows": [], "seq": 0}

    def connection(self):
        return _FakeConnection(self._state)


def _postgres_store(pool: _FakePool | None = None) -> PostgresGovernanceAuditLog:
    """Build distinct app/maintenance pool identities over one fake database."""
    app_pool = pool or _FakePool()
    maintenance_pool = _FakePool(state=app_pool._state)
    return PostgresGovernanceAuditLog(pool=app_pool, maintenance_pool=maintenance_pool)


def _rec(tenant, target, window, action=ACTION_IDENTITY_DORMANT_REVOKE):
    return make_governance_audit_record(
        tenant_id=tenant,
        actor="cleanup-loop",
        action=action,
        target_type="agent_identity",
        target_id=target,
        reason="dormant beyond retention",
        before_state="active",
        after_state="revoked",
        observed_at="2026-07-15T00:00:00Z",
        window_key=window,
    )


# ─── Tests ───────────────────────────────────────────────────────────────────


def test_append_read_and_chain_verifies():
    store = _postgres_store()
    a = store.append(_rec("acme", "id-1", "w1"))
    b = store.append(_rec("acme", "id-2", "w2"))

    # Chain links: second record's prev_hash is the first record's hash.
    assert a.prev_hash == ""
    assert b.prev_hash == a.record_hash

    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    token = set_current_tenant("acme")
    try:
        got = store.get(a.action_id)
    finally:
        reset_current_tenant(token)
    assert got is not None and got.action_id == a.action_id

    result = store.verify_chain()
    assert result["tampered"] == 0
    assert result["verified"] == 2


def test_idempotent_append():
    store = _postgres_store()
    rec = _rec("acme", "id-1", "w1")
    first = store.append(rec)
    second = store.append(_rec("acme", "id-1", "w1"))  # same deterministic action_id

    assert first.action_id == second.action_id
    assert first.record_hash == second.record_hash
    assert len(store.list(tenant_id="acme")) == 1
    assert store.verify_chain()["checked"] == 1


def test_tenant_isolation_get_denied_cross_tenant():
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    store = _postgres_store()
    acme = store.append(_rec("acme", "id-a", "w1"))
    globex = store.append(_rec("globex", "id-b", "w1"))

    token = set_current_tenant("acme")
    try:
        assert store.get(acme.action_id) is not None
        # globex's record is invisible under acme's RLS session.
        assert store.get(globex.action_id) is None
    finally:
        reset_current_tenant(token)

    # list is tenant-scoped.
    assert [r.tenant_id for r in store.list(tenant_id="acme")] == ["acme"]
    assert [r.tenant_id for r in store.list(tenant_id="globex")] == ["globex"]


def test_per_tenant_chains_both_verify():
    store = _postgres_store()
    store.append(_rec("acme", "id-a1", "w1"))
    store.append(_rec("acme", "id-a2", "w2"))
    store.append(_rec("globex", "id-b1", "w1"))

    result = store.verify_chain()
    assert result["tampered"] == 0
    assert result["verified"] == 3


def test_cross_tenant_same_action_both_persist():
    """Two tenants, identical (action, target_id, window_key): neither dropped.

    Pre-fix a global UNIQUE(action_id) + tenant-blind derive collapsed these to
    one id, silently dropping the second tenant's row while verify_chain still
    reported healthy. Tenant-folded ids + composite unique keep both.
    """
    store = _postgres_store()
    acme = store.append(_rec("acme", "id-shared", "w1"))
    globex = store.append(_rec("globex", "id-shared", "w1"))

    assert acme.action_id != globex.action_id
    assert [r.tenant_id for r in store.list(tenant_id="acme")] == ["acme"]
    assert [r.tenant_id for r in store.list(tenant_id="globex")] == ["globex"]
    # Each tenant is a genesis chain of its own.
    assert acme.prev_hash == ""
    assert globex.prev_hash == ""
    result = store.verify_chain()
    assert result["verified"] == 2
    assert result["tampered"] == 0


def test_verify_chain_and_head_hash_are_tenant_scoped():
    store = _postgres_store()
    store.append(_rec("acme", "id-a1", "w1"))
    a2 = store.append(_rec("acme", "id-a2", "w2"))
    store.append(_rec("globex", "id-b1", "w1"))

    # Per-tenant verify sees only that tenant's rows.
    assert store.verify_chain(tenant_id="acme") == {"verified": 2, "tampered": 0, "checked": 2}
    assert store.verify_chain(tenant_id="globex") == {"verified": 1, "tampered": 0, "checked": 1}

    # Per-tenant head is that tenant's latest record_hash; tenants differ.
    assert store.head_hash("acme") == a2.record_hash
    assert store.head_hash("acme") != store.head_hash("globex")

    # No-arg head fingerprints all chains and is stable across a no-op append.
    combined = store.head_hash()
    assert combined
    store.append(_rec("acme", "id-a2", "w2"))  # idempotent duplicate
    assert store.head_hash() == combined


def test_shared_pool_is_cluster_consistent():
    """Two store instances over one backend must see each other's writes."""
    pool = _FakePool()
    node_a = _postgres_store(pool)
    node_b = _postgres_store(pool)

    rec_a = node_a.append(_rec("acme", "id-a", "w1"))
    # node_b, a different replica, appends onto node_a's head — one chain.
    rec_b = node_b.append(_rec("acme", "id-b", "w2"))

    assert rec_b.prev_hash == rec_a.record_hash
    assert len(node_b.list(tenant_id="acme")) == 2
    assert node_b.verify_chain()["tampered"] == 0


def test_tamper_is_detected():
    pool = _FakePool()
    store = _postgres_store(pool)
    store.append(_rec("acme", "id-a", "w1"))
    store.append(_rec("acme", "id-b", "w2"))

    # Corrupt a persisted row's payload after the fact.
    row = pool._state["rows"][0]
    tampered = json.loads(row["data"])
    tampered["reason"] = "silently rewritten"
    row["data"] = json.dumps(tampered, sort_keys=True)

    assert store.verify_chain()["tampered"] >= 1


def test_backend_selection_prefers_postgres(monkeypatch):
    from agent_bom.api import governance_audit_log as mod

    set_governance_audit_log(None)
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgres://agent_bom_app@localhost/test")
    monkeypatch.setattr(
        "agent_bom.api.postgres_governance_audit._get_pool",
        lambda: _FakePool(),
    )
    try:
        log = mod.get_governance_audit_log()
        assert isinstance(log, PostgresGovernanceAuditLog)
    finally:
        set_governance_audit_log(None)


def test_backend_selection_memory_and_sqlite(monkeypatch, tmp_path):
    from agent_bom.api import governance_audit_log as mod

    # Ephemeral opt-out → in-memory.
    set_governance_audit_log(None)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    monkeypatch.setenv("AGENT_BOM_EPHEMERAL_STORE", "1")
    try:
        assert isinstance(mod.get_governance_audit_log(), InMemoryGovernanceAuditLog)
    finally:
        set_governance_audit_log(None)

    # Default → durable SQLite.
    monkeypatch.delenv("AGENT_BOM_EPHEMERAL_STORE", raising=False)
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "cp.db"))
    set_governance_audit_log(None)
    try:
        assert isinstance(mod.get_governance_audit_log(), SQLiteGovernanceAuditLog)
    finally:
        set_governance_audit_log(None)


# ─── Chain fork guard under concurrency ──────────────────────────────────────


def test_a_stale_head_read_is_re_sealed_instead_of_forking() -> None:
    """The race, made deterministic.

    Threads alone do not reproduce this: the fake is fast enough that the GIL
    serialises them and each writer happens to read a fresh head, so a threaded
    test passes even with the guard removed — it proves nothing.

    So the race is injected instead. The second append is served ONE stale head
    (the value the first writer saw), which is exactly what a concurrent replica
    observes. The insert then collides on ``UNIQUE (tenant_id, prev_hash)`` and
    the store must re-read, re-seal against the real head, and land a linear
    chain rather than a fork or a dropped record.
    """
    state = {"rows": [], "seq": 0}
    pool = _FakePool(state=state)
    store = _postgres_store(pool)

    first = store.append(_rec("acme", "identity-a", "w1"))

    stale_head = {"served": False}
    real_execute = _FakeConnection.execute

    def stale_head_once(self, sql, params=None):
        s_norm = " ".join(sql.lower().split())
        if "select record_hash from governance_audit_log" in s_norm and not stale_head["served"]:
            stale_head["served"] = True
            # What the first writer saw before it committed: an empty chain.
            return _FakeCursor([])
        return real_execute(self, sql, params)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(_FakeConnection, "execute", stale_head_once)
        second = store.append(_rec("acme", "identity-b", "w2"))

    assert stale_head["served"], "the stale head was never served — the race was not exercised"

    rows = [r for r in state["rows"] if r["tenant_id"] == "acme"]
    assert len(rows) == 2, f"both records must persist, got {len(rows)}"
    predecessors = [r["prev_hash"] for r in rows]
    assert len(set(predecessors)) == 2, f"the chain forked: two records claim {predecessors}"
    assert second.prev_hash == first.record_hash, "the loser must be re-sealed onto the winner"


def test_a_fork_race_never_drops_the_record() -> None:
    """The guard must reject the row, not the write.

    A constraint without the retry would turn a race into a silently missing
    audit record — worse than the fork it prevents.
    """
    state = {"rows": [], "seq": 0}
    store = _postgres_store(_FakePool(state=state))

    first = store.append(_rec("acme", "identity-a", "w1"))
    second = store.append(_rec("acme", "identity-b", "w2"))

    assert second.prev_hash == first.record_hash, "the second record must chain onto the first"
    assert len([r for r in state["rows"] if r["tenant_id"] == "acme"]) == 2
