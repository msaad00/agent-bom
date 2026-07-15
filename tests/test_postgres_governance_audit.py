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

import json

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

        if "set_config('app.tenant_id'" in s:
            self.tenant = params[0]
            return _FakeCursor()
        if "set_config('app.bypass_rls'" in s:
            self.bypass = params[0] == "1"
            return _FakeCursor()
        if "set_config('statement_timeout'" in s:
            return _FakeCursor()

        if s.startswith("insert into governance_audit_log"):
            action_id, tenant_id, action, observed_at, record_hash, data = params
            rows = self._state["rows"]
            if any(r["action_id"] == action_id for r in rows):
                return _FakeCursor()  # ON CONFLICT DO NOTHING
            self._state["seq"] += 1
            rows.append(
                {
                    "seq": self._state["seq"],
                    "action_id": action_id,
                    "tenant_id": tenant_id,
                    "action": action,
                    "observed_at": observed_at,
                    "record_hash": record_hash,
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
            rows = sorted(
                (r for r in self._visible() if r["tenant_id"] == params[0]),
                key=lambda r: r["seq"],
                reverse=True,
            )[: params[1]]
            return _FakeCursor([(r["data"],) for r in rows])

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

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


class _FakePool:
    def __init__(self):
        self._state = {"rows": [], "seq": 0}

    def connection(self):
        return _FakeConnection(self._state)


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
    store = PostgresGovernanceAuditLog(pool=_FakePool())
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
    store = PostgresGovernanceAuditLog(pool=_FakePool())
    rec = _rec("acme", "id-1", "w1")
    first = store.append(rec)
    second = store.append(_rec("acme", "id-1", "w1"))  # same deterministic action_id

    assert first.action_id == second.action_id
    assert first.record_hash == second.record_hash
    assert len(store.list(tenant_id="acme")) == 1
    assert store.verify_chain()["checked"] == 1


def test_tenant_isolation_get_denied_cross_tenant():
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    store = PostgresGovernanceAuditLog(pool=_FakePool())
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
    store = PostgresGovernanceAuditLog(pool=_FakePool())
    store.append(_rec("acme", "id-a1", "w1"))
    store.append(_rec("acme", "id-a2", "w2"))
    store.append(_rec("globex", "id-b1", "w1"))

    result = store.verify_chain()
    assert result["tampered"] == 0
    assert result["verified"] == 3


def test_shared_pool_is_cluster_consistent():
    """Two store instances over one backend must see each other's writes."""
    pool = _FakePool()
    node_a = PostgresGovernanceAuditLog(pool=pool)
    node_b = PostgresGovernanceAuditLog(pool=pool)

    rec_a = node_a.append(_rec("acme", "id-a", "w1"))
    # node_b, a different replica, appends onto node_a's head — one chain.
    rec_b = node_b.append(_rec("acme", "id-b", "w2"))

    assert rec_b.prev_hash == rec_a.record_hash
    assert len(node_b.list(tenant_id="acme")) == 2
    assert node_b.verify_chain()["tampered"] == 0


def test_tamper_is_detected():
    pool = _FakePool()
    store = PostgresGovernanceAuditLog(pool=pool)
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
