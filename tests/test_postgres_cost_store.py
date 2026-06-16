"""PostgresCostStore — cluster-safe LLM cost persistence.

Uses a functional in-memory fake pool that actually persists the two cost
tables and implements the exact SQL the store issues, so the tests prove the
property that matters for multi-replica deployments: spend and budgets written
through one store instance are visible to another instance sharing the same
backend (no node-local divergence).
"""

from __future__ import annotations

import pytest

from agent_bom.api.cost_store import (
    CostBudget,
    LLMCostRecord,
    check_budget_enforcement,
    get_cost_store,
    set_cost_store,
)
from agent_bom.api.postgres_cost import PostgresCostStore


class _FakeCursor:
    def __init__(self, rows=None):
        self.rows = rows or []

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class _FakeConnection:
    """Minimal Postgres-shaped engine for the two cost tables."""

    def __init__(self, state):
        self._state = state  # shared across connections from one pool

    def execute(self, sql, params=None):
        s = " ".join(sql.lower().split())
        params = params or ()
        costs = self._state["costs"]  # (tenant, call_id) -> tuple
        budgets = self._state["budgets"]  # (tenant, agent) -> tuple

        if s.startswith("insert into llm_costs"):
            key = (params[0], params[1])
            costs.setdefault(key, tuple(params))  # ON CONFLICT DO NOTHING
            return _FakeCursor()
        if s.startswith("insert into llm_cost_budgets"):
            budgets[(params[0], params[1])] = tuple(params)  # ON CONFLICT DO UPDATE
            return _FakeCursor()
        if "sum(cost_usd) from llm_costs" in s.replace("coalesce(", "").replace(", 0.0)", ""):
            tenant = params[0]
            rows = [r for r in costs.values() if r[0] == tenant]
            if "and agent = %s" in s:
                rows = [r for r in rows if r[2] == params[1]]
            return _FakeCursor([(sum(r[8] for r in rows),)])
        if "from llm_costs where tenant_id" in s:
            rows = sorted(
                (r for r in costs.values() if r[0] == params[0]),
                key=lambda r: r[10],
                reverse=True,
            )[: params[1]]
            return _FakeCursor(list(rows))
        if "from llm_cost_budgets where tenant_id" in s:
            row = budgets.get((params[0], params[1]))
            return _FakeCursor([row] if row else [])
        # DDL, RLS helpers, set_config, schema-version bookkeeping → no-op.
        return _FakeCursor()

    def commit(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


class _FakePool:
    def __init__(self):
        self._state = {"costs": {}, "budgets": {}}

    def connection(self):
        return _FakeConnection(self._state)


def _rec(call_id, agent, cost, observed_at):
    return LLMCostRecord(
        tenant_id="acme",
        call_id=call_id,
        agent=agent,
        session_id="s1",
        provider="openai",
        model="gpt-4o",
        input_tokens=100,
        output_tokens=50,
        cost_usd=cost,
        priced=True,
        observed_at=observed_at,
    )


def test_record_dedup_and_total_spend():
    store = PostgresCostStore(pool=_FakePool())
    store.record_cost(_rec("c1", "agent-a", 1.5, "2026-06-15T00:00:00Z"))
    store.record_cost(_rec("c1", "agent-a", 1.5, "2026-06-15T00:00:01Z"))  # dup call_id
    store.record_cost(_rec("c2", "agent-b", 2.0, "2026-06-15T00:00:02Z"))

    assert store.total_spend("acme") == pytest.approx(3.5)
    assert store.total_spend("acme", agent="agent-a") == pytest.approx(1.5)
    assert store.total_spend("acme", agent="agent-b") == pytest.approx(2.0)
    assert len(store.list_records("acme")) == 2


def test_budget_upsert_and_get():
    store = PostgresCostStore(pool=_FakePool())
    store.set_budget(CostBudget("acme", "", 10.0, "2026-06-15T00:00:00Z", "report"))
    store.set_budget(CostBudget("acme", "", 5.0, "2026-06-15T00:00:05Z", "enforce"))  # update
    b = store.get_budget("acme", "")
    assert b is not None and b.limit_usd == 5.0 and b.mode == "enforce"
    assert store.get_budget("acme", "missing") is None


def test_shared_pool_is_cluster_consistent():
    """Two store instances over one backend must see each other's writes."""
    pool = _FakePool()
    node_a = PostgresCostStore(pool=pool)
    node_b = PostgresCostStore(pool=pool)

    node_a.record_cost(_rec("c1", "agent-a", 4.0, "2026-06-15T00:00:00Z"))
    node_a.set_budget(CostBudget("acme", "", 3.0, "2026-06-15T00:00:00Z", "enforce"))

    # node_b, simulating a different replica, sees node_a's spend + budget.
    assert node_b.total_spend("acme") == pytest.approx(4.0)
    blocked, budget, spend = check_budget_enforcement(node_b, "acme", "agent-a")
    assert blocked is True
    assert budget is not None and budget.mode == "enforce"
    assert spend == pytest.approx(4.0)


def test_get_cost_store_prefers_postgres(monkeypatch):
    set_cost_store(None)
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgres://localhost/test")
    monkeypatch.setattr("agent_bom.api.postgres_cost._get_pool", lambda: _FakePool())
    try:
        store = get_cost_store()
        assert isinstance(store, PostgresCostStore)
    finally:
        set_cost_store(None)
