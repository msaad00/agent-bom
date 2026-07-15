"""Owner-scoped FinOps budgets: spend + enforcement joined to the accountable owner.

Covers #3909: a spend budget can be scoped to the accountable human/team owner
(as recorded on the governing blueprint header) and enforced at the same
pre-invocation gateway point as tenant/agent/cost-center caps. Owner-level
reporting attributes spend to the owner that governs each agent.
"""

from __future__ import annotations

from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api.blueprint_store import (
    BlueprintComposition,
    InMemoryBlueprintStore,
    approve_version,
    create_blueprint,
    set_blueprint_store,
    submit_version_for_approval,
)
from agent_bom.api.cost_owner import agent_owner_index, owner_cost_report, owner_spend
from agent_bom.api.cost_store import (
    CostBudget,
    InMemoryCostStore,
    LLMCostRecord,
    check_owner_budget_enforcement,
    set_cost_store,
    summarize_by_owner,
)
from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry


def _approved_blueprint(store: InMemoryBlueprintStore, *, tenant: str, owner: str, agents: list[str], name: str = "wf") -> str:
    bp, version = create_blueprint(
        store,
        tenant_id=tenant,
        name=name,
        owner=owner,
        composition=BlueprintComposition(agents=agents),
        created_by="tester",
    )
    submit_version_for_approval(store, tenant_id=tenant, blueprint_id=bp.blueprint_id, version=version.version, submitted_by="tester")
    approve_version(store, tenant_id=tenant, blueprint_id=bp.blueprint_id, version=version.version, approver="approver")
    return bp.blueprint_id


def _rec(agent: str, cost: float, call_id: str) -> LLMCostRecord:
    return LLMCostRecord(
        tenant_id="t1",
        call_id=call_id,
        agent=agent,
        session_id="s1",
        provider="openai",
        model="gpt-4o",
        input_tokens=10,
        output_tokens=10,
        cost_usd=cost,
        priced=True,
        observed_at="2026-06-01T00:00:00Z",
    )


# ── owner attribution + spend ────────────────────────────────────────────────


def test_agent_owner_index_maps_agents_to_owner():
    bp_store = InMemoryBlueprintStore()
    _approved_blueprint(bp_store, tenant="t1", owner="team-alpha", agents=["planner", "coder"])
    set_blueprint_store(bp_store)
    try:
        index = agent_owner_index("t1")
    finally:
        set_blueprint_store(None)
    assert index["planner"][0] == "team-alpha"
    assert index["coder"][0] == "team-alpha"


def test_draft_only_blueprint_does_not_attribute():
    # A blueprint whose version is never approved is not in-effect: its agents
    # are not attributed to the owner.
    bp_store = InMemoryBlueprintStore()
    create_blueprint(bp_store, tenant_id="t1", name="wf", owner="team-alpha", composition=BlueprintComposition(agents=["planner"]))
    set_blueprint_store(bp_store)
    try:
        assert agent_owner_index("t1") == {}
    finally:
        set_blueprint_store(None)


def test_owner_spend_sums_across_governed_agents():
    bp_store = InMemoryBlueprintStore()
    _approved_blueprint(bp_store, tenant="t1", owner="team-alpha", agents=["planner", "coder"])
    cost = InMemoryCostStore()
    cost.record_cost(_rec("planner", 4.0, "c1"))
    cost.record_cost(_rec("coder", 6.0, "c2"))
    cost.record_cost(_rec("stranger", 99.0, "c3"))  # ungoverned agent, not the owner's spend
    set_blueprint_store(bp_store)
    try:
        index = agent_owner_index("t1")
        assert owner_spend(cost, index, "t1", "team-alpha") == 10.0
    finally:
        set_blueprint_store(None)


# ── enforcement decision (pure) ──────────────────────────────────────────────


def test_check_owner_budget_blocks_when_exceeded():
    store = InMemoryCostStore()
    store.set_budget(CostBudget(tenant_id="t1", agent="", limit_usd=10.0, updated_at="now", mode="enforce", owner="team-alpha"))
    blocked, budget = check_owner_budget_enforcement(store, "t1", "team-alpha", "", spend=12.0)
    assert blocked is True and budget is not None and budget.owner == "team-alpha"


def test_check_owner_budget_report_mode_never_blocks():
    store = InMemoryCostStore()
    store.set_budget(CostBudget(tenant_id="t1", agent="", limit_usd=1.0, updated_at="now", mode="report", owner="team-alpha"))
    blocked, _budget = check_owner_budget_enforcement(store, "t1", "team-alpha", "", spend=99.0)
    assert blocked is False


def test_owner_budget_does_not_collide_with_tenant_wide():
    # An owner budget and a tenant-wide budget coexist (widened key, #3909).
    store = InMemoryCostStore()
    store.set_budget(CostBudget(tenant_id="t1", agent="", limit_usd=100.0, updated_at="now", mode="enforce"))
    store.set_budget(CostBudget(tenant_id="t1", agent="", limit_usd=5.0, updated_at="now", mode="enforce", owner="team-alpha"))
    assert store.get_budget("t1", "").limit_usd == 100.0
    assert store.get_budget("t1", "", owner="team-alpha").limit_usd == 5.0


# ── reporting ────────────────────────────────────────────────────────────────


def test_summarize_by_owner_attributes_and_flags_unattributed():
    records = [_rec("planner", 4.0, "c1"), _rec("coder", 6.0, "c2"), _rec("stranger", 2.0, "c3")]
    report = summarize_by_owner(records, {"planner": "team-alpha", "coder": "team-alpha"})
    by_owner = {row["key"]: row["cost_usd"] for row in report["by_owner"]}
    assert by_owner["team-alpha"] == 10.0
    assert by_owner["unattributed"] == 2.0


def test_owner_cost_report_uses_blueprint_index():
    bp_store = InMemoryBlueprintStore()
    _approved_blueprint(bp_store, tenant="t1", owner="team-alpha", agents=["planner"])
    cost = InMemoryCostStore()
    set_blueprint_store(bp_store)
    try:
        report = owner_cost_report(cost, "t1", [_rec("planner", 3.0, "c1")])
    finally:
        set_blueprint_store(None)
    assert report["by_owner"][0]["key"] == "team-alpha"


# ── gateway pre-invocation enforcement ───────────────────────────────────────


async def _ok_caller(upstream, message, extra_headers):
    return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}


def _call(token: str = "token-a", tool: str = "read_file") -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {}, "_meta": {"agent_identity": token}},
    }


def _settings() -> GatewaySettings:
    return GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")]),
        policy={"agent_tokens": {"token-a": "agent-a", "token-b": "agent-b"}},
        upstream_caller=_ok_caller,
    )


@pytest.fixture()
def gateway_env():
    bp_store = InMemoryBlueprintStore()
    _approved_blueprint(bp_store, tenant="default", owner="team-alpha", agents=["agent-a"])
    cost = InMemoryCostStore()
    set_blueprint_store(bp_store)
    set_cost_store(cost)
    try:
        yield cost
    finally:
        set_cost_store(None)
        set_blueprint_store(None)


def _is_blocked(resp) -> bool:
    body = resp.json()
    return resp.status_code == 200 and isinstance(body.get("error"), dict) and body["error"].get("code") == -32001


def test_gateway_blocks_when_owner_budget_exceeded(gateway_env):
    cost = gateway_env
    # agent-a is governed by team-alpha; team-alpha has already burned its cap.
    cost.record_cost(
        LLMCostRecord("default", "c1", "agent-a", "s", "openai", "gpt-4o", 1, 1, 20.0, True, "2026-06-01T00:00:00Z")
    )
    cost.set_budget(CostBudget(tenant_id="default", agent="", limit_usd=10.0, updated_at="now", mode="enforce", owner="team-alpha"))
    client = TestClient(create_gateway_app(_settings()))
    resp = client.post("/mcp/filesystem", json=_call())
    assert _is_blocked(resp), resp.text
    assert "owner" in resp.json()["error"]["message"]


def test_gateway_allows_when_owner_under_budget(gateway_env):
    cost = gateway_env
    cost.record_cost(
        LLMCostRecord("default", "c1", "agent-a", "s", "openai", "gpt-4o", 1, 1, 2.0, True, "2026-06-01T00:00:00Z")
    )
    cost.set_budget(CostBudget(tenant_id="default", agent="", limit_usd=10.0, updated_at="now", mode="enforce", owner="team-alpha"))
    client = TestClient(create_gateway_app(_settings()))
    resp = client.post("/mcp/filesystem", json=_call())
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_gateway_report_mode_owner_budget_never_blocks(gateway_env):
    cost = gateway_env
    cost.record_cost(
        LLMCostRecord("default", "c1", "agent-a", "s", "openai", "gpt-4o", 1, 1, 99.0, True, "2026-06-01T00:00:00Z")
    )
    cost.set_budget(CostBudget(tenant_id="default", agent="", limit_usd=1.0, updated_at="now", mode="report", owner="team-alpha"))
    client = TestClient(create_gateway_app(_settings()))
    resp = client.post("/mcp/filesystem", json=_call())
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_gateway_ungoverned_agent_is_noop(gateway_env):
    cost = gateway_env
    # agent-b has no governing blueprint -> owner enforcement is a no-op.
    cost.set_budget(CostBudget(tenant_id="default", agent="", limit_usd=0.0, updated_at="now", mode="enforce", owner="team-alpha"))
    client = TestClient(create_gateway_app(_settings()))
    resp = client.post("/mcp/filesystem", json=_call(token="token-b"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


# ── API surface ──────────────────────────────────────────────────────────────


@pytest.fixture()
def api():
    from agent_bom.api.server import app

    bp_store = InMemoryBlueprintStore()
    _approved_blueprint(bp_store, tenant="default", owner="team-alpha", agents=["agent-a"])
    cost = InMemoryCostStore()
    cost.record_cost(
        LLMCostRecord("default", "c1", "agent-a", "s", "openai", "gpt-4o", 1, 1, 7.0, True, "2026-06-01T00:00:00Z")
    )
    set_blueprint_store(bp_store)
    set_cost_store(cost)
    try:
        yield TestClient(app)
    finally:
        set_cost_store(None)
        set_blueprint_store(None)


def test_set_and_get_owner_budget(api):
    put = api.put("/v1/observability/costs/budget", json={"limit_usd": 25.0, "owner": "team-alpha", "mode": "enforce"})
    assert put.status_code == 200, put.text
    body = put.json()
    assert body["owner"] == "team-alpha"
    assert body["spend_usd"] == 7.0  # resolved across team-alpha's agents

    got = api.get("/v1/observability/costs/budget", params={"owner": "team-alpha"}).json()
    assert got["configured"] is True
    assert got["owner"] == "team-alpha"
    assert got["limit_usd"] == 25.0


def test_owner_and_agent_budgets_mutually_exclusive(api):
    resp = api.put("/v1/observability/costs/budget", json={"limit_usd": 5.0, "owner": "team-alpha", "agent": "agent-a"})
    assert resp.status_code == 400, resp.text


def test_workflow_requires_owner(api):
    resp = api.put("/v1/observability/costs/budget", json={"limit_usd": 5.0, "workflow": "wf-1"})
    assert resp.status_code == 400, resp.text


def test_costs_report_includes_by_owner(api):
    report = api.get("/v1/observability/costs").json()
    by_owner = {row["key"]: row["cost_usd"] for row in report["by_owner"]}
    assert by_owner["team-alpha"] == 7.0
