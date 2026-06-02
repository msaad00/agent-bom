"""FinOps cost pipeline: pricing, persistence/aggregation, and the API surface."""

from __future__ import annotations

import pytest

from agent_bom.api.cost_store import (
    CostBudget,
    InMemoryCostStore,
    LLMCostRecord,
    budget_status,
    set_cost_store,
    summarize,
)
from agent_bom.cost_model import compute_cost_usd, is_priced, lookup_price, reset_price_overrides


@pytest.fixture(autouse=True)
def _fresh_overrides(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_COST_MODEL_JSON", raising=False)
    reset_price_overrides()
    yield
    reset_price_overrides()


# ── cost model ────────────────────────────────────────────────────────────────


def test_longest_prefix_wins():
    # gpt-4o-mini must resolve to the mini price, not the gpt-4o price.
    assert lookup_price("openai", "gpt-4o-mini-2024-07-18").input_per_mtok == 0.15
    assert lookup_price("openai", "gpt-4o-2024-11-20").input_per_mtok == 2.50


def test_compute_cost_usd():
    # 1M input @ $2.50 + 1M output @ $10.00 = $12.50
    assert compute_cost_usd("openai", "gpt-4o", 1_000_000, 1_000_000) == 12.5


def test_provider_alias_resolves():
    assert is_priced("azure", "gpt-4o")  # azure -> openai
    assert is_priced("aws_bedrock", "claude-3-5-sonnet-20241022")  # bedrock -> anthropic


def test_unknown_model_is_zero_not_error():
    assert compute_cost_usd("openai", "totally-made-up", 1000, 1000) == 0.0
    assert is_priced("openai", "totally-made-up") is False


def test_operator_override(monkeypatch):
    monkeypatch.setenv(
        "AGENT_BOM_COST_MODEL_JSON",
        '{"openai": {"gpt-4o": {"input_per_mtok": 1.0, "output_per_mtok": 2.0}}}',
    )
    reset_price_overrides()
    assert compute_cost_usd("openai", "gpt-4o", 1_000_000, 1_000_000) == 3.0


# ── store + aggregation ─────────────────────────────────────────────────────────


def _rec(agent="agent-a", model="gpt-4o", provider="openai", cost=1.0, call_id="c1", priced=True):
    return LLMCostRecord(
        tenant_id="t1",
        call_id=call_id,
        agent=agent,
        session_id="s1",
        provider=provider,
        model=model,
        input_tokens=100,
        output_tokens=50,
        cost_usd=cost,
        priced=priced,
        observed_at="2026-06-01T00:00:00Z",
    )


def test_store_dedupes_by_call_id():
    store = InMemoryCostStore()
    store.record_cost(_rec(call_id="dup"))
    store.record_cost(_rec(call_id="dup", cost=99.0))
    assert store.total_spend("t1") == 1.0


def test_total_spend_scoped_by_agent():
    store = InMemoryCostStore()
    store.record_cost(_rec(agent="a", call_id="1", cost=2.0))
    store.record_cost(_rec(agent="b", call_id="2", cost=3.0))
    assert store.total_spend("t1") == 5.0
    assert store.total_spend("t1", agent="a") == 2.0


def test_summarize_rollups():
    records = [
        _rec(agent="a", model="gpt-4o", call_id="1", cost=2.0),
        _rec(agent="b", model="gpt-4o-mini", call_id="2", cost=0.5),
        _rec(agent="a", model="gpt-4o", call_id="3", cost=1.0, priced=False),
    ]
    report = summarize(records)
    assert report["total_cost_usd"] == 3.5
    assert report["total_calls"] == 3
    assert report["unpriced_calls"] == 1
    top_agent = report["by_agent"][0]
    assert top_agent["key"] == "a" and top_agent["cost_usd"] == 3.0


def test_budget_status_exceeded():
    budget = CostBudget(tenant_id="t1", agent="", limit_usd=10.0, updated_at="2026-06-01T00:00:00Z")
    assert budget_status(5.0, budget)["exceeded"] is False
    assert budget_status(10.0, budget)["exceeded"] is True
    assert budget_status(12.0, budget)["remaining_usd"] == -2.0
    assert budget_status(5.0, None)["configured"] is False


def test_zero_budget_is_a_hard_cap():
    # A zero budget means "no spend allowed" — any spend must flag exceeded.
    budget = CostBudget(tenant_id="t1", agent="", limit_usd=0.0, updated_at="2026-06-01T00:00:00Z")
    assert budget_status(0.01, budget)["exceeded"] is True
    assert budget_status(0.0, budget)["exceeded"] is True
    assert budget_status(0.0, budget)["utilization"] is None  # no divide-by-zero


# ── end-to-end via the API ──────────────────────────────────────────────────────


def _ml_otlp_payload():
    return {
        "resourceSpans": [
            {
                "scopeSpans": [
                    {
                        "scope": {"name": "openai"},
                        "spans": [
                            {
                                "traceId": "trace-cost-1",
                                "spanId": "span-cost-1",
                                "name": "openai.chat.completions",
                                "startTimeUnixNano": 1_000_000_000,
                                "endTimeUnixNano": 2_000_000_000,
                                "attributes": [
                                    {"key": "gen_ai.system", "value": {"stringValue": "openai"}},
                                    {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-4o"}},
                                    {"key": "gen_ai.usage.input_tokens", "value": {"intValue": 1_000_000}},
                                    {"key": "gen_ai.usage.output_tokens", "value": {"intValue": 1_000_000}},
                                    {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
                                ],
                                "status": {"code": 0},
                            }
                        ],
                    }
                ]
            }
        ]
    }


@pytest.fixture()
def client():
    from starlette.testclient import TestClient

    from agent_bom.api.server import app

    set_cost_store(InMemoryCostStore())
    try:
        yield TestClient(app)
    finally:
        set_cost_store(None)


def test_traces_ingest_persists_costs_and_endpoint_reports(client):
    resp = client.post("/v1/traces", json=_ml_otlp_payload())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["llm_calls"] == 1
    assert body["llm_cost_usd"] == 12.5

    costs = client.get("/v1/observability/costs").json()
    assert costs["total_cost_usd"] == 12.5
    assert costs["total_calls"] == 1
    assert costs["by_model"][0]["key"] == "gpt-4o"
    assert costs["budget"]["configured"] is False


def test_set_budget_then_exceeded_flag(client):
    client.post("/v1/traces", json=_ml_otlp_payload())  # $12.50 spend
    put = client.put("/v1/observability/costs/budget", json={"limit_usd": 10.0})
    assert put.status_code == 200, put.text
    assert put.json()["exceeded"] is True

    status = client.get("/v1/observability/costs/budget").json()
    assert status["limit_usd"] == 10.0
    assert status["exceeded"] is True
    assert status["spend_usd"] == 12.5


def test_set_budget_rejects_bad_input(client):
    assert client.put("/v1/observability/costs/budget", json={}).status_code == 400
    assert client.put("/v1/observability/costs/budget", json={"limit_usd": -5}).status_code == 400


def test_check_budget_enforcement_modes():
    from agent_bom.api.cost_store import check_budget_enforcement

    store = InMemoryCostStore()
    store.record_cost(_rec(agent="a", cost=12.5, call_id="x"))
    # report mode never blocks, even over limit
    store.set_budget(CostBudget("t1", "a", 10.0, "2026-06-02", "report"))
    assert check_budget_enforcement(store, "t1", "a")[0] is False
    # enforce + over limit blocks; enforce + under does not
    store.set_budget(CostBudget("t1", "a", 10.0, "2026-06-02", "enforce"))
    assert check_budget_enforcement(store, "t1", "a")[0] is True
    store.set_budget(CostBudget("t1", "a", 100.0, "2026-06-02", "enforce"))
    assert check_budget_enforcement(store, "t1", "a")[0] is False


def test_tenant_wide_enforce_budget_blocks_unscoped_agent():
    from agent_bom.api.cost_store import check_budget_enforcement

    store = InMemoryCostStore()
    store.record_cost(_rec(agent="b", cost=12.5, call_id="y"))
    store.set_budget(CostBudget("t1", "", 10.0, "2026-06-02", "enforce"))
    assert check_budget_enforcement(store, "t1", "b")[0] is True


def test_set_budget_mode_via_api(client):
    put = client.put("/v1/observability/costs/budget", json={"limit_usd": 5.0, "mode": "enforce"})
    assert put.status_code == 200, put.text
    assert put.json()["mode"] == "enforce"
    bad = client.put("/v1/observability/costs/budget", json={"limit_usd": 5.0, "mode": "bogus"})
    assert bad.status_code == 400
