"""FinOps cost pipeline: pricing, persistence/aggregation, and the API surface."""

from __future__ import annotations

import pytest

from agent_bom.api.cost_store import (
    CostBudget,
    InMemoryCostStore,
    LLMCostRecord,
    SQLiteCostStore,
    budget_status,
    set_cost_store,
    summarize,
)
from agent_bom.cost_model import (
    RATE_LIST_PRICE,
    RATE_RECONCILED,
    RATE_UNPRICED,
    ModelPrice,
    compute_cost_usd,
    is_priced,
    lookup_price,
    price_call,
    reset_price_overrides,
)


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


# ── reconcilable rates (estimate vs reconciled actual) ───────────────────────────


def test_price_call_defaults_to_list_price_estimate():
    # No override anywhere: figure equals the static table and is labelled an
    # estimate so the UI can show 'list-price estimate'.
    rated = price_call("openai", "gpt-4o", 1_000_000, 1_000_000)
    assert rated.cost_usd == compute_cost_usd("openai", "gpt-4o", 1_000_000, 1_000_000) == 12.5
    assert rated.priced is True
    assert rated.rate_source == RATE_LIST_PRICE
    assert rated.is_estimated is True


def test_injected_rates_override_static_and_label_reconciled():
    # An injected negotiated rate wins over the static list price and is labelled
    # a reconciled actual (not an estimate).
    rates = {"openai": {"gpt-4o": ModelPrice(1.0, 2.0)}}
    rated = price_call("openai", "gpt-4o", 1_000_000, 1_000_000, rates=rates)
    assert rated.cost_usd == 3.0  # 1.0 + 2.0, not the 12.5 list price
    assert rated.rate_source == RATE_RECONCILED
    assert rated.is_estimated is False


def test_injected_rates_accept_dict_shape_and_win_over_env(monkeypatch):
    # Injected rates take precedence over the env override table, and the dict
    # ``{input_per_mtok, output_per_mtok}`` shape is accepted.
    monkeypatch.setenv(
        "AGENT_BOM_COST_MODEL_JSON",
        '{"openai": {"gpt-4o": {"input_per_mtok": 5.0, "output_per_mtok": 5.0}}}',
    )
    reset_price_overrides()
    rates = {"openai": {"gpt-4o": {"input_per_mtok": 1.0, "output_per_mtok": 2.0}}}
    rated = price_call("openai", "gpt-4o", 1_000_000, 1_000_000, rates=rates)
    assert rated.cost_usd == 3.0
    assert rated.rate_source == RATE_RECONCILED


def test_env_override_is_reconciled(monkeypatch):
    monkeypatch.setenv(
        "AGENT_BOM_COST_MODEL_JSON",
        '{"openai": {"gpt-4o": {"input_per_mtok": 1.0, "output_per_mtok": 2.0}}}',
    )
    reset_price_overrides()
    rated = price_call("openai", "gpt-4o", 1_000_000, 1_000_000)
    assert rated.cost_usd == 3.0
    assert rated.rate_source == RATE_RECONCILED
    assert rated.is_estimated is False


def test_unpriced_call_is_unpriced_estimate():
    rated = price_call("openai", "totally-unknown-model", 1_000, 1_000)
    assert rated.cost_usd == 0.0
    assert rated.priced is False
    assert rated.rate_source == RATE_UNPRICED
    assert rated.is_estimated is True


def test_malformed_injected_rate_is_skipped_not_raised():
    # A bad negotiated-rate row must not break pricing; it falls back to list.
    rates = {"openai": {"gpt-4o": {"input_per_mtok": "oops"}}}
    rated = price_call("openai", "gpt-4o", 1_000_000, 1_000_000, rates=rates)
    assert rated.rate_source == RATE_LIST_PRICE
    assert rated.cost_usd == 12.5


def test_record_rate_source_round_trips_through_sqlite(tmp_path):
    store = SQLiteCostStore(str(tmp_path / "cost.db"))
    store.record_cost(_rec(call_id="est", cost_center=""))  # default: list_price
    store.record_cost(
        LLMCostRecord(
            tenant_id="t1",
            call_id="actual",
            agent="agent-a",
            session_id="s1",
            provider="openai",
            model="gpt-4o",
            input_tokens=100,
            output_tokens=50,
            cost_usd=1.0,
            priced=True,
            observed_at="2026-06-01T00:00:00Z",
            rate_source=RATE_RECONCILED,
            is_estimated=False,
        )
    )
    by_id = {r.call_id: r for r in store.list_records("t1")}
    assert by_id["est"].rate_source == RATE_LIST_PRICE
    assert by_id["est"].is_estimated is True
    assert by_id["actual"].rate_source == RATE_RECONCILED
    assert by_id["actual"].is_estimated is False


def test_summarize_reports_estimated_vs_reconciled():
    records = [
        _rec(call_id="a", cost=2.0),  # estimated (default)
        LLMCostRecord(
            tenant_id="t1",
            call_id="b",
            agent="agent-a",
            session_id="s1",
            provider="openai",
            model="gpt-4o",
            input_tokens=1,
            output_tokens=1,
            cost_usd=3.0,
            priced=True,
            observed_at="2026-06-01T00:00:00Z",
            rate_source=RATE_RECONCILED,
            is_estimated=False,
        ),
    ]
    out = summarize(records)
    assert out["estimated_calls"] == 1
    assert out["reconciled_calls"] == 1
    assert out["reconciled_cost_usd"] == 3.0


# ── store + aggregation ─────────────────────────────────────────────────────────


def _rec(agent="agent-a", model="gpt-4o", provider="openai", cost=1.0, call_id="c1", priced=True, cost_center="", allocation_tags=None):
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
        cost_center=cost_center,
        allocation_tags=allocation_tags or {},
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


# ── chargeback / showback allocation (#2925) ────────────────────────────────────


def test_by_cost_center_rollup():
    records = [
        _rec(call_id="1", cost=2.0, cost_center="team-search"),
        _rec(call_id="2", cost=3.0, cost_center="team-search"),
        _rec(call_id="3", cost=1.0, cost_center="team-rag"),
        _rec(call_id="4", cost=0.5),  # unallocated
    ]
    report = summarize(records)
    by_cc = {b["key"]: b["cost_usd"] for b in report["by_cost_center"]}
    assert by_cc["team-search"] == 5.0
    assert by_cc["team-rag"] == 1.0
    assert by_cc["unallocated"] == 0.5
    # top bucket sorts by spend
    assert report["by_cost_center"][0]["key"] == "team-search"


def test_summarize_by_tag():
    from agent_bom.api.cost_store import summarize_by_tag

    records = [
        _rec(call_id="1", cost=2.0, allocation_tags={"env": "prod"}),
        _rec(call_id="2", cost=4.0, allocation_tags={"env": "prod"}),
        _rec(call_id="3", cost=1.0, allocation_tags={"env": "dev"}),
        _rec(call_id="4", cost=0.5),  # no env tag -> unallocated
    ]
    report = summarize_by_tag(records, "env")
    assert report["tag_key"] == "env"
    by_tag = {b["key"]: b["cost_usd"] for b in report["by_tag"]}
    assert by_tag == {"prod": 6.0, "dev": 1.0, "unallocated": 0.5}


def test_total_spend_by_cost_center():
    store = InMemoryCostStore()
    store.record_cost(_rec(call_id="1", cost=2.0, cost_center="team-a"))
    store.record_cost(_rec(call_id="2", cost=3.0, cost_center="team-a"))
    store.record_cost(_rec(call_id="3", cost=9.0, cost_center="team-b"))
    assert store.total_spend_by_cost_center("t1", "team-a") == 5.0
    assert store.total_spend_by_cost_center("t1", "team-b") == 9.0
    assert store.total_spend_by_cost_center("t1", "team-missing") == 0.0


def test_cost_center_budget_keyed_independently_of_agent():
    store = InMemoryCostStore()
    store.set_budget(CostBudget("t1", "", 10.0, "2026-06-02", "enforce", cost_center="team-a"))
    store.set_budget(CostBudget("t1", "agent-x", 99.0, "2026-06-02", "report"))
    cc_budget = store.get_budget("t1", "", cost_center="team-a")
    assert cc_budget is not None and cc_budget.limit_usd == 10.0 and cc_budget.cost_center == "team-a"
    # agent budget is a different key, untouched by the cost-center budget
    agent_budget = store.get_budget("t1", "agent-x")
    assert agent_budget is not None and agent_budget.limit_usd == 99.0


def test_check_cost_center_budget_enforcement():
    from agent_bom.api.cost_store import check_cost_center_budget_enforcement

    store = InMemoryCostStore()
    store.record_cost(_rec(call_id="1", cost=8.0, cost_center="team-a"))
    store.record_cost(_rec(call_id="2", cost=5.0, cost_center="team-a"))
    # report mode never blocks
    store.set_budget(CostBudget("t1", "", 10.0, "2026-06-02", "report", cost_center="team-a"))
    assert check_cost_center_budget_enforcement(store, "t1", "team-a")[0] is False
    # enforce + over limit (13 >= 10) blocks
    store.set_budget(CostBudget("t1", "", 10.0, "2026-06-02", "enforce", cost_center="team-a"))
    assert check_cost_center_budget_enforcement(store, "t1", "team-a")[0] is True
    # enforce + under limit does not
    store.set_budget(CostBudget("t1", "", 100.0, "2026-06-02", "enforce", cost_center="team-a"))
    assert check_cost_center_budget_enforcement(store, "t1", "team-a")[0] is False
    # no cost center -> never blocks
    assert check_cost_center_budget_enforcement(store, "t1", "")[0] is False


def test_sqlite_store_persists_allocation(tmp_path):
    from agent_bom.api.cost_store import SQLiteCostStore

    db = str(tmp_path / "alloc.db")
    store = SQLiteCostStore(db)
    store.record_cost(_rec(call_id="1", cost=2.0, cost_center="team-a", allocation_tags={"env": "prod", "team": "search"}))
    store.set_budget(CostBudget("t1", "", 5.0, "2026-06-02", "enforce", cost_center="team-a"))
    # reopen to prove durability + migration idempotency
    store2 = SQLiteCostStore(db)
    rec = store2.list_records("t1")[0]
    assert rec.cost_center == "team-a"
    assert rec.allocation_tags == {"env": "prod", "team": "search"}
    assert store2.total_spend_by_cost_center("t1", "team-a") == 2.0
    budget = store2.get_budget("t1", "", cost_center="team-a")
    assert budget is not None and budget.limit_usd == 5.0 and budget.mode == "enforce"


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


def _ml_otlp_payload_with_allocation():
    payload = _ml_otlp_payload()
    payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"].extend(
        [
            {"key": "agent.cost_center", "value": {"stringValue": "team-search"}},
            {"key": "allocation.tag.env", "value": {"stringValue": "prod"}},
        ]
    )
    return payload


def test_ingest_maps_cost_center_and_tags(client):
    resp = client.post("/v1/traces", json=_ml_otlp_payload_with_allocation())
    assert resp.status_code == 200, resp.text

    costs = client.get("/v1/observability/costs?tag=env").json()
    by_cc = {b["key"]: b["cost_usd"] for b in costs["by_cost_center"]}
    assert by_cc["team-search"] == 12.5
    by_tag = {b["key"]: b["cost_usd"] for b in costs["tag_rollup"]["by_tag"]}
    assert by_tag["prod"] == 12.5

    scoped = client.get("/v1/observability/costs?cost_center=team-search").json()
    assert scoped["total_cost_usd"] == 12.5


def test_cost_center_budget_via_api(client):
    client.post("/v1/traces", json=_ml_otlp_payload_with_allocation())  # $12.50 to team-search
    put = client.put("/v1/observability/costs/budget", json={"limit_usd": 10.0, "cost_center": "team-search", "mode": "enforce"})
    assert put.status_code == 200, put.text
    body = put.json()
    assert body["cost_center"] == "team-search"
    assert body["exceeded"] is True
    assert body["mode"] == "enforce"

    status = client.get("/v1/observability/costs/budget?cost_center=team-search").json()
    assert status["spend_usd"] == 12.5
    assert status["exceeded"] is True


def test_agent_and_cost_center_budget_mutually_exclusive(client):
    bad = client.put("/v1/observability/costs/budget", json={"limit_usd": 5.0, "agent": "a", "cost_center": "team-x"})
    assert bad.status_code == 400
