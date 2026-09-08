"""Headlines cover the ledger; bounded history must never masquerade as totals."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from agent_bom.api.cost_forecast import forecast_for_tenant
from agent_bom.api.cost_store import CostBudget, InMemoryCostStore, LLMCostRecord, SQLiteCostStore, set_cost_store
from agent_bom.api.routes.observability import _build_llm_costs_report_sync
from agent_bom.api.routes.overview import _cost_snapshot


@pytest.fixture(params=["memory", "sqlite"])
def ledger(request, tmp_path):
    store = InMemoryCostStore() if request.param == "memory" else SQLiteCostStore(str(tmp_path / "cost.db"))
    old = LLMCostRecord("t1", "old", "older-agent", "s", "provider", "model", 100, 50, 2.5, True, "2026-06-01T00:00:00Z", "engineering")
    store.record_cost(old)
    store.record_cost(
        replace(old, call_id="unpriced", agent="new-agent", cost_usd=0, priced=False, observed_at="2026-06-02T00:00:00Z", cost_center="")
    )
    store.record_cost(replace(old, tenant_id="other", call_id="private", cost_usd=999))
    set_cost_store(store)
    yield store
    set_cost_store(None)


def test_complete_totals_survive_bounded_history(ledger):
    report = _build_llm_costs_report_sync("t1", agent=None, cost_center=None, tag=None, limit=1)
    assert report["total_calls"] == 2
    assert report["total_cost_usd"] == 2.5
    assert report["total_input_tokens"] == 200
    assert report["unpriced_calls"] == 1
    assert report["agents"] == 2
    assert report["history"]["returned_calls"] == 1
    assert report["history"]["complete"] is False
    assert report["forecast"]["status"] == "incomplete_history"
    assert report["forecast"]["burn_rate_usd_per_day"] is None
    snapshot = _cost_snapshot(SimpleNamespace(state=SimpleNamespace(tenant_id="t1")))
    assert snapshot["total_cost_usd"] == report["total_cost_usd"]
    assert snapshot["total_calls"] == report["total_calls"]


def test_filters_apply_before_history_limit(ledger):
    report = _build_llm_costs_report_sync("t1", agent="older-agent", cost_center="engineering", tag=None, limit=1)
    assert report["total_calls"] == 1
    assert report["history"]["complete"] is True
    assert report["by_agent"][0]["key"] == "older-agent"
    assert report["by_cost_center"][0]["key"] == "engineering"
    assert ledger.report_totals("other")["total_cost_usd"] == 999
    assert ledger.report_totals("missing")["total_calls"] == 0


def test_tenant_budget_fallback_uses_tenant_spend(ledger):
    ledger.set_budget(CostBudget("t1", "", 2, "2026-06-01T00:00:00Z"))
    report = _build_llm_costs_report_sync("t1", agent="new-agent", cost_center=None, tag=None, limit=1)
    assert report["total_cost_usd"] == 0
    assert report["budget"]["spend_usd"] == 2.5
    assert report["budget"]["exceeded"] is True
    assert report["forecast"]["status"] == "budget_scope_mismatch"


def test_forecast_endpoint_marks_truncated_history(ledger):
    forecast = forecast_for_tenant("t1", limit=1)
    assert forecast["status"] == "incomplete_history"
    assert forecast["days_remaining"] is None
    assert forecast["current_spend_usd"] == 2.5


def test_unavailable_store_is_not_zero(monkeypatch):
    def unavailable():
        raise RuntimeError("private backend detail")

    monkeypatch.setattr("agent_bom.api.cost_store.get_cost_store", unavailable)
    result = _cost_snapshot(SimpleNamespace(state=SimpleNamespace(tenant_id="t1")))
    assert result["available"] is False
    assert result["total_cost_usd"] is None
    assert result["total_calls"] is None


def test_totals_exceed_previous_overview_limit(tmp_path):
    store = SQLiteCostStore(str(tmp_path / "busy.db"))
    rec = LLMCostRecord("busy", "0", "agent", "", "provider", "model", 2, 3, 0.5, True, "2026-06-01T00:00:00Z")
    for i in range(10001):
        store.record_cost(replace(rec, call_id=str(i)))
    assert store.report_totals("busy")["total_calls"] == 10001
    assert store.report_totals("busy")["total_cost_usd"] == 5000.5
    assert store.report_totals("busy")["total_output_tokens"] == 30003


def test_postgres_totals_and_filters_enforce_rls():
    import os

    from psycopg_pool import ConnectionPool

    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_cost import PostgresCostStore

    dsn = os.environ.get("COST_REPORT_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("requires isolated Postgres with a NOSUPERUSER NOBYPASSRLS test role")
    with ConnectionPool(dsn) as pool:
        store = PostgresCostStore(pool=pool)
        token = set_current_tenant("cost-scope-a")
        try:
            rec = LLMCostRecord(
                "cost-scope-a", "older", "old-agent", "", "provider", "model", 100, 50, 2.5, True, "2026-06-01T00:00:00Z", "eng"
            )
            store.record_cost(rec)
            store.record_cost(replace(rec, call_id="newer", agent="new-agent", observed_at="2026-06-02T00:00:00Z"))
            assert store.report_totals("cost-scope-a")["total_cost_usd"] == 5
            assert store.report_totals("cost-scope-a", agent="old-agent", cost_center="eng")["total_calls"] == 1
            assert store.list_records("cost-scope-a", agent="old-agent", cost_center="eng", limit=1)[0].call_id == "older"
            sibling = set_current_tenant("cost-scope-b")
            try:
                store.record_cost(replace(rec, tenant_id="cost-scope-b", cost_usd=999))
                assert store.report_totals("cost-scope-b")["total_cost_usd"] == 999
            finally:
                reset_current_tenant(sibling)
            assert store.report_totals("cost-scope-b")["total_calls"] == 0
            assert store.list_records("cost-scope-b") == []
            assert store.report_totals("cost-scope-a")["total_calls"] == 2
        finally:
            reset_current_tenant(token)
