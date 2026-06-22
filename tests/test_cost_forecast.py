"""Burn-rate forecasting and budget-runway projection over persisted costs."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agent_bom.api.cost_forecast import forecast_for_tenant, forecast_spend
from agent_bom.api.cost_store import CostBudget, InMemoryCostStore, LLMCostRecord, set_cost_store

_NOW = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


def _rec(cost: float, *, hours_ago: float, agent: str = "agent-a", call_id: str = "") -> LLMCostRecord:
    observed = (_NOW - timedelta(hours=hours_ago)).isoformat()
    return LLMCostRecord(
        tenant_id="t1",
        call_id=call_id or f"c-{agent}-{hours_ago}-{cost}",
        agent=agent,
        session_id="s1",
        provider="openai",
        model="gpt-4o",
        input_tokens=10,
        output_tokens=10,
        cost_usd=cost,
        priced=True,
        observed_at=observed,
    )


def _budget(limit: float, *, agent: str = "", mode: str = "report") -> CostBudget:
    return CostBudget(tenant_id="t1", agent=agent, limit_usd=limit, updated_at="2026-06-01T00:00:00Z", mode=mode)


# ── steady burn → correct runway ───────────────────────────────────────────────


def test_steady_burn_yields_expected_runway():
    # $1/hour for 24h = $24 spent, $24/day burn. Budget $120, $96 remaining -> 4 days.
    records = [_rec(1.0, hours_ago=h) for h in range(1, 25)]
    fc = forecast_spend(records, budget=_budget(120.0), now=_NOW)
    assert fc["status"] == "ok"
    assert fc["current_spend_usd"] == 24.0
    assert fc["burn_rate_usd_per_day"] == pytest.approx(24.0, rel=0.05)
    assert fc["days_remaining"] == pytest.approx(4.0, rel=0.05)
    exhaustion = datetime.fromisoformat(fc["projected_exhaustion_at"])
    assert (exhaustion - _NOW).total_seconds() == pytest.approx(4 * 86400, rel=0.05)


def test_projected_period_spend_extends_current():
    records = [_rec(2.0, hours_ago=h) for h in range(1, 25)]  # $48 over 24h
    fc = forecast_spend(records, budget=_budget(1000.0), now=_NOW)
    # Period runs to end of June; projected spend must exceed what's already spent.
    assert fc["projected_period_spend_usd"] > fc["current_spend_usd"]
    assert fc["period_end"].startswith("2026-07-01")


# ── accelerating burn → 24h rate dominates, shorter runway ─────────────────────


def test_accelerating_burn_uses_faster_window():
    # Calm 7d baseline (small spend long ago) plus a sharp recent spike.
    old = [_rec(0.1, hours_ago=h, call_id=f"old-{h}") for h in range(48, 168, 6)]
    spike = [_rec(5.0, hours_ago=h, call_id=f"spike-{h}") for h in range(1, 13)]
    fc = forecast_spend(old + spike, budget=_budget(10_000.0), now=_NOW)
    assert fc["status"] == "ok"
    assert fc["burn_rate_basis"] == "trailing_24h"
    # 24h rate (~$120/day from the spike) must exceed the diluted 7d rate.
    assert fc["burn_rate_usd_per_day"] > 60.0


# ── empty / sparse history → null + safe status, never raise ───────────────────


def test_empty_history_is_safe():
    fc = forecast_spend([], budget=_budget(100.0), now=_NOW)
    assert fc["status"] == "insufficient_history"
    assert fc["burn_rate_usd_per_day"] is None
    assert fc["days_remaining"] is None
    assert fc["projected_exhaustion_at"] is None


def test_single_record_is_insufficient():
    fc = forecast_spend([_rec(5.0, hours_ago=1.0)], budget=_budget(100.0), now=_NOW)
    assert fc["status"] == "insufficient_history"


def test_garbage_timestamps_do_not_raise():
    bad = [
        LLMCostRecord("t1", "x1", "a", "s", "openai", "gpt-4o", 1, 1, 3.0, True, "not-a-date"),
        LLMCostRecord("t1", "x2", "a", "s", "openai", "gpt-4o", 1, 1, 3.0, True, ""),
    ]
    fc = forecast_spend(bad, budget=_budget(100.0), now=_NOW)
    # Spend still totals, but no parseable timestamps -> insufficient history.
    assert fc["current_spend_usd"] == 6.0
    assert fc["status"] == "insufficient_history"


def test_stale_records_outside_windows():
    # All records older than 7d -> a rate cannot be derived from trailing windows.
    records = [_rec(1.0, hours_ago=h, call_id=f"s-{h}") for h in (200, 300, 400)]
    fc = forecast_spend(records, budget=_budget(100.0), now=_NOW)
    assert fc["status"] == "stale"
    assert fc["burn_rate_usd_per_day"] is None


# ── budget already exceeded → 0 days ───────────────────────────────────────────


def test_budget_already_exceeded_zero_days():
    records = [_rec(10.0, hours_ago=h) for h in range(1, 13)]  # $120 spent
    fc = forecast_spend(records, budget=_budget(50.0), now=_NOW)
    assert fc["status"] == "budget_exceeded"
    assert fc["days_remaining"] == 0.0
    assert fc["projected_exhaustion_at"] == _NOW.isoformat()
    # Still reports how fast it overran.
    assert fc["burn_rate_usd_per_day"] is not None


def test_zero_budget_is_exceeded_by_any_spend():
    records = [_rec(0.5, hours_ago=h) for h in (1, 2)]
    fc = forecast_spend(records, budget=_budget(0.0), now=_NOW)
    assert fc["status"] == "budget_exceeded"
    assert fc["days_remaining"] == 0.0


# ── no budget configured → runway is null but rate is reported ─────────────────


def test_no_budget_reports_rate_without_runway():
    records = [_rec(1.0, hours_ago=h) for h in range(1, 25)]
    fc = forecast_spend(records, budget=None, now=_NOW)
    assert fc["status"] == "no_budget"
    assert fc["burn_rate_usd_per_day"] is not None
    assert fc["projected_period_spend_usd"] is not None
    assert fc["days_remaining"] is None


# ── store-backed helper resolves budget precedence ─────────────────────────────


def test_forecast_for_tenant_prefers_agent_budget():
    store = InMemoryCostStore()
    set_cost_store(store)
    try:
        for h in range(1, 25):
            store.record_cost(_rec(1.0, hours_ago=h, agent="agent-a", call_id=f"a-{h}"))
        store.set_budget(_budget(50.0, agent=""))  # tenant-wide
        store.set_budget(_budget(120.0, agent="agent-a"))  # agent-scoped wins
        fc = forecast_for_tenant("t1", agent="agent-a", now=_NOW)
        assert fc["tenant_id"] == "t1"
        assert fc["budget_limit_usd"] == 120.0
        assert fc["status"] == "ok"
    finally:
        set_cost_store(None)


def test_forecast_for_tenant_falls_back_to_tenant_budget():
    store = InMemoryCostStore()
    set_cost_store(store)
    try:
        for h in range(1, 25):
            store.record_cost(_rec(1.0, hours_ago=h, agent="agent-b", call_id=f"b-{h}"))
        store.set_budget(_budget(200.0, agent=""))  # only tenant-wide exists
        fc = forecast_for_tenant("t1", agent="agent-b")
        assert fc["budget_limit_usd"] == 200.0
    finally:
        set_cost_store(None)


# ── API surface ────────────────────────────────────────────────────────────────


@pytest.fixture()
def client():
    from starlette.testclient import TestClient

    from agent_bom.api.server import app

    store = InMemoryCostStore()
    set_cost_store(store)
    try:
        yield TestClient(app), store
    finally:
        set_cost_store(None)


def test_forecast_endpoint_returns_projection(client):
    test_client, store = client
    now = datetime.now(timezone.utc)
    for h in range(1, 25):
        observed = (now - timedelta(hours=h)).isoformat()
        store.record_cost(LLMCostRecord("t1", f"e-{h}", "agent-a", "s", "openai", "gpt-4o", 1, 1, 1.0, True, observed))
    store.set_budget(CostBudget("t1", "", 1000.0, now.isoformat(), "report"))

    # require_request_tenant_id resolves to a default tenant in test mode; assert
    # the contract shape rather than tenant identity.
    resp = test_client.get("/v1/observability/costs/forecast")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["schema_version"] == "observability.cost_forecast.v1"
    assert "burn_rate_usd_per_day" in body
    assert "days_remaining" in body
    assert "projected_exhaustion_at" in body
    assert "projected_period_spend_usd" in body


def test_costs_endpoint_embeds_forecast(client):
    test_client, store = client
    now = datetime.now(timezone.utc)
    for h in range(1, 25):
        observed = (now - timedelta(hours=h)).isoformat()
        store.record_cost(LLMCostRecord("t1", f"c-{h}", "agent-a", "s", "openai", "gpt-4o", 1, 1, 1.0, True, observed))
    resp = test_client.get("/v1/observability/costs")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "forecast" in body
    assert body["forecast"]["schema_version"] == "observability.cost_forecast.v1"
