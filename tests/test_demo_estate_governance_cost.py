"""The governance and cost pages read stores the graph/findings seeds never touch.

On a demo estate with thousands of assets these returned:

    /v1/governance/blueprints  -> {"count": 0, "blueprints": []}
    /v1/observability/costs    -> {"total_calls": 1}

so both surfaces rendered as empty shells and read as a broken product rather
than an unconfigured one. Same defect class the fleet/runtime seed already
closed for the AI BOM page.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture()
def seeded(monkeypatch: pytest.MonkeyPatch):
    """A clean, isolated pair of stores.

    Both stores are process-level singletons resolved on first use, so setting
    the home directory alone is not enough — an already-resolved store keeps its
    original path and the seed reads as "already populated".
    """
    monkeypatch.setenv("AGENT_BOM_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("AGENT_BOM_EPHEMERAL_STORE", "1")

    from agent_bom.api import blueprint_store, cost_store
    from agent_bom.demo_estate.showcase_governance import seed_showcase_governance_and_cost

    blueprint_store.set_blueprint_store(None)
    cost_store._COST_STORE = None
    try:
        yield seed_showcase_governance_and_cost(tenant_id="default")
    finally:
        blueprint_store.set_blueprint_store(None)
        cost_store._COST_STORE = None


def _blueprints():
    from agent_bom.api.blueprint_store import get_blueprint_store

    return get_blueprint_store().list_blueprints("default", limit=100).blueprints


def _costs():
    from agent_bom.api.cost_store import get_cost_store

    return get_cost_store().list_records("default", limit=3000)


def test_blueprints_are_seeded(seeded) -> None:
    assert seeded["blueprints"] > 0
    assert len(_blueprints()) == seeded["blueprints"]


def test_blueprint_lifecycle_is_not_uniformly_approved(seeded) -> None:
    """A governance page where everything is approved shows no governance.

    The draft / pending / approved spread is what makes the approval workflow
    legible at a glance.
    """
    statuses = {blueprint.approval_status for blueprint in _blueprints()}

    assert {"approved", "pending", "draft"} <= statuses


def test_approved_versions_carry_an_approver(seeded) -> None:
    """An approved version is never orphaned — the store's own rule."""
    from agent_bom.api.blueprint_store import get_blueprint_store

    store = get_blueprint_store()
    for blueprint in _blueprints():
        if blueprint.approval_status != "approved":
            continue
        versions = store.list_versions("default", blueprint.blueprint_id)
        approved = [v for v in versions if v.status == "approved"]
        assert approved, blueprint.blueprint_id
        for version in approved:
            assert version.approver, blueprint.blueprint_id


def test_every_written_cost_record_persists(seeded) -> None:
    """The regression: one agent legitimately calls more than one model.

    Keying a record on agent+day alone made the second model overwrite the
    first, silently dropping a whole provider's spend — 84 written, 70 stored.
    """
    assert len(_costs()) == seeded["cost_records"]


def test_one_agent_can_span_multiple_models(seeded) -> None:
    """Pins the specific shape that exposed the collision."""
    pairs = {(record.agent, record.model) for record in _costs()}
    multi = [agent for agent in {a for a, _ in pairs} if len({m for a2, m in pairs if a2 == agent}) > 1]

    assert multi, "expected at least one agent calling more than one model"


def test_spend_is_enterprise_scale(seeded) -> None:
    """Leadership is the audience for this page; a ~$18 total undersells it.

    Not asserting an exact figure — only that the demo lands in a range a real
    estate would recognise rather than a rounding error.
    """
    total = sum(record.cost_usd for record in _costs())

    assert total > 1_000, f"demo spend {total} is too small to read as a real estate"


def test_spend_spans_several_cost_centers(seeded) -> None:
    """Chargeback and showback need more than one allocation unit to compare."""
    centers = {record.cost_center for record in _costs() if record.cost_center}

    assert len(centers) >= 3


def test_spend_has_a_slope_for_forecasting(seeded) -> None:
    """A flat line gives burn-rate and runway nothing to extrapolate from."""
    by_day: dict[str, float] = {}
    for record in _costs():
        by_day[record.observed_at[:10]] = by_day.get(record.observed_at[:10], 0.0) + record.cost_usd

    days = [by_day[key] for key in sorted(by_day)]
    assert len(days) > 1
    assert days[-1] > days[0]


def test_seeding_is_idempotent(seeded, monkeypatch: pytest.MonkeyPatch) -> None:
    """Bootstrap runs on every boot; a second pass must not duplicate rows."""
    from agent_bom.demo_estate.showcase_governance import seed_showcase_governance_and_cost

    before_blueprints, before_costs = len(_blueprints()), len(_costs())
    again = seed_showcase_governance_and_cost(tenant_id="default")

    assert again == {"blueprints": 0, "cost_records": 0}
    assert len(_blueprints()) == before_blueprints
    assert len(_costs()) == before_costs


# ── UTC day rollover ────────────────────────────────────────────────────────


def test_spend_tops_up_on_a_day_rollover_without_duplicating(monkeypatch: pytest.MonkeyPatch) -> None:
    """Seeded spend went permanently dark at the first midnight.

    The old guard treated "any records exist" as "already seeded", so the
    trailing window kept the boot day's timestamps forever: the cost page and
    the gateway's ``calls_today`` both counted 0 LLM calls from then on, and no
    restart short of wiping the store brought them back. Records are keyed by
    absolute date now, so a later pass fills only the days that are missing.
    """
    monkeypatch.setenv("AGENT_BOM_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("AGENT_BOM_EPHEMERAL_STORE", "1")

    from agent_bom.api import cost_store
    from agent_bom.demo_estate.showcase_governance import _seed_cost_records

    cost_store._COST_STORE = None
    try:
        today = datetime.now(timezone.utc)
        yesterday = today - timedelta(days=1)

        seeded_yesterday = _seed_cost_records(tenant_id="default", now=yesterday)
        assert seeded_yesterday > 0
        stored = cost_store.get_cost_store().list_records("default", limit=5000)
        assert not [r for r in stored if r.observed_at.startswith(today.date().isoformat())]

        topped_up = _seed_cost_records(tenant_id="default", now=today)

        assert topped_up > 0, "the day that rolled over was never filled in"
        after = cost_store.get_cost_store().list_records("default", limit=5000)
        assert [r for r in after if r.observed_at.startswith(today.date().isoformat())]
        # Only the new day is written — the thirteen days already stored are
        # left exactly as they were rather than re-priced under new ids.
        assert len(after) == len(stored) + topped_up
        assert len({r.call_id for r in after}) == len(after)
    finally:
        cost_store._COST_STORE = None


def test_operator_spend_is_never_joined_by_demo_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    """The rollover top-up must not turn into a licence to write on real data."""
    monkeypatch.setenv("AGENT_BOM_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("AGENT_BOM_EPHEMERAL_STORE", "1")

    from agent_bom.api import cost_store
    from agent_bom.api.cost_store import LLMCostRecord
    from agent_bom.demo_estate.showcase_governance import _seed_cost_records

    cost_store._COST_STORE = None
    try:
        store = cost_store.get_cost_store()
        store.record_cost(
            LLMCostRecord(
                tenant_id="default",
                call_id="operator-call-1",
                agent="real-agent",
                session_id="real-session",
                provider="anthropic",
                model="claude-sonnet-5",
                input_tokens=10,
                output_tokens=5,
                cost_usd=0.01,
                priced=True,
                observed_at=datetime.now(timezone.utc).isoformat(),
            )
        )

        assert _seed_cost_records(tenant_id="default") == 0
        assert len(store.list_records("default", limit=100)) == 1
    finally:
        cost_store._COST_STORE = None
