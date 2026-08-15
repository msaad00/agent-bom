"""Synthetic demo surfaces use the same tenant-scoped stores as real readers."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest


@pytest.fixture()
def isolated_surface_stores(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENT_BOM_EPHEMERAL_STORE", "1")

    from agent_bom.api.campaign_store import InMemoryCampaignStore, set_campaign_store
    from agent_bom.api.skills_scan_store import InMemorySkillsScanStore, set_skills_scan_store
    from agent_bom.cloud.side_scan_lifecycle import reset_side_scan_state_store

    set_campaign_store(InMemoryCampaignStore())
    set_skills_scan_store(InMemorySkillsScanStore())
    reset_side_scan_state_store()
    try:
        yield
    finally:
        set_campaign_store(None)
        set_skills_scan_store(None)
        reset_side_scan_state_store()


def test_demo_auxiliary_surfaces_are_nonempty_and_explicitly_synthetic(isolated_surface_stores) -> None:
    from agent_bom.api.campaign_store import get_campaign_store
    from agent_bom.api.skills_scan_store import get_skills_scan_store
    from agent_bom.cloud.side_scan_lifecycle import get_side_scan_state_store
    from agent_bom.demo_estate.showcase_surfaces import seed_showcase_auxiliary_surfaces

    summary = seed_showcase_auxiliary_surfaces(tenant_id="default")

    latest_skill = get_skills_scan_store().latest_for_tenant("default")
    assert latest_skill is not None
    assert latest_skill.payload["synthetic"] is True
    assert latest_skill.payload["summary"]["files_scanned"] == len(latest_skill.payload["files"]) > 0
    assert all(row["synthetic"] is True for row in latest_skill.payload["files"])

    side_scans = get_side_scan_state_store().list_recent(tenant_id="default", limit=10)
    assert side_scans
    assert all(row.account_id.startswith("synthetic-demo-") for row in side_scans)
    assert all("synthetic_demo_evidence" in row.warning_codes for row in side_scans)
    assert all(row.to_evidence_dict()["clean_workload_assertion"] is False for row in side_scans)

    queue = get_campaign_store().list_verification_queue("default", after="", limit=10)
    assert queue
    assert all(row.title.startswith("Synthetic demo:") for row in queue)
    assert all(row.owner and row.sla_due_at for row in queue)

    assert summary == {"skills_scans": 1, "cwpp_executions": 3, "verification_queue": 1}


def test_demo_auxiliary_seeding_is_idempotent(isolated_surface_stores) -> None:
    from agent_bom.api.campaign_store import get_campaign_store
    from agent_bom.api.skills_scan_store import get_skills_scan_store
    from agent_bom.cloud.side_scan_lifecycle import get_side_scan_state_store
    from agent_bom.demo_estate.showcase_surfaces import seed_showcase_auxiliary_surfaces

    first = seed_showcase_auxiliary_surfaces(tenant_id="default")
    second = seed_showcase_auxiliary_surfaces(tenant_id="default")

    assert first == {"skills_scans": 1, "cwpp_executions": 3, "verification_queue": 1}
    assert second == {"skills_scans": 0, "cwpp_executions": 0, "verification_queue": 0}
    assert len(get_skills_scan_store().list_for_tenant("default")) == 1
    assert len(get_side_scan_state_store().list_recent(tenant_id="default", limit=10)) == 3
    assert len(get_campaign_store().list_verification_queue("default", after="", limit=10)) == 1


def test_demo_cost_projection_reconciles_with_the_seeded_ledger(
    isolated_surface_stores,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """The demo forecast must stay on the same order of magnitude as its ledger."""
    monkeypatch.setenv("AGENT_BOM_HOME", str(tmp_path))

    from agent_bom.api import cost_store
    from agent_bom.api.cost_forecast import forecast_for_tenant
    from agent_bom.demo_estate.showcase_governance import seed_showcase_governance_and_cost

    cost_store._COST_STORE = None
    now = datetime.now(timezone.utc)
    try:
        seed_showcase_governance_and_cost(tenant_id="default", now=now)
        forecast = forecast_for_tenant("default", now=now)
        current = float(forecast["current_spend_usd"])
        projected = float(forecast["projected_period_spend_usd"])

        assert 1_000 < current < 100_000
        assert current <= projected < current * 10
    finally:
        cost_store._COST_STORE = None
