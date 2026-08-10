"""Demo drift incidents must reach the store the product reads.

`build_showcase_graph` computed drift incidents into a private `_DriftStore` it
handed straight back to its caller, while every drift surface — the governance
overlay, the gateway drift lookup, and the tiles above them — reads the
process-global `get_drift_incident_store()`. The estate therefore described
drift in its own graph and reported 0 incidents everywhere a viewer would look.

Same defect class as the identity, fleet, governance and gateway seeds before
it: evidence computed and never surfaced.
"""

from __future__ import annotations

import pytest

from agent_bom.demo_estate.showcase_drift import seed_showcase_drift_incidents


@pytest.fixture()
def drift_store(monkeypatch: pytest.MonkeyPatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_HOME", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_EPHEMERAL_STORE", "1")
    from agent_bom.api import drift_incident_store as mod

    mod.set_drift_incident_store(None)
    try:
        yield mod.get_drift_incident_store()
    finally:
        mod.set_drift_incident_store(None)


def test_seeding_populates_the_store_the_surfaces_query(drift_store) -> None:
    result = seed_showcase_drift_incidents(tenant_id="default")

    assert result["seeded"] > 0
    incidents = drift_store.list("default", limit=50)
    assert len(incidents) == result["seeded"]


def test_incidents_reference_seeded_blueprints(drift_store) -> None:
    """An incident pointing at a blueprint that does not exist is a dead end."""
    from agent_bom.demo_estate.showcase_governance import _BLUEPRINTS

    seed_showcase_drift_incidents(tenant_id="default")
    known = {str(b["id"]) for b in _BLUEPRINTS}

    for incident in drift_store.list("default", limit=50):
        assert incident.blueprint_id in known, incident.blueprint_id


def test_seeding_is_idempotent(drift_store) -> None:
    """Bootstrap runs on every boot; a second pass must not duplicate rows."""
    seed_showcase_drift_incidents(tenant_id="default")
    before = len(drift_store.list("default", limit=50))

    seed_showcase_drift_incidents(tenant_id="default")

    assert len(drift_store.list("default", limit=50)) == before


def test_operator_incidents_are_never_joined_by_demo_rows(drift_store) -> None:
    from agent_bom.api.drift_incident_store import DriftIncident

    drift_store.upsert(
        DriftIncident(
            incident_id="real-incident-1",
            tenant_id="default",
            blueprint_id="bp-operator-own",
            status="drift_detected",
            drift_score=0.9,
            violation_count=1,
            warning_count=0,
            top_violations=[],
            first_detected_at="2026-08-01T00:00:00+00:00",
            last_detected_at="2026-08-01T01:00:00+00:00",
        )
    )

    assert seed_showcase_drift_incidents(tenant_id="default")["seeded"] == 0
    assert len(drift_store.list("default", limit=50)) == 1
