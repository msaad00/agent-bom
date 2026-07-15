"""Accepting drift promotes a NEW pending blueprint version (never auto-approved).

Covers #3905: resolving a drift incident with an "accept drift" disposition
composes a new draft version of the governing persisted blueprint from the
observed (drifted) state and submits it for approval (draft -> pending). A plain
close keeps the historical close-only behavior. Accepting drift never
auto-approves — the new version still requires the approve capability.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api.blueprint_store import (
    STATUS_APPROVED,
    STATUS_PENDING,
    InMemoryBlueprintStore,
    promote_drift_to_draft_version,
    seed_blueprints_from_archetypes,
    set_blueprint_store,
)
from agent_bom.api.drift_incident_store import DriftIncident, InMemoryDriftIncidentStore, set_drift_incident_store

# ── lifecycle unit ───────────────────────────────────────────────────────────


def test_promote_creates_pending_version_not_approved():
    store = InMemoryBlueprintStore()
    seed_blueprints_from_archetypes(store, tenant_id="t1")
    bp = next(b for b in store.iter_all_blueprints() if b.seeded_from == "developer")
    assert bp.current_version == 1 and bp.approval_status == STATUS_APPROVED

    version = promote_drift_to_draft_version(
        store,
        tenant_id="t1",
        blueprint_id=bp.blueprint_id,
        observed_categories=["production_write"],
        incident_id="inc-x",
        created_by="alice",
    )
    assert version is not None
    # New version enters the approval workflow at pending — not approved.
    assert version.version == 2
    assert version.status == STATUS_PENDING
    # The observed drift is folded into the new composition, and the base
    # (approved) composition is preserved.
    assert "production_write" in version.composition.tools
    assert "accepted_drift:inc-x" in version.composition.guardrails
    # Header reflects a pending latest version; the in-effect approved version is
    # still v1 (accepting drift did NOT auto-approve).
    refreshed = store.get_blueprint("t1", bp.blueprint_id)
    assert refreshed is not None
    assert refreshed.latest_version == 2
    assert refreshed.approval_status == STATUS_PENDING
    assert refreshed.current_version == 1


def test_promote_missing_blueprint_returns_none():
    store = InMemoryBlueprintStore()
    assert (
        promote_drift_to_draft_version(store, tenant_id="t1", blueprint_id="nope", observed_categories=["x"]) is None
    )


# ── API surface ──────────────────────────────────────────────────────────────


@pytest.fixture()
def client():
    from agent_bom.api.server import app

    bp_store = InMemoryBlueprintStore()
    seed_blueprints_from_archetypes(bp_store, tenant_id="default")
    set_blueprint_store(bp_store)

    drift_store = InMemoryDriftIncidentStore()
    drift_store.upsert(
        DriftIncident(
            incident_id="inc-1",
            tenant_id="default",
            blueprint_id="developer",
            status="drift_detected",
            drift_score=0.6,
            violation_count=1,
            warning_count=0,
            top_violations=[{"tool_name": "deploy", "category": "production_write", "severity": "high"}],
            first_detected_at="2026-06-01T00:00:00Z",
            last_detected_at="2026-06-01T00:00:00Z",
        )
    )
    set_drift_incident_store(drift_store)
    try:
        yield TestClient(app), bp_store
    finally:
        set_drift_incident_store(None)
        set_blueprint_store(None)


def _seed_bid(bp_store: InMemoryBlueprintStore) -> str:
    return next(b for b in bp_store.iter_all_blueprints() if b.seeded_from == "developer").blueprint_id


def test_accept_drift_emits_pending_version(client):
    api, bp_store = client
    bid = _seed_bid(bp_store)

    resp = api.post("/v1/runtime/drift/incidents/inc-1/resolve", json={"disposition": "accept_drift", "note": "own it"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["resolved"] is True
    assert body["disposition"] == "accept_drift"
    promoted = body["promoted_version"]
    assert promoted is not None
    assert promoted["blueprint_id"] == bid
    assert promoted["version"] == 2
    assert promoted["status"] == "pending"

    # The new version is visible and pending; the approved (in-effect) version is
    # still v1 — accepting drift required a fresh approval, not a silent apply.
    detail = api.get(f"/v1/governance/blueprints/{bid}").json()
    assert detail["blueprint"]["approval_status"] == "pending"
    assert detail["blueprint"]["current_version"] == 1
    v2 = api.get(f"/v1/governance/blueprints/{bid}/versions/2").json()["version"]
    assert v2["status"] == "pending"
    assert "production_write" in v2["composition"]["tools"]


def test_plain_close_does_not_promote(client):
    api, bp_store = client
    bid = _seed_bid(bp_store)

    resp = api.post("/v1/runtime/drift/incidents/inc-1/resolve", json={"note": "ignored", "disposition": "reject"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["resolved"] is True
    assert body["disposition"] == "reject"
    assert "promoted_version" not in body
    # No new version created — the blueprint still has a single approved version.
    detail = api.get(f"/v1/governance/blueprints/{bid}").json()
    assert detail["blueprint"]["latest_version"] == 1
    assert detail["blueprint"]["approval_status"] == "approved"


def test_accepted_drift_version_still_requires_approve_capability(client, monkeypatch):
    api, bp_store = client
    bid = _seed_bid(bp_store)
    api.post("/v1/runtime/drift/incidents/inc-1/resolve", json={"disposition": "accept"})
    # A non-admin contributor cannot approve the promoted pending version.
    monkeypatch.setenv("AGENT_BOM_NO_AUTH_ROLE", "analyst")
    denied = api.post(f"/v1/governance/blueprints/{bid}/versions/2/approve")
    assert denied.status_code == 403, denied.text
    monkeypatch.delenv("AGENT_BOM_NO_AUTH_ROLE", raising=False)
    assert api.get(f"/v1/governance/blueprints/{bid}/versions/2").json()["version"]["status"] == "pending"
