"""Overview identity metrics are uncapped records, never implied unique actors."""

from types import SimpleNamespace

import pytest
from starlette.requests import Request

from agent_bom.api.agent_identity_store import AgentIdentity, InMemoryAgentIdentityStore, SQLiteAgentIdentityStore
from agent_bom.api.routes import overview


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_identity_aggregate_is_uncapped_and_tenant_scoped(tmp_path, monkeypatch, backend):
    store = InMemoryAgentIdentityStore() if backend == "memory" else SQLiteAgentIdentityStore(str(tmp_path / "identities.db"))
    for n in range(1003):
        store.put(
            AgentIdentity(
                identity_id=f"id:{n}",
                agent_id="shared-agent",
                tenant_id="tenant-a",
                token_hash=f"hash:{n}",
                token_prefix="test",
                role="viewer",
                blueprint_id="",
                status="active",
                issued_at="2026-01-01T00:00:00+00:00",
                expires_at="2099-01-01T00:00:00+00:00",
            )
        )
    store.put(
        AgentIdentity(
            identity_id="other",
            agent_id="shared-agent",
            tenant_id="tenant-b",
            token_hash="hash:other",
            token_prefix="test",
            role="viewer",
            blueprint_id="",
            status="active",
            issued_at="2026-01-01T00:00:00+00:00",
            expires_at="2099-01-01T00:00:00+00:00",
        )
    )
    monkeypatch.setattr("agent_bom.api.agent_identity_store.get_agent_identity_store", lambda: store)
    monkeypatch.setattr(overview, "_get_fleet_store", lambda: SimpleNamespace(list_by_tenant=lambda _tenant: []))
    monkeypatch.setattr(overview, "_tenant_id", lambda _request: "tenant-a")
    snapshot = overview._identity_snapshot(Request({"type": "http"}))
    assert snapshot["managed_identities"] == 1003
    assert snapshot["managed_identities_available"] is True
    assert snapshot["count_definition"] == "managed identity records by lifecycle status; fleet registrations are separate"
    assert store.count("tenant-b") == 1


def test_identity_failure_is_unavailable_not_zero(monkeypatch):
    def fail():
        raise RuntimeError("synthetic unavailable store")

    monkeypatch.setattr("agent_bom.api.agent_identity_store.get_agent_identity_store", fail)
    monkeypatch.setattr(overview, "_get_fleet_store", fail)
    monkeypatch.setattr(overview, "_tenant_id", lambda _request: "tenant-a")
    snapshot = overview._identity_snapshot(Request({"type": "http"}))
    assert snapshot["managed_identities"] is None
    assert snapshot["fleet_agents"] is None
    assert overview._identity_status(snapshot) == "unavailable"


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_identity_count_matches_lifecycle_selection(tmp_path, backend):
    store = InMemoryAgentIdentityStore() if backend == "memory" else SQLiteAgentIdentityStore(str(tmp_path / "lifecycle.db"))
    for status in ("active", "rotating", "revoked", "expired"):
        store.put(
            AgentIdentity(
                identity_id=status,
                agent_id="a",
                tenant_id="tenant-a",
                token_hash=status,
                token_prefix="test",
                role="viewer",
                blueprint_id="",
                status=status,
                issued_at="2026-01-01T00:00:00Z",
                expires_at="2026-01-02T00:00:00Z",
            )
        )
    assert store.count("tenant-a") == len(store.list("tenant-a")) == 2
    assert store.count("tenant-a", include_inactive=True) == len(store.list("tenant-a", include_inactive=True)) == 4
    assert store.count("other", include_inactive=True) == 0
