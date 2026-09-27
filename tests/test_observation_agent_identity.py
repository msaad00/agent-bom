"""Agent names never establish observation membership, even if unique today."""

import pytest
from starlette.testclient import TestClient

from agent_bom.agent_manifest import build_control_plane_agent_manifest
from agent_bom.api import stores
from agent_bom.api.fleet_store import FleetAgent, InMemoryFleetStore
from agent_bom.api.mcp_observation_store import (
    InMemoryMCPObservationStore,
    MCPObservation,
    SQLiteMCPObservationStore,
    agent_observation_id,
    merge_observations,
)
from agent_bom.api.routes.discovery import _observation_ids
from agent_bom.api.server import app
from agent_bom.models import Agent, AgentType, MCPServer
from tests._host_discovery import host_bound_to


def observed(**kwargs):
    return MCPObservation(observation_id="receipt", server_stable_id="server", server_name="tools", agent_name="same", **kwargs)


def uses(manifest):
    return {(edge["source"], edge["target"]) for edge in manifest["graph"]["edges"] if edge["relationship"] == "uses"}


def test_same_name_uses_explicit_identity_and_survives_rename():
    fleet = [FleetAgent(agent_id=key, canonical_id=f"canonical-{key}", name="same", agent_type="custom") for key in ("a", "b")]
    receipt = observed(agent_id="b", agent_canonical_id="canonical-b")
    assert uses(build_control_plane_agent_manifest(fleet, [receipt], tenant_id="default")) == {("b", "server")}
    fleet[1].name = "renamed"
    assert uses(build_control_plane_agent_manifest(fleet, [receipt], tenant_id="default")) == {("b", "server")}


@pytest.mark.parametrize("binding", [{}, {"agent_id": "missing"}, {"agent_id": "a", "agent_canonical_id": "wrong"}])
def test_unbound_and_conflicting_receipts_never_fall_back_to_unique_name(binding):
    fleet = [FleetAgent(agent_id="a", name="same", agent_type="custom")]
    manifest = build_control_plane_agent_manifest(fleet, [observed(**binding)], tenant_id="default")
    assert uses(manifest) == set()
    assert manifest["mcp_servers"][0]["agent_binding"] == "unbound"


def test_cross_tenant_and_ambiguous_canonical_ids_cannot_bind():
    fleet = [FleetAgent(agent_id=key, canonical_id="shared", name="same", agent_type="custom") for key in ("a", "b")]
    assert uses(build_control_plane_agent_manifest(fleet, [observed(agent_canonical_id="shared")], tenant_id="default")) == set()
    assert uses(build_control_plane_agent_manifest(fleet, [observed(agent_id="a", tenant_id="other")], tenant_id="default")) == set()


def test_discovery_observation_key_distinguishes_same_name_deployments():
    server = MCPServer(name="tools", command="tools")
    a, b = [Agent(name="same", agent_type=AgentType.CUSTOM, config_path=path) for path in ("/a/config", "/b/config")]
    assert _observation_ids(a, server)[0] != _observation_ids(b, server)[0]
    assert _observation_ids(a, server)[1] is None
    before = _observation_ids(a, server, {"agent_id": "registered-id"})
    a.name = "renamed"
    assert _observation_ids(a, server, {"agent_id": "registered-id"}) == before
    assert agent_observation_id("a:b", "c") != agent_observation_id("a", "b:c")


def test_merge_rejects_other_agent_or_tenant():
    with pytest.raises(ValueError, match="agent identity"):
        merge_observations(observed(agent_id="a"), observed(agent_id="b"))
    with pytest.raises(ValueError, match="tenant mismatch"):
        merge_observations(observed(agent_id="a"), observed(agent_id="a", tenant_id="other"))
    with pytest.raises(ValueError, match="agent identity"):
        merge_observations(observed(), observed(agent_id="a"))


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_identity_fields_roundtrip_and_tenant_isolation(backend, tmp_path):
    store = InMemoryMCPObservationStore() if backend == "memory" else SQLiteMCPObservationStore(str(tmp_path / "observations.db"))
    store.put(observed(agent_id="a", agent_canonical_id="canonical-a"))
    result = store.get("default", "receipt")
    assert result.agent_id == "a"
    assert result.agent_canonical_id == "canonical-a"
    assert store.get("other", "receipt") is None


def test_fleet_sync_same_name_identity_and_rename(monkeypatch):
    fleet, observations = InMemoryFleetStore(), InMemoryMCPObservationStore()
    monkeypatch.setattr(stores, "_fleet_store", fleet)
    monkeypatch.setattr(stores, "_mcp_observation_store", observations)
    client = TestClient(app)
    agents = [
        {"name": "same", "agent_type": "custom", "canonical_id": key, "mcp_servers": [{"name": "tools", "stable_id": "server"}]}
        for key in ("provider-deployment-a", "provider-deployment-b")
    ]
    response = client.post("/v1/fleet/sync", json={"source_id": "provider-account", "agents": agents})
    assert response.status_code == 200, response.text
    rows = fleet.list_by_tenant("default")
    assert len(rows) == 2
    ids = {row.canonical_id: row.agent_id for row in rows}
    assert {row.agent_id for row in observations.list_by_tenant("default")} == set(ids.values())
    agents[1]["name"] = "renamed"
    response = client.post("/v1/fleet/sync", json={"source_id": "provider-account", "agents": [agents[1]]})
    assert response.status_code == 200, response.text
    assert len(fleet.list_by_tenant("default")) == 2
    assert fleet.get(ids["provider-deployment-b"], tenant_id="default").name == "renamed"


def test_agent_detail_rejects_ambiguous_label_and_accepts_exact_id(monkeypatch):
    for key, value in host_bound_to("default").items():
        monkeypatch.setenv(key, value)
    agents = [Agent(name="same", agent_type=AgentType.CUSTOM, config_path=path) for path in ("/a", "/b")]
    monkeypatch.setattr("agent_bom.api.routes.discovery._discover_agents_with_demo_fallback", lambda: agents)
    monkeypatch.setattr(stores, "_fleet_store", InMemoryFleetStore())
    client = TestClient(app)
    assert client.get("/v1/agents/same").status_code == 409
    result = client.get(f"/v1/agents/{agents[1].canonical_id}")
    assert result.status_code == 200, result.text
    assert result.json()["agent"]["canonical_id"] == agents[1].canonical_id


def test_scan_history_does_not_correlate_by_agent_or_server_label(monkeypatch):
    from types import SimpleNamespace

    from agent_bom.api.routes.discovery import _build_scan_history_index

    job = SimpleNamespace(result={"agents": [{"name": "same", "mcp_servers": [{"name": "tools"}]}]}, created_at="", completed_at="")
    monkeypatch.setattr("agent_bom.api.routes.discovery._completed_jobs", lambda tenant: [job])
    assert _build_scan_history_index("default") == {}
    job.result["agents"][0]["canonical_id"] = "agent-1"
    job.result["agents"][0]["mcp_servers"][0]["canonical_id"] = "server-1"
    assert set(_build_scan_history_index("default")) == {("agent-1", "server-1")}


def test_sync_rejects_name_only_and_cross_source_rebinding_before_writes(monkeypatch):
    fleet = InMemoryFleetStore()
    monkeypatch.setattr(stores, "_fleet_store", fleet)
    client = TestClient(app)
    assert client.post("/v1/fleet/sync", json={"agents": [{"name": "same"}]}).status_code == 422
    fleet.put(FleetAgent(agent_id="registered", canonical_id="native-id", source_id="source-a", name="same", agent_type="custom"))
    result = client.post("/v1/fleet/sync", json={"source_id": "source-b", "agents": [{"name": "same", "canonical_id": "native-id"}]})
    assert result.status_code == 409
    assert len(fleet.list_by_tenant("default")) == 1
    assert fleet.get("registered", tenant_id="default").source_id == "source-a"
