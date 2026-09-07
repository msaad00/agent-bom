"""Inventory counts preserve occurrence identity and shared-server memberships."""

import asyncio

import pytest
from starlette.requests import Request

from agent_bom.api.fleet_store import FleetAgent, InMemoryFleetStore, SQLiteFleetStore
from agent_bom.api.mcp_observation_store import InMemoryMCPObservationStore, MCPObservation, SQLiteMCPObservationStore
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.routes import agent_manifest, scan
from agent_bom.api.store import InMemoryJobStore, SQLiteJobStore


def _request(tenant="tenant-a"):
    return Request({"type": "http", "state": {"tenant_id": tenant}})


def _agent(environment, *, identified=True, version="5.3"):
    agent = {
        "name": "same-agent",
        "environment": environment,
        "mcp_servers": [{"name": "same-server", "packages": [{"name": "pyyaml", "version": version, "ecosystem": "pypi"}]}],
    }
    if identified:
        agent["canonical_id"] = f"agent:{environment}"
        agent["mcp_servers"][0]["canonical_id"] = f"server:{environment}"
    return agent


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_inventory_pages_preserve_distinct_occurrences_and_unknown_identity(tmp_path, monkeypatch, backend):
    store = InMemoryJobStore() if backend == "memory" else SQLiteJobStore(str(tmp_path / "jobs.db"))
    rows = [
        _agent("prod"),
        _agent("dev"),
        _agent("prod"),
        _agent("prod", version="6.0"),
        _agent("unknown", identified=False),
        _agent("unknown", identified=False),
    ]
    store.put(
        ScanJob(
            job_id="job",
            tenant_id="tenant-a",
            status=JobStatus.DONE,
            created_at="2026-09-07T10:00:00Z",
            request=ScanRequest(),
            result={"agents": rows},
        )
    )
    monkeypatch.setattr(scan, "_get_store", lambda: store)
    pages = [asyncio.run(scan.list_inventory(_request(), limit=2, offset=offset)) for offset in (0, 2, 4)]
    assert {page["package_total"] for page in pages} == {5}
    packages = [package for page in pages for package in page["packages"]]
    assert len(packages) == 5
    assert {(row["server_id"], row["version"]) for row in packages if row["server_id"]} == {
        ("server:prod", "5.3"),
        ("server:dev", "5.3"),
        ("server:prod", "6.0"),
    }
    assert sum(not row["server_id"] for row in packages) == 2
    assert asyncio.run(scan.list_inventory(_request("tenant-b"), limit=2, offset=0))["package_total"] == 0


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
@pytest.mark.parametrize("reverse", [False, True])
def test_manifest_counts_shared_server_once_without_losing_memberships(tmp_path, monkeypatch, backend, reverse):
    fleet = InMemoryFleetStore() if backend == "memory" else SQLiteFleetStore(str(tmp_path / "fleet.db"))
    observations = InMemoryMCPObservationStore() if backend == "memory" else SQLiteMCPObservationStore(str(tmp_path / "observations.db"))
    names = ["beta", "alpha"]
    if reverse:
        names.reverse()
    for name in names:
        fleet.put(FleetAgent(agent_id=f"agent-{name}", tenant_id="tenant-a", name=name, agent_type="custom", environment=name))
        observations.put(
            MCPObservation(
                tenant_id="tenant-a",
                observation_id=f"{name}:shared",
                server_stable_id="shared",
                server_name="shared-server",
                agent_name=name,
                credential_env_vars=[f"{name.upper()}_KEY"],
            )
        )
    observations.put(
        MCPObservation(
            tenant_id="tenant-a", observation_id="distinct", server_stable_id="distinct", server_name="shared-server", agent_name="alpha"
        )
    )
    monkeypatch.setattr(agent_manifest, "_get_fleet_store", lambda: fleet)
    monkeypatch.setattr(agent_manifest, "_get_mcp_observation_store", lambda: observations)
    result = asyncio.run(agent_manifest.get_agent_bom_manifest(_request()))
    assert result["summary"]["mcp_servers"] == 2
    assert len({row["id"] for row in result["mcp_servers"]}) == 2
    shared = next(row for row in result["mcp_servers"] if row["id"] == "shared")
    assert shared["agent_names"] == ["alpha", "beta"]
    assert shared["agent_name"] == ""
    assert shared["observation_ids"] == ["alpha:shared", "beta:shared"]
    assert len(shared["observations"]) == 2
    uses = {(edge["source"], edge["target"]) for edge in result["graph"]["edges"] if edge["relationship"] == "uses"}
    assert uses == {("agent-alpha", "shared"), ("agent-beta", "shared"), ("agent-alpha", "distinct")}
    assert [row["name"] for row in result["agents"]] == ["alpha", "beta"]
    assert asyncio.run(agent_manifest.get_agent_bom_manifest(_request("tenant-b")))["summary"]["mcp_servers"] == 0


def test_conflicting_canonical_aliases_remain_observation_scoped():
    from agent_bom.agent_manifest import build_control_plane_agent_manifest

    observations = [
        MCPObservation(
            tenant_id="tenant-a",
            observation_id=f"obs-{scope}",
            server_stable_id="shared-label-id",
            server_canonical_id=f"canonical:{scope}",
            server_name="same-server",
        )
        for scope in ("prod", "dev")
    ]
    result = build_control_plane_agent_manifest([], observations, tenant_id="tenant-a")
    assert result["summary"]["mcp_servers"] == 2
    assert len({row["id"] for row in result["mcp_servers"]}) == 2
    assert {row["identity_basis"] for row in result["mcp_servers"]} == {"observation"}
    assert {row["server_stable_id"] for row in result["mcp_servers"]} == {"shared-label-id"}
    assert {row["canonical_id"] for row in result["mcp_servers"]} == {"canonical:prod", "canonical:dev"}


def test_changed_contract_models_preserve_raw_response_and_publish_schemas(monkeypatch):
    from agent_bom.api.models import AgentBomManifestResponse, InventoryResponse
    from agent_bom.api.server import app

    monkeypatch.setattr(scan, "_get_store", InMemoryJobStore)
    raw = asyncio.run(scan.list_inventory(_request(), limit=2, offset=0))
    assert InventoryResponse.model_validate(raw).model_dump() == raw
    monkeypatch.setattr(agent_manifest, "_get_fleet_store", InMemoryFleetStore)
    monkeypatch.setattr(agent_manifest, "_get_mcp_observation_store", InMemoryMCPObservationStore)
    raw_manifest = asyncio.run(agent_manifest.get_agent_bom_manifest(_request()))
    assert AgentBomManifestResponse.model_validate(raw_manifest).model_dump() == raw_manifest
    schema = app.openapi()
    assert schema["paths"]["/v1/inventory"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/InventoryResponse"
    )
    assert schema["paths"]["/v1/agent-bom/manifest"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/AgentBomManifestResponse"
    )


def test_observation_scoped_conflicts_do_not_recover_membership_by_name():
    from agent_bom.agent_manifest import _graph, _observed_server_entities

    observations = [
        MCPObservation(
            tenant_id="tenant-a",
            observation_id=f"obs-{scope}",
            server_stable_id="shared",
            server_canonical_id=f"canonical:{scope}",
            server_name="server",
            agent_name="assistant",
        )
        for scope in ("prod", "dev")
    ]
    servers = _observed_server_entities(observations)
    graph = _graph([{"id": "agent", "name": "assistant", "mcp_server_ids": ["shared"]}], servers)
    assert not [edge for edge in graph["edges"] if edge["relationship"] == "uses"]
    assert all(row["agent_names"] == ["assistant"] for row in servers)


def test_http_serialization_retains_nonempty_inventory_and_shared_manifest(monkeypatch):
    from fastapi import FastAPI
    from fastapi import Request as FastAPIRequest
    from fastapi.testclient import TestClient

    monkeypatch.setattr("agent_bom.agent_manifest.now_utc_iso", lambda: "2026-09-07T10:00:00Z")

    jobs = InMemoryJobStore()
    jobs.put(
        ScanJob(
            job_id="job",
            tenant_id="tenant-a",
            status=JobStatus.DONE,
            created_at="2026-09-07T10:00:00Z",
            request=ScanRequest(),
            result={"agents": [_agent("prod"), _agent("dev")]},
        )
    )
    fleet = InMemoryFleetStore()
    observations = InMemoryMCPObservationStore()
    for name in ("alpha", "beta"):
        fleet.put(FleetAgent(agent_id=name, tenant_id="tenant-a", name=name, agent_type="custom"))
        observations.put(
            MCPObservation(
                tenant_id="tenant-a", observation_id=name, server_stable_id="shared", server_name="shared-server", agent_name=name
            )
        )
    monkeypatch.setattr(scan, "_get_store", lambda: jobs)
    monkeypatch.setattr(agent_manifest, "_get_fleet_store", lambda: fleet)
    monkeypatch.setattr(agent_manifest, "_get_mcp_observation_store", lambda: observations)
    app = FastAPI()

    @app.middleware("http")
    async def fixture_tenant(request: FastAPIRequest, call_next):
        request.state.tenant_id = "tenant-a"
        return await call_next(request)

    app.include_router(scan.router)
    app.include_router(agent_manifest.router)
    client = TestClient(app)
    inventory = client.get("/inventory?limit=2&offset=0")
    assert inventory.status_code == 200
    assert inventory.json() == asyncio.run(scan.list_inventory(_request(), limit=2, offset=0))
    manifest = client.get("/agent-bom/manifest")
    assert manifest.status_code == 200
    assert manifest.json() == asyncio.run(agent_manifest.get_agent_bom_manifest(_request()))
