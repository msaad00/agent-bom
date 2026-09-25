"""One agent population across surfaces: posture counts equal the estate agent list."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_graph_store, _get_store, set_graph_store
from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())


def _save_snapshot(store: SQLiteGraphStore, tenant: str, scan_id: str, agent_ids: list[str]) -> None:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=tenant)
    for agent_id in agent_ids:
        graph.add_node(UnifiedNode(id=f"agent:{agent_id}", entity_type=EntityType.AGENT, label=agent_id))
    graph.add_node(UnifiedNode(id="server:shared", entity_type=EntityType.SERVER, label="shared-mcp"))
    store.save_graph(graph)


def _complete_job(tenant: str, job_id: str) -> None:
    job = ScanJob(job_id=job_id, tenant_id=tenant, created_at="2026-09-25T12:00:00Z", request=ScanRequest())
    job.status = JobStatus.DONE
    job.completed_at = "2026-09-25T12:01:00Z"
    job.result = {"findings": []}
    _get_store().put(job)


@pytest.fixture
def graph_store(tmp_path):
    original = _get_graph_store()
    store = SQLiteGraphStore(tmp_path / "agents.db")
    set_graph_store(store)
    set_job_store(InMemoryJobStore())
    try:
        yield store
    finally:
        set_graph_store(original)


def _agent_list_total(client: TestClient, tenant: str) -> int:
    body = client.get("/v1/inventory/assets?type=agent&limit=1", headers=proxy_headers(role="analyst", tenant=tenant)).json()
    return int(body["pagination"]["total"])


def test_posture_agent_count_equals_estate_agent_list_total(graph_store) -> None:
    tenant = "agent-population-alpha"
    # The same canonical agent seen twice in one snapshot is one agent.
    _save_snapshot(graph_store, tenant, "agents-alpha-1", ["orders", "billing", "orders", "support"])
    client = TestClient(app)

    agents = client.get("/v1/posture/counts", headers=proxy_headers(role="analyst", tenant=tenant)).json()["agents"]

    assert agents["total"] == 3
    assert agents["total"] == _agent_list_total(client, tenant)
    assert agents["scan_id"] == "agents-alpha-1"
    assert agents["basis"] == "graph_agents"


def test_posture_agent_count_is_tenant_isolated(graph_store) -> None:
    alpha, beta, empty = "agent-population-iso-a", "agent-population-iso-b", "agent-population-iso-empty"
    _save_snapshot(graph_store, alpha, "agents-iso-a", ["a1", "a2", "a3", "a4"])
    _save_snapshot(graph_store, beta, "agents-iso-b", ["b1"])
    client = TestClient(app)

    def counts(tenant: str) -> dict:
        return client.get("/v1/posture/counts", headers=proxy_headers(role="analyst", tenant=tenant)).json()["agents"]

    assert counts(alpha)["total"] == 4 == _agent_list_total(client, alpha)
    assert counts(beta)["total"] == 1 == _agent_list_total(client, beta)
    assert counts(beta)["scan_id"] == "agents-iso-b"
    assert counts(empty) == {"total": 0, "scan_id": None, "basis": "graph_agents"}


def test_posture_agent_count_refreshes_when_a_new_scan_lands(graph_store) -> None:
    tenant = "agent-population-refresh"
    _save_snapshot(graph_store, tenant, "agents-refresh-1", ["one"])
    client = TestClient(app)
    headers = proxy_headers(role="analyst", tenant=tenant)
    assert client.get("/v1/posture/counts", headers=headers).json()["agents"]["total"] == 1

    _save_snapshot(graph_store, tenant, "agents-refresh-2", ["one", "two"])
    _complete_job(tenant, "agents-refresh-2")

    agents = client.get("/v1/posture/counts", headers=headers).json()["agents"]
    assert agents["total"] == 2 == _agent_list_total(client, tenant)
    assert agents["scan_id"] == "agents-refresh-2"


def test_posture_counts_survive_a_graph_backend_without_inventory_queries(graph_store, monkeypatch) -> None:
    tenant = "agent-population-unsupported"

    def unsupported(*args, **kwargs):
        raise NotImplementedError("query_inventory")

    monkeypatch.setattr(graph_store, "query_inventory", unsupported)
    response = TestClient(app).get("/v1/posture/counts", headers=proxy_headers(role="analyst", tenant=tenant))

    assert response.status_code == 200
    assert response.json()["agents"] == {"total": None, "scan_id": None, "basis": "graph_agents"}
