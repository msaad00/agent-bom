"""Authenticated tenant scope, backend capability, and response bounds for graph REST routes."""

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agent_bom.api import auth, stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.middleware import APIKeyMiddleware, TrustHeadersMiddleware
from agent_bom.api.routes import graph as routes
from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.path_evidence import annotate_attack_path_evidence
from agent_bom.graph.rollup import drill_down

TENANTS = ("tenant-a", "tenant-b")


def _path_graph(tenant: str) -> UnifiedGraph:
    graph = UnifiedGraph(tenant_id=tenant, scan_id="shared-scan", created_at="2026-09-25T00:00:00Z")
    source, target = "principal:reader", "data:store"
    graph.add_node(UnifiedNode(id=source, entity_type=EntityType.SERVICE_ACCOUNT, label=f"{tenant}-reader"))
    graph.add_node(UnifiedNode(id=target, entity_type=EntityType.DATA_STORE, label=f"{tenant}-store"))
    graph.add_edge(UnifiedEdge(source=source, target=target, relationship=RelationshipType.CAN_ACCESS))
    path = AttackPath(source=source, target=target, hops=[source, target], edges=["can_access"], composite_risk=50.0)
    graph.attack_paths = [annotate_attack_path_evidence(path, graph)]
    return graph


def _container_graph(tenant: str, children: int) -> UnifiedGraph:
    graph = UnifiedGraph(tenant_id=tenant, scan_id="shared-scan", created_at="2026-09-25T00:00:00Z")
    graph.add_node(UnifiedNode(id="account:root", entity_type=EntityType.ACCOUNT, label="root"))
    for index in range(children):
        child = f"res:{index:05d}"
        graph.add_node(UnifiedNode(id=child, entity_type=EntityType.CLOUD_RESOURCE, label=child))
        graph.add_edge(UnifiedEdge(source="account:root", target=child, relationship=RelationshipType.CONTAINS))
    return graph


@pytest.fixture
def api(tmp_path, monkeypatch):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    # "default" holds its own evidence so a fall-through to it is observable.
    for tenant in (*TENANTS, "default"):
        store.save_graph(_path_graph(tenant))
    monkeypatch.setattr(stores, "_graph_store", store)
    monkeypatch.delenv("AGENT_BOM_MCP_TENANT_ID", raising=False)
    monkeypatch.delenv("AGENT_BOM_TENANT_ID", raising=False)
    keys = auth.KeyStore()
    monkeypatch.setattr(auth, "_key_store", keys)
    headers = {}
    for tenant in TENANTS:
        token, key = auth.create_api_key(tenant, auth.Role.VIEWER, tenant_id=tenant)
        keys.add(key)
        headers[tenant] = {"Authorization": f"Bearer {token}"}
    app = FastAPI()
    app.include_router(routes.router, prefix="/v1")
    app.add_middleware(APIKeyMiddleware, api_key="", allow_unauthenticated=False)
    app.add_middleware(TrustHeadersMiddleware)
    with TestClient(app) as client:
        yield client, store, headers


def _labels(payload: dict) -> set[str]:
    return {node["label"] for node in payload["nodes"]}


@pytest.mark.parametrize("mcp_process_tenant", [None, "tenant-b"])
def test_exposure_paths_use_authenticated_tenant_not_mcp_process_tenant(api, monkeypatch, mcp_process_tenant):
    client, _, headers = api
    if mcp_process_tenant:
        monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", mcp_process_tenant)
    for tenant, other in (("tenant-a", "tenant-b"), ("tenant-b", "tenant-a")):
        response = client.get(
            "/v1/graph/exposure-paths",
            params={"tenant_id": other},
            headers={**headers[tenant], "X-Agent-Bom-Tenant-ID": other},
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["tenant_id"] == tenant
        assert payload["total"] == 1
        assert _labels(payload) == {f"{tenant}-reader", f"{tenant}-store"}
        assert other not in response.text
        assert "default-reader" not in response.text


def test_should_i_deploy_uses_authenticated_tenant(api):
    client, _, headers = api
    for tenant in TENANTS:
        response = client.post(
            "/v1/graph/should-i-deploy",
            json={"candidate": f"{tenant}-store", "tenant_id": "default"},
            headers=headers[tenant],
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["tenant_id"] == tenant
        assert payload["matchedPathCount"] == 1
        matched = json.dumps(payload["matchedPaths"])
        assert f"{tenant}-store" in matched
        assert all(label not in response.text for label in ("default-store", *(f"{t}-store" for t in TENANTS if t != tenant)))


def test_mcp_tool_wrapper_still_binds_to_process_tenant(api, monkeypatch):
    import asyncio

    from agent_bom.mcp_tools.graph import exposure_paths_impl

    _, store, _ = api
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-b")
    payload = json.loads(asyncio.run(exposure_paths_impl(tenant_id="tenant-a", _get_graph_store=lambda: store)))
    assert payload["tenant_id"] == "tenant-b"
    assert _labels(payload) == {"tenant-b-reader", "tenant-b-store"}


def _unsupported_identity(**_kwargs):
    raise NotImplementedError("Generation-pinned graph pages are not supported by this backend")


def test_rollup_skips_cache_when_snapshot_identity_is_unsupported(api, monkeypatch):
    client, store, headers = api
    monkeypatch.setattr(store, "snapshot_identity", _unsupported_identity)
    for _ in range(2):
        response = client.get("/v1/graph/rollup", params={"scan_id": "shared-scan"}, headers=headers["tenant-a"])
        assert response.status_code == 200, response.text
        assert response.json()["tenant_id"] == "tenant-a"


def test_exposure_paths_report_unsupported_backend_instead_of_500(api, monkeypatch):
    client, store, headers = api
    monkeypatch.setattr(store, "snapshot_identity", _unsupported_identity)
    response = client.get("/v1/graph/exposure-paths", headers=headers["tenant-a"])
    assert response.status_code == 501
    assert response.json()["detail"]["code"] == "AGENTBOM_MCP_UNSUPPORTED_BACKEND"


def test_rollup_drilldown_is_bounded_and_pageable(api):
    client, store, headers = api
    store.save_graph(_container_graph("tenant-a", 250))
    first = client.get("/v1/graph/rollup", params={"scan_id": "shared-scan", "node": "account:root"}, headers=headers["tenant-a"])
    assert first.status_code == 200, first.text
    page = first.json()
    assert len(page["children"]) == 200
    assert page["summary"]["direct_child_count"] == 250
    assert page["summary"]["returned_child_count"] == 200
    assert page["completeness"]["truncated"] is True
    assert page["completeness"]["total"] == 250
    assert page["completeness"]["reason"] == "child_page_limit"
    assert page["pagination"] == {"offset": 0, "limit": 200, "returned": 200, "total": 250, "has_more": True, "next_offset": 200}

    rest = client.get(
        "/v1/graph/rollup",
        params={"scan_id": "shared-scan", "node": "account:root", "offset": 200},
        headers=headers["tenant-a"],
    ).json()
    assert len(rest["children"]) == 50
    assert rest["pagination"]["has_more"] is False
    assert rest["pagination"]["next_offset"] is None
    seen = [child["id"] for child in page["children"]] + [child["id"] for child in rest["children"]]
    assert sorted(seen) == [f"res:{index:05d}" for index in range(250)]

    small = client.get(
        "/v1/graph/rollup",
        params={"scan_id": "shared-scan", "node": "account:root", "limit": 10},
        headers=headers["tenant-a"],
    ).json()
    assert len(small["children"]) == 10
    assert small["pagination"]["next_offset"] == 10

    for bad in ({"limit": 0}, {"limit": 1001}, {"offset": -1}):
        response = client.get(
            "/v1/graph/rollup",
            params={"scan_id": "shared-scan", "node": "account:root", **bad},
            headers=headers["tenant-a"],
        )
        assert response.status_code == 422


def test_drill_down_fits_in_one_page_stays_complete():
    payload = drill_down(_container_graph("tenant-a", 3), "account:root", limit=200)
    assert len(payload["children"]) == 3
    assert payload["completeness"]["complete"] is True
    assert payload["pagination"]["has_more"] is False


@pytest.mark.parametrize(
    "path",
    ["/v1/graph", "/v1/graph/rollup", "/v1/graph/exposure-paths", "/v1/graph/search", "/v1/graph/node-neighbors"],
)
@pytest.mark.parametrize("field", ["scan_id", "node", "q", "source", "node_id"])
def test_nul_in_any_query_parameter_is_rejected_before_routing(api, path, field):
    client, _, headers = api
    response = client.get(f"{path}?{field}=bad%00id", headers=headers["tenant-a"])
    assert response.status_code == 422
    assert "NUL" in response.text


def test_nul_in_query_rejected_on_findings_through_real_app(monkeypatch):
    from agent_bom.api.server import app

    client = TestClient(app)
    for path in ("/v1/findings", "/v1/graph"):
        response = client.get(f"{path}?scan_id=bad%00id")
        assert response.status_code == 422, (path, response.text)
