"""Authenticated recorded relationship pagination without full-neighborhood reads."""

import sqlite3

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agent_bom.api import auth, stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.middleware import APIKeyMiddleware, TrustHeadersMiddleware
from agent_bom.api.neptune_graph import NeptuneGraphStore
from agent_bom.api.routes import graph as routes
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode

ROOT = "agent:/exact/root"


def graph(tenant="tenant-a", scan="scan", created="2026-09-23T00:00:00Z"):
    result = UnifiedGraph(tenant_id=tenant, scan_id=scan, created_at=created)
    for id_ in (ROOT, "peer", "incoming"):
        result.add_node(UnifiedNode(id=id_, entity_type=EntityType.AGENT, label=f"{tenant}:{id_}"))
    for source, target, relationship in [
        (ROOT, "peer", RelationshipType.USES),
        (ROOT, "peer", RelationshipType.CONTAINS),
        (ROOT, ROOT, RelationshipType.USES),
        ("incoming", ROOT, RelationshipType.USES),
    ]:
        result.add_edge(UnifiedEdge(source=source, target=target, relationship=relationship))
    return result


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    db = tmp_path / "graph.db"
    store = SQLiteGraphStore(db)
    for tenant in ("tenant-a", "tenant-b"):
        store.save_graph(graph(tenant))
    monkeypatch.setattr(stores, "_graph_store", store)
    keys = auth.KeyStore()
    monkeypatch.setattr(auth, "_key_store", keys)
    tokens = {}
    for tenant in ("tenant-a", "tenant-b"):
        token, key = auth.create_api_key(tenant, auth.Role.VIEWER, tenant_id=tenant)
        keys.add(key)
        tokens[tenant] = {"Authorization": f"Bearer {token}"}
    app = FastAPI()
    app.include_router(routes.router, prefix="/v1")
    app.add_middleware(APIKeyMiddleware, api_key="", allow_unauthenticated=False)
    app.add_middleware(TrustHeadersMiddleware)
    with TestClient(app) as client:
        yield client, store, db, tokens


def fetch(boundary, tenant="tenant-a", **params):
    client, _, _, tokens = boundary
    return client.get("/v1/graph/incident-edges", params={"node_id": ROOT, **params}, headers=tokens[tenant])


def test_pages_keep_parallel_relationships_self_loop_and_exact_ids(boundary, monkeypatch):
    _, store, _, _ = boundary
    for name in ("node_context", "load_graph", "impact_of", "latest_snapshot_id"):
        monkeypatch.setattr(store, name, lambda **kwargs: pytest.fail("unbounded graph method called"))
    response = fetch(boundary, limit=1)
    seen = []
    while True:
        assert response.status_code == 200
        body = response.json()
        assert body["scan_id"] == "scan"
        assert body["node"]["id"] == ROOT
        assert len(body["edges"]) == 1
        assert body["completeness"]["scope"] == "incident_edge_page"
        assert body["completeness"]["total"] is None
        edge = body["edges"][0]
        assert {edge["source_id"], edge["target_id"]} <= {node["id"] for node in body["nodes"]}
        seen.append((edge["source_id"], edge["target_id"], edge["relationship"]))
        if not body["next_cursor"]:
            assert body["completeness"]["complete"]
            break
        assert not body["completeness"]["complete"]
        response = fetch(boundary, limit=1, scan_id=body["scan_id"], cursor=body["next_cursor"])
    assert len(seen) == len(set(seen)) == 4


@pytest.mark.parametrize("direction,count", [("out", 3), ("in", 2), ("both", 4)])
def test_direction_filters_recorded_endpoints(boundary, direction, count):
    body = fetch(boundary, direction=direction).json()
    assert len(body["edges"]) == count
    for edge in body["edges"]:
        if direction == "out":
            assert edge["source_id"] == ROOT
        if direction == "in":
            assert edge["target_id"] == ROOT


def test_auth_tenant_and_cursor_scope_fail_closed(boundary):
    client, _, _, tokens = boundary
    assert client.get("/v1/graph/incident-edges", params={"node_id": ROOT}).status_code == 401
    page = fetch(boundary, limit=1).json()
    cursor = page["next_cursor"]
    for params in ({"direction": "in"}, {"node_id": "peer"}, {"scan_id": "missing"}, {"tenant": "tenant-b"}):
        response = fetch(boundary, cursor=cursor, **params)
        assert response.status_code == 400
        assert "tenant-a" not in response.text
    response = client.get(
        "/v1/graph/incident-edges",
        params={"node_id": ROOT, "tenant_id": "tenant-b"},
        headers={**tokens["tenant-a"], "X-Agent-Bom-Tenant-ID": "tenant-b"},
    )
    if response.status_code == 200:
        assert all(node["label"].startswith("tenant-a:") for node in response.json()["nodes"])
    else:
        assert response.status_code == 403


@pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 101}, {"direction": "sideways"}, {"cursor": "x" * 8193}])
def test_invalid_query_bounds(boundary, params):
    assert fetch(boundary, **params).status_code == 422


def test_missing_and_stale_snapshots_never_claim_complete(boundary):
    _, store, _, _ = boundary
    missing = fetch(boundary, node_id="missing").json()
    assert not missing["found"] and not missing["completeness"]["complete"]
    assert missing["snapshot_generation"] is None
    page = fetch(boundary, limit=1).json()
    store.save_graph(graph())  # Same ID, timestamp and manifest; new durable generation.
    assert fetch(boundary, cursor=page["next_cursor"]).status_code == 400
    assert fetch(boundary, cursor="not-a-token").status_code == 400


def test_latest_cursor_requires_returned_snapshot_id(boundary):
    _, store, _, _ = boundary
    page = fetch(boundary, limit=1).json()
    store.save_graph(graph(scan="new", created="2026-09-24T00:00:00Z"))
    assert fetch(boundary, cursor=page["next_cursor"]).status_code == 400
    assert fetch(boundary, cursor=page["next_cursor"], scan_id=page["scan_id"]).status_code == 200


def test_missing_generation_and_endpoints_are_honest(boundary):
    _, _, db, _ = boundary
    initial = fetch(boundary, limit=1).json()
    with sqlite3.connect(db) as conn:
        conn.execute("DELETE FROM graph_nodes WHERE tenant_id='tenant-a' AND id='peer'")
    body = fetch(boundary).json()
    assert body["completeness"]["missing_endpoint_count"] == 1
    assert not body["completeness"]["complete"]
    assert all(edge["target_id"] != "peer" for edge in body["edges"])
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE graph_snapshots SET snapshot_generation='' WHERE tenant_id='tenant-a'")
    assert fetch(boundary).status_code == 400
    assert fetch(boundary, cursor=initial["next_cursor"]).status_code == 400


def test_neptune_is_explicitly_unsupported(boundary, monkeypatch):
    monkeypatch.setattr(stores, "_graph_store", object.__new__(NeptuneGraphStore))
    response = fetch(boundary)
    assert response.status_code == 501
    assert response.json()["detail"] == "Incident relationship paging is not supported by this graph backend"


def test_cross_node_expansion_requires_same_snapshot_generation(boundary):
    _, store, _, _ = boundary
    first = fetch(boundary).json()
    assert first["next_cursor"] is None  # Even an exhausted root page must pin future expansions.
    generation = first["snapshot_generation"]
    assert len(generation) == 32
    assert fetch(boundary, node_id="peer", snapshot_generation=generation, scan_id=first["scan_id"]).status_code == 200
    store.save_graph(graph())
    response = fetch(boundary, node_id="peer", snapshot_generation=generation, scan_id=first["scan_id"])
    assert response.status_code == 400
    current = fetch(boundary).json()
    assert current["snapshot_generation"] != generation
    assert (
        fetch(boundary, node_id="peer", snapshot_generation=current["snapshot_generation"], scan_id=current["scan_id"]).status_code == 200
    )


@pytest.mark.parametrize("route", ["incident-edges", "node-neighbors", "node-context"])
@pytest.mark.parametrize("field", ["node_id", "scan_id"])
def test_graph_identity_rejects_nul_before_store_access(boundary, monkeypatch, route, field):
    client, store, _, tokens = boundary
    for method in ("incident_edges_page", "node_context", "latest_snapshot_id"):
        monkeypatch.setattr(store, method, lambda **kwargs: pytest.fail("invalid identifier reached database"))
    response = client.get(f"/v1/graph/{route}", params={"node_id": ROOT, field: "bad\x00id"}, headers=tokens["tenant-a"])
    assert response.status_code == 422


def test_rollup_cache_is_generation_and_tenant_scoped(boundary, monkeypatch):
    client, store, _, tokens = boundary
    real_load = store.load_rollup_graph
    loads = []

    def load(**kwargs):
        loads.append(kwargs)
        return real_load(**kwargs)

    monkeypatch.setattr(store, "load_rollup_graph", load)
    first = client.get("/v1/graph/rollup?scan_id=scan", headers=tokens["tenant-a"])
    repeated = client.get("/v1/graph/rollup?scan_id=scan", headers=tokens["tenant-a"])
    assert first.status_code == repeated.status_code == 200
    assert first.json() == repeated.json()
    assert len(loads) == 1
    other = client.get("/v1/graph/rollup?scan_id=scan", headers=tokens["tenant-b"])
    assert other.status_code == 200
    assert len(loads) == 2
    replacement = graph()
    replacement.add_node(UnifiedNode(id="new", entity_type=EntityType.AGENT, label="New agent"))
    store.save_graph(replacement)
    changed = client.get("/v1/graph/rollup?scan_id=scan", headers=tokens["tenant-a"])
    assert changed.status_code == 200
    assert changed.json()["summary"]["total_nodes"] == 4
    assert len(loads) == 3
    assert client.get("/v1/graph/rollup?scan_id=scan").status_code == 401
