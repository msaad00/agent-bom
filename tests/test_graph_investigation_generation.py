"""Impact, traversal and detail are one revision, even across replacements."""

import pytest

from tests.test_graph_tenant_scope_and_bounds import _path_graph, api  # noqa: F401


def _read(client, headers, kind, generation=None):
    params = {"scan_id": "shared-scan"}
    if generation is not None:
        params["snapshot_generation"] = generation
    if kind == "query":
        return client.post("/v1/graph/query", json=params | {"roots": ["data:store"], "direction": "reverse"}, headers=headers)
    key = "node" if kind == "impact" else "node_id"
    return client.get(f"/v1/graph/{kind}", params=params | {key: "data:store"}, headers=headers)


@pytest.mark.parametrize("kind,method", [("impact", "impact_of"), ("query", "traverse_subgraph"), ("node-context", "node_context")])
def test_replacement_during_investigation_discards_response(api, monkeypatch, kind, method):  # noqa: F811
    client, store, headers = api
    original = getattr(store, method)

    def replace(**kwargs):
        value = original(**kwargs)
        store.save_graph(_path_graph("tenant-a"))
        return value

    monkeypatch.setattr(store, method, replace)
    response = _read(client, headers["tenant-a"], kind)
    assert response.status_code == 409
    assert "restart" in response.json()["detail"].lower()


@pytest.mark.parametrize("kind", ["impact", "query", "node-context"])
def test_investigation_reuses_revision_and_rejects_replacement_and_other_tenant(api, kind):  # noqa: F811
    client, store, headers = api
    impact = _read(client, headers["tenant-a"], "impact").json()
    assert impact["scan_id"] == "shared-scan"
    assert impact["tenant_id"] == "tenant-a"
    revision = impact["snapshot_generation"]
    assert _read(client, headers["tenant-a"], kind, revision).status_code == 200
    assert _read(client, headers["tenant-b"], kind, revision).status_code == 409
    store.save_graph(_path_graph("tenant-a"))
    assert _read(client, headers["tenant-a"], kind, revision).status_code == 409


def test_impact_declares_recorded_topology_boundary(api):  # noqa: F811
    client, _, headers = api
    impact = _read(client, headers["tenant-a"], "impact").json()
    assert impact["interpretation"] == {
        "basis": "recorded_reverse_reachability",
        "execution": "not_established",
        "collection_coverage": "unknown",
        "traversable_only": False,
        "max_depth": 4,
    }
    assert impact["affected_count"] == 1


def test_impact_and_canvas_include_the_same_nontraversable_context(api):  # noqa: F811
    from tests.test_graph_tenant_scope_and_bounds import _container_graph

    client, store, headers = api
    store.save_graph(_container_graph("tenant-a", 1))
    impact = client.get("/v1/graph/impact", params={"node": "res:00000"}, headers=headers["tenant-a"]).json()
    context = client.post(
        "/v1/graph/query",
        json={
            "roots": ["res:00000"],
            "scan_id": impact["scan_id"],
            "snapshot_generation": impact["snapshot_generation"],
            "direction": "reverse",
            "traversable_only": False,
        },
        headers=headers["tenant-a"],
    ).json()
    assert impact["affected_nodes"] == ["account:root"]
    assert {n["id"] for n in context["nodes"]} == {"res:00000", "account:root"}
    assert context["edges"][0]["relationship"] == "contains"


def test_latest_is_resolved_once_before_multiread_query(api, monkeypatch):  # noqa: F811
    client, store, headers = api
    original = store.nodes_by_ids

    def advance(**kwargs):
        nodes = original(**kwargs)
        newer = _path_graph("tenant-a")
        newer.scan_id = "newer-scan"
        newer.created_at = "2026-10-01T00:00:00Z"
        store.save_graph(newer)
        return nodes

    monkeypatch.setattr(store, "nodes_by_ids", advance)
    response = client.post("/v1/graph/query", json={"roots": ["data:store"], "direction": "reverse"}, headers=headers["tenant-a"])
    assert response.status_code == 200
    assert response.json()["scan_id"] == "shared-scan"


@pytest.mark.parametrize("kind", ["impact", "query", "node-context"])
def test_legacy_backend_cannot_accept_a_requested_investigation_pin(api, monkeypatch, kind):  # noqa: F811
    from tests.test_graph_tenant_scope_and_bounds import _unsupported_identity

    client, store, headers = api
    monkeypatch.setattr(store, "snapshot_identity", _unsupported_identity)
    assert _read(client, headers["tenant-a"], kind).status_code == 200
    assert _read(client, headers["tenant-a"], kind, "a" * 32).status_code == 501
