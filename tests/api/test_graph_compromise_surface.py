"""Compromise assessments are authenticated, tenant-scoped, pinned reads."""

import pytest

from tests.test_graph_tenant_scope_and_bounds import _path_graph, api  # noqa: F401


def _body(**changes):
    return {"root_node_id": "principal:reader", "assume_control": True, "scan_id": "shared-scan", **changes}


def test_compromise_is_a_pinned_read_with_explicit_unknowns(api):  # noqa: F811
    client, _, headers = api
    response = client.post("/v1/graph/compromise", json=_body(), headers=headers["tenant-a"])
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["tenant_id"] == "tenant-a"
    assert body["snapshot_generation"]
    assert body["scan_id"] == "shared-scan"
    assert body["actions"][0]["permission"] == "unknown"
    assert body["current_access"] == "not_evaluated"
    assert body["execution"] == "not_established"


def test_compromise_rejects_anonymous_and_never_accepts_body_tenant(api):  # noqa: F811
    client, _, headers = api
    assert client.post("/v1/graph/compromise", json=_body()).status_code == 401
    response = client.post("/v1/graph/compromise", json=_body(tenant_id="tenant-b"), headers=headers["tenant-a"])
    assert response.status_code == 422


@pytest.mark.parametrize(
    "changes",
    [{"assume_control": False}, {"assume_control": 1}, {"root_node_id": " "}, {"root_node_id": "x\x00y"}, {"max_relationships": 513}],
)
def test_compromise_rejects_invalid_or_implicit_assumptions(api, changes):  # noqa: F811
    client, _, headers = api
    assert client.post("/v1/graph/compromise", json=_body(**changes), headers=headers["tenant-a"]).status_code == 422


def test_compromise_rejects_changed_snapshot_and_cross_tenant_generation(api):  # noqa: F811
    client, store, headers = api
    first = client.post("/v1/graph/compromise", json=_body(), headers=headers["tenant-a"])
    assert first.status_code == 200
    body = _body(snapshot_generation=first.json()["snapshot_generation"])
    assert client.post("/v1/graph/compromise", json=body, headers=headers["tenant-b"]).status_code == 409
    store.save_graph(_path_graph("tenant-a"))
    assert client.post("/v1/graph/compromise", json=body, headers=headers["tenant-a"]).status_code == 409


def test_compromise_discards_a_snapshot_replaced_during_read(api, monkeypatch):  # noqa: F811
    client, store, headers = api
    original = store.traverse_subgraph

    def replace(**kwargs):
        graph = original(**kwargs)
        store.save_graph(_path_graph("tenant-a"))
        return graph

    monkeypatch.setattr(store, "traverse_subgraph", replace)
    assert client.post("/v1/graph/compromise", json=_body(), headers=headers["tenant-a"]).status_code == 409


def test_compromise_rejects_incomplete_snapshot_instead_of_promoting_partial_allows(api, monkeypatch):  # noqa: F811
    client, store, headers = api
    original = store.traverse_subgraph

    def partial(**kwargs):
        graph, depths, truncated = original(**kwargs)
        graph.completeness.truncated = True
        return graph, depths, truncated

    monkeypatch.setattr(store, "traverse_subgraph", partial)
    assert client.post("/v1/graph/compromise", json=_body(), headers=headers["tenant-a"]).status_code == 413


def test_compromise_missing_tenant_snapshot_is_not_default_fallback(api):  # noqa: F811
    client, _, headers = api
    response = client.post("/v1/graph/compromise", json=_body(scan_id="missing"), headers=headers["tenant-a"])
    assert response.status_code == 404


def test_compromise_bounds_the_storage_read_instead_of_loading_the_estate(api, monkeypatch):  # noqa: F811
    client, store, headers = api

    def forbidden(**kwargs):
        pytest.fail("assessments must use a bounded root-centered storage read")

    monkeypatch.setattr(store, "load_graph", forbidden)
    response = client.post("/v1/graph/compromise", json=_body(), headers=headers["tenant-a"])
    assert response.status_code == 200


def test_compromise_preserves_action_denials_in_bounded_storage_read(api):  # noqa: F811
    from datetime import datetime, timezone

    from tests.graph.test_compromise import graph, receipt

    client, store, headers = api
    stamp = datetime.now(timezone.utc).isoformat()
    snapshot = graph(receipt(observed_at=stamp), receipt(observed_at=stamp, decision="explicit_deny"))
    snapshot.tenant_id = "tenant-a"
    snapshot.scan_id = "shared-scan"
    store.save_graph(snapshot)
    response = client.post("/v1/graph/compromise", json=_body(), headers=headers["tenant-a"])
    assert response.status_code == 200, response.text
    action = response.json()["actions"][0]
    assert action["permission"] == "denied_at_collection"
    assert action["action"] == "storage.objects.get"
    assert action["binding_ids"] == ["binding:read"]


def test_compromise_finding_root_keeps_affected_component_link(api):  # noqa: F811
    from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedNode

    client, store, headers = api
    snapshot = _path_graph("tenant-a")
    snapshot.add_node(UnifiedNode(id="finding:one", entity_type=EntityType.VULNERABILITY, label="Finding"))
    snapshot.add_edge(UnifiedEdge(source="principal:reader", target="finding:one", relationship=RelationshipType.VULNERABLE_TO))
    store.save_graph(snapshot)
    body = _body(root_node_id="finding:one", affected_node_id="principal:reader", assume_exploitation=True)
    response = client.post("/v1/graph/compromise", json=body, headers=headers["tenant-a"])
    assert response.status_code == 200, response.text
    assert response.json()["assumed_control_node_id"] == "principal:reader"
    assert response.json()["exploitation"] == "assumed_not_verified"
