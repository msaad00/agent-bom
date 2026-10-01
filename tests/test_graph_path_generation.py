"""No response page may cross a persisted graph generation."""

import pytest

from tests.test_graph_tenant_scope_and_bounds import _path_graph, api  # noqa: F401


def test_replacement_with_same_scan_and_timestamp_rejects_old_page(api):  # noqa: F811
    client, store, headers = api
    params = {"scan_id": "shared-scan", "limit": 1}
    page = client.get("/v1/graph/attack-paths", params=params, headers=headers["tenant-a"]).json()
    token = page["snapshot_generation"]
    store.save_graph(_path_graph("tenant-a"))
    response = client.get(
        "/v1/graph/attack-paths", params=params | {"offset": 1, "snapshot_generation": token}, headers=headers["tenant-a"]
    )
    assert response.status_code == 409
    assert "restart" in response.json()["detail"].lower()


def test_continuation_requires_generation_and_cannot_use_other_tenant_token(api):  # noqa: F811
    client, _, headers = api
    params = {"scan_id": "shared-scan", "limit": 1}
    page = client.get("/v1/graph/attack-paths", params=params, headers=headers["tenant-a"]).json()
    assert client.get("/v1/graph/attack-paths", params=params | {"offset": 1}, headers=headers["tenant-a"]).status_code == 422
    assert (
        client.get(
            "/v1/graph/attack-paths",
            params=params | {"offset": 1, "snapshot_generation": page["snapshot_generation"]},
            headers=headers["tenant-b"],
        ).status_code
        == 409
    )


def test_replacement_during_hydration_discards_entire_response(api, monkeypatch):  # noqa: F811
    client, store, headers = api
    original = store.edges_for_node_ids

    def replace(**kwargs):
        store.save_graph(_path_graph("tenant-a"))
        return original(**kwargs)

    monkeypatch.setattr(store, "edges_for_node_ids", replace)
    response = client.get("/v1/graph/attack-paths", params={"scan_id": "shared-scan"}, headers=headers["tenant-a"])
    assert response.status_code == 409
    assert "nodes" not in response.json()


def test_reused_writer_token_does_not_reuse_reader_revision(api):  # noqa: F811
    client, store, headers = api
    graph = _path_graph("tenant-a")

    def save():
        store.save_graph_streaming(
            tenant_id=graph.tenant_id,
            scan_id=graph.scan_id,
            created_at=graph.created_at,
            nodes=graph.nodes.values(),
            edges=graph.edges,
            attack_paths=graph.attack_paths,
            write_generation="same-owner",
        )

    save()
    first = client.get("/v1/graph/attack-paths", params={"scan_id": graph.scan_id}, headers=headers["tenant-a"]).json()
    save()
    assert store.snapshot_identity(tenant_id=graph.tenant_id, scan_id=graph.scan_id)[1] == "same-owner"
    assert (
        client.get(
            "/v1/graph/attack-paths",
            params={"scan_id": graph.scan_id, "snapshot_generation": first["snapshot_generation"]},
            headers=headers["tenant-a"],
        ).status_code
        == 409
    )


def test_rollup_replacement_during_load_discards_entire_response(api, monkeypatch):  # noqa: F811
    client, store, headers = api
    original = store.load_rollup_graph

    def replace(**kwargs):
        graph = original(**kwargs)
        store.save_graph(_path_graph("tenant-a"))
        return graph

    monkeypatch.setattr(store, "load_rollup_graph", replace)
    response = client.get("/v1/graph/rollup", params={"scan_id": "shared-scan"}, headers=headers["tenant-a"])
    assert response.status_code == 409
    assert "top_level" not in response.json()


def test_rollup_continuation_requires_unchanged_revision(api):  # noqa: F811
    client, store, headers = api
    from tests.test_graph_tenant_scope_and_bounds import _container_graph

    store.save_graph(_container_graph("tenant-a", 4))
    params = {"scan_id": "shared-scan", "node": "account:root", "limit": 2}
    first = client.get("/v1/graph/rollup", params=params, headers=headers["tenant-a"]).json()
    assert client.get("/v1/graph/rollup", params=params | {"offset": 2}, headers=headers["tenant-a"]).status_code == 422
    continuation = params | {"offset": 2, "snapshot_generation": first["snapshot_generation"]}
    assert client.get("/v1/graph/rollup", params=continuation, headers=headers["tenant-a"]).status_code == 200
    store.save_graph(_container_graph("tenant-a", 5))
    assert client.get("/v1/graph/rollup", params=continuation, headers=headers["tenant-a"]).status_code == 409


@pytest.mark.parametrize("route,params", [("/v1/graph", {}), ("/v1/graph/search", {"q": "reader"}), ("/v1/graph/agents", {})])
def test_node_selector_and_search_pages_pin_replacements(api, route, params):  # noqa: F811
    client, store, headers = api
    params = params | {"scan_id": "shared-scan", "limit": 1}
    first = client.get(route, params=params, headers=headers["tenant-a"])
    assert first.status_code == 200
    revision = first.json()["snapshot_generation"]
    assert client.get(route, params=params | {"offset": 1}, headers=headers["tenant-a"]).status_code == 422
    store.save_graph(_path_graph("tenant-a"))
    assert client.get(route, params=params | {"offset": 1, "snapshot_generation": revision}, headers=headers["tenant-a"]).status_code == 409
