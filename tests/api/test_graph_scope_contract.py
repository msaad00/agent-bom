"""Observed-only, bounded graph-scope API contracts."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app, configure_api
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import EntityType, NodeDimensions, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.scope import select_observed_scope

PROXY_SECRET = "synthetic-test-proxy-secret-with-32-bytes"


@pytest.fixture
def scoped_graph_client(tmp_path) -> Iterator[TestClient]:
    store = SQLiteGraphStore(tmp_path / "scoped-graph.db")
    graph = UnifiedGraph(
        scan_id="scope-scan",
        tenant_id="default",
        created_at="2026-07-26T12:00:00+00:00",
    )
    graph.add_node(
        UnifiedNode(
            id="asset:account-a",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="synthetic account A asset",
            attributes={"account_id": "111111111111", "cloud_provider": "aws"},
        )
    )
    graph.add_node(
        UnifiedNode(
            id="asset:account-b",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="synthetic account B asset",
            attributes={"account_id": "222222222222", "cloud_provider": "aws"},
        )
    )
    graph.add_node(
        UnifiedNode(
            id="application:repo-a",
            entity_type=EntityType.APPLICATION,
            label="synthetic repository",
            attributes={"repository": "example/repository"},
        )
    )
    graph.add_node(
        UnifiedNode(
            id="agent:prod",
            entity_type=EntityType.AGENT,
            label="synthetic prod agent",
            dimensions=NodeDimensions(environment="production"),
        )
    )
    graph.add_node(
        UnifiedNode(
            id="server:prod",
            entity_type=EntityType.SERVER,
            label="synthetic prod server",
            dimensions=NodeDimensions(environment="production"),
        )
    )
    graph.add_node(
        UnifiedNode(
            id="tool:prod",
            entity_type=EntityType.TOOL,
            label="synthetic prod tool",
        )
    )
    graph.add_edge(UnifiedEdge(source="agent:prod", target="server:prod", relationship=RelationshipType.USES))
    graph.add_edge(UnifiedEdge(source="server:prod", target="tool:prod", relationship=RelationshipType.PROVIDES_TOOL))
    store.save_graph(graph)

    original = api_stores._graph_store
    set_graph_store(store)
    try:
        yield TestClient(app)
    finally:
        set_graph_store(original)


@pytest.mark.parametrize(
    ("scope", "scope_id", "expected"),
    [
        ("account", "111111111111", {"asset:account-a"}),
        ("repository", "example/repository", {"application:repo-a"}),
        ("environment", "production", {"agent:prod", "server:prod"}),
    ],
)
def test_scoped_graph_uses_only_explicit_persisted_scope_values(
    scoped_graph_client: TestClient,
    scope: str,
    scope_id: str,
    expected: set[str],
) -> None:
    response = scoped_graph_client.get(
        "/v1/graph/scoped",
        params={"scope": scope, "scope_id": scope_id},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert {node["id"] for node in body["nodes"]} == expected
    assert body["scope"] == {
        "kind": scope,
        "id": scope_id,
        "observed": True,
        "basis": "persisted_node_attributes",
    }
    assert body["completeness"]["source"]["status"] == "complete"
    assert body["completeness"]["result"]["complete"] is True


def test_investigation_scope_is_bounded_from_an_observed_root(scoped_graph_client: TestClient) -> None:
    response = scoped_graph_client.get(
        "/v1/graph/scoped",
        params={
            "scope": "investigation",
            "scope_id": "agent:prod",
            "max_depth": 1,
            "limit": 10,
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert {node["id"] for node in body["nodes"]} == {"agent:prod", "server:prod"}
    assert {(edge["source_id"], edge["target_id"]) for edge in body["edges"]} == {
        ("agent:prod", "server:prod")
    }
    assert body["scope"]["basis"] == "persisted_graph_traversal"
    assert body["scope"]["observed"] is True


def test_estate_scope_keeps_explicit_null_identifier(scoped_graph_client: TestClient) -> None:
    response = scoped_graph_client.get("/v1/graph/scoped", params={"scope": "estate"})

    assert response.status_code == 200
    assert response.json()["scope"]["id"] is None


def test_attribute_scope_caps_dense_edges_deterministically() -> None:
    graph = UnifiedGraph(scan_id="dense-scope", tenant_id="default")
    for index in range(3):
        graph.add_node(
            UnifiedNode(
                id=f"asset:{index}",
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"synthetic asset {index}",
                attributes={"account_id": "111111111111"},
            )
        )
    for source in range(3):
        for target in range(3):
            if source != target:
                graph.add_edge(
                    UnifiedEdge(
                        source=f"asset:{source}",
                        target=f"asset:{target}",
                        relationship=RelationshipType.USES,
                    )
                )

    selected = select_observed_scope(
        graph,
        kind="account",
        scope_id="111111111111",
        max_depth=1,
        max_nodes=3,
        max_edges=2,
    )

    assert [(edge.source, edge.target) for edge in selected.graph.edges] == [
        ("asset:0", "asset:1"),
        ("asset:0", "asset:2"),
    ]
    assert selected.truncated is True
    assert selected.reason == "scope_edge_limit"
    assert selected.total_edges == 6


def test_scoped_graph_does_not_infer_unobserved_organization_or_repository(
    scoped_graph_client: TestClient,
) -> None:
    unknown = scoped_graph_client.get(
        "/v1/graph/scoped",
        params={"scope": "repository", "scope_id": "label-derived-repository"},
    )
    organization = scoped_graph_client.get(
        "/v1/graph/scoped",
        params={"scope": "organization", "scope_id": "synthetic-org"},
    )

    assert unknown.status_code == 200
    assert unknown.json()["nodes"] == []
    assert unknown.json()["scope"]["observed"] is False
    assert organization.status_code == 422


def test_scoped_graph_openapi_declares_scope_and_completeness_contract() -> None:
    schema = app.openapi()
    operation = schema["paths"]["/v1/graph/scoped"]["get"]
    response_schema = operation["responses"]["200"]["content"]["application/json"]["schema"]

    assert response_schema["$ref"].endswith("/ScopedGraphResponse")
    scope_values = next(
        parameter["schema"]["enum"]
        for parameter in operation["parameters"]
        if parameter["name"] == "scope"
    )
    assert scope_values == ["estate", "account", "repository", "environment", "investigation"]
    properties = schema["components"]["schemas"]["ScopedGraphResponse"]["properties"]
    assert {"scope", "nodes", "edges", "completeness"} <= properties.keys()
    completeness = schema["components"]["schemas"]["ScopedGraphCompleteness"]["properties"]
    assert {"source", "result", "edges"} <= completeness.keys()


def test_managed_trial_rejects_estate_scope_but_keeps_account_scope(
    scoped_graph_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BOM_MANAGED_TRIAL_MODE", "1")

    estate = scoped_graph_client.get("/v1/graph/scoped", params={"scope": "estate"})
    account = scoped_graph_client.get(
        "/v1/graph/scoped",
        params={"scope": "account", "scope_id": "111111111111"},
    )

    assert estate.status_code == 403
    assert "account-scoped" in estate.json()["detail"]
    assert account.status_code == 200


def test_scoped_graph_requires_auth_and_preserves_tenant_isolation(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = SQLiteGraphStore(tmp_path / "tenant-scoped-graph.db")
    for tenant, node_id, account_id in (
        ("tenant-alpha", "asset:alpha", "111111111111"),
        ("tenant-beta", "asset:beta", "222222222222"),
    ):
        graph = UnifiedGraph(scan_id=f"scan-{tenant}", tenant_id=tenant)
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"synthetic {tenant} asset",
                attributes={"account_id": account_id},
            )
        )
        store.save_graph(graph)

    original = api_stores._graph_store
    set_graph_store(store)
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)
    configure_api(api_key=None)
    client = TestClient(app)
    headers = {
        "X-Agent-Bom-Role": "viewer",
        "X-Agent-Bom-Tenant-ID": "tenant-alpha",
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }
    try:
        unauthenticated = client.get(
            "/v1/graph/scoped",
            params={"scope": "account", "scope_id": "111111111111"},
        )
        alpha = client.get(
            "/v1/graph/scoped",
            params={"scope": "account", "scope_id": "111111111111"},
            headers=headers,
        )
        beta_from_alpha = client.get(
            "/v1/graph/scoped",
            params={"scope": "account", "scope_id": "222222222222"},
            headers=headers,
        )

        assert unauthenticated.status_code == 401
        assert {node["id"] for node in alpha.json()["nodes"]} == {"asset:alpha"}
        assert beta_from_alpha.json()["nodes"] == []
        assert beta_from_alpha.json()["scope"]["observed"] is False
    finally:
        set_graph_store(original)
        monkeypatch.undo()
        configure_api(api_key=None)
