"""Shared containment must not turn repeated memberships into unique assets."""

from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.rollup import RollupFilters, drill_down, rollup_view
from agent_bom.graph.types import EntityType, RelationshipType


def _shared_estate(*, root: bool = False) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="shared-snapshot", tenant_id="tenant-a")
    for node_id, kind, severity in (
        ("scope:a", EntityType.ACCOUNT, ""),
        ("scope:b", EntityType.ACCOUNT, ""),
        ("pkg:shared", EntityType.PACKAGE, "critical"),
        ("pkg:only-a", EntityType.PACKAGE, "low"),
    ):
        graph.add_node(UnifiedNode(id=node_id, entity_type=kind, label=node_id, severity=severity))
    pairs = [("scope:a", "pkg:shared"), ("scope:b", "pkg:shared"), ("scope:a", "pkg:only-a")]
    if root:
        graph.add_node(UnifiedNode(id="org", entity_type=EntityType.ORG, label="Org"))
        pairs.extend([("org", "scope:a"), ("org", "scope:b")])
    for source, target in pairs:
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=RelationshipType.CONTAINS))
    return graph


def _assert_shared_counts(payload: dict, *, distinct: int, memberships: int) -> None:
    metadata = payload["aggregate_count_metadata"]
    assert metadata["distinct_descendants"] == distinct
    assert metadata["descendant_memberships"] == memberships
    assert metadata["shared_descendants"] == 1
    assert metadata["extra_memberships"] == memberships - distinct
    assert metadata["additive"] is False
    assert metadata["source_truncated"] is False


def test_rollup_counts_shared_asset_once_in_distinct_denominator() -> None:
    payload = rollup_view(_shared_estate())
    _assert_shared_counts(payload, distinct=2, memberships=3)
    assert sum(item["aggregate"]["descendant_count"] for item in payload["top_level"]) == 3
    assert payload["summary"]["total_nodes"] == 4


def test_drilldown_counts_shared_asset_once_across_sibling_scopes() -> None:
    graph = _shared_estate(root=True)
    root_metadata = rollup_view(graph)["aggregate_count_metadata"]
    assert root_metadata["distinct_descendants"] == 4
    assert root_metadata["additive"] is True
    _assert_shared_counts(drill_down(graph, "org"), distinct=2, memberships=3)


def test_overlap_counts_use_the_same_filtered_members_as_aggregates() -> None:
    _assert_shared_counts(rollup_view(_shared_estate(), filters=RollupFilters(min_severity="critical")), distinct=1, memberships=2)
    payload = rollup_view(_shared_estate(), filters=RollupFilters(min_severity="critical", exposed_only=True))
    assert payload["aggregate_count_metadata"]["distinct_descendants"] == 0
    assert payload["aggregate_count_metadata"]["descendant_memberships"] == 0


def test_bounded_source_does_not_claim_estate_wide_overlap_counts() -> None:
    graph = _shared_estate()
    graph.completeness.truncated = True
    graph.completeness.reason = "node_budget"
    metadata = rollup_view(graph)["aggregate_count_metadata"]
    assert metadata["source_truncated"] is True
    assert metadata["reason"] == "node_budget"
    assert metadata["basis"] == "returned_entry_descendants"
    assert drill_down(graph, "missing")["aggregate_count_metadata"]["source_truncated"] is True


def test_cycles_terminate_and_do_not_count_duplicate_edges_twice() -> None:
    graph = _shared_estate(root=True)
    graph.add_edge(UnifiedEdge(source="pkg:shared", target="scope:a", relationship=RelationshipType.CONTAINS))
    payload = drill_down(graph, "org")
    counts = payload["aggregate_count_metadata"]
    assert counts["descendant_memberships"] == sum(item["aggregate"]["descendant_count"] for item in payload["children"])
    assert counts["distinct_descendants"] == 3
    assert counts["extra_memberships"] == 2


def test_overlap_counts_survive_persistence_and_api_json(tmp_path) -> None:
    from starlette.testclient import TestClient

    from agent_bom.api import stores
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.server import app

    graph = _shared_estate(root=True)
    graph.tenant_id = "default"
    store = SQLiteGraphStore(tmp_path / "overlap.db")
    store.save_graph(graph)
    original = stores._graph_store
    try:
        stores.set_graph_store(store)
        response = TestClient(app).get("/v1/graph/rollup", params={"scan_id": graph.scan_id, "node": "org"})
        assert response.status_code == 200
        _assert_shared_counts(response.json(), distinct=2, memberships=3)
        assert response.json()["tenant_id"] == "default"
    finally:
        stores.set_graph_store(original)
