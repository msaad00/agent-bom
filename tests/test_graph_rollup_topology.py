"""The collapsed graph must render as a topology, not a grid of cards.

`rollup_view` / `drill_down` collapse thousands of nodes into a handful of
containers, but they collapsed the EDGES to nothing: `buildRollupFlowGraph`
returned `edges: []`, the canvas drew disconnected cards, and the view told the
reader that "aggregate cards are not rendered relationship evidence" — a
security graph admitting it was not showing a graph.

Containment is not the interesting relationship at this level; it is the nesting
the roll-up already expresses. What matters is the OTHER edges — an account
whose workload reaches another account's data, an identity assuming a role
across a boundary. Those exist in the graph and were simply never projected.
"""

from __future__ import annotations

import pytest

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.rollup import cross_container_edges, drill_down, rollup_view
from agent_bom.graph.types import EntityType, RelationshipType


def _graph() -> UnifiedGraph:
    """Two accounts under one org, with a cross-account edge and internal noise."""
    graph = UnifiedGraph(scan_id="t", tenant_id="default")
    for node_id, entity in (
        ("org", EntityType.ORG),
        ("acct-a", EntityType.ACCOUNT),
        ("acct-b", EntityType.ACCOUNT),
        ("wl-a", EntityType.CLOUD_RESOURCE),
        ("wl-a2", EntityType.CLOUD_RESOURCE),
        ("db-b", EntityType.DATA_STORE),
    ):
        graph.add_node(UnifiedNode(id=node_id, entity_type=entity, label=node_id))
    for source, target in (("org", "acct-a"), ("org", "acct-b"), ("acct-a", "wl-a"), ("acct-a", "wl-a2"), ("acct-b", "db-b")):
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=RelationshipType.CONTAINS))
    # Two cross-account reads, plus one edge internal to acct-a.
    graph.add_edge(UnifiedEdge(source="wl-a", target="db-b", relationship=RelationshipType.CAN_ACCESS))
    graph.add_edge(UnifiedEdge(source="wl-a2", target="db-b", relationship=RelationshipType.CAN_ACCESS))
    graph.add_edge(UnifiedEdge(source="wl-a", target="wl-a2", relationship=RelationshipType.DEPENDS_ON))
    return graph


def test_cross_container_edges_aggregate_by_container() -> None:
    graph = _graph()
    children = {"org": ["acct-a", "acct-b"], "acct-a": ["wl-a", "wl-a2"], "acct-b": ["db-b"]}

    edges = cross_container_edges(graph, ["acct-a", "acct-b"], children)

    assert len(edges) == 1, edges
    edge = edges[0]
    assert (edge["source"], edge["target"]) == ("acct-a", "acct-b")
    # Both underlying reads collapse into one weighted relationship.
    assert edge["count"] == 2
    assert "can_access" in edge["relationships"]


def test_edges_internal_to_one_container_are_dropped() -> None:
    """A container already stands for its own internals; a self-loop is noise."""
    graph = _graph()
    children = {"org": ["acct-a", "acct-b"], "acct-a": ["wl-a", "wl-a2"], "acct-b": ["db-b"]}

    edges = cross_container_edges(graph, ["acct-a", "acct-b"], children)

    assert not [e for e in edges if e["source"] == e["target"]]
    # wl-a -> wl-a2 lives entirely inside acct-a and must not appear.
    assert sum(int(e["count"]) for e in edges) == 2


def test_containment_is_never_emitted_as_a_relationship() -> None:
    """Containment is the nesting, not a link to draw between siblings."""
    graph = _graph()
    children = {"org": ["acct-a", "acct-b"], "acct-a": ["wl-a", "wl-a2"], "acct-b": ["db-b"]}

    edges = cross_container_edges(graph, ["acct-a", "acct-b"], children)

    for edge in edges:
        assert "contains" not in edge["relationships"], edge


def test_drilldown_response_carries_edges() -> None:
    """The level the operator actually looks at must ship its relationships.

    An org has one root, so nothing crosses at the top — the edges matter one
    level down, between accounts. A response that omits them is what produced
    the card grid.
    """
    graph = _graph()

    view = drill_down(graph, "org")

    assert view["mode"] == "drilldown"
    assert len(view["children"]) == 2
    edges = view.get("edges")
    assert edges, "drill-down returned no cross-container edges"
    assert {(e["source"], e["target"]) for e in edges} == {("acct-a", "acct-b")}


def test_rollup_response_exposes_an_edges_key() -> None:
    """Present even when empty, so the client never has to guess the shape."""
    graph = _graph()

    view = rollup_view(graph)

    assert "edges" in view
    assert isinstance(view["edges"], list)


def test_rollup_reports_relationship_rows_cut_by_the_edge_cap() -> None:
    """The 400-row projection cap must not look like the whole topology."""
    graph = UnifiedGraph(scan_id="edge-cap", tenant_id="default")
    node_ids = [f"account:{index:02d}" for index in range(21)]
    for node_id in node_ids:
        graph.add_node(UnifiedNode(id=node_id, entity_type=EntityType.ACCOUNT, label=node_id))
    for source in node_ids:
        for target in node_ids:
            if source != target:
                graph.add_edge(UnifiedEdge(source=source, target=target, relationship=RelationshipType.CAN_ACCESS))

    view = rollup_view(graph)

    assert len(view["edges"]) == 400
    assert view["edge_count_metadata"] == {
        "definition": "Aggregated non-containment container-to-container relationship rows in the roll-up source graph.",
        "source_total": 420,
        "returned": 400,
        "truncated": True,
        "source_truncated": False,
        "reason": "rollup_edge_limit",
    }


def test_drilldown_reports_complete_relationship_row_counts() -> None:
    view = drill_down(_graph(), "org")

    assert view["edge_count_metadata"]["source_total"] == 1
    assert view["edge_count_metadata"]["returned"] == 1
    assert view["edge_count_metadata"]["truncated"] is False
    assert view["edge_count_metadata"]["reason"] == ""


@pytest.mark.parametrize("missing", ["source", "target"])
def test_edges_referencing_absent_containers_are_dropped(missing: str) -> None:
    """An edge to a container that is not on screen cannot be drawn."""
    graph = _graph()
    children = {"acct-a": ["wl-a", "wl-a2"], "acct-b": ["db-b"]}
    visible = ["acct-b"] if missing == "source" else ["acct-a"]

    assert cross_container_edges(graph, visible, children) == []
