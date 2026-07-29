"""A filtered view of a truncated graph is still truncated.

`load_graph` bounds a large snapshot and records that on `completeness`.
`filtered_view` then built a fresh UnifiedGraph copying scan_id, tenant_id,
created_at and analysis_status — but NOT completeness — so the derived view
reported `truncated=False` and `/v1/graph` answered "complete" over data it had
already dropped nodes from.

Truncation is a property of the SOURCE. Filtering cannot make it untrue: the
nodes that were never loaded might have matched the filter, and nobody can know
whether they did. The honest answer is "still truncated, and here is what this
view actually contains".
"""

from __future__ import annotations

from agent_bom.graph.container import GraphFilterOptions, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _truncated_graph() -> UnifiedGraph:
    """Six nodes upstream, three actually loaded — the shape load_graph produces."""
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a"))
    graph.add_node(UnifiedNode(id="pkg:p", entity_type=EntityType.PACKAGE, label="p"))
    graph.add_node(UnifiedNode(id="cve:c", entity_type=EntityType.VULNERABILITY, label="c", severity="critical"))
    graph.add_edge(UnifiedEdge(source="agent:a", target="pkg:p", relationship=RelationshipType.USES))
    graph.completeness.truncated = True
    graph.completeness.node_budget = 3
    graph.completeness.total_nodes = 6
    graph.completeness.returned_nodes = 3
    graph.completeness.reason = "node_budget"
    return graph


def test_entity_filter_preserves_the_truncation_fact():
    view = _truncated_graph().filtered_view(GraphFilterOptions(entity_types={EntityType.AGENT}))
    assert view.completeness.truncated is True, "a filtered view of truncated data is still truncated"
    assert view.completeness.reason


def test_relationship_scoped_filter_preserves_it_too():
    """The edge-scoped branch builds a SECOND graph — it must carry it as well."""
    view = _truncated_graph().filtered_view(GraphFilterOptions(relationship_types={RelationshipType.USES}))
    assert view.completeness.truncated is True
    assert view.completeness.reason


def test_returned_count_reflects_this_view_not_the_source():
    view = _truncated_graph().filtered_view(GraphFilterOptions(entity_types={EntityType.AGENT}))
    assert view.completeness.returned_nodes == len(view.nodes)


def test_upstream_total_is_preserved_so_omitted_stays_honest():
    """total_nodes is what the SOURCE had; it must not be rewritten to the view size."""
    view = _truncated_graph().filtered_view(GraphFilterOptions(entity_types={EntityType.AGENT}))
    assert view.completeness.total_nodes == 6
    assert view.completeness.omitted_nodes > 0


def test_a_complete_graph_stays_complete_after_filtering():
    """No false positives — filtering a whole snapshot must not claim truncation."""
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a"))
    graph.add_node(UnifiedNode(id="pkg:p", entity_type=EntityType.PACKAGE, label="p"))

    view = graph.filtered_view(GraphFilterOptions(entity_types={EntityType.AGENT}))
    assert view.completeness.truncated is False
