"""A bounded graph load must say so.

Loading a whole snapshot into memory is what makes the investigation view fall
over: 200k nodes measured at ~783 MB and 8.3s per request, and the read path
allows several concurrent. Capping it is necessary, but a silently truncated
graph is worse than a slow one — a user cannot tell an empty blast radius from
a trimmed one. So the cap is paired with a declared completeness descriptor,
and the nodes that survive are the highest-risk ones rather than an arbitrary
page.
"""

from __future__ import annotations

import pytest

from agent_bom.graph import UnifiedGraph
from agent_bom.graph.container import GraphCompleteness


def test_a_graph_defaults_to_complete() -> None:
    graph = UnifiedGraph(scan_id="s1", tenant_id="t1")

    assert graph.completeness.truncated is False
    assert graph.completeness.node_budget is None
    assert graph.completeness.total_nodes == 0


def test_completeness_records_what_was_omitted() -> None:
    completeness = GraphCompleteness(truncated=True, node_budget=100, total_nodes=250, returned_nodes=100)

    assert completeness.omitted_nodes == 150
    assert completeness.truncated is True


def test_completeness_serializes_through_the_shared_contract() -> None:
    """One completeness shape for the whole graph API, not a second one."""
    completeness = GraphCompleteness(truncated=True, node_budget=100, total_nodes=250, returned_nodes=100, reason="node_budget")

    payload = completeness.to_dict()

    assert payload["status"] == "truncated"
    assert payload["complete"] is False
    assert payload["truncated"] is True
    assert payload["total"] == 250
    assert payload["returned"] == 100
    assert payload["reason"] == "node_budget"


def test_untruncated_completeness_reports_no_omissions() -> None:
    completeness = GraphCompleteness(total_nodes=42, returned_nodes=42)

    assert completeness.omitted_nodes == 0
    payload = completeness.to_dict()
    assert payload["truncated"] is False
    assert payload["status"] == "complete"


@pytest.mark.parametrize("budget", [0, -1, None])
def test_non_positive_budget_means_unbounded(budget: int | None) -> None:
    """A caller that needs a whole graph (diff, compare) must be able to say so."""
    from agent_bom.graph.container import resolve_node_budget

    assert resolve_node_budget(budget) is None


def test_positive_budget_is_honoured() -> None:
    from agent_bom.graph.container import resolve_node_budget

    assert resolve_node_budget(500) == 500


def _graph_with(node_count: int) -> UnifiedGraph:
    from agent_bom.graph import EntityType, UnifiedEdge, UnifiedNode
    from agent_bom.graph.container import RelationshipType

    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    for i in range(node_count):
        graph.add_node(
            UnifiedNode(
                id=f"agent:a{i}",
                entity_type=EntityType.AGENT,
                label=f"a{i}",
                risk_score=float(i),
            )
        )
    for i in range(node_count - 1):
        graph.add_edge(
            UnifiedEdge(
                source=f"agent:a{i}",
                target=f"agent:a{i + 1}",
                relationship=RelationshipType.USES,
            )
        )
    return graph


def test_budget_keeps_the_highest_risk_nodes() -> None:
    from agent_bom.graph.container import apply_node_budget

    graph = apply_node_budget(_graph_with(10), 3)

    assert set(graph.nodes) == {"agent:a9", "agent:a8", "agent:a7"}
    assert graph.completeness.truncated is True
    assert graph.completeness.total_nodes == 10
    assert graph.completeness.returned_nodes == 3
    assert graph.completeness.omitted_nodes == 7


def test_budget_drops_edges_whose_endpoints_went() -> None:
    from agent_bom.graph.container import apply_node_budget

    graph = apply_node_budget(_graph_with(10), 3)

    node_ids = set(graph.nodes)
    assert all(edge.source in node_ids and edge.target in node_ids for edge in graph.edges), "a dangling edge survived the trim"


def test_graph_under_budget_is_untouched_and_marked_complete() -> None:
    from agent_bom.graph.container import apply_node_budget

    graph = apply_node_budget(_graph_with(4), 100)

    assert len(graph.nodes) == 4
    assert graph.completeness.truncated is False
    assert graph.completeness.omitted_nodes == 0


def test_unbounded_budget_never_trims() -> None:
    from agent_bom.graph.container import apply_node_budget

    graph = apply_node_budget(_graph_with(6), None)

    assert len(graph.nodes) == 6
    assert graph.completeness.truncated is False
