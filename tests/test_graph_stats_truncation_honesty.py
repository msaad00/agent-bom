"""`stats` and `completeness` in one response must describe the same graph.

`/v1/graph` answered with `completeness {"truncated": true, "total": 100000}`
sitting next to `stats.total_nodes: 10826`, and its own docstring promised
"Stats reflect the full (unpaginated) graph". Both numbers were computed
honestly — one over the estate, one over what survived the load-time node
budget — and put side by side with nothing saying they measured different
things. A reader takes the smaller one as the estate.

`stats` now carries `total_nodes_source`: the estate total before the load was
bounded. Equal to `total_nodes` on an unbounded load, larger otherwise, always
reconcilable with `completeness.total`.
"""

from __future__ import annotations

from agent_bom.api.routes.graph import _filtered_graph_response
from agent_bom.graph.container import UnifiedGraph, apply_node_budget
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

ESTATE_NODES = 60
NODE_BUDGET = 12


def _estate() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    previous = ""
    for index in range(ESTATE_NODES):
        node_id = f"pkg:{index:03d}"
        graph.add_node(UnifiedNode(id=node_id, entity_type=EntityType.PACKAGE, label=node_id, risk_score=float(index)))
        if previous:
            graph.add_edge(UnifiedEdge(source=previous, target=node_id, relationship=RelationshipType.DEPENDS_ON))
        previous = node_id
    return graph


def test_stats_declare_the_estate_total_behind_a_bounded_load():
    stats = apply_node_budget(_estate(), NODE_BUDGET).stats()
    assert stats["total_nodes"] == NODE_BUDGET
    assert stats["total_nodes_source"] == ESTATE_NODES


def test_stats_of_an_unbounded_graph_report_the_same_number_twice():
    """The field is always present, so clients never branch on its absence."""
    stats = _estate().stats()
    assert stats["total_nodes"] == stats["total_nodes_source"] == ESTATE_NODES


def test_stats_source_total_never_undercounts_what_is_in_hand():
    """A graph built by hand leaves completeness.total_nodes at 0; echoing that
    back would claim an estate smaller than the nodes in the response."""
    graph = _estate()
    graph.completeness.total_nodes = 0
    assert graph.stats()["total_nodes_source"] >= graph.stats()["total_nodes"]


def test_graph_response_stats_reconcile_with_its_own_completeness():
    """The two numbers in one payload must not contradict each other."""
    payload = _filtered_graph_response(apply_node_budget(_estate(), NODE_BUDGET), offset=0, limit=5)

    completeness = payload["completeness"]
    stats = payload["stats"]
    assert completeness["truncated"] is True
    assert completeness["total"] == ESTATE_NODES
    assert stats["total_nodes_source"] == completeness["total"], "stats and completeness disagree about the estate size"
    assert stats["total_nodes"] == NODE_BUDGET, "stats.total_nodes stays what was loaded"


def test_graph_response_on_a_complete_graph_agrees_everywhere():
    payload = _filtered_graph_response(_estate(), offset=0, limit=ESTATE_NODES)

    assert payload["completeness"]["complete"] is True
    assert payload["stats"]["total_nodes"] == payload["stats"]["total_nodes_source"] == ESTATE_NODES


def test_route_docstring_no_longer_promises_unpaginated_stats():
    """The docstring is the contract SDK users read; it claimed stats covered the
    full graph while the budgeted branch shipped stats over the bounded one."""
    from agent_bom.api.routes.graph import get_graph

    doc = get_graph.__doc__ or ""
    assert "Stats reflect the full (unpaginated) graph" not in doc
    assert "total_nodes_source" in doc
