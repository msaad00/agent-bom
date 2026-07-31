"""Every derived UnifiedGraph view inherits the source snapshot's truncation.

``filtered_view`` learned this (a filtered view of a truncated snapshot is still
truncated). The five typed views — inventory / attack-path / lateral-movement /
compliance / runtime — did not: they returned ``self._subgraph(...)`` straight
out, so the derived graph carried a default ``GraphCompleteness`` and reported
``truncated=False`` over data the loader had already dropped nodes from.

Truncation is a property of the SOURCE. No projection of it can be complete.
The test enumerates the view methods off the class so a sixth view cannot be
added without deciding — and proving — what it reports.
"""

from __future__ import annotations

import inspect

import pytest

from agent_bom.graph.container import GraphFilterOptions, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

# Extra call arguments per view. A view discovered on the class but missing here
# fails ``test_every_view_method_is_covered`` — the regression guard.
VIEW_ARGS: dict[str, tuple[tuple, dict]] = {
    "inventory_view": ((), {}),
    "attack_path_view": ((), {}),
    "lateral_movement_view": ((), {}),
    "compliance_view": ((), {}),
    "runtime_view": ((), {}),
    "filtered_view": ((GraphFilterOptions(entity_types={EntityType.AGENT}),), {}),
}


def _view_method_names() -> list[str]:
    return sorted(
        name
        for name, member in inspect.getmembers(UnifiedGraph, predicate=inspect.isfunction)
        if name.endswith("_view") and not name.startswith("_")
    )


def _truncated_graph() -> UnifiedGraph:
    """A snapshot bounded at load: 4 of 61 nodes, wired for every typed view."""
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(
        UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a", compliance_tags=["SOC2-CC6.1"]),
    )
    graph.add_node(
        UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="s", compliance_tags=["SOC2-CC6.1"]),
    )
    graph.add_node(UnifiedNode(id="cred:c", entity_type=EntityType.CREDENTIAL, label="c"))
    graph.add_node(UnifiedNode(id="cve:v", entity_type=EntityType.VULNERABILITY, label="v", severity="critical"))
    graph.add_edge(UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES))
    graph.add_edge(UnifiedEdge(source="server:s", target="cred:c", relationship=RelationshipType.EXPOSES_CRED))
    graph.add_edge(UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.INVOKED))
    graph.add_edge(UnifiedEdge(source="server:s", target="cve:v", relationship=RelationshipType.VULNERABLE_TO))
    graph.completeness.truncated = True
    graph.completeness.node_budget = 4
    graph.completeness.total_nodes = 61
    graph.completeness.returned_nodes = 4
    graph.completeness.reason = "node_budget"
    return graph


def _call(graph: UnifiedGraph, name: str) -> UnifiedGraph:
    args, kwargs = VIEW_ARGS[name]
    return getattr(graph, name)(*args, **kwargs)


def test_every_view_method_is_covered():
    """A new ``*_view`` must be added to VIEW_ARGS, forcing this contract on it."""
    assert set(_view_method_names()) == set(VIEW_ARGS), (
        "a UnifiedGraph view was added or removed without deciding what it reports for completeness"
    )


@pytest.mark.parametrize("view_name", sorted(VIEW_ARGS))
def test_view_of_a_truncated_graph_is_still_truncated(view_name: str):
    view = _call(_truncated_graph(), view_name)
    assert view.completeness.truncated is True, f"{view_name} claimed completeness over a bounded snapshot"
    assert view.completeness.reason == "node_budget"
    assert view.completeness.to_dict()["status"] == "truncated"


@pytest.mark.parametrize("view_name", sorted(VIEW_ARGS))
def test_view_keeps_the_upstream_total_and_its_own_returned_count(view_name: str):
    view = _call(_truncated_graph(), view_name)
    assert view.completeness.total_nodes == 61, f"{view_name} rewrote the estate total to its own size"
    assert view.completeness.returned_nodes == len(view.nodes)
    assert view.completeness.node_budget == 4


@pytest.mark.parametrize("view_name", sorted(VIEW_ARGS))
def test_view_of_a_complete_graph_stays_complete(view_name: str):
    """No false positives: projecting a whole snapshot must not invent truncation."""
    graph = _truncated_graph()
    graph.completeness.truncated = False
    graph.completeness.reason = ""
    graph.completeness.node_budget = None
    graph.completeness.total_nodes = len(graph.nodes)
    graph.completeness.returned_nodes = len(graph.nodes)

    view = _call(graph, view_name)
    assert view.completeness.truncated is False
    assert view.completeness.to_dict()["complete"] is True


@pytest.mark.parametrize("view_name", sorted(VIEW_ARGS))
def test_view_never_reports_a_total_below_what_it_returned(view_name: str):
    """A hand-built graph leaves ``total_nodes`` at 0; a view must not echo that
    back next to a non-zero ``returned`` — ``total: 0, returned: 4`` is nonsense."""
    graph = _truncated_graph()
    graph.completeness = type(graph.completeness)()  # pristine, as builders leave it

    payload = _call(graph, view_name).completeness.to_dict()
    assert payload["total"] >= payload["returned"]
