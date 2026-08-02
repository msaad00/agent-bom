"""``traverse_subgraph`` may not launder its source's truncation, or its own.

Every other derived view — ``inventory_view``, ``attack_path_view``,
``lateral_movement_view``, ``compliance_view``, ``runtime_view``,
``filtered_view``, ``rollup_view``, ``drill_down`` — routes through
``UnifiedGraph._inherit_completeness``, so a projection of a bounded snapshot
stays bounded. ``traverse_subgraph`` did not: it returned a fresh
``UnifiedGraph`` carrying a default ``GraphCompleteness``, which reports
``status: complete`` over data the loader had already dropped nodes from.

The Postgres variant was worse than laundered — it was self-contradictory,
returning N nodes while claiming ``returned: 0``.

``POST /v1/graph/query`` happens to be safe today because the route carries the
traversal bool in a separate tuple slot, but any other consumer, and any
composition with ``filtered_view``, inherits the laundered "complete".

The tests assert the *reported* completeness against the graph actually
returned, and pin container/Postgres to the same shape so the two cannot drift.
"""

from __future__ import annotations

import os

import pytest

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

REQUIRES_POSTGRES = pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="AGENT_BOM_POSTGRES_URL is required for the live Postgres traverse_subgraph contract",
)

CHAIN_NODES = 20


def chain(total_nodes: int = CHAIN_NODES, *, scan_id: str = "s", tenant_id: str = "t") -> UnifiedGraph:
    """``n0 -> n1 -> ... -> n{total-1}``, every hop traversable."""
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)
    for index in range(total_nodes):
        graph.add_node(UnifiedNode(id=f"n{index}", entity_type=EntityType.AGENT, label=f"n{index}"))
    for index in range(total_nodes - 1):
        graph.add_edge(
            UnifiedEdge(
                source=f"n{index}",
                target=f"n{index + 1}",
                relationship=RelationshipType.USES,
                traversable=True,
            )
        )
    return graph


def mark_truncated(graph: UnifiedGraph, *, total: int = 60) -> UnifiedGraph:
    """Model a snapshot the loader bounded: we hold N of ``total`` nodes."""
    graph.completeness.truncated = True
    graph.completeness.node_budget = len(graph.nodes)
    graph.completeness.total_nodes = total
    graph.completeness.returned_nodes = len(graph.nodes)
    graph.completeness.reason = "node_budget"
    return graph


@pytest.fixture
def postgres_graph_store():
    """A live PostgresGraphStore bound to an isolated, self-cleaning tenant."""
    from uuid import uuid4

    from agent_bom.api import postgres_common
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore

    postgres_common.reset_pool()
    tenant = f"traverse-{uuid4().hex[:12]}"
    token = set_current_tenant(tenant)
    store = PostgresGraphStore()
    try:
        yield store, tenant
    finally:
        try:
            store.delete_tenant(tenant_id=tenant)
        finally:
            reset_current_tenant(token)
            pool = postgres_common._pool
            if pool is not None:
                pool.close()
            postgres_common.reset_pool()


class TestContainerTraverseSubgraphCompleteness:
    def test_a_traversal_of_a_truncated_snapshot_is_still_truncated(self):
        source = mark_truncated(chain())

        sub, _depths, traversal_truncated = source.traverse_subgraph(["n0"], max_depth=3)
        completeness = sub.completeness.to_dict()

        assert traversal_truncated is False  # the traversal itself fit its budget
        assert completeness["truncated"] is True, "a projection of a bounded snapshot cannot be complete"
        assert completeness["reason"] == "node_budget"
        assert completeness["total"] == 60

    def test_returned_matches_the_nodes_actually_returned(self):
        """The self-contradiction guard: never `returned: 0` beside N nodes."""
        source = mark_truncated(chain())

        sub, _depths, _truncated = source.traverse_subgraph(["n0"], max_depth=3)

        assert len(sub.nodes) == 4
        assert sub.completeness.to_dict()["returned"] == len(sub.nodes)

    def test_a_budget_bounded_traversal_of_a_complete_snapshot_is_truncated(self):
        source = chain()
        assert source.completeness.truncated is False

        sub, _depths, traversal_truncated = source.traverse_subgraph(["n0"], max_depth=19, max_nodes=5)
        completeness = sub.completeness.to_dict()

        assert traversal_truncated is True
        assert completeness["truncated"] is True
        assert completeness["reason"] == "traversal_budget"
        assert completeness["returned"] == len(sub.nodes)

    def test_a_complete_traversal_of_a_complete_snapshot_stays_complete(self):
        """Paired guard: the fix may not mark everything truncated."""
        source = chain()

        sub, _depths, traversal_truncated = source.traverse_subgraph(["n0"], max_depth=19)
        completeness = sub.completeness.to_dict()

        assert traversal_truncated is False
        assert completeness["truncated"] is False
        assert completeness["complete"] is True
        assert completeness["returned"] == len(sub.nodes) == CHAIN_NODES

    def test_a_filtered_view_of_a_traversal_keeps_the_truncation(self):
        """Composition is where a laundered 'complete' would escape unnoticed."""
        from agent_bom.graph.container import GraphFilterOptions

        source = mark_truncated(chain())
        sub, _depths, _truncated = source.traverse_subgraph(["n0"], max_depth=3)

        view = sub.filtered_view(GraphFilterOptions(entity_types={EntityType.AGENT}))

        assert view.completeness.to_dict()["truncated"] is True


@REQUIRES_POSTGRES
class TestPostgresTraverseSubgraphCompleteness:
    def test_returned_matches_the_nodes_actually_returned(self, postgres_graph_store):
        """The shipped bug: 7 nodes returned while reporting ``returned: 0``."""
        store, tenant = postgres_graph_store
        store.save_graph(chain(scan_id="pg-chain", tenant_id=tenant))

        graph, _depths, _truncated = store.traverse_subgraph(tenant_id=tenant, scan_id="pg-chain", roots=["n0"], max_depth=6)
        completeness = graph.completeness.to_dict()

        assert len(graph.nodes) == 7
        assert completeness["returned"] == len(graph.nodes)

    def test_a_budget_bounded_traversal_is_truncated(self, postgres_graph_store):
        store, tenant = postgres_graph_store
        store.save_graph(chain(scan_id="pg-chain", tenant_id=tenant))

        graph, _depths, truncated = store.traverse_subgraph(tenant_id=tenant, scan_id="pg-chain", roots=["n0"], max_depth=19, max_nodes=5)
        completeness = graph.completeness.to_dict()

        assert truncated is True
        assert completeness["truncated"] is True
        assert completeness["reason"] == "traversal_budget"
        assert completeness["returned"] == len(graph.nodes)

    def test_a_complete_traversal_stays_complete(self, postgres_graph_store):
        """Paired guard against a blanket 'truncated'."""
        store, tenant = postgres_graph_store
        store.save_graph(chain(scan_id="pg-chain", tenant_id=tenant))

        graph, _depths, truncated = store.traverse_subgraph(tenant_id=tenant, scan_id="pg-chain", roots=["n0"], max_depth=19)
        completeness = graph.completeness.to_dict()

        assert truncated is False
        assert completeness["truncated"] is False
        assert completeness["complete"] is True
        assert completeness["returned"] == len(graph.nodes) == CHAIN_NODES

    @pytest.mark.parametrize(("max_depth", "max_nodes"), [(6, 500), (19, 5), (19, 500), (3, 500)])
    def test_postgres_traversal_matches_the_in_memory_ground_truth(self, postgres_graph_store, max_depth, max_nodes):
        """Differential: identical nodes, edges, depths AND completeness.

        The in-memory container is the ground truth. Any optimisation to either
        traversal has to keep both sides answering the same thing.
        """
        store, tenant = postgres_graph_store
        source = chain(scan_id="pg-chain", tenant_id=tenant)
        store.save_graph(source)

        expected, expected_depths, expected_truncated = source.traverse_subgraph(["n0"], max_depth=max_depth, max_nodes=max_nodes)
        actual, actual_depths, actual_truncated = store.traverse_subgraph(
            tenant_id=tenant, scan_id="pg-chain", roots=["n0"], max_depth=max_depth, max_nodes=max_nodes
        )

        assert set(actual.nodes) == set(expected.nodes)
        assert {(e.source, e.target) for e in actual.edges} == {(e.source, e.target) for e in expected.edges}
        assert actual_depths == expected_depths
        assert actual_truncated == expected_truncated
        assert actual.completeness.to_dict() == expected.completeness.to_dict()
