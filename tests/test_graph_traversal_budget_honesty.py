"""A bounded traversal must say so — and must never certify its own bound as the total.

``bfs_paths`` walks the graph under a hard ``max_nodes``/``max_edges``/deadline
budget and already computes a ``truncated`` flag. Both store implementations
threw that flag away at the unpack site, so ``/v1/graph/paths`` had no way to
know its answer was bounded. That is worse than a missing signal: the route
still emitted a ``completeness`` block, but one describing only the *pagination*
of the returned page — asserting a ``total`` equal to the truncated walk's own
count. A client paging to exhaustion collected the bound and believed it had
everything.

The invariant pinned here is the one ``/v1/graph/query`` already holds: when a
traversal budget cut the walk short, the response says ``truncated`` with
``reason="traversal_budget"`` and reports **no** total, because the total is
precisely what a bounded walk cannot know.

Every assertion compares the *reported* number against an independently known
ground truth, and each honesty test is paired with a complete-graph twin so a
fix that simply hard-codes "truncated" cannot pass.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

# ``bfs_paths`` hard-codes this budget in both stores. A tree larger than it is
# the only way to exercise the truncation path end to end.
BFS_MAX_NODES = 5000
BIG_TREE_NODES = 8421
SMALL_TREE_NODES = 40

REQUIRES_POSTGRES = pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="AGENT_BOM_POSTGRES_URL is required for the live Postgres traversal-budget contract",
)


def tree(total_nodes: int, *, scan_id: str, tenant_id: str = "default", branching: int = 4) -> UnifiedGraph:
    """A rooted tree at ``n0``: every node except the root is reachable from it."""
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)
    for index in range(total_nodes):
        graph.add_node(UnifiedNode(id=f"n{index}", entity_type=EntityType.AGENT, label=f"n{index}"))
    for index in range(1, total_nodes):
        parent = (index - 1) // branching
        graph.add_edge(
            UnifiedEdge(
                source=f"n{parent}",
                target=f"n{index}",
                relationship=RelationshipType.USES,
                traversable=True,
            )
        )
    return graph


@pytest.fixture
def postgres_graph_store():
    """A live PostgresGraphStore bound to an isolated, self-cleaning tenant."""
    from uuid import uuid4

    from agent_bom.api import postgres_common
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore

    postgres_common.reset_pool()
    tenant = f"budget-{uuid4().hex[:12]}"
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


@pytest.fixture
def sqlite_graph_store(tmp_path):
    """Install a real SQLite-backed graph store behind the API routes."""
    from agent_bom.api import stores as api_stores

    original = api_stores._graph_store
    store = SQLiteGraphStore(tmp_path / "graph.db")
    set_graph_store(store)
    try:
        yield store
    finally:
        set_graph_store(original)


class TestBfsPathsReportsItsBudget:
    def test_truncated_walk_is_reported_as_truncated(self, tmp_path):
        """8,421-node tree, budget 5,000: the walk is bounded and must admit it."""
        store = SQLiteGraphStore(tmp_path / "graph.db")
        store.save_graph(tree(BIG_TREE_NODES, scan_id="big"))

        paths, reachable, truncated = store.bfs_paths(tenant_id="default", scan_id="big", source="n0", max_depth=10)

        true_reachable = BIG_TREE_NODES - 1
        assert truncated is True
        # The under-report is real, and is exactly what the flag exists to disclose.
        assert len(reachable) < true_reachable
        assert len(reachable) <= BFS_MAX_NODES
        assert len(paths) <= BFS_MAX_NODES

    def test_complete_walk_is_reported_as_complete(self, tmp_path):
        """The paired guard: a graph inside the budget reports the true total."""
        store = SQLiteGraphStore(tmp_path / "graph.db")
        store.save_graph(tree(SMALL_TREE_NODES, scan_id="small"))

        paths, reachable, truncated = store.bfs_paths(tenant_id="default", scan_id="small", source="n0", max_depth=10)

        assert truncated is False
        assert len(reachable) == SMALL_TREE_NODES - 1
        assert len(paths) == SMALL_TREE_NODES - 1


class TestGraphPathsRouteCompleteness:
    """The user-visible number: what ``GET /v1/graph/paths`` certifies as fact."""

    @staticmethod
    def _get(**params) -> dict:
        query = "&".join(f"{key}={value}" for key, value in params.items())
        response = TestClient(app).get(f"/v1/graph/paths?{query}")
        assert response.status_code == 200, response.text
        return response.json()

    def test_truncated_traversal_reports_no_total_and_the_budget_reason(self, sqlite_graph_store):
        sqlite_graph_store.save_graph(tree(BIG_TREE_NODES, scan_id="big"))

        body = self._get(source_id="n0", scan_id="big", max_depth=10, limit=5)
        completeness = body["completeness"]

        assert completeness["truncated"] is True
        assert completeness["reason"] == "traversal_budget"
        # The defect: a `total` WAS asserted, and it was the bound, not the truth.
        assert "total" not in completeness, (
            f"a budget-bounded walk cannot know the total, yet reported {completeness.get('total')!r} "
            f"(true reachable = {BIG_TREE_NODES - 1})"
        )
        assert body["truncated"] is True
        assert body["reachable_count"] < BIG_TREE_NODES - 1

    def test_complete_traversal_still_reports_the_true_total(self, sqlite_graph_store):
        """Paired guard: nothing here may become unconditionally 'truncated'."""
        sqlite_graph_store.save_graph(tree(SMALL_TREE_NODES, scan_id="small"))

        body = self._get(source_id="n0", scan_id="small", max_depth=10, limit=1000)
        completeness = body["completeness"]

        assert body["truncated"] is False
        assert completeness["truncated"] is False
        assert completeness["complete"] is True
        assert completeness["total"] == SMALL_TREE_NODES - 1
        assert body["reachable_count"] == SMALL_TREE_NODES - 1

    def test_page_limit_alone_keeps_the_true_total_and_its_own_reason(self, sqlite_graph_store):
        """Pagination truncation is a weaker, different claim: the total IS known."""
        sqlite_graph_store.save_graph(tree(SMALL_TREE_NODES, scan_id="small"))

        body = self._get(source_id="n0", scan_id="small", max_depth=10, limit=5)
        completeness = body["completeness"]

        assert completeness["truncated"] is True
        assert completeness["reason"] == "path_page_limit"
        assert completeness["returned"] == 5
        assert completeness["total"] == SMALL_TREE_NODES - 1


@REQUIRES_POSTGRES
class TestPostgresBfsPathsReportsItsBudget:
    def test_truncated_walk_is_reported_as_truncated(self, postgres_graph_store):
        store, tenant = postgres_graph_store
        store.save_graph(tree(BIG_TREE_NODES, scan_id="pg-big", tenant_id=tenant))

        paths, reachable, truncated = store.bfs_paths(tenant_id=tenant, scan_id="pg-big", source="n0", max_depth=10)

        assert truncated is True
        assert len(reachable) < BIG_TREE_NODES - 1
        assert len(paths) <= BFS_MAX_NODES

    def test_complete_walk_is_reported_as_complete(self, postgres_graph_store):
        store, tenant = postgres_graph_store
        store.save_graph(tree(SMALL_TREE_NODES, scan_id="pg-small", tenant_id=tenant))

        _paths, reachable, truncated = store.bfs_paths(tenant_id=tenant, scan_id="pg-small", source="n0", max_depth=10)

        assert truncated is False
        assert len(reachable) == SMALL_TREE_NODES - 1
