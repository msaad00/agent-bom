"""``/v1/graph/rollup?node=X`` must not materialise the whole snapshot.

Drilling into one container returns that container's direct children. The
shipped path answered it by loading every node and edge of the snapshot and
then reading twenty entries out of the result, so the cost of a twenty-row
answer grew with the estate:

    5,065 nodes ->    53.9 ms   (5,065 materialised, 20 answered)
   20,046 nodes ->   265.8 ms  (20,046 materialised, 20 answered)
   40,091 nodes ->   571.2 ms  (40,091 materialised, 20 answered)
   80,181 nodes -> 1,169.1 ms  (80,181 materialised, 20 answered)

The containment subtree under the drill target is the only part of the estate
the answer depends on, and the stores already expose an incremental walk
(``traverse_subgraph``, the primitive that made ``impact_of`` sublinear). So the
fetch is scoped to that subtree instead.

The core guard is differential: the scoped read must produce the *same payload*
as full materialisation — same children, same aggregates, same summary, same
completeness dict — for every shape of drill target. An optimisation that
changes the answer is a defect, not an optimisation.

The honesty guards are the twins of the ones #4595 landed: a bounded read must
report itself bounded, and a complete read must still report the true total.
Scoping the fetch introduces a *new* bound (the traversal budget), which is
exactly the kind of self-inflicted cut that got reported as "complete" before.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore, containment_drilldown_graph
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.rollup import (
    ROLLUP_CONTAINMENT_RELATIONSHIP_TYPES,
    ROLLUP_CONTAINMENT_RELATIONSHIPS,
    RollupFilters,
    drill_down,
)
from agent_bom.graph.types import EntityType, RelationshipType

TENANT = "rollup-tenant"
# The tenant the API middleware establishes for an unauthenticated test request.
API_TENANT = "default"
SCAN = "rollup-scan"

ACCOUNTS = 4
APPS_PER_ACCOUNT = 3
RESOURCES_PER_APP = 5


def _estate(tenant: str = TENANT) -> UnifiedGraph:
    """org -> account -> application -> cloud resource, plus a non-containment edge.

    The ``USES`` edge and the orphan exist so a scoped fetch that quietly widened
    its relationship filter, or that missed a node the full load sees, shows up
    as a payload difference rather than passing by luck.
    """
    graph = UnifiedGraph(scan_id=SCAN, tenant_id=tenant)
    graph.add_node(UnifiedNode(id="org-0", entity_type=EntityType.ORG, label="org-0"))
    graph.add_node(UnifiedNode(id="orphan-0", entity_type=EntityType.AGENT, label="orphan-0"))
    for account in range(ACCOUNTS):
        acct = f"acct-{account}"
        graph.add_node(UnifiedNode(id=acct, entity_type=EntityType.ACCOUNT, label=acct))
        graph.add_edge(UnifiedEdge(source="org-0", target=acct, relationship=RelationshipType.CONTAINS))
        for app_index in range(APPS_PER_ACCOUNT):
            app = f"app-{account}-{app_index}"
            graph.add_node(UnifiedNode(id=app, entity_type=EntityType.APPLICATION, label=app))
            graph.add_edge(UnifiedEdge(source=acct, target=app, relationship=RelationshipType.CONTAINS))
            for resource in range(RESOURCES_PER_APP):
                res = f"res-{account}-{app_index}-{resource}"
                graph.add_node(
                    UnifiedNode(
                        id=res,
                        entity_type=EntityType.CLOUD_RESOURCE,
                        label=res,
                        severity="critical" if resource == 0 else "low",
                        attributes={"internet_exposed": resource == 1},
                    )
                )
                graph.add_edge(UnifiedEdge(source=app, target=res, relationship=RelationshipType.CONTAINS))
            graph.add_edge(UnifiedEdge(source=app, target="orphan-0", relationship=RelationshipType.USES))
    # account -> cloud resource via OWNS: the inventory shape drill-down rolls up
    # even though the relationship is not CONTAINS.
    graph.add_node(UnifiedNode(id="owned-0", entity_type=EntityType.CLOUD_RESOURCE, label="owned-0", severity="high"))
    graph.add_edge(UnifiedEdge(source="acct-0", target="owned-0", relationship=RelationshipType.OWNS))
    return graph


def _persist(db_path, tenant: str) -> SQLiteGraphStore:
    backend = SQLiteGraphStore(db_path=db_path)
    graph = _estate(tenant)
    backend.save_graph_streaming(
        scan_id=SCAN,
        tenant_id=tenant,
        nodes=iter(list(graph.nodes.values())),
        edges=iter(list(graph.edges)),
    )
    return backend


@pytest.fixture
def store(tmp_path) -> SQLiteGraphStore:
    return _persist(tmp_path / "graph.db", TENANT)


@pytest.fixture
def api_store(tmp_path) -> SQLiteGraphStore:
    """The same estate under the tenant an API request resolves to."""
    return _persist(tmp_path / "api-graph.db", API_TENANT)


def _full_materialisation(store: SQLiteGraphStore, tenant: str = TENANT) -> UnifiedGraph:
    """The shipped fetch: every node and edge of the snapshot."""
    return store.load_graph(tenant_id=tenant, scan_id=SCAN, relationship_types=ROLLUP_CONTAINMENT_RELATIONSHIPS)


DRILL_TARGETS = [
    "org-0",  # root: the whole tree hangs off it
    "acct-0",  # mid-tree, and the OWNS child
    "app-1-2",  # one level above the leaves
    "res-0-0-0",  # a leaf with no children
    "orphan-0",  # present but outside the containment tree
    "does-not-exist",  # absent from the snapshot entirely
]


class TestScopedDrillDownMatchesFullMaterialisation:
    """The differential guard: same answer, smaller read."""

    @pytest.mark.parametrize("node_id", DRILL_TARGETS)
    @pytest.mark.parametrize("node_budget", [None, 2, 7, 10_000], ids=["default", "cut-at-2", "cut-at-7", "ample"])
    def test_payload_is_identical_to_the_full_load(self, store, node_id, node_budget):
        """Identical at every budget: the threshold picks a strategy, not an answer."""
        expected = drill_down(_full_materialisation(store), node_id)
        scoped = drill_down(
            containment_drilldown_graph(store, tenant_id=TENANT, scan_id=SCAN, node_id=node_id, node_budget=node_budget),
            node_id,
        )
        assert json.dumps(scoped, sort_keys=True) == json.dumps(expected, sort_keys=True)

    @pytest.mark.parametrize(
        "filters",
        [
            RollupFilters(min_severity="high"),
            RollupFilters(exposed_only=True),
            RollupFilters(min_severity="critical", exposed_only=True),
        ],
    )
    def test_payload_is_identical_under_filters(self, store, filters):
        expected = drill_down(_full_materialisation(store), "acct-0", filters=filters)
        scoped = drill_down(
            containment_drilldown_graph(store, tenant_id=TENANT, scan_id=SCAN, node_id="acct-0"),
            "acct-0",
            filters=filters,
        )
        assert json.dumps(scoped, sort_keys=True) == json.dumps(expected, sort_keys=True)

    def test_the_scoped_read_is_smaller_than_the_snapshot(self, store):
        """Structural, not timing: the fetch must not touch the whole estate."""
        snapshot = _full_materialisation(store)
        scoped = containment_drilldown_graph(store, tenant_id=TENANT, scan_id=SCAN, node_id="app-1-2")
        assert len(scoped.nodes) == RESOURCES_PER_APP + 1  # the app plus its resources
        assert len(scoped.nodes) < len(snapshot.nodes)

    def test_an_absent_node_does_not_materialise_the_estate(self, store):
        scoped = containment_drilldown_graph(store, tenant_id=TENANT, scan_id=SCAN, node_id="does-not-exist")
        assert scoped.nodes == {}

    def test_the_scoped_graph_is_labelled_with_the_resolved_tenant(self, store):
        """A graph that mislabels its own tenant is a cross-tenant footgun."""
        scoped = containment_drilldown_graph(store, tenant_id=TENANT, scan_id=SCAN, node_id="acct-0")
        assert scoped.tenant_id == TENANT
        default_store = SQLiteGraphStore(db_path=store._db_path)
        blank = default_store.traverse_subgraph(tenant_id="", scan_id=SCAN, roots=["acct-0"])[0]
        assert blank.tenant_id == default_store.load_graph(tenant_id="", scan_id=SCAN).tenant_id


class TestSubtreesTooLargeForTheFastPathFallBack:
    """The budget selects a fetch strategy; it never bounds the answer.

    A truncated walk would ship every ``descendant_count`` in the response as a
    silent floor, and at the root of the containment tree the subtree *is* the
    estate, so the walk is slower than one bulk read anyway (143ms vs 57ms on a
    5,065-node snapshot). Both reasons point the same way: fall back, do not cut.
    """

    def test_a_subtree_over_the_budget_returns_the_full_materialisation(self, store):
        expected = drill_down(_full_materialisation(store), "org-0")
        scoped = containment_drilldown_graph(store, tenant_id=TENANT, scan_id=SCAN, node_id="org-0", node_budget=3)
        assert json.dumps(drill_down(scoped, "org-0"), sort_keys=True) == json.dumps(expected, sort_keys=True)

    def test_the_fallback_answer_is_never_reported_as_truncated(self, store):
        """The twin: blanket pessimism fails here."""
        scoped = containment_drilldown_graph(store, tenant_id=TENANT, scan_id=SCAN, node_id="org-0", node_budget=3)
        completeness = drill_down(scoped, "org-0")["completeness"]
        assert completeness["truncated"] is False
        assert completeness["complete"] is True
        assert completeness.get("reason", "") == ""
        assert completeness["total"] == ACCOUNTS
        assert completeness["returned"] == ACCOUNTS

    def test_a_subtree_within_the_budget_still_reports_the_true_total(self, store):
        payload = drill_down(containment_drilldown_graph(store, tenant_id=TENANT, scan_id=SCAN, node_id="acct-0"), "acct-0")
        completeness = payload["completeness"]
        assert completeness["truncated"] is False
        assert completeness["complete"] is True
        assert completeness.get("reason", "") == ""
        # acct-0 contains 3 applications and OWNS one resource.
        assert completeness["total"] == APPS_PER_ACCOUNT + 1
        assert completeness["returned"] == APPS_PER_ACCOUNT + 1

    def test_the_walk_is_only_taken_when_the_subtree_fits(self, store, monkeypatch):
        calls: list[str] = []
        for name in ("load_graph", "traverse_subgraph"):
            original = getattr(type(store), name)

            def _spy(self, *args, _name=name, _original=original, **kwargs):
                calls.append(_name)
                return _original(self, *args, **kwargs)

            monkeypatch.setattr(type(store), name, _spy)

        containment_drilldown_graph(store, tenant_id=TENANT, scan_id=SCAN, node_id="app-0-0")
        assert calls == ["traverse_subgraph"], calls
        calls.clear()
        containment_drilldown_graph(store, tenant_id=TENANT, scan_id=SCAN, node_id="org-0", node_budget=3)
        assert calls == ["traverse_subgraph", "load_graph"], calls

    def test_the_node_budget_binds_before_the_depth_limit(self, store):
        """``max_depth`` cuts a walk *without* setting the truncation flag.

        The fallback is selected by that flag, so a depth-bound walk would
        return a short subtree that looks complete and never fall back — the
        drill-down would report "no children" for containers that have them.
        A walk of depth d visits d+1 distinct nodes, so a depth limit equal to
        the node budget can only be reached after the node budget has already
        reported itself.
        """
        graph, _depths, truncated = store.traverse_subgraph(
            tenant_id=TENANT,
            scan_id=SCAN,
            roots=["org-0"],
            direction="forward",
            max_depth=1,
            max_nodes=10_000,
            relationship_types=set(ROLLUP_CONTAINMENT_RELATIONSHIP_TYPES),
        )
        assert truncated is False and len(graph.nodes) < len(_estate().nodes), (
            "depth-limited walks still report themselves complete; the scoped fetch must not rely on max_depth"
        )
        deep = containment_drilldown_graph(store, tenant_id=TENANT, scan_id=SCAN, node_id="org-0", node_budget=8)
        assert json.dumps(drill_down(deep, "org-0"), sort_keys=True) == json.dumps(
            drill_down(_full_materialisation(store), "org-0"), sort_keys=True
        )


class TestSQLiteTraverseSubgraphCompletenessParity:
    """#4595 fixed the container and Postgres; the default backend was left out.

    Routing drill-down through ``traverse_subgraph`` makes the SQLite store's
    laundered completeness reachable from a shipped endpoint, so it is pinned to
    the in-memory container the same way the Postgres variant is.
    """

    def _in_memory(self, **kwargs):
        return _estate().traverse_subgraph(**kwargs)

    @pytest.mark.parametrize("max_nodes", [3, 10, 500])
    def test_sqlite_traversal_matches_the_in_memory_ground_truth(self, store, max_nodes):
        kwargs = dict(roots=["org-0"], direction="forward", max_depth=6, max_nodes=max_nodes)
        expected, expected_depths, expected_truncated = self._in_memory(**kwargs)
        actual, actual_depths, actual_truncated = store.traverse_subgraph(tenant_id=TENANT, scan_id=SCAN, **kwargs)

        assert actual_truncated == expected_truncated
        assert set(actual.nodes) == set(expected.nodes)
        assert {(e.source, e.target) for e in actual.edges} == {(e.source, e.target) for e in expected.edges}
        assert actual_depths == expected_depths
        assert actual.completeness.to_dict() == expected.completeness.to_dict()

    def test_returned_matches_the_nodes_actually_returned(self, store):
        graph, _depths, _truncated = store.traverse_subgraph(tenant_id=TENANT, scan_id=SCAN, roots=["acct-0"], max_depth=4)
        assert graph.completeness.to_dict()["returned"] == len(graph.nodes)
        assert len(graph.nodes) > 0


class TestContainmentTaxonomyHasOneSource:
    def test_the_fetched_relationships_are_the_ones_rolled_up(self):
        """A containment relationship added to the roll-up but not to the fetch
        would silently drop children out of every drill-down."""
        from agent_bom.graph.rollup import _ACCOUNT_RESOURCE_CONTAINMENT_RELS, _CONTAINMENT_RELS

        assert ROLLUP_CONTAINMENT_RELATIONSHIPS == _CONTAINMENT_RELS | _ACCOUNT_RESOURCE_CONTAINMENT_RELS
        assert {r.value for r in ROLLUP_CONTAINMENT_RELATIONSHIP_TYPES} == set(ROLLUP_CONTAINMENT_RELATIONSHIPS)


class TestRollupEndpointScopesItsFetch:
    """The endpoint, not just the helper: a drill-down must not call ``load_graph``."""

    @pytest.fixture
    def client(self, api_store):
        from starlette.testclient import TestClient

        from agent_bom.api import stores as api_stores
        from agent_bom.api.server import app
        from agent_bom.api.stores import set_graph_store

        original = api_stores._graph_store
        set_graph_store(api_store)
        try:
            yield TestClient(app)
        finally:
            set_graph_store(original)

    def _calls(self, api_store, monkeypatch) -> list[str]:
        seen: list[str] = []
        for name in ("load_graph", "traverse_subgraph"):
            original = getattr(type(api_store), name)

            def _spy(self, *args, _name=name, _original=original, **kwargs):
                seen.append(_name)
                return _original(self, *args, **kwargs)

            monkeypatch.setattr(type(api_store), name, _spy)
        return seen

    def test_a_drill_down_request_never_loads_the_whole_snapshot(self, api_store, client, monkeypatch):
        calls = self._calls(api_store, monkeypatch)
        response = client.get("/v1/graph/rollup", params={"scan_id": SCAN, "node": "acct-0"})
        assert response.status_code == 200, response.text
        assert response.json()["node"]["id"] == "acct-0"
        assert calls == ["traverse_subgraph"], calls

    def test_the_drill_down_response_is_the_full_materialisation_answer(self, api_store, client):
        expected = drill_down(_full_materialisation(api_store, API_TENANT), "acct-0")
        response = client.get("/v1/graph/rollup", params={"scan_id": SCAN, "node": "acct-0"})
        assert response.status_code == 200, response.text
        assert response.json() == expected

    def test_attack_path_mode_drill_down_is_scoped_too(self, api_store, client, monkeypatch):
        """``node`` wins over ``mode`` in the payload, so it must win in the fetch."""
        expected = drill_down(_full_materialisation(api_store, API_TENANT), "acct-0")
        calls = self._calls(api_store, monkeypatch)
        response = client.get("/v1/graph/rollup", params={"scan_id": SCAN, "node": "acct-0", "mode": "attack_path"})
        assert response.status_code == 200, response.text
        assert calls == ["traverse_subgraph"], calls
        assert response.json() == expected

    def test_the_top_level_rollup_still_loads_the_estate(self, api_store, client, monkeypatch):
        """No ``node``: the roll-up aggregates the whole estate and must fetch it."""
        calls = self._calls(api_store, monkeypatch)
        response = client.get("/v1/graph/rollup", params={"scan_id": SCAN})
        assert response.status_code == 200, response.text
        assert calls == ["load_graph"], calls


class TestPartialBackendsKeepTheirAnswer:
    """A backend without an incremental walk falls back, it does not 501."""

    def test_an_unsupported_traversal_falls_back_to_the_full_load(self, store):
        from agent_bom.api.neptune_graph import NeptuneGraphStoreUnsupportedOperationError

        class _NoTraversal:
            def __init__(self, inner):
                self._inner = inner
                self.loaded = False

            def traverse_subgraph(self, **_kwargs):
                raise NeptuneGraphStoreUnsupportedOperationError("traverse_subgraph")

            def load_graph(self, **kwargs):
                self.loaded = True
                return self._inner.load_graph(**kwargs)

        partial = _NoTraversal(store)
        graph = containment_drilldown_graph(partial, tenant_id=TENANT, scan_id=SCAN, node_id="acct-0")  # type: ignore[arg-type]
        assert partial.loaded is True
        assert drill_down(graph, "acct-0") == drill_down(_full_materialisation(store), "acct-0")


class TestTraversalEdgeLookupIsSargable:
    """The walk is only incremental if its per-hop edge query is indexed.

    The frontier lookup runs once per hop. Served as a prefix scan of
    ``(tenant_id, scan_id)`` it reads every edge in the snapshot on every hop —
    the walk materialises 21 nodes and still costs time linear in estate size.
    Measured on an 80,181-node snapshot, per hop:

        (source_id OR target_id), no composite index   12,876 us  full scan
        (source_id OR target_id), stats not collected  12,876 us  full scan
        (source_id OR target_id), after ANALYZE            28 us  MULTI-INDEX OR
        UNION of two branches, stats or no stats            33 us  two index seeks

    So the guard is on the plan the store's OWN query produces, on a store that
    has never been ANALYZEd — which is every store right after a scan writes it.
    """

    def _plan(self, store, **kwargs) -> str:
        conn = sqlite3.connect(str(store._db_path))
        conn.row_factory = sqlite3.Row
        try:
            captured: dict[str, tuple] = {}

            class _ExplainingConn:
                def execute(self, sql, params=()):
                    captured["call"] = (sql, list(params))
                    return conn.execute(sql, params)

            store._filtered_edge_rows(
                _ExplainingConn(),  # type: ignore[arg-type]
                tenant_id=TENANT,
                scan_id=SCAN,
                frontier={"acct-0"},
                **kwargs,
            )
            sql, params = captured["call"]
            return " | ".join(str(row[-1]) for row in conn.execute("EXPLAIN QUERY PLAN " + sql, params))
        finally:
            conn.close()

    @pytest.mark.parametrize(
        "kwargs",
        [
            {},
            {"traversable_only": True},
            {"relationship_types": set(ROLLUP_CONTAINMENT_RELATIONSHIP_TYPES)},
            {"static_only": True},
        ],
    )
    def test_every_frontier_read_seeks_on_the_node_id(self, store, kwargs):
        plan = self._plan(store, **kwargs)
        assert "source_id=?" in plan, plan
        assert "target_id=?" in plan, plan

    def test_the_composite_frontier_indexes_exist(self, store):
        conn = sqlite3.connect(str(store._db_path))
        try:
            indexes = {row[1] for row in conn.execute("PRAGMA index_list(graph_edges)")}
        finally:
            conn.close()
        assert {"idx_ge_tenant_scan_source", "idx_ge_tenant_scan_target"} <= indexes, indexes
