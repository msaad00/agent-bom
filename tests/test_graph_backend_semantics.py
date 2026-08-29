"""One graph, one set of answers — whichever backend and whichever read path.

Five semantics that had drifted apart, all pre-dating the completeness (#4760)
and edge-dedup (#4762) work:

1. **A severity floor narrows findings; it must not delete the topology.** Only
   finding-like nodes (vulnerability, misconfiguration, drift incident) carry a
   severity — agents, servers, packages, resources and identities all rank 0. A
   floor applied to every node collapses a populated estate to a scatter of
   disconnected findings. SQLite's paging path learned this in #2879; Postgres,
   both backends' ``load_graph``, and the in-memory filter never did, so the
   same question got two answers depending on which store answered and which
   query parameters were set.

2. **A node budget must bound the read, not the result.** Postgres pushes the
   budget into SQL; SQLite materialized the whole snapshot and trimmed
   afterwards — a bound that is declared but applied too late to help. The
   selected nodes must also drive endpoint-indexed edge reads; otherwise the
   store still scans every edge in the snapshot and filters them in Python.

3. **Deep ``offset`` is O(offset).** ``/v1/graph`` and ``/v1/graph/agents``
   reject it past a cap; ``/v1/graph/search`` accepted any offset.

4. **``GET /v1/graph`` documented an induced subgraph it has never returned.**
   ``edges_for_node_ids`` matches ``source OR target`` on purpose — that is what
   keeps a severity-ranked finding page attached to its assets, and it is how
   the containment-ancestor walk finds parents. The docstring was the defect,
   not the behaviour; the response now says how many edges cross the boundary.

5. **An unfiltered stats read must be served, not recomputed.** SQLite reads the
   entity-type and severity breakdowns materialised on the snapshot row;
   Postgres re-ran both GROUP BYs over ``graph_nodes`` on every page view.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any, Iterator

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode

CONTEXT_NODES = {"agent:a", "server:fs", "pkg:express", "cloud:bucket", "role:deploy"}
HIGH_FLOOR = 4  # "high"


def _estate(scan_id: str = "sev-topo") -> UnifiedGraph:
    """A connected estate: context nodes plus one critical and one low finding."""
    g = UnifiedGraph(scan_id=scan_id, tenant_id="default")
    g.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="billing-agent"))
    g.add_node(UnifiedNode(id="server:fs", entity_type=EntityType.SERVER, label="mcp-fs"))
    g.add_node(UnifiedNode(id="pkg:express", entity_type=EntityType.PACKAGE, label="express@4"))
    g.add_node(UnifiedNode(id="cloud:bucket", entity_type=EntityType.CLOUD_RESOURCE, label="pii-bucket"))
    g.add_node(UnifiedNode(id="role:deploy", entity_type=EntityType.ROLE, label="deploy-role"))
    g.add_node(UnifiedNode(id="vuln:crit", entity_type=EntityType.VULNERABILITY, label="CVE-CRIT", severity="critical", risk_score=9.5))
    g.add_node(UnifiedNode(id="vuln:low", entity_type=EntityType.VULNERABILITY, label="CVE-LOW", severity="low", risk_score=2.0))
    g.add_edge(UnifiedEdge(source="agent:a", target="server:fs", relationship=RelationshipType.USES))
    g.add_edge(UnifiedEdge(source="server:fs", target="pkg:express", relationship=RelationshipType.DEPENDS_ON))
    g.add_edge(UnifiedEdge(source="pkg:express", target="vuln:crit", relationship=RelationshipType.VULNERABLE_TO))
    g.add_edge(UnifiedEdge(source="pkg:express", target="vuln:low", relationship=RelationshipType.VULNERABLE_TO))
    g.add_edge(UnifiedEdge(source="role:deploy", target="cloud:bucket", relationship=RelationshipType.CAN_ACCESS))
    return g


# ── 1. one judgement about what a severity floor means ──────────────────────


class TestSeverityFloorJudgement:
    """The predicate itself, so every backend has one thing to agree with."""

    def test_non_finding_nodes_are_never_dropped_by_a_floor(self) -> None:
        from agent_bom.graph.severity_floor import node_passes_severity_floor

        for entity_type in (EntityType.AGENT, EntityType.SERVER, EntityType.PACKAGE, EntityType.CLOUD_RESOURCE, EntityType.ROLE):
            assert node_passes_severity_floor(entity_type=entity_type, severity="", min_severity_rank=5), (
                f"{entity_type} carries no severity; a floor must not delete it"
            )

    def test_findings_below_the_floor_are_dropped(self) -> None:
        from agent_bom.graph.severity_floor import node_passes_severity_floor

        assert not node_passes_severity_floor(entity_type=EntityType.VULNERABILITY, severity="low", min_severity_rank=HIGH_FLOOR)
        assert node_passes_severity_floor(entity_type=EntityType.VULNERABILITY, severity="critical", min_severity_rank=HIGH_FLOOR)

    def test_drift_incidents_are_findings_like_their_siblings(self) -> None:
        """The route's in-memory predicate knew only two of the three finding types."""
        from agent_bom.graph.severity_floor import node_passes_severity_floor

        assert not node_passes_severity_floor(entity_type=EntityType.DRIFT_INCIDENT, severity="low", min_severity_rank=HIGH_FLOOR)
        assert node_passes_severity_floor(entity_type=EntityType.DRIFT_INCIDENT, severity="critical", min_severity_rank=HIGH_FLOOR)

    def test_no_floor_admits_everything(self) -> None:
        from agent_bom.graph.severity_floor import node_passes_severity_floor

        assert node_passes_severity_floor(entity_type=EntityType.VULNERABILITY, severity="", min_severity_rank=0)

    @pytest.mark.parametrize("placeholder", ["?", "%s"])
    def test_sql_fragment_matches_the_predicate_for_both_drivers(self, placeholder: str) -> None:
        from agent_bom.graph.severity_floor import severity_floor_sql

        sql, params = severity_floor_sql(0, placeholder=placeholder)
        assert sql == "" and params == [], "no floor means no clause"

        sql, params = severity_floor_sql(HIGH_FLOOR, placeholder=placeholder)
        assert placeholder in sql
        assert sql.count(placeholder) == len(params)
        assert "entity_type NOT IN" in sql, "the clause must exempt non-finding entity types"


# ── the backends, exercised the same way ────────────────────────────────────


@pytest.fixture
def sqlite_store(tmp_path: Path) -> SQLiteGraphStore:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_estate())
    return store


@pytest.fixture
def postgres_store() -> Iterator[Any]:
    """Live Postgres when one is configured; skipped otherwise.

    The source-level pin below runs everywhere, so a runner without a database
    still fails if Postgres re-grows its own severity judgement.
    """
    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("AGENT_BOM_POSTGRES_URL not set")
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore

    store = PostgresGraphStore()
    token = set_current_tenant("default")
    try:
        store.save_graph(_estate())
        yield store
    finally:
        reset_current_tenant(token)


@pytest.fixture(params=["sqlite", "postgres"])
def graph_store(request: pytest.FixtureRequest) -> Any:
    return request.getfixturevalue(f"{request.param}_store")


class TestSeverityFloorKeepsTopologyOnEveryBackend:
    def test_inventory_query_is_exact_and_finding_aware(self, graph_store: Any) -> None:
        from agent_bom.graph.ocsf import FINDING_ENTITY_TYPES

        finding_types = {entity_type.value for entity_type in FINDING_ENTITY_TYPES}
        result = graph_store.query_inventory(
            tenant_id="default",
            asset_entity_types={entity_type.value for entity_type in EntityType} - finding_types,
            severity="critical",
            limit=50,
        )
        assert result["scan_id"] == "sev-topo"
        assert result["total"] == 1
        assert [node.id for node in result["nodes"]] == ["pkg:express"]
        assert result["finding_summaries"]["pkg:express"] == {
            "total": 2,
            "by_severity": {"critical": 1, "low": 1},
            "ids": ["vuln:crit", "vuln:low"],
            "top_severity": "critical",
        }
        assert result["facets"]["severity"] == [
            {"value": None, "count": 4},
            {"value": "critical", "count": 1},
        ]

    def test_page_nodes(self, graph_store: Any) -> None:
        _scan, _created, nodes, total, _cursor = graph_store.page_nodes(tenant_id="default", min_severity_rank=HIGH_FLOOR, limit=100)
        ids = {n.id for n in nodes}
        assert CONTEXT_NODES <= ids, f"severity floor deleted the topology: {sorted(ids)}"
        assert "vuln:crit" in ids
        assert "vuln:low" not in ids
        assert total == len(ids), "the page total must count the same nodes the page returns"

    def test_snapshot_stats(self, graph_store: Any) -> None:
        stats = graph_store.snapshot_stats(tenant_id="default", min_severity_rank=HIGH_FLOOR)
        assert stats["total_nodes"] == len(CONTEXT_NODES) + 1

    def test_search_nodes(self, graph_store: Any) -> None:
        results, total, _cursor = graph_store.search_nodes(tenant_id="default", query="express", min_severity_rank=HIGH_FLOOR, limit=50)
        assert {n.id for n in results} == {"pkg:express"}, "a package matched the query and carries no severity"
        assert total == 1

    def test_load_graph_keeps_the_graph_connected(self, graph_store: Any) -> None:
        graph = graph_store.load_graph(tenant_id="default", min_severity_rank=HIGH_FLOOR)
        assert CONTEXT_NODES <= set(graph.nodes), f"severity floor deleted the topology: {sorted(graph.nodes)}"
        assert "vuln:crit" in graph.nodes
        assert "vuln:low" not in graph.nodes
        # The path pkg:express -> vuln:crit survives, so the finding is still
        # attached to something rather than floating alone.
        assert any(e.source == "pkg:express" and e.target == "vuln:crit" for e in graph.edges)


def test_postgres_does_not_hand_roll_its_own_severity_floor() -> None:
    """Enforced on every runner, database or not.

    Postgres compared ``severity_id >= %s`` against every node in four separate
    places. The shared fragment is the only permitted spelling.
    """
    import inspect

    from agent_bom.api.postgres_graph import PostgresGraphStore

    for method in ("load_graph", "snapshot_stats", "page_nodes", "search_nodes"):
        source = inspect.getsource(getattr(PostgresGraphStore, method))
        assert "severity_id >= " not in source, (
            f"PostgresGraphStore.{method} still compares severity_id directly, which drops every "
            "context node the finding hangs off; use severity_floor_sql"
        )
        assert "severity_floor" in source, f"PostgresGraphStore.{method} should build its floor with the shared helper"


def test_postgres_inventory_is_native_sql_not_python_paging() -> None:
    import inspect

    from agent_bom.api.postgres_graph import PostgresGraphStore

    source = inspect.getsource(PostgresGraphStore.query_inventory)
    assert "page_nodes" not in source and "search_nodes" not in source
    assert "COUNT(*)" in source
    assert "jsonb_array_elements_text" in source
    assert "finding_severity" in source


# ── 2. a node budget must bound the read, not just the result ───────────────


class TestNodeBudgetBoundsTheRead:
    def test_sqlite_load_graph_does_not_materialize_the_whole_snapshot(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Count the nodes the load actually builds, not the ones it returns.

        SQLite read every row and trimmed afterwards, so a 5,000-node snapshot
        under a 50-node budget still built 5,000 ``UnifiedNode`` objects. At the
        200k-node estate the investigation budget exists to protect, that is the
        ~783 MB the budget was introduced to avoid.
        """
        from agent_bom.db import graph_store as sqlite_graph_store

        estate_size = 5_000
        budget = 50

        big = UnifiedGraph(scan_id="budget-scan", tenant_id="default")
        for i in range(estate_size):
            big.add_node(UnifiedNode(id=f"asset:{i}", entity_type=EntityType.CLOUD_RESOURCE, label=f"asset-{i}", risk_score=i / 100.0))
        store = SQLiteGraphStore(tmp_path / "graph.db")
        store.save_graph(big)

        built = 0
        real_node = sqlite_graph_store.UnifiedNode

        def counting_node(*args: Any, **kwargs: Any) -> UnifiedNode:
            nonlocal built
            built += 1
            return real_node(*args, **kwargs)

        monkeypatch.setattr(sqlite_graph_store, "UnifiedNode", counting_node)
        graph = store.load_graph(tenant_id="default", node_budget=budget)

        assert len(graph.nodes) == budget
        assert built <= budget, f"built {built} nodes to return {budget}: the budget was applied after materialization"
        assert graph.completeness.truncated is True
        assert graph.completeness.total_nodes == estate_size
        assert graph.completeness.returned_nodes == budget
        assert graph.completeness.reason == "node_budget"

    def test_sqlite_budget_keeps_the_highest_risk_nodes(self, tmp_path: Path) -> None:
        """Bounding earlier must not change *which* nodes survive."""
        big = UnifiedGraph(scan_id="budget-rank", tenant_id="default")
        for i in range(200):
            big.add_node(UnifiedNode(id=f"asset:{i}", entity_type=EntityType.CLOUD_RESOURCE, label=f"asset-{i}", risk_score=float(i)))
        store = SQLiteGraphStore(tmp_path / "graph.db")
        store.save_graph(big)

        graph = store.load_graph(tenant_id="default", node_budget=10)
        assert set(graph.nodes) == {f"asset:{i}" for i in range(190, 200)}

    def test_sqlite_unbounded_load_still_reports_complete(self, sqlite_store: SQLiteGraphStore) -> None:
        graph = sqlite_store.load_graph(tenant_id="default")
        assert graph.completeness.truncated is False
        assert graph.completeness.returned_nodes == len(graph.nodes)

    def test_sqlite_budgeted_load_keeps_only_edges_between_kept_nodes(self, tmp_path: Path) -> None:
        big = UnifiedGraph(scan_id="budget-edges", tenant_id="default")
        for i in range(50):
            big.add_node(UnifiedNode(id=f"asset:{i}", entity_type=EntityType.CLOUD_RESOURCE, label=f"a{i}", risk_score=float(i)))
        for i in range(49):
            big.add_edge(UnifiedEdge(source=f"asset:{i}", target=f"asset:{i + 1}", relationship=RelationshipType.DEPENDS_ON))
        store = SQLiteGraphStore(tmp_path / "graph.db")
        store.save_graph(big)

        graph = store.load_graph(tenant_id="default", node_budget=10)
        for edge in graph.edges:
            assert edge.source in graph.nodes and edge.target in graph.nodes

    def test_sqlite_budgeted_edge_read_seeks_from_selected_node_ids(self, tmp_path: Path) -> None:
        """A node budget must also keep the edge read off the snapshot-wide index."""
        from agent_bom.db import graph_store as sqlite_graph_store

        graph = UnifiedGraph(scan_id="budget-edge-plan", tenant_id="default")
        for i in range(40):
            graph.add_node(
                UnifiedNode(
                    id=f"asset:{i}",
                    entity_type=EntityType.CLOUD_RESOURCE,
                    label=f"asset-{i}",
                    risk_score=float(i),
                )
            )
        for i in range(39):
            graph.add_edge(
                UnifiedEdge(
                    source=f"asset:{i}",
                    target=f"asset:{i + 1}",
                    relationship=RelationshipType.DEPENDS_ON,
                )
            )

        db_path = tmp_path / "graph.db"
        SQLiteGraphStore(db_path).save_graph(graph)
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        captured: list[tuple[str, list[Any]]] = []

        class _RecordingConnection:
            def execute(self, sql: str, params: list[Any] | tuple[Any, ...] = ()):
                if "graph_edges" in sql:
                    captured.append((sql, list(params)))
                return conn.execute(sql, params)

        try:
            loaded = sqlite_graph_store.load_graph(
                _RecordingConnection(),  # type: ignore[arg-type]
                tenant_id="default",
                scan_id="budget-edge-plan",
                node_budget=10,
            )
            edge_sql, edge_params = captured[-1]
            plan = [str(row[3]) for row in conn.execute(f"EXPLAIN QUERY PLAN {edge_sql}", edge_params)]
        finally:
            conn.close()

        assert len(loaded.nodes) == 10
        graph_edge_steps = [step for step in plan if "graph_edges" in step or "idx_ge_tenant_scan_source" in step]
        assert graph_edge_steps, plan
        assert all("source_id=?" in step or "rowid=?" in step for step in graph_edge_steps), (
            f"budgeted load still reads the whole edge snapshot: {graph_edge_steps}"
        )


# ── the API surfaces ────────────────────────────────────────────────────────


@pytest.fixture
def client(sqlite_store: SQLiteGraphStore) -> Iterator[TestClient]:
    original = api_stores._graph_store
    set_graph_store(sqlite_store)
    try:
        yield TestClient(app)
    finally:
        set_graph_store(original)


# ── 3. deep offset is O(offset) on every paged surface ──────────────────────


@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("/v1/graph", {}),
        ("/v1/graph/agents", {}),
        ("/v1/graph/search", {"q": "express"}),
    ],
)
def test_deep_offset_is_rejected_on_every_node_paging_surface(client: TestClient, path: str, params: dict[str, str]) -> None:
    from agent_bom.api.graph_store import MAX_NODE_PAGE_OFFSET

    response = client.get(path, params={**params, "offset": MAX_NODE_PAGE_OFFSET + 1, "limit": 1})
    assert response.status_code == 422, f"{path} accepted an offset past the cap"
    assert "cursor" in response.json()["detail"], "the rejection must name the supported alternative"


def test_shallow_offset_still_works_on_search(client: TestClient) -> None:
    response = client.get("/v1/graph/search", params={"q": "express", "offset": 0, "limit": 10})
    assert response.status_code == 200


# ── 4. the graph response is the induced subgraph it documents ──────────────


def _paged_estate(scan_id: str = "dangle") -> UnifiedGraph:
    """High-risk nodes that fill page one, each attached to a low-risk neighbour."""
    g = UnifiedGraph(scan_id=scan_id, tenant_id="default")
    for i in range(3):
        g.add_node(UnifiedNode(id=f"agent:{i}", entity_type=EntityType.AGENT, label=f"agent-{i}", risk_score=9.0 - i))
        g.add_node(UnifiedNode(id=f"server:{i}", entity_type=EntityType.SERVER, label=f"srv-{i}", risk_score=0.0))
        g.add_edge(UnifiedEdge(source=f"agent:{i}", target=f"server:{i}", relationship=RelationshipType.USES))
    return g


@pytest.fixture
def paged_client(tmp_path: Path) -> Iterator[TestClient]:
    store = SQLiteGraphStore(tmp_path / "paged.db")
    store.save_graph(_paged_estate())
    original = api_stores._graph_store
    set_graph_store(store)
    try:
        yield TestClient(app)
    finally:
        set_graph_store(original)


def test_graph_page_counts_the_edges_that_cross_its_boundary(paged_client: TestClient) -> None:
    """The payload is not induced — so it must say how far past its nodes it reaches.

    Dropping these edges was the wrong fix and was tried first: a page ranked by
    severity puts the findings on it and their assets off it, so an induced page
    hands back unattached dots (and starves the containment-ancestor walk, which
    finds parents by looking at exactly these edges). The defect was the claim,
    not the behaviour.
    """
    response = paged_client.get("/v1/graph", params={"limit": 3})
    assert response.status_code == 200
    body = response.json()
    node_ids = {n["id"] for n in body["nodes"]}
    crossing = [(e["source"], e["target"]) for e in body["edges"] if e["source"] not in node_ids or e["target"] not in node_ids]
    assert crossing, "fixture no longer produces a boundary-crossing page, so this proves nothing"
    assert body["completeness"]["boundary_edges"] == len(crossing), (
        "the response must declare how many of its edges reach past its node list"
    )


def test_a_whole_page_declares_no_boundary_edges(paged_client: TestClient) -> None:
    """When the page holds the whole estate, nothing crosses the boundary."""
    response = paged_client.get("/v1/graph", params={"limit": 500})
    body = response.json()
    node_ids = {n["id"] for n in body["nodes"]}
    assert len(node_ids) == 6
    assert len(body["edges"]) == 3
    assert body["completeness"]["boundary_edges"] == 0


def test_the_documented_contract_matches_what_the_route_returns(paged_client: TestClient) -> None:
    """The docstring claimed an induced subgraph the route has never returned."""
    from agent_bom.api.routes.graph import get_graph

    doc = get_graph.__doc__ or ""
    assert "only include edges between returned nodes" not in doc
    assert "boundary_edges" in doc


# ── 5. an unfiltered stats read is served, not recomputed ───────────────────


class TestSnapshotStatsReadsMaintainedCounts:
    """``/v1/graph`` calls ``snapshot_stats`` on every page.

    The entity-type and severity breakdowns are accumulated at write time, so an
    unfiltered read is an O(1) lookup on the snapshot row. SQLite does that;
    Postgres re-ran both GROUP BYs over ``graph_nodes`` on every request, which
    is O(N) per page view of an estate that only gets bigger. The two backends
    must answer this from the same place — and, whichever place, with the same
    numbers.
    """

    def test_sqlite_serves_the_breakdown_from_the_snapshot_row(self, sqlite_store: SQLiteGraphStore) -> None:
        import sqlite3

        conn = sqlite3.connect(sqlite_store._db_path)
        conn.execute(
            "UPDATE graph_snapshots SET node_type_counts = ?, risk_summary = ? WHERE scan_id = 'sev-topo'",
            ('{"agent": 41}', '{"critical": 42}'),
        )
        conn.commit()
        conn.close()

        stats = sqlite_store.snapshot_stats(tenant_id="default", scan_id="sev-topo")
        assert stats["node_types"] == {"agent": 41}
        assert stats["severity_counts"] == {"critical": 42}

    def test_postgres_serves_the_breakdown_from_the_snapshot_row(self, postgres_store: Any) -> None:
        """Tampered sentinels come back only if the read never touched graph_nodes."""
        from agent_bom.api.postgres_common import _tenant_connection

        with _tenant_connection(postgres_store._pool) as conn:
            conn.execute(
                "UPDATE graph_snapshots SET node_type_counts = %s, risk_summary = %s WHERE scan_id = %s AND tenant_id = %s",
                ('{"agent": 41}', '{"critical": 42}', "sev-topo", "default"),
            )
            conn.commit()

        stats = postgres_store.snapshot_stats(tenant_id="default", scan_id="sev-topo")
        assert stats["node_types"] == {"agent": 41}, "Postgres re-aggregated graph_nodes instead of reading the maintained counts"
        assert stats["severity_counts"] == {"critical": 42}

    def test_postgres_falls_back_to_the_live_group_by_for_legacy_snapshots(self, postgres_store: Any) -> None:
        """Rows written before the column existed are NULL; they must not read as empty."""
        from agent_bom.api.postgres_common import _tenant_connection

        with _tenant_connection(postgres_store._pool) as conn:
            conn.execute(
                "UPDATE graph_snapshots SET node_type_counts = NULL WHERE scan_id = %s AND tenant_id = %s",
                ("sev-topo", "default"),
            )
            conn.commit()

        stats = postgres_store.snapshot_stats(tenant_id="default", scan_id="sev-topo")
        assert stats["node_types"] == {"agent": 1, "server": 1, "package": 1, "cloud_resource": 1, "role": 1, "vulnerability": 2}
        assert stats["severity_counts"] == {"critical": 1, "low": 1}

    def test_the_maintained_breakdown_equals_the_live_one(self, graph_store: Any) -> None:
        """A cached count that disagrees with the estate is worse than a slow one."""
        cached = graph_store.snapshot_stats(tenant_id="default", scan_id="sev-topo")
        # An entity-type filter that admits everything forces the recompute path
        # without narrowing the population it counts.
        live = graph_store.snapshot_stats(
            tenant_id="default",
            scan_id="sev-topo",
            entity_types={"agent", "server", "package", "cloud_resource", "role", "vulnerability"},
        )
        assert cached["node_types"] == live["node_types"]
        assert cached["severity_counts"] == live["severity_counts"]
        assert cached["total_nodes"] == live["total_nodes"]

    def test_both_backends_report_the_same_stats(self, sqlite_store: SQLiteGraphStore, postgres_store: Any) -> None:
        sqlite_stats = sqlite_store.snapshot_stats(tenant_id="default", scan_id="sev-topo")
        postgres_stats = postgres_store.snapshot_stats(tenant_id="default", scan_id="sev-topo")
        for key in ("total_nodes", "total_edges", "node_types", "severity_counts", "relationship_types"):
            assert sqlite_stats[key] == postgres_stats[key], f"backends disagree on {key}"
