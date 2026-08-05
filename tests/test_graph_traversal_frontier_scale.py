"""Attack-path search must cost the walk, not the snapshot.

``bfs_paths`` (and every other caller of the shared SQLite ``_walk_graph``)
issues one frontier query per node it dequeues. That query asked for
``source_id IN (...) OR target_id IN (...)`` in a single disjunction, which
SQLite cannot drive from either single-column index: the plan collapses to
``SEARCH graph_edges USING INDEX idx_ge_tenant_scan (tenant_id=? AND scan_id=?)``
— a scan of every edge in the snapshot, repeated once per visited node. The
work is therefore O(visited x snapshot_edges): the *unreachable* remainder of
the estate is re-read for every hop of a path that never touches it.

Two guards live here, and they pull in opposite directions on purpose:

* the **scale** guards pin the cost model — the frontier query must be driven
  by an index on ``source_id``/``target_id``, and growing the part of the
  snapshot the walk never reaches must not grow the walk's work;
* the **differential** guards pin the answer — for a matrix of directions,
  filters, depths and budgets, the optimised frontier query must return the
  same rows in the same order as the pre-fix disjunction, so every downstream
  ``discovery_order``/``parent_by_node``/path list is byte-identical. The one
  exception is deliberate and documented at the golden test: when a plan change
  swaps between equally valid shortest routes, reachability and path counts
  still hold and are asserted separately.

Without the differential half, "make it fast" could silently reorder or drop
paths; without the scale half, "keep it correct" leaves the wall in place.

Work is counted in SQLite VDBE steps via the progress handler rather than in
milliseconds: opcode counts are deterministic for a given plan and dataset,
where wall-clock on a shared host is not.
"""

from __future__ import annotations

import hashlib
import json
import random
import sqlite3
from typing import Any

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.db import graph_store as sqlite_graph_store
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

_PROGRESS_OPS = 1_000

# SHA-256 of the 32-case attack-path answer matrix. Originally captured from
# src at 3fc34db8f, then re-blessed once when endpoint indexes and ORDER BY
# rowid changed which of several equal-length routes is reported. Reachability,
# path counts and path validity were unchanged and are asserted directly. See
# TestFrontierQueryIsAnswerIdentical.test_reference_matches_pre_fix_release.
ANSWER_GOLDEN_DIGEST = "6826d89b4c2ac7f86055a66185f4d18eed563b0aebfb1a22c28b4477e1a932c8"

_DYNAMIC = (RelationshipType.INVOKED, RelationshipType.ACCESSED, RelationshipType.DELEGATED_TO)
_STATIC = (RelationshipType.USES, RelationshipType.DEPENDS_ON, RelationshipType.CAN_ACCESS)


def _tree_with_ballast(
    *,
    scan_id: str,
    reachable_nodes: int,
    ballast_edges: int,
    tenant_id: str = "default",
    branching: int = 4,
) -> UnifiedGraph:
    """A fixed reachable tree rooted at ``n0`` plus ``ballast_edges`` unreachable edges.

    The walk from ``n0`` always visits exactly ``reachable_nodes`` nodes no
    matter how large the ballast is, so any growth in traversal work as the
    ballast grows is work spent on parts of the estate the answer never
    contains. Branching keeps the tree inside the API's ``max_depth`` ceiling.
    """
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)
    for index in range(reachable_nodes):
        graph.add_node(UnifiedNode(id=f"n{index}", entity_type=EntityType.AGENT, label=f"n{index}"))
    for index in range(1, reachable_nodes):
        graph.add_edge(
            UnifiedEdge(
                source=f"n{(index - 1) // branching}",
                target=f"n{index}",
                relationship=RelationshipType.USES,
                traversable=True,
            )
        )
    for index in range(ballast_edges):
        left, right = f"b{index}", f"b{index}x"
        graph.add_node(UnifiedNode(id=left, entity_type=EntityType.RESOURCE, label=left))
        graph.add_node(UnifiedNode(id=right, entity_type=EntityType.RESOURCE, label=right))
        graph.add_edge(UnifiedEdge(source=left, target=right, relationship=RelationshipType.USES, traversable=True))
    return graph


def _walk_ticks(store: SQLiteGraphStore, *, scan_id: str, source: str, max_depth: int = 10) -> tuple[int, int]:
    """Return (VDBE ticks, paths found) for one ``bfs_paths`` call."""
    ticks = 0
    original_open = store._open_ro_conn

    def counting_open() -> sqlite3.Connection | None:
        conn = original_open()
        if conn is not None:

            def handler() -> int:
                nonlocal ticks
                ticks += 1
                return 0

            conn.set_progress_handler(handler, _PROGRESS_OPS)
        return conn

    store._open_ro_conn = counting_open  # type: ignore[method-assign]
    try:
        paths, _reachable, _truncated, _depth_limited = store.bfs_paths(
            tenant_id="default", scan_id=scan_id, source=source, max_depth=max_depth
        )
    finally:
        store._open_ro_conn = original_open  # type: ignore[method-assign]
    return ticks, len(paths)


class TestFrontierQueryCostsTheWalkNotTheSnapshot:
    @pytest.mark.parametrize("with_statistics", [False, True], ids=["without-stats", "with-stats"])
    def test_frontier_query_is_driven_by_an_endpoint_index(self, tmp_path, with_statistics):
        """The per-hop query must SEARCH by ``source_id``/``target_id``, never scan the snapshot.

        Asserted on the plan rather than the clock so it holds on a loaded host,
        and asserted in BOTH statistics states.

        The ``without-stats`` case is the original and stricter one: the endpoint
        indexes must carry this plan on their own, so it can never be satisfied
        merely by ``sqlite_stat1``. It used to be written as "assert sqlite_stat1
        does not exist", which held only because nothing recorded statistics.
        The graph store now records them deliberately -- the node read path needs
        them to choose between two indexes sharing a leading prefix -- so absence
        is no longer a property of a real database and asserting it would test
        the fixture rather than the code. Dropping the table explicitly keeps the
        original guarantee provable, and the ``with-stats`` case adds the state
        production actually runs in.
        """
        store = SQLiteGraphStore(tmp_path / "graph.db")
        store.save_graph(_tree_with_ballast(scan_id="plan", reachable_nodes=8, ballast_edges=200))

        # Settle the store's own once-per-process schema init first: it opens a
        # write connection and records statistics, so dropping them before this
        # point would simply see them recreated.
        primer = store._open_ro_conn()
        assert primer is not None
        primer.close()

        writable = sqlite3.connect(tmp_path / "graph.db")
        try:
            if with_statistics:
                sqlite_graph_store.refresh_query_planner_stats(writable)
            else:
                writable.execute("DROP TABLE IF EXISTS sqlite_stat1")
                writable.commit()
        finally:
            writable.close()

        conn = store._open_ro_conn()
        assert conn is not None
        try:
            sql, params = store._frontier_edge_query(
                tenant_id="default",
                scan_id="plan",
                frontier={"n0"},
                traversable_only=True,
                relationship_types=None,
                static_only=False,
                dynamic_only=False,
            )
            plan_rows = conn.execute(f"EXPLAIN QUERY PLAN {sql}", params).fetchall()
            recorded = conn.execute("SELECT count(*) FROM sqlite_master WHERE name = 'sqlite_stat1'").fetchone()[0]
        finally:
            conn.close()

        assert bool(recorded) is with_statistics, "the statistics precondition for this case did not hold"

        details = [str(row[3]) for row in plan_rows]
        graph_edge_steps = [detail for detail in details if "graph_edges" in detail]
        assert graph_edge_steps, f"no graph_edges access in the plan at all: {details}"
        # Every touch of graph_edges must be anchored on an endpoint (or on the
        # rowid the endpoint branches produced). A step keyed only on
        # (tenant_id, scan_id) reads the whole snapshot.
        unanchored = [
            detail for detail in graph_edge_steps if not ("source_id=?" in detail or "target_id=?" in detail or "rowid=?" in detail)
        ]
        assert not unanchored, f"frontier query still scans the whole snapshot: {unanchored}"
        assert [detail for detail in graph_edge_steps if "source_id=?" in detail], f"no source-side seek: {details}"
        assert [detail for detail in graph_edge_steps if "target_id=?" in detail], f"no target-side seek: {details}"

    def test_unreachable_estate_does_not_cost_the_walk(self, tmp_path):
        """Hold the answer fixed, grow the rest of the estate 16x: work must stay flat.

        The reachable chain is identical in both snapshots, so both calls return
        the same paths. Only the edges the walk can never reach differ.
        """
        store = SQLiteGraphStore(tmp_path / "graph.db")
        store.save_graph(_tree_with_ballast(scan_id="small", reachable_nodes=60, ballast_edges=500))
        store.save_graph(_tree_with_ballast(scan_id="large", reachable_nodes=60, ballast_edges=8_000))

        small_ticks, small_paths = _walk_ticks(store, scan_id="small", source="n0")
        large_ticks, large_paths = _walk_ticks(store, scan_id="large", source="n0")

        assert small_paths == large_paths == 59, "the reachable answer must be identical in both snapshots"
        # Pre-fix this ratio tracks the ballast ratio (16x). An endpoint-indexed
        # frontier pays only the b-tree descent, which grows with log(edges).
        assert large_ticks <= max(small_ticks * 3, small_ticks + 200), (
            f"traversal work scales with the unreachable snapshot: {small_ticks} -> {large_ticks} kticks"
        )


# ── Differential guard: the optimised frontier query must be answer-identical ──


def _legacy_frontier_rows(
    conn: sqlite3.Connection,
    *,
    tenant_id: str,
    scan_id: str,
    frontier: set[str],
    traversable_only: bool = False,
    relationship_types: set[RelationshipType] | None = None,
    static_only: bool = False,
    dynamic_only: bool = False,
) -> list[sqlite3.Row]:
    """The pre-fix frontier query, verbatim, as the differential reference.

    Kept as literal SQL rather than by calling the store so that a future change
    to the optimised query is compared against the historical contract and not
    against itself.

    ``INDEXED BY idx_ge_tenant_scan`` pins the plan the pre-fix query actually
    ran under. It is not decoration: the disjunction never named an index, so
    its row order was whatever the planner chose, and merely *adding* the
    endpoint indexes moves the pre-fix query onto ``idx_ge_tenant_scan_target``
    and reorders its rows. Forcing the historical index reproduces the
    historical answer, which is what this reference exists to be. That the
    reference needs pinning at all is the point: order used to be an accident of
    the planner, and ``ORDER BY rowid`` in the shipped query now makes it a
    contract. ``test_reference_matches_pre_fix_release`` cross-checks this
    reference against output captured from the pre-fix code itself.
    """
    from agent_bom.api.graph_store import _DYNAMIC_RELATIONSHIP_VALUES

    if not frontier:
        return []
    ordered = sorted(frontier)
    placeholders = ",".join("?" for _ in ordered)
    where = [
        "tenant_id = ?",
        "scan_id = ?",
        f"(source_id IN ({placeholders}) OR target_id IN ({placeholders}))",
    ]
    params: list[Any] = [tenant_id, scan_id, *ordered, *ordered]
    if traversable_only:
        where.append("traversable = 1")
    if relationship_types:
        rel_values = sorted(rel.value if isinstance(rel, RelationshipType) else str(rel) for rel in relationship_types)
        where.append(f"relationship IN ({','.join('?' for _ in rel_values)})")
        params.extend(rel_values)
    if static_only:
        where.append(f"relationship NOT IN ({','.join('?' for _ in _DYNAMIC_RELATIONSHIP_VALUES)})")
        params.extend(sorted(_DYNAMIC_RELATIONSHIP_VALUES))
    if dynamic_only:
        where.append(f"relationship IN ({','.join('?' for _ in _DYNAMIC_RELATIONSHIP_VALUES)})")
        params.extend(sorted(_DYNAMIC_RELATIONSHIP_VALUES))
    return conn.execute(
        f"SELECT * FROM graph_edges INDEXED BY idx_ge_tenant_scan WHERE {' AND '.join(where)}",  # nosec B608 - test-local reference query
        params,
    ).fetchall()


def _as_store_method(reference):
    """Bind the module-level reference query as a store method (drops ``self``)."""

    def bound(_self, conn, **kwargs):
        return reference(conn, **kwargs)

    return bound


def _tangled_graph(*, scan_id: str, tenant_id: str, nodes: int, edges: int, seed: int) -> UnifiedGraph:
    """A dense, mixed-direction, mixed-relationship graph with dead ends and cycles."""
    rng = random.Random(seed)
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)
    entity_types = [EntityType.AGENT, EntityType.RESOURCE, EntityType.CREDENTIAL, EntityType.SERVER]
    for index in range(nodes):
        graph.add_node(
            UnifiedNode(
                id=f"v{index}",
                entity_type=entity_types[index % len(entity_types)],
                label=f"v{index}",
            )
        )
    relationships = [*_STATIC, *_DYNAMIC]
    for _ in range(edges):
        left = rng.randrange(nodes)
        right = rng.randrange(nodes)
        if left == right:
            continue
        graph.add_edge(
            UnifiedEdge(
                source=f"v{left}",
                target=f"v{right}",
                relationship=rng.choice(relationships),
                direction="bidirectional" if rng.random() < 0.25 else "directed",
                traversable=rng.random() < 0.8,
            )
        )
    return graph


_FILTER_MATRIX = [
    {},
    {"traversable_only": True},
    {"relationship_types": {RelationshipType.USES, RelationshipType.INVOKED}},
    {"static_only": True},
    {"dynamic_only": True},
    {"traversable_only": True, "relationship_types": {RelationshipType.DEPENDS_ON}},
]


class TestFrontierQueryIsAnswerIdentical:
    @pytest.fixture
    def tangled_store(self, tmp_path):
        store = SQLiteGraphStore(tmp_path / "graph.db")
        store.save_graph(_tangled_graph(scan_id="main", tenant_id="default", nodes=120, edges=600, seed=11))
        # Noise the walk must never pick up: a second snapshot and a second
        # tenant sharing the very same node identifiers.
        store.save_graph(_tangled_graph(scan_id="other", tenant_id="default", nodes=120, edges=600, seed=22))
        store.save_graph(_tangled_graph(scan_id="main", tenant_id="tenant-b", nodes=120, edges=600, seed=33))
        return store

    @pytest.mark.parametrize("filters", _FILTER_MATRIX)
    @pytest.mark.parametrize("frontier", [{"v0"}, {"v7"}, {"v0", "v7", "v42"}, {"missing"}, set()])
    def test_rows_match_the_legacy_disjunction(self, tangled_store, filters, frontier):
        """Same rows, same order, for every filter combination the walker uses."""
        conn = tangled_store._open_ro_conn()
        assert conn is not None
        try:
            expected = _legacy_frontier_rows(conn, tenant_id="default", scan_id="main", frontier=frontier, **filters)
            actual = tangled_store._filtered_edge_rows(conn, tenant_id="default", scan_id="main", frontier=frontier, **filters)
        finally:
            conn.close()

        def key(row: sqlite3.Row) -> tuple:
            return (row["source_id"], row["target_id"], row["relationship"], row["direction"], row["traversable"])

        assert [key(row) for row in actual] == [key(row) for row in expected]

    @pytest.mark.parametrize("direction", ["forward", "reverse", "both"])
    @pytest.mark.parametrize("max_depth", [1, 3, 6])
    def test_traversal_output_matches_the_legacy_walk(self, tangled_store, direction, max_depth):
        """The walk's own products — order, parents, budget flag — must not move."""
        conn = tangled_store._open_ro_conn()
        assert conn is not None
        try:
            optimised = tangled_store._walk_graph(
                conn,
                tenant_id="default",
                scan_id="main",
                roots=["v0"],
                direction=direction,
                max_depth=max_depth,
                max_nodes=5000,
                max_edges=25_000,
                deadline_monotonic=None,
                traversable_only=True,
                relationship_types=None,
                static_only=False,
                dynamic_only=False,
                include_roots=True,
            )
            original = SQLiteGraphStore._filtered_edge_rows
            SQLiteGraphStore._filtered_edge_rows = _as_store_method(_legacy_frontier_rows)  # type: ignore[method-assign,assignment]
            try:
                legacy = tangled_store._walk_graph(
                    conn,
                    tenant_id="default",
                    scan_id="main",
                    roots=["v0"],
                    direction=direction,
                    max_depth=max_depth,
                    max_nodes=5000,
                    max_edges=25_000,
                    deadline_monotonic=None,
                    traversable_only=True,
                    relationship_types=None,
                    static_only=False,
                    dynamic_only=False,
                    include_roots=True,
                )
            finally:
                SQLiteGraphStore._filtered_edge_rows = original  # type: ignore[method-assign]
        finally:
            conn.close()

        # scan id, visited set, depths, parents, discovery order, truncated flag.
        assert optimised[0] == legacy[0]
        assert optimised[2] == legacy[2]
        assert optimised[3] == legacy[3]
        assert sorted(optimised[4]) == sorted(legacy[4])
        assert optimised[5] == legacy[5]
        assert optimised[6] == legacy[6]
        assert optimised[7] == legacy[7]
        assert optimised[6], "the differential fixture must actually reach nodes"

    def test_budget_truncation_point_is_unchanged(self, tangled_store):
        """A walk cut by ``max_nodes`` must be cut at the same node, in the same order."""
        conn = tangled_store._open_ro_conn()
        assert conn is not None
        kwargs = dict(
            tenant_id="default",
            scan_id="main",
            roots=["v0"],
            direction="forward",
            max_depth=10,
            max_nodes=17,
            max_edges=25_000,
            deadline_monotonic=None,
            traversable_only=False,
            relationship_types=None,
            static_only=False,
            dynamic_only=False,
            include_roots=True,
        )
        try:
            optimised = tangled_store._walk_graph(conn, **kwargs)  # type: ignore[arg-type]
            original = SQLiteGraphStore._filtered_edge_rows
            SQLiteGraphStore._filtered_edge_rows = _as_store_method(_legacy_frontier_rows)  # type: ignore[method-assign,assignment]
            try:
                legacy = tangled_store._walk_graph(conn, **kwargs)  # type: ignore[arg-type]
            finally:
                SQLiteGraphStore._filtered_edge_rows = original  # type: ignore[method-assign]
        finally:
            conn.close()

        assert optimised[7] is True, "the fixture must actually hit the node budget"
        assert optimised[6] == legacy[6]
        assert optimised[2] == legacy[2]
        assert optimised[7] == legacy[7]

    def test_reference_matches_pre_fix_release(self, tangled_store):
        """Golden: the shipped answer is fixed, and the invariants below hold.

        32 cases — ``bfs_paths`` over two tenants x three sources x five depths,
        plus ``impact_of`` (the reverse walk over the same shared primitive).
        A change here means attack-path results moved for real users; it is not
        a snapshot to re-bless without deciding that the move is correct.

        This digest was re-blessed once, deliberately. It originally captured
        ``src`` at 3fc34db8f. Two later changes altered which representative
        route the walk reports: the roll-up work added endpoint indexes, and
        this branch pinned the frontier to ``ORDER BY rowid``. A node reachable
        by several equal-length routes has several equally valid shortest
        paths, and the one returned follows edge visit order -- so a plan
        change swaps the exemplar without changing the answer.

        The re-bless was justified against the invariants that actually matter,
        which are asserted below rather than left to the digest: the reachable
        set, the number of paths, and the validity of every path are unchanged.
        Only the choice among equal-length routes moved. Pre-change that choice
        was an accident of whichever plan the query planner picked; it is now
        pinned, so this digest is stable in a way the old one was not.
        """
        cases: dict[str, Any] = {}
        for tenant in ("default", "tenant-b"):
            for depth in (1, 2, 3, 5, 10):
                for source in ("v0", "v7", "v42"):
                    paths, reachable, truncated, _depth_limited = tangled_store.bfs_paths(
                        tenant_id=tenant, scan_id="main", source=source, max_depth=depth
                    )
                    cases[f"{tenant}|{source}|{depth}"] = {
                        "paths": paths,
                        "reachable": sorted(reachable),
                        "truncated": truncated,
                    }
            cases[f"impact|{tenant}"] = tangled_store.impact_of(tenant_id=tenant, scan_id="main", node_id="v5", max_depth=4)

        assert len(cases) == 32
        payload = json.dumps(cases, indent=0, sort_keys=True).encode()
        assert hashlib.sha256(payload).hexdigest() == ANSWER_GOLDEN_DIGEST, (
            "attack-path output diverged from the pinned answer. Before re-blessing, check the "
            "invariants below: if they still hold, only the representative route changed; if they "
            "do not, reachability itself moved and the digest is not the thing to edit."
        )

        # The invariants the digest is a proxy for. A future plan change may
        # legitimately swap one equal-length route for another, but it must
        # never change what is reachable, how many paths there are, or make a
        # path that does not follow real edges.
        real_edges: set[tuple[str, str]] = set()
        for edge in _tangled_graph(scan_id="main", tenant_id="default", nodes=120, edges=600, seed=11).edges:
            real_edges.add((edge.source, edge.target))
            real_edges.add((edge.target, edge.source))
        walked = cases["default|v0|10"]["paths"]
        assert len(walked) == 118
        assert cases["default|v0|10"]["reachable"] == sorted({node for path in walked for node in path[1:]})
        for path in walked:
            assert path[0] == "v0", "every path must start at the source"
            assert len(set(path)) == len(path), "a path must not revisit a node"
            for hop in zip(path, path[1:]):
                assert hop in real_edges, f"path traverses an edge that does not exist: {hop}"

    def test_bfs_paths_output_is_identical_across_tenants_and_snapshots(self, tangled_store):
        """End to end: the shipped path list, in order, plus tenant isolation."""
        default_paths, default_reachable, default_truncated, _default_depth_limited = tangled_store.bfs_paths(
            tenant_id="default", scan_id="main", source="v0", max_depth=5
        )
        other_paths, _other_reachable, _, _ = tangled_store.bfs_paths(tenant_id="tenant-b", scan_id="main", source="v0", max_depth=5)

        assert default_paths, "the fixture must produce paths"
        assert default_truncated is False
        assert all(path[0] == "v0" for path in default_paths)
        assert {path[-1] for path in default_paths} <= default_reachable
        # Tenant B holds the same node ids over a different edge set: identical
        # answers would mean the frontier query lost its tenant predicate.
        assert other_paths != default_paths
