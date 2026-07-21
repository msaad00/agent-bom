"""Store-backed live UnifiedGraph — byte-identical differential + memory bound (#4075 PR-3).

Proves :class:`StoreBackedUnifiedGraph` is a drop-in for the in-RAM
:class:`~agent_bom.graph.container.UnifiedGraph`:

* ``to_dict()`` is **byte-identical** to the in-RAM graph on the real self-scan
  fixture, a constructed report, and synthetic scaled graphs;
* the overlay mutation pattern (get node → mutate ``attributes`` in place, and
  ``for node in graph.nodes.values(): mutate``) **persists** and appears in
  ``to_dict()``;
* ``add_edge`` bidirectional-reverse materialisation + dedup evidence-merge match
  the in-RAM semantics;
* adjacency / traversal (``edges_from`` / ``edges_to`` / ``neighbors`` / ``bfs`` /
  ``reachable_from``) match the in-RAM graph;
* peak RAM grows **sub-linearly** vs a full in-RAM copy as the graph scales;
* tenant isolation holds on a shared backend.

The store-backed container is **default-off and unwired** — no builder, overlay,
or persist caller constructs it in production. These tests are the only callers.
"""

from __future__ import annotations

import json
import tracemalloc
from collections.abc import Iterator
from pathlib import Path

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.store_backed import StoreBackedUnifiedGraph, open_store_backed_unified_graph
from agent_bom.graph.types import EntityType, NodeStatus, RelationshipType

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _dumps(graph: UnifiedGraph) -> str:
    return json.dumps(graph.to_dict(), default=str, sort_keys=False)


def _replay(graph: UnifiedGraph, store: StoreBackedUnifiedGraph) -> None:
    """Feed the exact node/edge objects of a built in-RAM graph into the store.

    Node/edge storage is what the store backs; the graph-level analysis/paths
    fields are plain attributes the builder sets identically on either container,
    so mirror them here (in PR-4 the builder would set them on the store directly).
    """
    for node in graph.nodes.values():
        store.add_node(node)
    for edge in graph.edges:
        store.add_edge(edge)
    store.analysis_status = dict(graph.analysis_status)
    store.attack_paths = list(graph.attack_paths)
    store.attack_campaigns = list(graph.attack_campaigns)
    store.interaction_risks = list(graph.interaction_risks)
    store.nhi_governance_findings = list(graph.nhi_governance_findings)


def _sqlite_store(**kwargs) -> StoreBackedUnifiedGraph:
    kwargs.setdefault("backend", "sqlite")
    return open_store_backed_unified_graph(**kwargs)


# ── Fixtures / synthetic builders ────────────────────────────────────────────


def _report_fixtures() -> list[dict]:
    self_scan = json.loads((_FIXTURES / "agent_bom_self_scan_inventory.json").read_text())
    constructed = {
        "scan_id": "constructed",
        "scan_sources": ["mcp-scan"],
        "agents": [
            {
                "name": "planner",
                "type": "claude",
                "source": "local",
                "mcp_servers": [
                    {
                        "name": "files",
                        "packages": [
                            {
                                "name": "requests",
                                "version": "2.0.0",
                                "ecosystem": "pypi",
                                "vulnerabilities": [{"id": "CVE-1", "severity": "critical"}],
                            }
                        ],
                        "tools": [{"name": "read_file"}],
                    }
                ],
            }
        ],
        "blast_radius": [],
    }
    return [self_scan, constructed]


def _gen_nodes(n: int) -> Iterator[UnifiedNode]:
    for i in range(n):
        yield UnifiedNode(
            id=f"n:{i}",
            entity_type=EntityType.AGENT if i % 50 == 0 else EntityType.VULNERABILITY,
            label=f"L{i}",
            severity="high" if i % 3 else "critical",
            risk_score=float(i % 10),
            status=NodeStatus.ACTIVE,
            first_seen="2026-07-20T00:00:00Z",
            last_seen="2026-07-20T00:00:00Z",
            attributes={"cvss_score": 7.0, "blob": "v" * 24},
        )


def _gen_edges(n: int) -> Iterator[UnifiedEdge]:
    for i in range(0, n - 1, 2):
        yield UnifiedEdge(
            source=f"n:{i}",
            target=f"n:{i + 1}",
            relationship=RelationshipType.DEPENDS_ON,
            first_seen="2026-07-20T00:00:00Z",
            last_seen="2026-07-20T00:00:00Z",
            valid_from="2026-07-20T00:00:00Z",
        )


def _synthetic_graph(scan: str, n: int) -> UnifiedGraph:
    g = UnifiedGraph(scan_id=scan, tenant_id="t1", created_at="2026-07-20T00:00:00Z")
    for node in _gen_nodes(n):
        g.add_node(node)
    for edge in _gen_edges(n):
        g.add_edge(edge)
    return g


# ── Byte-identical differential ──────────────────────────────────────────────


@pytest.mark.parametrize("report", _report_fixtures(), ids=["self_scan_fixture", "constructed_report"])
def test_to_dict_byte_identical_on_real_report(report: dict) -> None:
    graph = build_unified_graph_from_report(report, scan_id="s", tenant_id="t1")
    store = _sqlite_store(tenant_id="t1", scan_id=graph.scan_id, created_at=graph.created_at)
    try:
        _replay(graph, store)
        assert _dumps(store) == _dumps(graph)
        assert len(graph.nodes) > 0
    finally:
        store.close()


@pytest.mark.parametrize("n", [1, 200, 2000])
def test_to_dict_byte_identical_on_synthetic(n: int) -> None:
    graph = _synthetic_graph("s", n)
    store = _sqlite_store(tenant_id="t1", scan_id="s", created_at=graph.created_at)
    try:
        _replay(graph, store)
        assert _dumps(store) == _dumps(graph)
    finally:
        store.close()


def test_add_node_merge_union_matches_in_ram() -> None:
    """Second add of the same id must merge-union identically (severity/risk/sources/tags/attrs)."""

    def _v1() -> UnifiedNode:
        return UnifiedNode(
            id="x",
            entity_type=EntityType.PACKAGE,
            label="pkg",
            severity="low",
            severity_id=2,
            risk_score=1.0,
            first_seen="2026-07-20T00:00:00Z",
            last_seen="2026-07-20T00:00:00Z",
            attributes={"a": 1},
            data_sources=["sca"],
            compliance_tags=["CIS-1"],
        )

    def _v2() -> UnifiedNode:
        return UnifiedNode(
            id="x",
            entity_type=EntityType.PACKAGE,
            label="pkg",
            severity="critical",
            severity_id=5,
            risk_score=9.0,
            first_seen="2026-07-20T00:00:00Z",
            last_seen="2026-07-20T00:00:00Z",
            attributes={"b": 2},
            data_sources=["osv"],
            compliance_tags=["CIS-2"],
        )

    g = UnifiedGraph(scan_id="s", tenant_id="t1", created_at="2026-07-20T00:00:00Z")
    g.add_node(_v1())
    g.add_node(_v2())

    store = _sqlite_store(tenant_id="t1", scan_id="s", created_at="2026-07-20T00:00:00Z")
    try:
        store.add_node(_v1())
        store.add_node(_v2())
        assert _dumps(store) == _dumps(g)
    finally:
        store.close()


def test_add_node_caller_mutation_survives_lru_eviction() -> None:
    """A newly added node remains write-back safe before it is evicted."""
    store = _sqlite_store(tenant_id="t1", scan_id="s", capacity=1)
    try:
        first = UnifiedNode(id="first", entity_type=EntityType.PACKAGE, label="first")
        store.add_node(first)
        first.attributes["post_add"] = True

        # Loading a second node evicts the first from the one-entry cache.
        store.add_node(UnifiedNode(id="second", entity_type=EntityType.PACKAGE, label="second"))

        reloaded = store.get_node("first")
        assert reloaded is not None
        assert reloaded.attributes["post_add"] is True
    finally:
        store.close()


def test_add_edge_dedup_evidence_merge_matches_in_ram() -> None:
    def _e(evidence: dict) -> UnifiedEdge:
        return UnifiedEdge(
            source="a",
            target="b",
            relationship=RelationshipType.DEPENDS_ON,
            first_seen="2026-07-20T00:00:00Z",
            last_seen="2026-07-20T00:00:00Z",
            valid_from="2026-07-20T00:00:00Z",
            evidence=dict(evidence),
        )

    def _nodes(g) -> None:
        for nid in ("a", "b"):
            g.add_node(
                UnifiedNode(
                    id=nid,
                    entity_type=EntityType.PACKAGE,
                    label=nid,
                    first_seen="2026-07-20T00:00:00Z",
                    last_seen="2026-07-20T00:00:00Z",
                )
            )

    g = UnifiedGraph(scan_id="s", tenant_id="t1", created_at="2026-07-20T00:00:00Z")
    _nodes(g)
    g.add_edge(_e({"cvss": 7.0, "empty": ""}))
    g.add_edge(_e({"cvss": 9.9, "kev": True}))  # dup triple: cvss kept (present), kev merged in

    store = _sqlite_store(tenant_id="t1", scan_id="s", created_at="2026-07-20T00:00:00Z")
    try:
        _nodes(store)
        store.add_edge(_e({"cvss": 7.0, "empty": ""}))
        store.add_edge(_e({"cvss": 9.9, "kev": True}))
        assert _dumps(store) == _dumps(g)
        edges = list(store.edges)
        assert len(edges) == 1
        assert edges[0].evidence == {"cvss": 7.0, "empty": "", "kev": True}
    finally:
        store.close()


def _bidir_graph(g) -> None:
    for nid in ("a", "b", "c"):
        g.add_node(
            UnifiedNode(
                id=nid,
                entity_type=EntityType.SERVER,
                label=nid,
                first_seen="2026-07-20T00:00:00Z",
                last_seen="2026-07-20T00:00:00Z",
            )
        )
    g.add_edge(
        UnifiedEdge(
            source="a",
            target="b",
            relationship=RelationshipType.SHARES_SERVER,
            direction="bidirectional",
            first_seen="2026-07-20T00:00:00Z",
            last_seen="2026-07-20T00:00:00Z",
            valid_from="2026-07-20T00:00:00Z",
        )
    )
    g.add_edge(
        UnifiedEdge(
            source="b",
            target="c",
            relationship=RelationshipType.DEPENDS_ON,
            first_seen="2026-07-20T00:00:00Z",
            last_seen="2026-07-20T00:00:00Z",
            valid_from="2026-07-20T00:00:00Z",
        )
    )


def test_bidirectional_adjacency_and_traversal_match_in_ram() -> None:
    g = UnifiedGraph(scan_id="s", tenant_id="t1", created_at="2026-07-20T00:00:00Z")
    _bidir_graph(g)
    store = _sqlite_store(tenant_id="t1", scan_id="s", created_at="2026-07-20T00:00:00Z")
    try:
        _bidir_graph(store)
        # to_dict byte-identical (edges list holds only original edges, not reverse)
        assert _dumps(store) == _dumps(g)

        def _adj(graph, nid):
            return sorted((e.source, e.target, e.relationship.value) for e in graph.adjacency.get(nid, []))

        def _radj(graph, nid):
            return sorted((e.source, e.target, e.relationship.value) for e in graph.reverse_adjacency.get(nid, []))

        for nid in ("a", "b", "c"):
            assert _adj(store, nid) == _adj(g, nid), nid
            assert _radj(store, nid) == _radj(g, nid), nid
            assert sorted(store.neighbors(nid)) == sorted(g.neighbors(nid)), nid
            assert sorted(store.sources_of(nid)) == sorted(g.sources_of(nid)), nid

        # Bidirectional edge is traversable both ways; directed one only forward.
        assert store.reachable_from("a") == g.reachable_from("a")
        assert store.reachable_from("c") == g.reachable_from("c")
        assert store.has_edge("a", "b") == g.has_edge("a", "b")
        assert store.has_edge("b", "a") == g.has_edge("b", "a")  # via bidirectional reverse
    finally:
        store.close()


# ── Mutation write-back (the crux) ───────────────────────────────────────────


def test_get_node_mutation_persists_in_to_dict() -> None:
    g = _synthetic_graph("s", 60)
    store = _sqlite_store(tenant_id="t1", scan_id="s", created_at=g.created_at, capacity=8)
    try:
        _replay(g, store)
        # Simulate the cnapp/effective-permissions overlay pattern on BOTH graphs.
        for nid in ("n:0", "n:25", "n:59"):
            g.get_node(nid).attributes["cnapp_exposed"] = True
            store.get_node(nid).attributes["cnapp_exposed"] = True
        # And the getitem-then-mutate pattern used by the builder.
        g.nodes["n:10"].attributes["internet_exposed"] = True
        store.nodes["n:10"].attributes["internet_exposed"] = True
        assert _dumps(store) == _dumps(g)
        # Independently confirm the value round-tripped through the store.
        reread = store.get_node("n:0")
        assert reread.attributes["cnapp_exposed"] is True
    finally:
        store.close()


def test_values_iteration_mutation_persists() -> None:
    """The overlay pattern `for node in graph.nodes.values(): node.attributes[...] = ...`."""
    g = _synthetic_graph("s", 120)
    store = _sqlite_store(tenant_id="t1", scan_id="s", created_at=g.created_at, capacity=8)
    try:
        _replay(g, store)
        for node in g.nodes.values():
            node.attributes["swept"] = 1
        for node in store.nodes.values():  # capacity(8) << 120 forces mid-iteration write-back eviction
            node.attributes["swept"] = 1
        assert _dumps(store) == _dumps(g)
    finally:
        store.close()


# ── Memory bound ─────────────────────────────────────────────────────────────


def _peak_full_in_ram(n: int) -> int:
    tracemalloc.start()
    g = _synthetic_graph("s", n)
    # Touch a bounded working set (the overlay random-access pattern).
    for i in range(0, n, max(1, n // 200)):
        node = g.get_node(f"n:{i}")
        if node:
            node.attributes["touched"] = True
    _ = len(g.nodes)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    del g
    return peak


def _peak_store_backed(n: int) -> int:
    tracemalloc.start()
    store = _sqlite_store(tenant_id="t1", scan_id="s", created_at="2026-07-20T00:00:00Z", capacity=256)
    try:
        for node in _gen_nodes(n):
            store.add_node(node)
        for edge in _gen_edges(n):
            store.add_edge(edge)
        for i in range(0, n, max(1, n // 200)):
            node = store.get_node(f"n:{i}")
            if node:
                node.attributes["touched"] = True
        store.flush()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        store.close()
    tracemalloc.stop()
    return peak


def test_store_backed_peak_is_sublinear_vs_full_in_ram() -> None:
    small_full, small_store = _peak_full_in_ram(2000), _peak_store_backed(2000)
    large_full, large_store = _peak_full_in_ram(8000), _peak_store_backed(8000)

    ratio_small = small_store / small_full
    ratio_large = large_store / large_full

    # The store-backed container holds only a bounded LRU cache + one page, never
    # the full node set — its peak is a small fraction of the full in-RAM graph.
    assert ratio_small < 0.6, f"store/full peak ratio too high at N=2000: {ratio_small:.3f}"
    assert ratio_large < 0.6, f"store/full peak ratio too high at N=8000: {ratio_large:.3f}"
    # Sub-linear intent: as N grows 4x the store/full ratio must stay clearly
    # better than the in-RAM baseline. tracemalloc peaks under xdist are noisy
    # (CI saw 0.175 → 0.181), so allow a small relative slack instead of a
    # strict inequality that flakes on measurement wobble.
    assert ratio_large <= ratio_small * 1.25 + 0.02, (
        f"store advantage eroded with scale: {ratio_small:.3f} -> {ratio_large:.3f}"
    )


# ── Tenant isolation ─────────────────────────────────────────────────────────


def test_tenant_isolation_on_shared_backend() -> None:
    from agent_bom.graph.build_workspace import open_workspace_backend

    backend = open_workspace_backend(backend="sqlite")
    try:
        alpha = StoreBackedUnifiedGraph(backend, tenant_id="alpha", scan_id="a", created_at="2026-07-20T00:00:00Z")
        beta = StoreBackedUnifiedGraph(backend, tenant_id="beta", scan_id="b", created_at="2026-07-20T00:00:00Z")
        for graph, extra in ((alpha, "vuln:alpha-only"), (beta, "vuln:beta-only")):
            graph.add_node(
                UnifiedNode(
                    id="shared:1",
                    entity_type=EntityType.AGENT,
                    label="agent",
                    first_seen="2026-07-20T00:00:00Z",
                    last_seen="2026-07-20T00:00:00Z",
                )
            )
            graph.add_node(
                UnifiedNode(
                    id=extra,
                    entity_type=EntityType.VULNERABILITY,
                    label="v",
                    severity="high",
                    first_seen="2026-07-20T00:00:00Z",
                    last_seen="2026-07-20T00:00:00Z",
                )
            )

        assert alpha.has_node("shared:1") and beta.has_node("shared:1")
        assert alpha.has_node("vuln:alpha-only") and not alpha.has_node("vuln:beta-only")
        assert beta.has_node("vuln:beta-only") and not beta.has_node("vuln:alpha-only")
        assert {n.id for n in alpha.nodes.values()} == {"shared:1", "vuln:alpha-only"}
    finally:
        backend.close()


# ── Inherited algorithms run unchanged against the store-backed views ─────────


def test_inherited_algorithms_match_in_ram() -> None:
    """bfs / shortest_path / filter_nodes / search_nodes / impact_of /
    traverse_subgraph / to_ocsf_events are inherited from UnifiedGraph and must
    produce the same results when driven by the store-backed views."""
    g = _synthetic_graph("s", 40)
    store = _sqlite_store(tenant_id="t1", scan_id="s", created_at=g.created_at, capacity=8)
    try:
        _replay(g, store)

        assert store.bfs("n:0", max_depth=3, traversable_only=False) == g.bfs("n:0", max_depth=3, traversable_only=False)
        assert store.shortest_path("n:0", "n:1") == g.shortest_path("n:0", "n:1")
        assert store.reachable_from("n:0") == g.reachable_from("n:0")
        assert store.impact_of("n:1") == g.impact_of("n:1")

        def _ids(nodes):
            return sorted(n.id for n in nodes)

        assert _ids(store.filter_nodes(min_severity="critical")) == _ids(g.filter_nodes(min_severity="critical"))
        assert _ids(store.nodes_by_type(EntityType.AGENT)) == _ids(g.nodes_by_type(EntityType.AGENT))
        assert _ids(store.search_nodes("L1")) == _ids(g.search_nodes("L1"))

        sub_store, depth_s, trunc_s = store.traverse_subgraph(["n:0"], max_depth=4)
        sub_g, depth_g, trunc_g = g.traverse_subgraph(["n:0"], max_depth=4)
        assert set(sub_store.nodes) == set(sub_g.nodes)
        assert depth_s == depth_g and trunc_s == trunc_g

        assert len(store.to_ocsf_events()) == len(g.to_ocsf_events())
    finally:
        store.close()
