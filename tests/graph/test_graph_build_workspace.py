"""Storage-backed graph build workspace (#4075, PR-1 producer-streaming foundation).

These pin the workspace primitive's contract on the SQLite backend:

* **parity oracle** — persisting a graph *through* the workspace yields a
  byte-identical snapshot (and identical delta digest) to persisting the graph's
  ``nodes.values()`` / ``edges`` directly;
* **bounded working set** — a full iteration over the workspace peaks at a small
  fraction of a full in-memory materialisation of the same nodes, and that
  fraction does not erode as N grows 4x (tracemalloc proof, à la the repo's
  existing ``prior_delta_digest`` peak guard). ``UnifiedNode`` is ``slots``-based
  and cannot be weak-referenced, so peak allocation is the honest instrument;
* **idempotency** — re-adding the same keys does not duplicate rows;
* **tenant isolation** — two tenants sharing a logical id stay separate.

The real-Postgres backend (incl. a cross-process writer race) is exercised in
``tests/graph/test_graph_build_workspace_postgres.py``.
"""

from __future__ import annotations

import tracemalloc
from pathlib import Path

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import RelationshipType, UnifiedEdge
from agent_bom.graph.build_workspace import (
    GraphBuildWorkspace,
    _SQLiteWorkspaceBackend,
    open_graph_build_workspace,
)
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, NodeStatus


@pytest.fixture(autouse=True)
def _force_sqlite_backends(monkeypatch: pytest.MonkeyPatch) -> None:
    # This file pins the SQLite-backed contract. Keep the SQLiteGraphStore's
    # retention lookup local (it routes to the Postgres pool when this env is
    # set) so the suite is deterministic regardless of an ambient Postgres URL.
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)


def _synthetic_graph(scan: str, n: int, tenant: str = "t1") -> UnifiedGraph:
    g = UnifiedGraph(scan_id=scan, tenant_id=tenant)
    for i in range(n):
        g.add_node(
            UnifiedNode(
                id=f"n:{i}",
                entity_type=EntityType.AGENT if i % 50 == 0 else EntityType.VULNERABILITY,
                label=f"L{i}",
                severity="high" if i % 3 else "critical",
                risk_score=float(i % 10),
                status=NodeStatus.ACTIVE,
                # No canonical_id in attributes on purpose — stresses the
                # from_dict canonical_id injection that parity must neutralise.
                attributes={"cvss_score": 7.0, "blob": "v" * 24},
            )
        )
    for i in range(0, n - 1, 2):
        g.add_edge(UnifiedEdge(source=f"n:{i}", target=f"n:{i + 1}", relationship=RelationshipType.DEPENDS_ON))
    return g


def _dump_rows(store: SQLiteGraphStore, tenant: str, scan: str) -> tuple[list, list]:
    import agent_bom.db.graph_store as sq

    with sq.open_graph_db(store._db_path) as conn:
        nodes = conn.execute(
            "SELECT id, entity_type, label, category_uid, class_uid, type_uid, status, "
            "risk_score, severity, severity_id, first_seen, last_seen, attributes, "
            "compliance_tags, data_sources, dimensions "
            "FROM graph_nodes WHERE tenant_id = ? AND scan_id = ? ORDER BY id",
            (tenant, scan),
        ).fetchall()
        edges = conn.execute(
            "SELECT source_id, target_id, relationship, direction, weight, traversable, "
            "first_seen, last_seen, valid_from, valid_to, confidence, provenance, "
            "source_scan_id, source_run_id, evidence, activity_id "
            "FROM graph_edges WHERE tenant_id = ? AND scan_id = ? "
            "ORDER BY source_id, target_id, relationship",
            (tenant, scan),
        ).fetchall()
    return [tuple(r) for r in nodes], [tuple(r) for r in edges]


def test_workspace_roundtrip_is_byte_identical_to_direct_stream(tmp_path: Path) -> None:
    graph = _synthetic_graph("s", 300)

    direct = SQLiteGraphStore(tmp_path / "direct.db")
    direct.save_graph_streaming(
        scan_id=graph.scan_id,
        tenant_id=graph.tenant_id,
        nodes=iter(graph.nodes.values()),
        edges=iter(graph.edges),
    )

    via_ws = SQLiteGraphStore(tmp_path / "via_ws.db")
    with GraphBuildWorkspace(_SQLiteWorkspaceBackend(), tenant_id=graph.tenant_id, batch_size=64) as ws:
        ws.add_nodes(graph.nodes.values())
        ws.add_edges(graph.edges)
        assert ws.node_count() == len(graph.nodes)
        assert ws.edge_count() == len(graph.edges)
        via_ws.save_graph_streaming(
            scan_id=graph.scan_id,
            tenant_id=graph.tenant_id,
            nodes=ws.iter_nodes(),
            edges=ws.iter_edges(),
        )

    d_nodes, d_edges = _dump_rows(direct, graph.tenant_id, graph.scan_id)
    w_nodes, w_edges = _dump_rows(via_ws, graph.tenant_id, graph.scan_id)
    assert d_nodes == w_nodes, "node rows diverged when routed through the workspace"
    assert d_edges == w_edges, "edge rows diverged when routed through the workspace"

    # Delta digest — the input to delta-alert computation — must also match.
    assert (
        direct.prior_delta_digest(tenant_id=graph.tenant_id, scan_id=graph.scan_id).nodes
        == via_ws.prior_delta_digest(tenant_id=graph.tenant_id, scan_id=graph.scan_id).nodes
    )


def test_workspace_roundtrip_byte_identical_on_real_builder_fixture(tmp_path: Path) -> None:
    import json

    from agent_bom.graph.builder import build_unified_graph_from_report

    report = json.loads((Path(__file__).parent.parent / "fixtures" / "agent_bom_self_scan_inventory.json").read_text())
    graph = build_unified_graph_from_report(report, scan_id="s", tenant_id="t1")
    assert len(graph.nodes) > 0

    direct = SQLiteGraphStore(tmp_path / "d.db")
    direct.save_graph_streaming(scan_id="s", tenant_id="t1", nodes=iter(graph.nodes.values()), edges=iter(graph.edges))

    via_ws = SQLiteGraphStore(tmp_path / "w.db")
    with GraphBuildWorkspace(_SQLiteWorkspaceBackend(), tenant_id="t1", batch_size=32) as ws:
        ws.add_nodes(graph.nodes.values())
        ws.add_edges(graph.edges)
        via_ws.save_graph_streaming(scan_id="s", tenant_id="t1", nodes=ws.iter_nodes(), edges=ws.iter_edges())

    assert _dump_rows(direct, "t1", "s") == _dump_rows(via_ws, "t1", "s")


def _node_gen(n: int):
    for i in range(n):
        yield UnifiedNode(
            id=f"n:{i}",
            entity_type=EntityType.VULNERABILITY,
            label=f"L{i}",
            severity="high",
            attributes={"cvss_score": 7.0, "blob": "v" * 64},
        )


def _materialize_peak(n: int) -> int:
    tracemalloc.start()
    everything = list(_node_gen(n))  # what the builder holds today: all N at once
    assert len(everything) == n
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    del everything
    return peak


def _iter_peak(n: int, batch: int) -> int:
    ws = GraphBuildWorkspace(_SQLiteWorkspaceBackend(), tenant_id="t1", batch_size=batch)
    try:
        ws.add_nodes(_node_gen(n))  # spill to store; producer never retained
        tracemalloc.start()
        # Consume without retaining — the working set is one fetch batch of
        # payload strings plus a single reconstructed node at a time.
        total = 0
        for node in ws.iter_nodes():
            total += len(node.id)
        assert total > 0
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return peak
    finally:
        ws.close()


def test_workspace_working_set_is_bounded_by_batch_not_total() -> None:
    batch = 100
    iter_small = _iter_peak(1000, batch)
    iter_large = _iter_peak(4000, batch)
    full_large = _materialize_peak(4000)

    # Streaming from the workspace never materialises the full node set: its peak
    # is a small fraction of holding all N nodes in memory (what the builder does
    # today), and that advantage does NOT erode as N grows 4x.
    frac_small = iter_small / full_large
    assert frac_small < 0.25, f"iter@1000 peak not a small fraction of full@4000: {frac_small:.3f}"
    assert iter_large <= iter_small * 1.6, f"working set grew with N (not bounded by batch): {iter_small} -> {iter_large}"
    # And the bounded stream stays well below a full materialisation at 4x N.
    assert iter_large < full_large * 0.5, f"iter@4000 {iter_large} not below half full@4000 {full_large}"


def test_workspace_add_is_idempotent(tmp_path: Path) -> None:
    graph = _synthetic_graph("s", 120)
    with GraphBuildWorkspace(_SQLiteWorkspaceBackend(), tenant_id="t1") as ws:
        ws.add_nodes(graph.nodes.values())
        ws.add_edges(graph.edges)
        ws.add_nodes(graph.nodes.values())  # retry / replay
        ws.add_edges(graph.edges)
        assert ws.node_count() == len(graph.nodes)
        assert ws.edge_count() == len(graph.edges)
        ids = [n.id for n in ws.iter_nodes()]
        assert len(ids) == len(set(ids)) == len(graph.nodes)


def test_workspace_tenant_isolation() -> None:
    with GraphBuildWorkspace(_SQLiteWorkspaceBackend(), tenant_id="alpha") as _unused:
        pass
    backend = _SQLiteWorkspaceBackend()
    alpha = GraphBuildWorkspace(backend, tenant_id="alpha")
    beta = GraphBuildWorkspace(backend, tenant_id="beta")
    try:
        alpha.add_nodes([UnifiedNode(id="shared:1", entity_type=EntityType.AGENT, label="alpha-agent")])
        alpha.add_nodes([UnifiedNode(id="a-only", entity_type=EntityType.VULNERABILITY, label="a")])
        beta.add_nodes([UnifiedNode(id="shared:1", entity_type=EntityType.AGENT, label="beta-agent")])
        beta.add_nodes([UnifiedNode(id="b-only", entity_type=EntityType.VULNERABILITY, label="b")])

        alpha_nodes = {n.id: n.label for n in alpha.iter_nodes()}
        beta_nodes = {n.id: n.label for n in beta.iter_nodes()}

        # Same logical id persists independently per tenant; no cross-leak.
        assert alpha_nodes["shared:1"] == "alpha-agent"
        assert beta_nodes["shared:1"] == "beta-agent"
        assert "a-only" in alpha_nodes and "a-only" not in beta_nodes
        assert "b-only" in beta_nodes and "b-only" not in alpha_nodes
    finally:
        backend.close()


def test_open_workspace_defaults_to_sqlite_without_postgres_url(monkeypatch) -> None:
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    ws = open_graph_build_workspace(tenant_id="t1")
    try:
        assert isinstance(ws._backend, _SQLiteWorkspaceBackend)
        ws.add_nodes([UnifiedNode(id="x", entity_type=EntityType.AGENT, label="x")])
        assert ws.node_count() == 1
    finally:
        ws.close()
