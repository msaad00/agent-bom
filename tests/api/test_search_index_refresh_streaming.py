"""Bounded (streamed) SQLite snapshot search-index refresh (#4075, PR-2).

``_refresh_snapshot_search_index`` used to ``.fetchall()`` every node row of the
snapshot and reconstruct a full ``UnifiedNode`` for each before inserting the
search mirror — an O(N) second materialisation of the whole node set, executed
at the persist peak while the builder's in-memory graph is still resident. This
pins that the refresh now streams in bounded batches (peak flat as the snapshot
grows) while producing a byte-identical ``graph_node_search`` table, on both the
``save_graph`` and ``save_graph_streaming`` write paths.
"""

from __future__ import annotations

import tracemalloc
from pathlib import Path

import agent_bom.db.graph_store as sg
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import RelationshipType, UnifiedEdge
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, NodeStatus


def _synthetic_graph(scan: str, n: int) -> UnifiedGraph:
    g = UnifiedGraph(scan_id=scan, tenant_id="t1")
    for i in range(n):
        g.add_node(
            UnifiedNode(
                id=f"n:{i}",
                entity_type=EntityType.AGENT if i % 50 == 0 else EntityType.VULNERABILITY,
                label=f"label-{i}",
                severity="high" if i % 3 else "critical",
                risk_score=float(i % 10),
                status=NodeStatus.ACTIVE,
                compliance_tags=["cis-1.1", "soc2"],
                data_sources=["mcp-scan"],
                attributes={"cvss_score": 7.0, "blob": "v" * 64, "purl": f"pkg:pypi/x-{i}@1.0"},
            )
        )
    for i in range(0, n - 1, 2):
        g.add_edge(UnifiedEdge(source=f"n:{i}", target=f"n:{i + 1}", relationship=RelationshipType.DEPENDS_ON))
    return g


def _refresh_peak(tmp_path: Path, n: int, monkeypatch) -> int:
    # Small batch so a streamed refresh is unambiguously flat; a fetchall refresh
    # ignores it and stays O(N).
    monkeypatch.setenv("AGENT_BOM_GRAPH_WRITE_BATCH_SIZE", "500")
    store = SQLiteGraphStore(tmp_path / f"r{n}.db")
    store.save_graph(_synthetic_graph("s", n))
    with sg.open_graph_db(store._db_path) as conn:
        tracemalloc.start()
        store._refresh_snapshot_search_index(conn, tenant_id="t1", scan_id="s")
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        conn.commit()
    return peak


def test_refresh_peak_is_bounded_as_snapshot_grows(tmp_path: Path, monkeypatch) -> None:
    small = _refresh_peak(tmp_path, 2000, monkeypatch)
    large = _refresh_peak(tmp_path, 8000, monkeypatch)

    # 4x the nodes must NOT cost ~4x the transient allocation; a fetchall refresh
    # is linear (~4x), a bounded streamed refresh stays roughly flat. Guard at 2x.
    assert large <= small * 2.0, f"refresh peak scales with snapshot size: {small} -> {large} (4x nodes)"


def _search_rows(store: SQLiteGraphStore, scan: str) -> list[tuple]:
    with sg.open_graph_db(store._db_path) as conn:
        return sorted(
            tuple(r)
            for r in conn.execute(
                "SELECT node_id, entity_type, severity, compliance_tags, data_sources, search_text "
                "FROM graph_node_search WHERE tenant_id = 't1' AND scan_id = ? ",
                (scan,),
            ).fetchall()
        )


def test_search_index_content_identical_across_write_paths(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_GRAPH_WRITE_BATCH_SIZE", "500")
    graph = _synthetic_graph("s", 1500)

    full = SQLiteGraphStore(tmp_path / "full.db")
    full.save_graph(graph)

    stream = SQLiteGraphStore(tmp_path / "stream.db")
    stream.save_graph_streaming(
        scan_id="s",
        tenant_id="t1",
        nodes=iter(graph.nodes.values()),
        edges=iter(graph.edges),
    )

    full_rows = _search_rows(full, "s")
    stream_rows = _search_rows(stream, "s")
    assert full_rows == stream_rows, "streamed vs full save produced different search rows"
    assert len(full_rows) == 1500, "every node must have a search row"
    # search_text is non-empty and lowercased (mirror content preserved).
    assert all(r[5] and r[5] == r[5].lower() for r in full_rows)
