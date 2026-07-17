"""Production write-path memory bound + streamed-persist equivalence (#4055/#4075).

`_persist_graph_snapshot` used to load the previous snapshot into a second full
``UnifiedGraph`` purely to compute delta alerts, so peak held up to *two*
materialised graphs. It now derives the delta from a bounded
``prior_delta_digest`` and persists via ``save_graph_streaming``. These tests
pin (a) the digest path's peak allocation is a small fraction of the full
prior-graph load and stays proportionally bounded as the prior snapshot grows,
(b) the production persist path realises that bound, (c) the streamed persist is
content-identical to the full ``save_graph`` on real report fixtures, and (d)
streamed persist keeps tenant isolation.
"""

from __future__ import annotations

import json
import tracemalloc
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import RelationshipType, UnifiedEdge
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.delta_digest import compute_delta_alerts_from_digest
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, NodeStatus
from agent_bom.graph.webhooks import compute_delta_alerts

_FIXTURES = Path(__file__).parent / "fixtures"


def _synthetic_graph(scan: str, n: int) -> UnifiedGraph:
    g = UnifiedGraph(scan_id=scan, tenant_id="t1")
    for i in range(n):
        g.add_node(
            UnifiedNode(
                id=f"n:{i}",
                entity_type=EntityType.AGENT if i % 50 == 0 else EntityType.VULNERABILITY,
                label=f"L{i}",
                severity="high" if i % 3 else "critical",
                risk_score=float(i % 10),
                status=NodeStatus.ACTIVE,
                attributes={"cvss_score": 7.0, "blob": "v" * 24},
            )
        )
    for i in range(0, n - 1, 2):
        g.add_edge(UnifiedEdge(source=f"n:{i}", target=f"n:{i + 1}", relationship=RelationshipType.DEPENDS_ON))
    return g


def _measure_digest_vs_full_load(tmp_path: Path, n: int) -> tuple[int, int]:
    store = SQLiteGraphStore(tmp_path / f"g{n}.db")
    store.save_graph(_synthetic_graph("scan-old", n))
    # A fresh new graph, held constant across both measurements. Add one brand-new
    # critical vuln so the delta is non-empty (exercises the equivalence too).
    new = _synthetic_graph("scan-new", n)
    new.add_node(
        UnifiedNode(id="vuln:brand-new", entity_type=EntityType.VULNERABILITY, label="CVE-NEW", severity="critical", risk_score=9.0)
    )

    tracemalloc.start()
    prev = store.load_graph(tenant_id="t1", scan_id="scan-old")
    full_alerts = compute_delta_alerts(prev, new)
    _, full_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    del prev

    tracemalloc.start()
    digest = store.prior_delta_digest(tenant_id="t1", scan_id="scan-old")
    digest_alerts = compute_delta_alerts_from_digest(digest, new)
    _, digest_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert digest_alerts == full_alerts, "digest delta diverged from full-graph delta"
    assert full_alerts, "fixture should produce a non-empty delta"
    return full_peak, digest_peak


def test_digest_peak_is_small_fraction_of_full_load_and_stays_bounded(tmp_path: Path) -> None:
    small_full, small_digest = _measure_digest_vs_full_load(tmp_path, 2000)
    large_full, large_digest = _measure_digest_vs_full_load(tmp_path, 8000)

    ratio_small = small_digest / small_full
    ratio_large = large_digest / large_full

    # The bounded digest never holds the prior graph's node objects / edges /
    # adjacency — only an id set + agent refs. Measured ~0.07; guard well clear.
    assert ratio_small < 0.4, f"digest/full peak ratio too high at N=2000: {ratio_small:.3f}"
    assert ratio_large < 0.4, f"digest/full peak ratio too high at N=8000: {ratio_large:.3f}"
    # The advantage must not erode as the prior snapshot grows 4x.
    assert ratio_large <= ratio_small * 1.5, f"digest advantage eroded with scale: {ratio_small:.3f} -> {ratio_large:.3f}"


def test_production_persist_path_does_not_materialise_full_prior_graph(tmp_path: Path, monkeypatch) -> None:
    import agent_bom.api.pipeline as pipeline
    import agent_bom.graph.builder as builder

    n = 8000
    store = SQLiteGraphStore(tmp_path / "pipe.db")
    store.save_graph(_synthetic_graph("scan-1", n))
    monkeypatch.setattr(pipeline, "_get_graph_store", lambda: store)

    new = _synthetic_graph("scan-2", 20)
    monkeypatch.setattr(builder, "build_unified_graph_from_report", lambda report_json, scan_id, tenant_id: new)

    job = SimpleNamespace(job_id="scan-2", tenant_id="t1", progress=[])
    tracemalloc.start()
    pipeline._persist_graph_snapshot(job, {"scan_id": "scan-2"})
    _, pipeline_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Cost of the eliminated step: loading the full prior graph for the delta.
    tracemalloc.start()
    prev = store.load_graph(tenant_id="t1", scan_id="scan-1")
    _ = compute_delta_alerts(prev, new)
    _, full_prior_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    del prev

    # The entire production persist (build + streamed save + digest delta) peaks
    # below what a single full prior-graph load for the delta alone would cost.
    assert pipeline_peak < full_prior_peak, f"persist peak {pipeline_peak} not below full prior-load {full_prior_peak}"
    # scan-2 actually persisted.
    assert store.latest_snapshot_id(tenant_id="t1") == "scan-2"


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
                            },
                        ],
                        "tools": [{"name": "read_file"}],
                    }
                ],
            }
        ],
        "blast_radius": [],
    }
    return [self_scan, constructed]


@pytest.mark.parametrize("report", _report_fixtures(), ids=["self_scan_fixture", "constructed_report"])
def test_streamed_persist_is_content_identical_to_full_save(tmp_path: Path, report: dict) -> None:
    graph = build_unified_graph_from_report(report, scan_id="s", tenant_id="t1")

    full_store = SQLiteGraphStore(tmp_path / "full.db")
    full_store.save_graph(graph)
    loaded_full = full_store.load_graph(tenant_id="t1", scan_id="s")

    graph2 = build_unified_graph_from_report(report, scan_id="s", tenant_id="t1")
    stream_store = SQLiteGraphStore(tmp_path / "stream.db")
    stream_store.save_graph_streaming(
        scan_id=graph2.scan_id,
        tenant_id=graph2.tenant_id,
        nodes=iter(graph2.nodes.values()),  # one-shot producer
        edges=iter(graph2.edges),
        attack_paths=graph2.attack_paths,
        interaction_risks=graph2.interaction_risks,
        created_at=graph2.created_at,
    )
    loaded_stream = stream_store.load_graph(tenant_id="t1", scan_id="s")

    def _nodes(g: UnifiedGraph) -> list[dict]:
        return sorted((n.to_dict() for n in g.nodes.values()), key=lambda d: d["id"])

    def _edges(g: UnifiedGraph) -> list[dict]:
        return sorted((e.to_dict() for e in g.edges), key=lambda d: (d["source"], d["target"], d["relationship"]))

    assert _nodes(loaded_stream) == _nodes(loaded_full)
    assert _edges(loaded_stream) == _edges(loaded_full)
    assert len(loaded_full.nodes) > 0


def test_streamed_persist_preserves_tenant_isolation(tmp_path: Path) -> None:
    store = SQLiteGraphStore(tmp_path / "multi.db")

    def _tenant_graph(tenant: str, extra_id: str) -> UnifiedGraph:
        g = UnifiedGraph(scan_id=f"{tenant}-scan", tenant_id=tenant)
        g.add_node(UnifiedNode(id="shared:1", entity_type=EntityType.AGENT, label=f"{tenant}-agent"))
        g.add_node(UnifiedNode(id=extra_id, entity_type=EntityType.VULNERABILITY, label="v", severity="high"))
        return g

    for tenant, extra in (("alpha", "vuln:alpha-only"), ("beta", "vuln:beta-only")):
        g = _tenant_graph(tenant, extra)
        store.save_graph_streaming(
            scan_id=g.scan_id,
            tenant_id=tenant,
            nodes=iter(g.nodes.values()),
            edges=iter(g.edges),
        )

    alpha = store.load_graph(tenant_id="alpha", scan_id="alpha-scan")
    beta = store.load_graph(tenant_id="beta", scan_id="beta-scan")

    # Same logical key ("shared:1") persists independently per tenant; neither
    # tenant's snapshot leaks the other's exclusive node.
    assert "shared:1" in alpha.nodes and "shared:1" in beta.nodes
    assert "vuln:alpha-only" in alpha.nodes and "vuln:alpha-only" not in beta.nodes
    assert "vuln:beta-only" in beta.nodes and "vuln:beta-only" not in alpha.nodes

    # The bounded digest read is tenant-scoped too.
    alpha_digest = store.prior_delta_digest(tenant_id="alpha", scan_id="alpha-scan")
    assert "vuln:alpha-only" in alpha_digest.nodes
    assert "vuln:beta-only" not in alpha_digest.nodes
