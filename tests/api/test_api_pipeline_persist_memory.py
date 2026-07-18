"""Full-scan write-path holds only one full current graph at persist peak (#4075).

``_run_scan_sync`` builds a unified graph in the output phase to surface
graph-derived findings, then the persist phase (``_persist_graph_snapshot``)
rebuilds the graph from the finalized report. The first (surfacing) graph is a
plain frame local; if it is not released before the persist phase rebuilds, the
full-scan path holds **two** full current graphs simultaneously — each carrying
its own node dict, edge list, and adjacency / reverse-adjacency indexes.

These tests drive the real ``_run_scan_sync`` and assert, via weakrefs on every
built ``UnifiedGraph``, that when the persist phase rebuilds no prior current
graph is still alive, so peak holds one full current graph, not two.
"""

from __future__ import annotations

import gc
import json
import weakref

from agent_bom.api import pipeline as pipeline_mod
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _run_scan_sync


def _scan_job(inventory_path: str) -> ScanJob:
    return ScanJob(
        job_id="persist-memory-scan",
        created_at="2026-07-18T00:00:00Z",
        request=ScanRequest(inventory=inventory_path, enrich=False, offline=True),
    )


def _inventory(tmp_path) -> str:
    p = tmp_path / "inv.json"
    p.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "source": "test",
                "agents": [
                    {
                        "name": "inv-agent",
                        "agent_type": "custom",
                        "mcp_servers": [{"name": "inv-server"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return str(p)


def _patch_scan(monkeypatch):
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda *a, **k: [])
    monkeypatch.setattr("agent_bom.scanners.scan_agents_sync", lambda agents, **k: [])
    monkeypatch.setattr(
        "agent_bom.api.pipeline._sync_scan_agents_to_fleet",
        lambda _agents, tenant_id="default": None,
    )


def test_persist_phase_rebuilds_with_no_prior_current_graph_alive(tmp_path, monkeypatch):
    """When the persist phase rebuilds the graph, the earlier surfacing graph
    must already be freed — the full-scan path never holds two full current
    graphs at once (#4075)."""
    _patch_scan(monkeypatch)

    from agent_bom.api.graph_store import SQLiteGraphStore

    store = SQLiteGraphStore(tmp_path / "persist.db")
    monkeypatch.setattr(pipeline_mod, "_get_graph_store", lambda: store)

    import agent_bom.graph.builder as builder

    real_build = builder.build_unified_graph_from_report
    refs: list[weakref.ref] = []
    alive_before_each_build: list[int] = []

    def _tracking(report_json, *, scan_id, tenant_id):
        gc.collect()
        alive_before_each_build.append(sum(1 for r in refs if r() is not None))
        graph = real_build(report_json, scan_id=scan_id, tenant_id=tenant_id)
        refs.append(weakref.ref(graph))
        return graph

    monkeypatch.setattr(builder, "build_unified_graph_from_report", _tracking)

    job = _scan_job(_inventory(tmp_path))
    _run_scan_sync(job)

    assert job.status == JobStatus.DONE, job.result
    # Full-scan path builds the graph twice: surfacing (output phase) + persist.
    assert len(alive_before_each_build) >= 2, f"expected >=2 graph builds (surfacing + persist), saw {len(alive_before_each_build)}"
    # The persist rebuild (the last build) must see zero prior current graphs
    # still alive — the surfacing graph must have been released first.
    assert alive_before_each_build[-1] == 0, (
        f"persist phase rebuilt the graph while {alive_before_each_build[-1]} prior full current graph(s) were still live"
    )
    # The scan actually persisted its snapshot.
    assert store.latest_snapshot_id(tenant_id="default") == job.job_id
