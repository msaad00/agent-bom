"""First consumer of the build workspace: the persist path (#4075, PR-1).

``_persist_graph_snapshot`` gains an opt-in
(``AGENT_BOM_GRAPH_BUILD_WORKSPACE``) that streams the built graph through the
storage-backed :class:`GraphBuildWorkspace` into the store instead of persisting
the materialised graph directly. This pins that the opt-in path produces a
**byte-identical** persisted snapshot and identical delta alerts to the shipped
default path — the correctness bar for the seam PR-2 emits into.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import agent_bom.api.pipeline as pipeline
import agent_bom.graph.builder as builder
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph.builder import build_unified_graph_from_report

_FIXTURES = Path(__file__).parent.parent / "fixtures"


def _dump_rows(store: SQLiteGraphStore, tenant: str, scan: str) -> tuple[list, list]:
    import agent_bom.db.graph_store as sq

    with sq.open_graph_db(store._db_path) as conn:
        nodes = conn.execute(
            "SELECT id, entity_type, label, status, risk_score, severity, severity_id, "
            "first_seen, last_seen, attributes, compliance_tags, data_sources, dimensions "
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


def _run_persist(tmp_path: Path, monkeypatch, *, enabled: bool, graph, store_name: str) -> SQLiteGraphStore:
    store = SQLiteGraphStore(tmp_path / store_name)
    monkeypatch.setattr(pipeline, "_get_graph_store", lambda: store)
    # Same pre-built graph both runs → removes build-time timestamp drift.
    monkeypatch.setattr(builder, "build_unified_graph_from_report", lambda report_json, scan_id, tenant_id: graph)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)  # force SQLite workspace backend
    if enabled:
        monkeypatch.setenv("AGENT_BOM_GRAPH_BUILD_WORKSPACE", "1")
    else:
        monkeypatch.delenv("AGENT_BOM_GRAPH_BUILD_WORKSPACE", raising=False)
    job = SimpleNamespace(job_id="scan-x", tenant_id="t1", progress=[])
    pipeline._persist_graph_snapshot(job, {"scan_id": "scan-x"})
    assert store.latest_snapshot_id(tenant_id="t1") == "scan-x"
    return store


@pytest.mark.parametrize("fixture", ["agent_bom_self_scan_inventory.json"])
def test_workspace_persist_is_byte_identical_to_direct(tmp_path: Path, monkeypatch, fixture: str) -> None:
    report = json.loads((_FIXTURES / fixture).read_text())
    graph = build_unified_graph_from_report(report, scan_id="scan-x", tenant_id="t1")
    assert len(graph.nodes) > 0

    with monkeypatch.context() as m:
        direct = _run_persist(tmp_path, m, enabled=False, graph=graph, store_name="direct.db")
        direct_rows = _dump_rows(direct, "t1", "scan-x")
    with monkeypatch.context() as m:
        via_ws = _run_persist(tmp_path, m, enabled=True, graph=graph, store_name="ws.db")
        ws_rows = _dump_rows(via_ws, "t1", "scan-x")

    assert direct_rows == ws_rows, "workspace persist diverged from the direct streamed save"


def test_workspace_persist_delta_alerts_identical(tmp_path: Path, monkeypatch) -> None:
    from agent_bom.graph.delta_digest import compute_delta_alerts_from_digest

    report = json.loads((_FIXTURES / "agent_bom_self_scan_inventory.json").read_text())
    graph = build_unified_graph_from_report(report, scan_id="scan-x", tenant_id="t1")

    with monkeypatch.context() as m:
        direct = _run_persist(tmp_path, m, enabled=False, graph=graph, store_name="d2.db")
        direct_alerts = compute_delta_alerts_from_digest(None, graph)
        _ = direct
    with monkeypatch.context() as m:
        via_ws = _run_persist(tmp_path, m, enabled=True, graph=graph, store_name="w2.db")
        ws_alerts = compute_delta_alerts_from_digest(None, graph)
        _ = via_ws

    assert direct_alerts == ws_alerts
