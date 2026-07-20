"""Store-backed build is byte-identical through the shipped persist path (#4055/#4075 PR-4).

``AGENT_BOM_GRAPH_STORE_BACKED_BUILD`` makes ``_persist_graph_snapshot`` build the
correlated graph into a per-build store-backed container (throwaway SQLite
workspace) instead of the in-RAM producer. This pins that the persisted snapshot —
nodes, edges, attack paths, NHI-governance findings, and analysis status — is
byte-identical to the shipped default (flag-off) path, on BOTH the SQLite and the
live Postgres persist targets. The build container is always SQLite (never the
shared Postgres workspace) even when the persist target is Postgres.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

import agent_bom.api.pipeline as pipeline
from agent_bom.api.graph_store import SQLiteGraphStore

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
_DSN = os.environ.get("AGENT_BOM_POSTGRES_URL", "").strip()
_FIXED = "2026-07-20T00:00:00Z"


def _normalized(graph) -> str:
    """to_dict() with per-run metadata (timestamps / snapshot identity) stripped."""
    data = graph.to_dict()
    meta = data.get("metadata", data)
    for key in ("created_at", "scan_id", "tenant_id", "generated_at", "exported_at"):
        if isinstance(meta, dict):
            meta.pop(key, None)
        data.pop(key, None)
    return json.dumps(data, default=str, sort_keys=True)


def _persist_and_load(store, *, enabled: bool, tenant: str, scan: str, report: dict, monkeypatch):
    from agent_bom.api.postgres_store import reset_current_tenant, set_current_tenant

    monkeypatch.setattr(pipeline, "_get_graph_store", lambda: store)
    # Freeze default timestamps so overlay-minted nodes/edges match across runs.
    monkeypatch.setattr("agent_bom.graph.node._now_iso", lambda: _FIXED)
    monkeypatch.setattr("agent_bom.graph.edge._now_iso", lambda: _FIXED, raising=False)
    if enabled:
        monkeypatch.setenv("AGENT_BOM_GRAPH_STORE_BACKED_BUILD", "1")
    else:
        monkeypatch.delenv("AGENT_BOM_GRAPH_STORE_BACKED_BUILD", raising=False)
    monkeypatch.delenv("AGENT_BOM_GRAPH_BUILD_WORKSPACE", raising=False)
    job = SimpleNamespace(job_id=scan, tenant_id=tenant, progress=[])
    pipeline._persist_graph_snapshot(job, dict(report, scan_id=scan))
    # Reads run under the tenant RLS context (a no-op for SQLite).
    token = set_current_tenant(tenant)
    try:
        assert store.latest_snapshot_id(tenant_id=tenant) == scan
        return store.load_graph(tenant_id=tenant, scan_id=scan)
    finally:
        reset_current_tenant(token)


def test_sqlite_persist_byte_identical_flag_on_vs_off(tmp_path: Path, monkeypatch) -> None:
    report = json.loads((_FIXTURES / "agent_bom_self_scan_inventory.json").read_text())

    with monkeypatch.context() as m:
        off = SQLiteGraphStore(tmp_path / "off.db")
        off_graph = _persist_and_load(off, enabled=False, tenant="t1", scan="scan-x", report=report, monkeypatch=m)
    with monkeypatch.context() as m:
        on = SQLiteGraphStore(tmp_path / "on.db")
        on_graph = _persist_and_load(on, enabled=True, tenant="t1", scan="scan-x", report=report, monkeypatch=m)

    assert len(off_graph.nodes) > 0
    assert len(on_graph.nodes) == len(off_graph.nodes)
    assert _normalized(on_graph) == _normalized(off_graph), "store-backed build persist diverged from the in-RAM path"
    # Explicit checks on the fields the task calls out.
    assert [p.to_dict() for p in on_graph.attack_paths] == [p.to_dict() for p in off_graph.attack_paths]
    assert on_graph.nhi_governance_findings == off_graph.nhi_governance_findings
    assert {k: v.status for k, v in on_graph.analysis_status.items()} == {k: v.status for k, v in off_graph.analysis_status.items()}


@pytest.mark.skipif(not _DSN, reason="AGENT_BOM_POSTGRES_URL not set")
def test_postgres_persist_byte_identical_flag_on_vs_off(monkeypatch) -> None:
    from agent_bom.api.postgres_store import PostgresGraphStore

    report = json.loads((_FIXTURES / "agent_bom_self_scan_inventory.json").read_text())
    scan = "scan-x"
    t_off = f"t-off-{uuid.uuid4().hex[:8]}"
    t_on = f"t-on-{uuid.uuid4().hex[:8]}"

    with monkeypatch.context() as m:
        m.setenv("AGENT_BOM_POSTGRES_URL", _DSN)
        off = PostgresGraphStore()
        off_graph = _persist_and_load(off, enabled=False, tenant=t_off, scan=scan, report=report, monkeypatch=m)
    with monkeypatch.context() as m:
        m.setenv("AGENT_BOM_POSTGRES_URL", _DSN)
        on = PostgresGraphStore()
        on_graph = _persist_and_load(on, enabled=True, tenant=t_on, scan=scan, report=report, monkeypatch=m)

    assert len(off_graph.nodes) > 0
    assert len(on_graph.nodes) == len(off_graph.nodes)
    assert _normalized(on_graph) == _normalized(off_graph), "store-backed build persist diverged from the in-RAM path (PG)"
