"""Pin scan persistence ordering and failure boundaries before service extraction."""

from __future__ import annotations

import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agent_bom.api import pipeline
from agent_bom.api.postgres_store import _current_tenant, reset_current_tenant, set_current_tenant


@pytest.fixture
def persistence(monkeypatch):
    events = []
    job = SimpleNamespace(job_id="job", tenant_id="tenant-a", result={}, progress=[])
    report = {"scan_id": "scan", "agents": []}
    graph = SimpleNamespace(
        scan_id="scan",
        tenant_id="tenant-a",
        nodes={"a": object(), "b": object()},
        edges=[object()],
        attack_paths=[],
        interaction_risks=[],
        analysis_status={},
        created_at="fixed",
    )
    store = Mock()

    def record(stage, result):
        def call(*args, **kwargs):
            events.append((stage, _current_tenant.get()))
            return result

        return Mock(side_effect=call)

    store.latest_snapshot_id = record("latest", "prior")
    store.prior_delta_digest = record("digest", object())
    store.save_graph_streaming = record("save", {"nodes": 12, "edges": 7})
    factory = record("store", store)
    monkeypatch.setattr(pipeline, "_get_graph_store", factory)
    monkeypatch.setenv("AGENT_BOM_GRAPH_STORE_BACKED_BUILD", "off")
    monkeypatch.setenv("AGENT_BOM_GRAPH_BUILD_WORKSPACE", "off")
    monkeypatch.setattr("agent_bom.api.cost_store.get_cost_store", lambda: object())
    cost = record("cost", [{"cost_usd": 2}])
    monkeypatch.setattr("agent_bom.api.cost_store.graph_cost_rollup", cost)
    build = record("build", graph)
    monkeypatch.setattr("agent_bom.graph.builder.build_unified_graph_from_report", build)
    link = record("link", None)
    monkeypatch.setattr("agent_bom.graph.asset_entity.link_report_findings_to_graph", link)
    monkeypatch.setattr("agent_bom.cloud.runtime_workload_evidence_store.get_runtime_workload_evidence_store", lambda: object())
    runtime = record("runtime", object())
    monkeypatch.setattr("agent_bom.cloud.runtime_workload_evidence.RuntimeWorkloadEvidenceIndex.from_store", runtime)
    enrich = record("enrich", None)
    monkeypatch.setattr("agent_bom.cloud.runtime_workload_evidence.enrich_graph_workload_runtime_evidence", enrich)
    delta = record("delta", [{"type": "new_node"}])
    monkeypatch.setattr("agent_bom.graph.delta_digest.compute_delta_alerts_from_digest", delta)
    dispatch = record("dispatch", {"configured": True, "delivered": 1, "attempted": 2, "outbound_channels": 2})
    monkeypatch.setattr("agent_bom.graph.webhooks.dispatch_delta_alerts", dispatch)
    return SimpleNamespace(**locals())


def test_write_is_tenant_bound_and_receipt_precedes_notifications(persistence):
    p = persistence
    original_dispatch = p.dispatch.side_effect

    def dispatch(*args, **kwargs):
        assert p.job.result["graph_persistence"] == {"status": "persisted", "scan_id": "scan", "nodes": 12, "edges": 7}
        return original_dispatch(*args, **kwargs)

    p.dispatch.side_effect = dispatch
    token = set_current_tenant("outer")
    try:
        pipeline._persist_graph_snapshot(p.job, p.report, lock=threading.Lock(), write_generation="owner")
        assert _current_tenant.get() == "outer"
    finally:
        reset_current_tenant(token)
    assert p.events == [
        (stage, "tenant-a")
        for stage in ("cost", "build", "link", "runtime", "enrich", "store", "latest", "digest", "save", "delta", "dispatch")
    ]
    assert p.report == {"scan_id": "scan", "agents": []}
    assert p.build.call_args.args[0] == {**p.report, "llm_cost_records": [{"cost_usd": 2}]}
    assert p.build.call_args.args[0]["agents"] is p.report["agents"]
    assert p.link.call_args.args[0] is p.report
    p.store.latest_snapshot_id.assert_called_once_with(tenant_id="tenant-a", snapshot_kind="scan")
    p.store.prior_delta_digest.assert_called_once_with(tenant_id="tenant-a", scan_id="prior")
    saved = p.store.save_graph_streaming.call_args.kwargs
    assert saved["write_generation"] == "owner"
    assert list(saved["nodes"]) == list(p.graph.nodes.values())
    assert saved["edges"] is p.graph.edges
    p.store.load_graph.assert_not_called()
    assert p.job.progress == [
        "Graph persisted: 12 nodes, 7 edges",
        "Graph delta alerts: 1",
        "Graph delta delivery: 1/2 via 2 outbound channel(s)",
    ]


@pytest.mark.parametrize("stage", ["factory", "latest_snapshot_id", "prior_delta_digest", "save_graph_streaming"])
def test_storage_failure_restores_context_and_does_not_claim_success(persistence, stage):
    p = persistence
    operation = p.factory if stage == "factory" else getattr(p.store, stage)
    operation.side_effect = RuntimeError("storage unavailable")
    token = set_current_tenant("outer")
    try:
        with pytest.raises(RuntimeError, match="storage unavailable"):
            pipeline._persist_graph_snapshot(p.job, p.report, lock=threading.Lock())
        assert _current_tenant.get() == "outer"
    finally:
        reset_current_tenant(token)
    assert p.job.result == {}
    assert p.job.progress == []
    p.delta.assert_not_called()
    p.dispatch.assert_not_called()


@pytest.mark.parametrize("stage", ["cost", "link", "runtime", "enrich"])
def test_optional_enrichment_failure_still_persists(persistence, stage):
    p = persistence
    getattr(p, stage).side_effect = RuntimeError("optional evidence unavailable")
    pipeline._persist_graph_snapshot(p.job, p.report)
    assert p.job.result["graph_persistence"]["status"] == "persisted"
    assert p.job.progress == []  # No lock means no progress writes, even after success.
    assert "write_generation" not in p.store.save_graph_streaming.call_args.kwargs
    if stage == "cost":
        assert p.build.call_args.args[0] is p.report


@pytest.mark.parametrize("stage", ["delta", "dispatch"])
@pytest.mark.parametrize("locked", [False, True])
def test_notification_failure_preserves_committed_receipt(persistence, stage, locked):
    p = persistence
    getattr(p, stage).side_effect = RuntimeError("notification unavailable")
    pipeline._persist_graph_snapshot(p.job, p.report, lock=threading.Lock() if locked else None)
    assert p.job.result["graph_persistence"]["status"] == "persisted"
    assert p.job.progress == (
        [
            "Graph delta alerting failed; snapshot persisted without delta notifications",
            "Graph persisted: 12 nodes, 7 edges",
        ]
        if locked
        else []
    )
    p.store.delete_snapshot.assert_not_called()


@pytest.mark.parametrize("previous", ["", "scan"])
def test_absent_or_same_prior_snapshot_skips_digest(persistence, previous):
    p = persistence
    p.store.latest_snapshot_id.return_value = previous
    p.store.latest_snapshot_id.side_effect = None
    p.store.save_graph_streaming.side_effect = None
    p.store.save_graph_streaming.return_value = {}
    p.delta.side_effect = None
    p.delta.return_value = []
    pipeline._persist_graph_snapshot(p.job, p.report, lock=threading.Lock())
    p.store.prior_delta_digest.assert_not_called()
    p.delta.assert_called_once_with(None, p.graph)
    p.dispatch.assert_not_called()
    assert p.job.result["graph_persistence"] == {"status": "persisted", "scan_id": "scan", "nodes": 2, "edges": 1}
    assert p.job.progress == ["Graph persisted: 2 nodes, 1 edges"]


@pytest.mark.parametrize(
    "delivery,expected",
    [
        ({"configured": False, "delivered": 0, "ocsf_event_count": 3}, "Graph delta export ready: 3 OCSF event(s)"),
        (None, "Graph delta export ready: 0 OCSF event(s)"),
    ],
)
def test_export_only_notification_progress(persistence, delivery, expected):
    p = persistence
    p.dispatch.side_effect = None
    p.dispatch.return_value = delivery
    pipeline._persist_graph_snapshot(p.job, p.report, lock=threading.Lock())
    assert p.job.progress == ["Graph persisted: 12 nodes, 7 edges", "Graph delta alerts: 1", expected]
