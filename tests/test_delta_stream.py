"""Tests for finding delta-stream export (#3514)."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, reset_compliance_hub_store, set_compliance_hub_store
from agent_bom.api.finding_lifecycle import collect_present_canonical_ids, normalize_observed_at
from agent_bom.delta_stream import (
    DeliveryDeltaStreamConnector,
    DeltaStreamDestination,
    DeltaStreamStore,
    FindingSnapshot,
    InMemoryDeltaSink,
    capture_hub_snapshots,
    compute_finding_deltas,
    emit_hub_finding_deltas_if_enabled,
    resolved_canonical_ids,
)


def _finding(
    finding_id: str,
    *,
    severity: str = "medium",
    cvss_score: float = 5.0,
    status: str = "open",
    source: str = "test-source",
) -> dict:
    return {
        "id": finding_id,
        "title": f"Finding {finding_id}",
        "severity": severity,
        "cvss_score": cvss_score,
        "status": status,
        "source": source,
        "origin": "bulk_ingest",
    }


def test_compute_finding_deltas_new_changed_resolved() -> None:
    prior = {
        "existing-open": FindingSnapshot.from_finding(_finding("existing-open"), source="src"),
        "will-resolve": FindingSnapshot.from_finding(_finding("will-resolve"), source="src"),
    }
    batch = [
        _finding("brand-new", severity="high"),
        _finding("existing-open", severity="critical", cvss_score=9.1),
    ]
    events = compute_finding_deltas(
        tenant_id="tenant-1",
        prior=prior,
        batch_findings=batch,
        resolved_canonical_ids={"will-resolve"},
        observed_at="2026-07-04T12:00:00Z",
        batch_id="batch-2",
        source="src",
    )
    kinds = {event.kind for event in events}
    assert kinds == {"new", "changed", "resolved"}
    by_kind = {event.kind: event for event in events}
    assert by_kind["new"].canonical_id.endswith("brand-new")
    assert by_kind["changed"].finding["severity"] == "critical"
    assert by_kind["resolved"].finding["status"] == "resolved"


def test_resolved_canonical_ids_from_prior_present() -> None:
    prior = {"a": FindingSnapshot.from_finding(_finding("a"), source="s"), "b": FindingSnapshot.from_finding(_finding("b"), source="s")}
    assert resolved_canonical_ids(prior, {"a"}) == {"b"}


def test_delivery_delta_stream_connector_memory_sink(tmp_path: Path) -> None:
    sink = InMemoryDeltaSink()
    store = DeltaStreamStore(tmp_path / "delta_stream.db")
    connector = DeliveryDeltaStreamConnector(
        DeltaStreamDestination(destination_id="test", url="", format="ndjson"),
        watermark_store=store,
        memory_sink=sink,
    )
    results = connector.emit_batch(
        "tenant-1",
        compute_finding_deltas(
            tenant_id="tenant-1",
            prior={},
            batch_findings=[_finding("one")],
            resolved_canonical_ids=set(),
            observed_at="2026-07-04T12:00:00Z",
            batch_id="batch-1",
            source="src",
        ),
        observed_at="2026-07-04T12:00:00Z",
        batch_id="batch-1",
    )
    assert results == [{"status": "delivered", "sink": "memory"}]
    assert len(sink.batches) == 1
    batch = sink.batches[0]
    assert batch["event_count"] == 1
    assert batch["events"][0]["event_type"] == "new"
    watermark = store.get_watermark("tenant-1", "test")
    assert watermark is not None
    assert watermark.batch_id == "batch-1"


def test_hub_ingest_emits_new_changed_resolved_via_memory_sink(tmp_path: Path) -> None:
    reset_compliance_hub_store()
    hub = InMemoryComplianceHubStore()
    set_compliance_hub_store(hub)

    tenant_id = f"delta-{uuid4().hex}"
    source = "agent-runtime"
    observed_at = normalize_observed_at(None)
    sink = InMemoryDeltaSink()
    watermark_store = DeltaStreamStore(tmp_path / "delta_stream.db")
    connector = DeliveryDeltaStreamConnector(
        DeltaStreamDestination(destination_id="mem", url="", format="ndjson"),
        watermark_store=watermark_store,
        memory_sink=sink,
    )

    batch1 = [
        _finding("finding-a", severity="medium", source=source),
        _finding("finding-b", severity="low", source=source),
    ]
    prior1 = capture_hub_snapshots(hub, tenant_id, source=source)
    hub.upsert_current_batch(tenant_id, batch1, observed_at=observed_at, batch_id="batch-1", source=source)
    emit_hub_finding_deltas_if_enabled(
        tenant_id=tenant_id,
        hub_store=hub,
        prior=prior1,
        batch_findings=batch1,
        resolved_canonical_ids=set(),
        observed_at=observed_at,
        batch_id="batch-1",
        source=source,
        connector=connector,
    )

    batch2 = [
        _finding("finding-a", severity="critical", cvss_score=9.8, source=source),
        _finding("finding-c", severity="high", source=source),
    ]
    prior2 = capture_hub_snapshots(hub, tenant_id, source=source)
    present = collect_present_canonical_ids(batch2, source=source)
    resolved_ids = resolved_canonical_ids(prior2, present)
    hub.upsert_current_batch(tenant_id, batch2, observed_at=observed_at, batch_id="batch-2", source=source)
    hub.reconcile_current_absent(
        tenant_id,
        present_canonical_ids=present,
        observed_at=observed_at,
        scope_source=source,
    )
    emit_hub_finding_deltas_if_enabled(
        tenant_id=tenant_id,
        hub_store=hub,
        prior=prior2,
        batch_findings=batch2,
        resolved_canonical_ids=resolved_ids,
        observed_at=observed_at,
        batch_id="batch-2",
        source=source,
        connector=connector,
    )

    assert len(sink.batches) == 2
    first_kinds = {event["event_type"] for event in sink.batches[0]["events"]}
    assert first_kinds == {"new"}
    second_kinds = {event["event_type"] for event in sink.batches[1]["events"]}
    assert second_kinds == {"changed", "new", "resolved"}

    reset_compliance_hub_store()
