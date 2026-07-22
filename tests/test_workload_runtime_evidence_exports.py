"""JSON/SARIF/HTML export parity for CWPP ``workload_runtime_evidence`` (#4158 C)."""

from __future__ import annotations

from datetime import datetime, timezone

from agent_bom.cloud.runtime_workload_evidence import (
    STATE_HAS_IOC,
    STATE_NO_SIGNAL,
    RuntimeEvidenceSource,
    RuntimeSourceRegistry,
    RuntimeWorkloadEvidenceIndex,
    attach_workload_runtime_evidence_to_finding_model,
    ingest_runtime_signals,
    no_runtime_signal_summary,
)
from agent_bom.cloud.runtime_workload_evidence_store import (
    InMemoryRuntimeWorkloadEvidenceStore,
    set_runtime_workload_evidence_store,
)
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import AIBOMReport
from agent_bom.output.html.document import to_html
from agent_bom.output.json_fmt import to_json
from agent_bom.output.sarif import to_sarif


def _workload_finding(*, with_ioc_summary: bool = False) -> Finding:
    finding = Finding(
        finding_type=FindingType.CIS_FAIL,
        source=FindingSource.CLOUD_CIS,
        asset=Asset(
            name="web",
            asset_type="cloud_resource",
            identifier="i-0abc",
            provider="aws",
            account_ref="aws:123456789012",
        ),
        severity="high",
        title="workload disk finding",
        description="demo",
        provider="aws",
        account_ref="aws:123456789012",
        evidence={"resource_id": "i-0abc", "provider": "aws"},
    )
    if with_ioc_summary:
        finding.workload_runtime_evidence = {
            "schema_version": "1.0",
            "state": STATE_HAS_IOC,
            "signal_count": 1,
            "clean_workload_assertion": False,
            "note": "Runtime evidence is additive and never a clean-workload claim.",
        }
    return finding


def test_json_sarif_html_carry_preattached_workload_runtime_evidence() -> None:
    finding = _workload_finding(with_ioc_summary=True)
    report = AIBOMReport(generated_at=datetime.now(timezone.utc), tool_version="0.0.0", findings=[finding])

    payload = to_json(report)
    exported = next(row for row in payload["findings"] if row["id"] == finding.id)
    assert exported["workload_runtime_evidence"]["state"] == STATE_HAS_IOC
    assert exported["workload_runtime_evidence"]["clean_workload_assertion"] is False

    sarif = to_sarif(report)
    props = next(
        result["properties"]
        for result in sarif["runs"][0]["results"]
        if result["properties"].get("workload_runtime_evidence")
    )
    assert props["workload_runtime_evidence"]["state"] == STATE_HAS_IOC
    assert props["workload_runtime_evidence"]["clean_workload_assertion"] is False

    html = to_html(report)
    assert 'class="workload-runtime-evidence"' in html
    assert "Runtime IOC" in html
    assert "clean-workload assertion" in html


def test_export_enrichment_from_store_marks_no_signal_honestly(monkeypatch) -> None:
    store = InMemoryRuntimeWorkloadEvidenceStore()
    set_runtime_workload_evidence_store(store)
    monkeypatch.setenv("AGENT_BOM_TENANT_ID", "tenant-export")
    try:
        registry = RuntimeSourceRegistry()
        registry.add(
            RuntimeEvidenceSource.register(
                source_id="edr-1",
                tenant_id="tenant-export",
                provider="aws",
                account_id="123456789012",
                kind="edr",
                secret="s3cr3t-token-value-1234",
            )
        )
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        ingest_runtime_signals(
            registry=registry,
            source_id="edr-1",
            secret="s3cr3t-token-value-1234",
            raw_signals=[
                {
                    "workload_ref": "i-other",
                    "dedup_key": "evt-1",
                    "signal_type": "ioc_detection",
                    "severity": "high",
                    "observed_at": now,
                    "title": "other workload",
                }
            ],
            store=store,
        )

        finding = _workload_finding()
        report = AIBOMReport(generated_at=datetime.now(timezone.utc), tool_version="0.0.0", findings=[finding])
        payload = to_json(report)
        exported = next(row for row in payload["findings"] if row["id"] == finding.id)
        assert exported["workload_runtime_evidence"]["state"] == STATE_NO_SIGNAL
        assert exported["workload_runtime_evidence"]["clean_workload_assertion"] is False

        html = to_html(report)
        assert "No runtime signal" in html
    finally:
        set_runtime_workload_evidence_store(None)


def test_attach_model_uses_asset_identity() -> None:
    finding = _workload_finding()
    index = RuntimeWorkloadEvidenceIndex.from_signals("tenant-a", [])
    # Empty index must not annotate (callers use optional_* which returns None).
    assert attach_workload_runtime_evidence_to_finding_model(finding, index) is False

    summary = no_runtime_signal_summary()
    # Non-empty index with no matching signals still annotates no_runtime_signal.
    index._by_workload["aws\x1f123456789012\x1fi-other"] = []  # type: ignore[attr-defined]
    # Force non-empty via a real signal-shaped key presence:
    index._by_workload["aws\x1f123456789012\x1fi-other"] = []  # noqa: SLF001
    # RuntimeWorkloadEvidenceIndex.is_empty checks the map; empty lists still count.
    assert index.is_empty() is False
    assert attach_workload_runtime_evidence_to_finding_model(finding, index) is True
    assert finding.workload_runtime_evidence == summary
