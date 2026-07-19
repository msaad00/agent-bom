"""Wiring test: CWPP workload runtime evidence surfaces in the findings read path.

Proves the stage-3 enrichment is actually wired into ``_iter_scan_findings`` (the
shared enricher behind ``GET /v1/findings``, overview, compliance, observability),
that it is gated on real signals, and that absence never renders as clean.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agent_bom.api.models import ScanJob, ScanRequest
from agent_bom.api.routes.scan import _iter_scan_findings
from agent_bom.cloud.runtime_workload_evidence import (
    STATE_HAS_IOC,
    STATE_NO_SIGNAL,
    RuntimeEvidenceSource,
    RuntimeSourceRegistry,
    ingest_runtime_signals,
)
from agent_bom.cloud.runtime_workload_evidence_store import (
    InMemoryRuntimeWorkloadEvidenceStore,
    set_runtime_workload_evidence_store,
)


@pytest.fixture
def clean_default_store():
    set_runtime_workload_evidence_store(None)
    try:
        yield
    finally:
        set_runtime_workload_evidence_store(None)


def _seed_store(tenant: str = "tenant-a") -> InMemoryRuntimeWorkloadEvidenceStore:
    store = InMemoryRuntimeWorkloadEvidenceStore()
    registry = RuntimeSourceRegistry()
    src = RuntimeEvidenceSource.register(
        source_id="edr-1",
        tenant_id=tenant,
        provider="aws",
        account_id="123456789012",
        kind="edr",
        secret="s3cr3t-token-value",
    )
    registry.add(src)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    ingest_runtime_signals(
        registry=registry,
        source_id="edr-1",
        secret="s3cr3t-token-value",
        raw_signals=[
            {
                "workload_ref": "i-0abc",
                "signal_type": "ioc_detection",
                "severity": "high",
                "observed_at": now,
                "dedup_key": "evt-1",
                "title": "known C2 contacted",
                "evidence": {"ioc_type": "domain"},
            }
        ],
        now=now,
        store=store,
    )
    set_runtime_workload_evidence_store(store)
    return store


def _job_with_workload_finding(tenant: str = "tenant-a") -> ScanJob:
    return ScanJob.model_construct(
        job_id="job-1",
        tenant_id=tenant,
        request=ScanRequest(),
        result={
            "findings": [
                {
                    "id": "f1",
                    "cve_id": "CVE-2026-1",
                    "provider": "aws",
                    "account_ref": "aws:123456789012",
                    "resource_id": "i-0abc",
                    "severity": "high",
                }
            ]
        },
    )


def test_workload_finding_is_enriched_when_tenant_has_signals(clean_default_store):
    _seed_store()
    rows = _iter_scan_findings(_job_with_workload_finding())
    assert len(rows) == 1
    ev = rows[0]["workload_runtime_evidence"]
    assert ev["state"] == STATE_HAS_IOC
    assert ev["clean_workload_assertion"] is False


def test_no_field_when_tenant_has_no_signals(clean_default_store):
    # default store empty -> read path is a no-op, no field attached (silence, not clean)
    rows = _iter_scan_findings(_job_with_workload_finding())
    assert "workload_runtime_evidence" not in rows[0]


def test_other_workload_marked_no_signal_not_clean(clean_default_store):
    _seed_store()
    job = ScanJob.model_construct(
        job_id="job-2",
        tenant_id="tenant-a",
        request=ScanRequest(),
        result={
            "findings": [
                {
                    "id": "f2",
                    "cve_id": "CVE-2026-2",
                    "provider": "aws",
                    "account_ref": "aws:123456789012",
                    "resource_id": "i-DIFFERENT",  # no signal for this workload
                    "severity": "high",
                }
            ]
        },
    )
    rows = _iter_scan_findings(job)
    ev = rows[0]["workload_runtime_evidence"]
    assert ev["state"] == STATE_NO_SIGNAL
    assert ev["clean_workload_assertion"] is False


def test_cross_tenant_signals_do_not_enrich_other_tenant(clean_default_store):
    _seed_store(tenant="tenant-a")
    # a job for tenant-b must not see tenant-a's signals
    rows = _iter_scan_findings(_job_with_workload_finding(tenant="tenant-b"))
    assert "workload_runtime_evidence" not in rows[0]
