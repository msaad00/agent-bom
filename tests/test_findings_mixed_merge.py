"""Mixed in-memory scan findings + bulk hub pagination (#3619 follow-up)."""

from __future__ import annotations

from uuid import uuid4

from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, set_compliance_hub_store
from agent_bom.api.routes.scan import _finding_sort_key, _merged_scan_bulk_page
from agent_bom.api.server import ScanJob, ScanRequest, app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_store
from agent_bom.api.models import JobStatus
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())


def _seed_bulk(store: InMemoryComplianceHubStore, tenant: str, count: int) -> None:
    findings = [
        {
            "id": f"bulk-{idx}",
            "severity": "medium",
            "cvss_score": float(idx % 10),
            "effective_reach_score": float(idx),
            "origin": "bulk_ingest",
            "source": "test",
            "batch_id": "merge-batch",
        }
        for idx in range(count)
    ]
    store.add(tenant, findings)
    store.upsert_current_batch(
        tenant,
        findings,
        observed_at="2026-07-06T00:00:00Z",
        batch_id="merge-batch",
        source="test",
    )


def test_merged_scan_bulk_page_matches_full_sort_reference() -> None:
    tenant = f"merge-{uuid4().hex}"
    store = InMemoryComplianceHubStore()
    scan_rows = [
        {
            "id": "scan-high",
            "severity": "critical",
            "cvss_score": 9.8,
            "effective_reach_score": 95.0,
            "origin": "native_scan",
            "source": "MCP_SCAN",
        },
        {
            "id": "scan-low",
            "severity": "low",
            "cvss_score": 2.0,
            "effective_reach_score": 5.0,
            "origin": "native_scan",
            "source": "MCP_SCAN",
        },
    ]
    _seed_bulk(store, tenant, 30)
    scan_sorted = sorted(scan_rows, key=lambda row: _finding_sort_key(row, "effective_reach"))

    for offset in (0, 2, 5, 10):
        for limit in (1, 3, 7):
            merged = _merged_scan_bulk_page(
                scan_sorted,
                bulk_list=store.list_page,
                tenant_id=tenant,
                sort_key="effective_reach",
                severity=None,
                scan_id=None,
                offset=offset,
                limit=limit,
            )
            bulk_rows = store.list(tenant)
            reference = sorted(scan_sorted + bulk_rows, key=lambda row: _finding_sort_key(row, "effective_reach"))
            assert [row["id"] for row in merged] == [row["id"] for row in reference[offset : offset + limit]]


def test_findings_api_merges_scan_and_bulk_at_deep_offset() -> None:
    tenant = f"api-merge-{uuid4().hex}"
    store = InMemoryComplianceHubStore()
    set_compliance_hub_store(store)
    _seed_bulk(store, tenant, 40)

    set_job_store(InMemoryJobStore())
    job = ScanJob(
        job_id="merge-scan-job",
        tenant_id=tenant,
        created_at="2026-07-06T10:00:00Z",
        request=ScanRequest(),
    )
    job.status = JobStatus.DONE
    job.completed_at = "2026-07-06T10:01:00Z"
    job.result = {
        "findings": [
            {
                "id": "scan-top",
                "vulnerability_id": "scan-top",
                "severity": "critical",
                "cvss_score": 10.0,
                "effective_reach_score": 99.0,
                "package": "pkg",
            }
        ]
    }
    _get_store().put(job)

    client = TestClient(app)
    headers = proxy_headers(tenant=tenant)
    body = client.get("/v1/findings?limit=5&offset=3&sort=effective_reach", headers=headers).json()
    assert body["count"] == 5

    scan_rows = [
        {
            "id": "scan-top",
            "severity": "critical",
            "cvss_score": 10.0,
            "effective_reach_score": 99.0,
            "origin": "native_scan",
        }
    ]
    bulk_rows, _ = store.list_page(tenant, limit=1000, offset=0)
    reference = sorted(
        scan_rows + bulk_rows,
        key=lambda row: _finding_sort_key(row, "effective_reach"),
    )
    assert [row["id"] for row in body["findings"]] == [row["id"] for row in reference[3:8]]
