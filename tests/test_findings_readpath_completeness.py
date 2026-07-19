"""Findings read-path completeness (pre-release audit 2026-07-19).

Two regressions where scan-derived findings failed to reach the consumer:

* Fix 1 — ``/v1/findings`` keyset pagination silently dropped in-memory scan
  findings: the merged scan+bulk branch never emitted a ``next_cursor`` so a
  client following the documented keyset contract (advance while ``has_more``)
  stopped after page 1 and lost the rest.
* Fix 2 — the scheduled findings export streamed ONLY the compliance hub, which
  the scan pipeline never writes, so a scan-based estate exported zero rows with
  no partiality warning even though ``/v1/findings`` shows them.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, set_compliance_hub_store
from agent_bom.api.models import JobStatus
from agent_bom.api.server import ScanJob, ScanRequest, app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_store
from agent_bom.export.runner import iter_current_findings, run_findings_export
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())


def _scan_finding(idx: int) -> dict[str, Any]:
    # Distinct effective_reach_score + id so the keyset order is total and the
    # 0-dup / 0-drop assertion is unambiguous.
    return {
        "id": f"scan-{idx:03d}",
        "vulnerability_id": f"CVE-2026-{idx:04d}",
        "severity": "high",
        "cvss_score": 5.0 + (idx % 5),
        "effective_reach_score": float(1000 - idx),
        "package": f"pkg-{idx}",
    }


def _seed_scan_job(tenant: str, count: int) -> None:
    set_job_store(InMemoryJobStore())
    job = ScanJob(
        job_id=f"scan-job-{uuid4().hex}",
        tenant_id=tenant,
        created_at="2026-07-19T10:00:00Z",
        request=ScanRequest(),
    )
    job.status = JobStatus.DONE
    job.completed_at = "2026-07-19T10:01:00Z"
    job.result = {"findings": [_scan_finding(i) for i in range(count)]}
    _get_store().put(job)


def _walk_keyset(client: TestClient, headers: dict[str, str], *, limit: int) -> list[str]:
    """Follow the documented keyset contract: advance while ``has_more``."""
    seen: list[str] = []
    cursor = ""
    guard = 0
    while True:
        guard += 1
        assert guard < 1000, "keyset walk did not terminate"
        url = f"/v1/findings?limit={limit}&sort=effective_reach"
        if cursor:
            url += f"&cursor={cursor}"
        body = client.get(url, headers=headers).json()
        seen.extend(str(row.get("id")) for row in body["findings"])
        if not body["has_more"]:
            break
        cursor = body["next_cursor"]
        assert cursor, "has_more was true but next_cursor was empty"
    return seen


# --------------------------------------------------------------------------
# Fix 1 — keyset pagination over in-memory scan findings
# --------------------------------------------------------------------------
def test_keyset_walks_all_scan_findings_zero_dup_zero_drop() -> None:
    tenant = f"scan-keyset-{uuid4().hex}"
    set_compliance_hub_store(InMemoryComplianceHubStore())
    _seed_scan_job(tenant, 19)

    client = TestClient(app)
    headers = proxy_headers(tenant=tenant)

    first = client.get("/v1/findings?limit=5&sort=effective_reach", headers=headers).json()
    assert first["count"] == 5
    assert first["total"] == 19
    # The bug: has_more was False here, stranding 14 findings.
    assert first["has_more"] is True
    assert first["next_cursor"]

    seen = _walk_keyset(client, headers, limit=5)
    assert len(seen) == 19, f"expected all 19 findings, got {len(seen)}"
    assert len(set(seen)) == 19, "keyset walk produced duplicates"
    assert set(seen) == {f"scan-{i:03d}" for i in range(19)}


def test_keyset_walk_cvss_sort_zero_dup_zero_drop() -> None:
    tenant = f"scan-cvss-{uuid4().hex}"
    set_compliance_hub_store(InMemoryComplianceHubStore())
    _seed_scan_job(tenant, 13)

    client = TestClient(app)
    headers = proxy_headers(tenant=tenant)

    seen: list[str] = []
    cursor = ""
    while True:
        url = "/v1/findings?limit=4&sort=cvss"
        if cursor:
            url += f"&cursor={cursor}"
        body = client.get(url, headers=headers).json()
        seen.extend(str(r.get("id")) for r in body["findings"])
        if not body["has_more"]:
            break
        cursor = body["next_cursor"]
    assert set(seen) == {f"scan-{i:03d}" for i in range(13)}
    assert len(seen) == 13


def test_merged_cursor_rejects_sort_mismatch_and_garbage() -> None:
    tenant = f"scan-badcur-{uuid4().hex}"
    set_compliance_hub_store(InMemoryComplianceHubStore())
    _seed_scan_job(tenant, 8)
    client = TestClient(app)
    headers = proxy_headers(tenant=tenant)

    first = client.get("/v1/findings?limit=3&sort=effective_reach", headers=headers).json()
    cursor = first["next_cursor"]
    assert cursor
    # Reusing an effective_reach cursor under a different sort must 400, not
    # silently mis-page.
    assert client.get(f"/v1/findings?limit=3&sort=cvss&cursor={cursor}", headers=headers).status_code == 400
    # Garbage cursor is rejected.
    assert client.get("/v1/findings?limit=3&cursor=not-a-cursor", headers=headers).status_code == 400
    # cursor + offset are mutually exclusive.
    assert client.get(f"/v1/findings?limit=3&offset=3&cursor={cursor}", headers=headers).status_code == 400


def test_keyset_walks_mixed_scan_and_bulk_zero_dup_zero_drop() -> None:
    tenant = f"mixed-keyset-{uuid4().hex}"
    store = InMemoryComplianceHubStore()
    set_compliance_hub_store(store)
    bulk = [
        {
            "id": f"bulk-{idx:03d}",
            "severity": "medium",
            "cvss_score": float(idx % 10),
            "effective_reach_score": float(500 - idx),
            "origin": "bulk_ingest",
            "source": "test",
            "batch_id": "mix-batch",
        }
        for idx in range(23)
    ]
    store.add(tenant, bulk)
    store.upsert_current_batch(tenant, bulk, observed_at="2026-07-19T00:00:00Z", batch_id="mix-batch", source="test")
    _seed_scan_job(tenant, 11)

    client = TestClient(app)
    headers = proxy_headers(tenant=tenant)

    seen = _walk_keyset(client, headers, limit=4)
    expected = {f"scan-{i:03d}" for i in range(11)} | {f"bulk-{i:03d}" for i in range(23)}
    assert len(seen) == len(expected), f"expected {len(expected)} rows, got {len(seen)}"
    assert len(set(seen)) == len(seen), "keyset walk produced duplicates"
    assert set(seen) == expected


# --------------------------------------------------------------------------
# Fix 2 — scheduled export must include scan-spine findings
# --------------------------------------------------------------------------
class _FakeDestination:
    kind = "s3"

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def write_findings(self, rows: Any, *, tenant_id: str, run_id: str) -> Any:
        from agent_bom.export.destinations import ExportResult

        self.rows = [dict(r) for r in rows]
        return ExportResult(kind=self.kind, destination_uri="s3://x/y", row_count=len(self.rows), byte_count=0)


def test_iter_current_findings_includes_scan_spine() -> None:
    tenant = f"export-scan-{uuid4().hex}"
    set_compliance_hub_store(InMemoryComplianceHubStore())  # hub is empty
    _seed_scan_job(tenant, 7)

    rows = list(iter_current_findings(tenant))
    ids = {str(r.get("id")) for r in rows}
    assert ids == {f"scan-{i:03d}" for i in range(7)}, f"scan-spine findings missing from export: {ids}"


def test_run_findings_export_ships_scan_findings_end_to_end() -> None:
    tenant = f"export-e2e-{uuid4().hex}"
    set_compliance_hub_store(InMemoryComplianceHubStore())
    _seed_scan_job(tenant, 5)

    dest = _FakeDestination()
    result = run_findings_export(tenant_id=tenant, kind="s3", config={}, destination=dest)
    assert result.row_count == 5, "scheduled export shipped zero scan-derived findings"
    assert {str(r.get("id")) for r in dest.rows} == {f"scan-{i:03d}" for i in range(5)}
