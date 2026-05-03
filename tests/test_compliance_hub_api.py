"""Tests for the Compliance Hub API endpoints (#1044 PR C).

Covers:
- POST /v1/compliance/ingest (SARIF / CycloneDX / CSV / JSON)
- GET /v1/compliance/hub/findings
- GET /v1/compliance/hub/posture
- DELETE /v1/compliance/hub/findings
- Tenant isolation: tenant A's hub findings must never appear for tenant B

The store is process-wide and in-memory (PR C scope), so tests reset it
between cases to avoid cross-test bleed.
"""

from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import reset_compliance_hub_store
from agent_bom.api.models import JobStatus
from agent_bom.api.server import app
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


@pytest.fixture(autouse=True)
def _reset_store():
    reset_compliance_hub_store()
    yield
    reset_compliance_hub_store()


def _client(tenant: str = "tenant-alpha", role: str = "admin") -> TestClient:
    client = TestClient(app)
    client.headers.update(proxy_headers(role=role, tenant=tenant))
    return client


def _sarif_doc() -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "external-secrets",
                        "rules": [
                            {
                                "id": "SECRET-AWS-ACCESS-KEY",
                                "shortDescription": {"text": "AWS access key"},
                                "properties": {"tags": ["secret", "CWE-798"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "SECRET-AWS-ACCESS-KEY",
                        "level": "error",
                        "message": {"text": "Hardcoded AWS access key"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/cfg.py"}}}],
                        "properties": {"security-severity": "9.5"},
                    }
                ],
            }
        ],
    }


# ─── POST /v1/compliance/ingest ──────────────────────────────────────────────


def test_ingest_sarif_returns_count_plus_framework_breakdown():
    resp = _client().post(
        "/v1/compliance/ingest",
        json={"format": "sarif", "content": json.dumps(_sarif_doc())},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["ingested"] == 1
    assert body["tenant_total"] == 1
    assert body["format"] == "sarif"
    # SECRET rule -> CREDENTIAL_EXPOSURE -> hub adds enterprise audit frameworks
    assert "soc2" in body["framework_hits"]
    assert "iso-27001" in body["framework_hits"]
    assert "nist-csf" in body["framework_hits"]


def test_ingest_invalid_format_returns_400():
    resp = _client().post(
        "/v1/compliance/ingest",
        json={"format": "xml", "content": "<x/>"},
    )
    assert resp.status_code == 400


def test_ingest_empty_content_returns_400():
    resp = _client().post(
        "/v1/compliance/ingest",
        json={"format": "sarif", "content": ""},
    )
    assert resp.status_code == 400


def test_ingest_unparseable_sarif_returns_422():
    resp = _client().post(
        "/v1/compliance/ingest",
        json={"format": "sarif", "content": json.dumps({"version": "2.1.0", "runs": []})},
    )
    assert resp.status_code == 422


def test_ingest_csv_classifies_cve_rows():
    csv = "Title,Severity,CVE\nlodash CVE,High,CVE-2021-23337\n"
    resp = _client().post(
        "/v1/compliance/ingest",
        json={"format": "csv", "content": csv},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["ingested"] == 1


# ─── GET /v1/compliance/hub/findings ─────────────────────────────────────────


def test_list_hub_findings_returns_what_we_ingested():
    client = _client()
    client.post(
        "/v1/compliance/ingest",
        json={"format": "sarif", "content": json.dumps(_sarif_doc())},
    )
    resp = client.get("/v1/compliance/hub/findings")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["count"] == 1
    assert body["findings"][0]["source"] == "EXTERNAL"


def test_list_hub_findings_pagination():
    client = _client()
    csv_rows = "Title,Severity\n" + "\n".join(f"row-{i},low" for i in range(50))
    client.post("/v1/compliance/ingest", json={"format": "csv", "content": csv_rows})

    resp = client.get("/v1/compliance/hub/findings?limit=10&offset=20")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 10
    assert body["total"] == 50
    assert body["offset"] == 20


# ─── Tenant isolation ────────────────────────────────────────────────────────


def test_hub_findings_are_tenant_scoped():
    """Tenant A's ingest must not appear under tenant B's hub findings."""
    a = _client(tenant="tenant-alpha")
    b = _client(tenant="tenant-beta")

    a.post("/v1/compliance/ingest", json={"format": "sarif", "content": json.dumps(_sarif_doc())})

    a_list = a.get("/v1/compliance/hub/findings").json()
    b_list = b.get("/v1/compliance/hub/findings").json()

    assert a_list["total"] == 1
    assert b_list["total"] == 0


# ─── GET /v1/compliance/hub/posture ──────────────────────────────────────────


def test_hub_posture_aggregates_hub_findings_per_framework():
    client = _client()
    client.post(
        "/v1/compliance/ingest",
        json={"format": "sarif", "content": json.dumps(_sarif_doc())},
    )

    resp = client.get("/v1/compliance/hub/posture")
    assert resp.status_code == 200
    body = resp.json()

    assert body["totals"]["hub"] == 1
    assert body["totals"]["combined"] >= 1
    # SECRET rule -> CREDENTIAL_EXPOSURE adds SOC 2
    assert body["framework_counts"]["hub"].get("soc2", 0) >= 1
    assert body["hub_severity_breakdown"]["critical"] == 1


def test_hub_posture_with_no_findings_returns_zeros():
    body = _client().get("/v1/compliance/hub/posture").json()
    assert body["totals"]["hub"] == 0
    assert body["framework_counts"]["hub"] == {}


def test_hub_posture_native_counts_aggregate_all_15_frameworks():
    """Regression: posture endpoint must aggregate every framework in
    TAG_MAPPED_FRAMEWORKS, not just an inline subset. Previously the
    aggregator silently dropped nist-800-53, fedramp, cmmc, and pci-dss.
    """
    from agent_bom.api.server import ScanJob, ScanRequest, set_job_store
    from agent_bom.api.store import InMemoryJobStore
    from agent_bom.api.stores import _get_store
    from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS

    set_job_store(InMemoryJobStore())

    # Build a single blast-radius row that has *every* tag field populated,
    # so a correctly wired aggregator must report a count for every slug.
    blast_row: dict[str, object] = {"package": "demo", "version": "1.0.0"}
    for metadata in TAG_MAPPED_FRAMEWORKS:
        blast_row[metadata.tag_field] = ["TAG-1"]

    job = ScanJob(
        job_id="posture-regression-job",
        tenant_id="tenant-alpha",
        created_at="2026-05-02T10:00:00Z",
        request=ScanRequest(),
    )
    job.status = JobStatus.DONE
    job.completed_at = "2026-05-02T10:01:00Z"
    job.result = {"agents": [], "blast_radius": [blast_row], "threat_framework_summary": {}}
    _get_store().put(job)

    body = _client().get("/v1/compliance/hub/posture").json()
    native_counts = body["framework_counts"]["native"]

    expected_slugs = {metadata.slug for metadata in TAG_MAPPED_FRAMEWORKS}
    assert len(expected_slugs) == 15, "TAG_MAPPED_FRAMEWORKS shape changed; update this regression and the posture aggregator together."
    # The four slugs that the legacy 10-tuple silently dropped.
    for slug in ("nist-800-53", "fedramp", "cmmc", "pci-dss"):
        assert native_counts.get(slug) == 1, f"posture endpoint dropped framework {slug!r}: got {native_counts}"
    # And every framework in the canonical list reports the row.
    for slug in expected_slugs:
        assert native_counts.get(slug) == 1, slug

    set_job_store(InMemoryJobStore())


# ─── DELETE /v1/compliance/hub/findings ──────────────────────────────────────


def test_clear_hub_findings_resets_store_for_tenant():
    client = _client()
    client.post(
        "/v1/compliance/ingest",
        json={"format": "sarif", "content": json.dumps(_sarif_doc())},
    )
    delete = client.delete("/v1/compliance/hub/findings")
    assert delete.status_code == 200
    assert delete.json()["removed"] == 1

    after = client.get("/v1/compliance/hub/findings").json()
    assert after["total"] == 0


def test_clear_hub_findings_does_not_affect_other_tenant():
    a = _client(tenant="tenant-alpha")
    b = _client(tenant="tenant-beta")
    a.post("/v1/compliance/ingest", json={"format": "sarif", "content": json.dumps(_sarif_doc())})
    b.post("/v1/compliance/ingest", json={"format": "sarif", "content": json.dumps(_sarif_doc())})

    a.delete("/v1/compliance/hub/findings")

    assert a.get("/v1/compliance/hub/findings").json()["total"] == 0
    assert b.get("/v1/compliance/hub/findings").json()["total"] == 1


def test_clear_requires_write_permission():
    """Read-only role cannot clear the hub store."""
    reader = TestClient(app)
    reader.headers.update(proxy_headers(role="viewer", tenant="tenant-alpha"))
    resp = reader.delete("/v1/compliance/hub/findings")
    assert resp.status_code in (401, 403), f"viewer should be denied (got {resp.status_code})"


# ─── SQLite backend ──────────────────────────────────────────────────────────


def test_sqlite_backend_persists_across_store_instances(tmp_path):
    """Findings written through one SQLiteComplianceHubStore must be
    readable from a fresh instance pointing at the same file. This is
    the single-node persistence contract: API restart -> findings still
    visible. In-memory backend would fail this test."""
    from agent_bom.api.compliance_hub_store import (
        SQLiteComplianceHubStore,
        set_compliance_hub_store,
    )

    db = tmp_path / "hub.db"
    store_a = SQLiteComplianceHubStore(str(db))
    set_compliance_hub_store(store_a)

    client = _client(tenant="tenant-alpha")
    client.post(
        "/v1/compliance/ingest",
        json={"format": "sarif", "content": json.dumps(_sarif_doc())},
    )
    assert client.get("/v1/compliance/hub/findings").json()["total"] == 1

    # Rebind to a fresh store instance with the same db path -> data persists.
    store_b = SQLiteComplianceHubStore(str(db))
    set_compliance_hub_store(store_b)

    after_restart = client.get("/v1/compliance/hub/findings").json()
    assert after_restart["total"] == 1, "SQLite persistence contract: findings must survive a store restart"


def test_sqlite_backend_keeps_tenant_data_separate(tmp_path):
    from agent_bom.api.compliance_hub_store import (
        SQLiteComplianceHubStore,
        set_compliance_hub_store,
    )

    set_compliance_hub_store(SQLiteComplianceHubStore(str(tmp_path / "x.db")))

    a = _client(tenant="tenant-alpha")
    b = _client(tenant="tenant-beta")
    a.post("/v1/compliance/ingest", json={"format": "sarif", "content": json.dumps(_sarif_doc())})

    assert a.get("/v1/compliance/hub/findings").json()["total"] == 1
    assert b.get("/v1/compliance/hub/findings").json()["total"] == 0


def test_sqlite_backend_clear_only_affects_caller_tenant(tmp_path):
    from agent_bom.api.compliance_hub_store import (
        SQLiteComplianceHubStore,
        set_compliance_hub_store,
    )

    set_compliance_hub_store(SQLiteComplianceHubStore(str(tmp_path / "y.db")))

    a = _client(tenant="tenant-alpha")
    b = _client(tenant="tenant-beta")
    a.post("/v1/compliance/ingest", json={"format": "sarif", "content": json.dumps(_sarif_doc())})
    b.post("/v1/compliance/ingest", json={"format": "sarif", "content": json.dumps(_sarif_doc())})

    a.delete("/v1/compliance/hub/findings")
    assert a.get("/v1/compliance/hub/findings").json()["total"] == 0
    assert b.get("/v1/compliance/hub/findings").json()["total"] == 1


def test_sqlite_backend_preserves_ingest_order(tmp_path):
    """`list` returns oldest-first; the SQLite ordinal column drives
    that contract. Pagination + UI rendering both depend on it."""
    from agent_bom.api.compliance_hub_store import (
        SQLiteComplianceHubStore,
        set_compliance_hub_store,
    )

    set_compliance_hub_store(SQLiteComplianceHubStore(str(tmp_path / "ord.db")))
    client = _client()
    for i in range(5):
        csv = f"Title,Severity\nrow-{i},low\n"
        client.post("/v1/compliance/ingest", json={"format": "csv", "content": csv})

    titles = [f["title"] for f in client.get("/v1/compliance/hub/findings").json()["findings"]]
    assert titles == [f"row-{i}" for i in range(5)]


def test_sqlite_backend_denormalises_framework_csv_for_aggregation(tmp_path):
    """The schema stores `applicable_frameworks_csv` so SQL-layer
    posture aggregation can filter without parsing JSON. This test
    asserts the column is populated for every row, which the column
    NOT NULL constraint partly guarantees but the actual contents are
    what aggregation will read."""
    import sqlite3

    from agent_bom.api.compliance_hub_store import (
        SQLiteComplianceHubStore,
        set_compliance_hub_store,
    )

    db = tmp_path / "csv.db"
    set_compliance_hub_store(SQLiteComplianceHubStore(str(db)))

    client = _client()
    client.post(
        "/v1/compliance/ingest",
        json={"format": "sarif", "content": json.dumps(_sarif_doc())},
    )

    direct = sqlite3.connect(str(db))
    rows = direct.execute(
        "SELECT applicable_frameworks_csv FROM compliance_hub_findings WHERE tenant_id = ?",
        ("tenant-alpha",),
    ).fetchall()
    direct.close()
    assert rows, "expected at least one row"
    csv_value = rows[0][0]
    # SECRET rule -> CREDENTIAL_EXPOSURE -> SOC 2 / ISO / NIST CSF must be in csv
    for slug in ("soc2", "iso-27001", "nist-csf"):
        assert slug in csv_value, f"{slug} missing from denormalised csv: {csv_value!r}"
