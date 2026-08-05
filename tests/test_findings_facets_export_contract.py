"""Canonical finding facets and filter/export parity.

The Findings UI must not infer taxonomy or counts from the current page. This
suite locks the API-owned contract: every row has a visible class (including
``unclassified``), facet counts are computed over the matching result set while
excluding only their own active dimension, and an async export accepts the same
filters as the list endpoint.
"""

from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, set_compliance_hub_store
from agent_bom.api.models import JobStatus
from agent_bom.api.report_job_store import reset_report_job_store
from agent_bom.api.report_worker import _run_report_job_sync
from agent_bom.api.server import ScanJob, ScanRequest, app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_store
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


@pytest.fixture(autouse=True)
def _stores() -> None:
    enable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())
    reset_report_job_store()
    yield
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())
    reset_report_job_store()
    disable_trusted_proxy_env()


def _headers(tenant: str, *, role: str = "analyst") -> dict[str, str]:
    return proxy_headers(tenant=tenant, role=role)


def _seed_scan(tenant: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    job = ScanJob(job_id=f"scan-{uuid4().hex}", tenant_id=tenant, created_at=now, request=ScanRequest())
    job.status = JobStatus.DONE
    job.completed_at = now
    job.result = {
        "findings": [
            {
                "id": "repo-high",
                "finding_type": "CVE",
                "source": "SBOM",
                "cve_id": "CVE-2026-1000",
                "security_domain": "vuln",
                "severity": "high",
            },
            {
                "id": "repo-medium",
                "finding_type": "CVE",
                "source": "SBOM",
                "cve_id": "CVE-2026-1001",
                "security_domain": "vuln",
                "severity": "medium",
            },
            {
                "id": "container-high",
                "finding_type": "CVE",
                "source": "CONTAINER",
                "cve_id": "CVE-2026-1002",
                "security_domain": "vuln",
                "severity": "high",
            },
            {
                "id": "secret-high",
                "finding_type": "CREDENTIAL_EXPOSURE",
                "source": "SECRET_SCAN",
                "security_domain": "aspm",
                "severity": "high",
            },
            {
                "id": "sast-low",
                "finding_type": "SAST",
                "source": "SAST",
                "security_domain": "aspm",
                "severity": "low",
            },
            {
                "id": "unknown-runtime",
                "finding_type": "FUTURE_RUNTIME_SIGNAL",
                "source": "FUTURE_RUNTIME",
                "security_domain": "aispm",
                "severity": "info",
            },
        ]
    }
    _get_store().put(job)


def _seed_resolved_repo_finding(tenant: str) -> None:
    store = InMemoryComplianceHubStore()
    row = {
        "id": "resolved-repo-high",
        "finding_type": "CVE",
        "source": "SBOM",
        "cve_id": "CVE-2026-1003",
        "security_domain": "vuln",
        "severity": "high",
        "origin": "bulk_ingest",
        "batch_id": "resolved-batch",
    }
    store.add(tenant, [row])
    store.upsert_current_batch(
        tenant,
        [row],
        observed_at="2026-07-25T00:00:00Z",
        batch_id="resolved-batch",
        source="fixture",
    )
    store.reconcile_current_absent(
        tenant,
        present_canonical_ids=set(),
        observed_at="2026-07-26T00:00:00Z",
    )
    set_compliance_hub_store(store)


def test_unknown_findings_are_visible_and_filterable_as_unclassified() -> None:
    tenant = "default"
    _seed_scan(tenant)
    from agent_bom.api.routes.scan import iter_tenant_scan_spine_findings

    assert len(iter_tenant_scan_spine_findings(tenant)) == 6

    response = TestClient(app).get(
        "/v1/findings?finding_class=unclassified&include_facets=true&window_days=0",
        headers=_headers(tenant),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert [row["id"] for row in body["findings"]] == ["unknown-runtime"], body
    row = body["findings"][0]
    assert row["finding_class"] == "unclassified"
    assert row["first_seen"] is None
    assert datetime.fromisoformat(row["last_observed"].replace("Z", "+00:00")).tzinfo is not None
    assert row["occurrence_count"] is None
    assert row["cvss_version"] is None
    assert row["epss_score"] is None
    assert row["owner"] is None
    assert body["facets"]["finding_class"]["unclassified"] == 1
    assert sum(body["facets"]["freshness"].values()) == 1
    assert body["facets"]["freshness"]["unavailable"] == 0
    assert body["facet_metadata"]["freshness"]["missing_or_invalid"] == "unavailable"
    assert body["facets_approximate"] is False


def test_facets_exclude_only_their_own_active_dimension() -> None:
    tenant = "default"
    _seed_scan(tenant)
    _seed_resolved_repo_finding(tenant)

    response = TestClient(app).get(
        ("/v1/findings?finding_class=vulnerability&severity=high&domain=aspm&status=open&include_facets=true&window_days=0"),
        headers=_headers(tenant),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert {row["id"] for row in body["findings"]} == {"repo-high"}
    assert body["total"] == 1

    # Class facet keeps severity/domain/status but drops finding_class.
    assert body["facets"]["finding_class"]["vulnerability"] == 1
    assert body["facets"]["finding_class"]["secret"] == 1
    # Severity facet keeps class/domain/status but drops severity.
    assert body["facets"]["severity"]["high"] == 1
    assert body["facets"]["severity"]["medium"] == 1
    # Status facet keeps class/severity/domain but drops status.
    assert body["facets"]["status"]["open"] == 1
    assert body["facets"]["status"]["resolved"] == 1
    # Domain membership overlaps by design. Dropping domain includes the
    # container CVE under vuln, while only repository CVEs also count as ASPM.
    assert body["facets"]["domain"]["vuln"] == 2
    assert body["facets"]["domain"]["aspm"] == 1


def test_facet_walk_is_single_pass_and_marks_scan_budget_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.routes.scan import _finding_facets_bounded

    calls = 0

    def _rows(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        for index in range(10):
            yield {
                "id": f"finding-{index}",
                "finding_type": "CVE",
                "source": "SBOM",
                "severity": "high",
            }

    monkeypatch.setattr("agent_bom.export.runner.iter_current_findings", _rows)

    facets, total, metadata = _finding_facets_bounded(
        "tenant-bounded-facets",
        severity=None,
        scan_id=None,
        since=None,
        scope={},
        status="open",
        scan_budget=3,
        deadline_seconds=60,
    )

    assert calls == 1
    assert total == 3
    assert facets["severity"]["high"] == 3
    assert metadata == {
        "status": "partial",
        "reason": "scan_budget",
        "scanned_rows": 3,
        "scan_budget": 3,
        "deadline_ms": 60_000,
        # A truncated walk with no store aggregate to fall back on leaves every
        # dimension — and the total — a lower bound, and now says so per
        # dimension rather than only as a single "approximate" flag.
        "total_exact": False,
        "dimensions": {
            "finding_class": "bounded",
            "severity": "bounded",
            "status": "bounded",
            "domain": "bounded",
            "freshness": "bounded",
        },
    }


def test_facet_deadline_starts_after_the_first_row_is_available(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.routes import scan as scan_routes

    clock = {"now": 0.0}

    def _rows(*_args, **_kwargs):
        # Model a database cursor whose first row takes longer than the Python
        # facet-processing budget to become available. Query latency must not
        # turn a non-empty result set into a zero-count response.
        clock["now"] = 2.0
        yield {
            "id": "finding-delayed",
            "finding_type": "CVE",
            "source": "SBOM",
            "severity": "high",
        }

    monkeypatch.setattr("agent_bom.export.runner.iter_current_findings", _rows)
    monkeypatch.setattr(scan_routes.time, "monotonic", lambda: clock["now"])

    facets, total, metadata = scan_routes._finding_facets_bounded(
        "tenant-delayed-facets",
        severity=None,
        scan_id=None,
        since=None,
        scope={},
        status="open",
        scan_budget=10,
        deadline_seconds=1.0,
    )

    assert total == 1
    assert facets["severity"]["high"] == 1
    assert metadata["scanned_rows"] == 1
    assert metadata["status"] == "complete"


def test_partial_zero_row_facet_walk_preserves_the_list_total(monkeypatch: pytest.MonkeyPatch) -> None:
    tenant = "default"
    _seed_scan(tenant)
    empty_facets = {
        "finding_class": {},
        "severity": {},
        "status": {},
        "domain": {},
        "freshness": {},
    }
    monkeypatch.setattr(
        "agent_bom.api.routes.scan._finding_facets_bounded",
        lambda *_args, **_kwargs: (
            empty_facets,
            0,
            {
                "status": "partial",
                "reason": "deadline",
                "scanned_rows": 0,
                "scan_budget": 50_000,
                "deadline_ms": 1_500,
                "total_exact": False,
                "dimensions": {
                    "finding_class": "bounded",
                    "severity": "bounded",
                    "status": "bounded",
                    "domain": "bounded",
                    "freshness": "bounded",
                },
            },
        ),
    )

    response = TestClient(app).get(
        "/v1/findings?include_facets=true&window_days=0",
        headers=_headers(tenant),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert len(body["findings"]) == 6
    assert body["total"] == 6
    assert body["total_approximate"] is True


def test_findings_envelope_total_never_contradicts_the_severity_facet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``total`` and ``facets.severity[<filter>]`` must agree in the response body.

    The row budget is lowered instead of seeding 50k rows; the store aggregate
    still answers the histogram exactly, which is precisely the combination that
    used to emit an exact facet beside a truncated total.
    """
    from agent_bom.api.routes import scan as scan_routes

    tenant = "tenant-facet-contradiction"
    store = InMemoryComplianceHubStore()
    rows = [
        {
            "id": f"contradiction-{index}",
            "canonical_id": f"contradiction-{index}",
            "finding_type": "CVE",
            "source": "SBOM",
            "severity": "critical" if index % 2 == 0 else "high",
            "origin": "bulk_ingest",
        }
        for index in range(24)
    ]
    store.add(tenant, rows)
    store.upsert_current_batch(tenant, rows, observed_at="2026-07-30T00:00:00Z", batch_id="contradiction", source="fixture")
    set_compliance_hub_store(store)
    monkeypatch.setattr(scan_routes, "_FACET_SCAN_BUDGET", 3)

    response = TestClient(app).get(
        "/v1/findings?include_facets=true&window_days=0&severity=critical",
        headers=_headers(tenant),
    )
    assert response.status_code == 200, response.text
    body = response.json()

    completeness = body["facet_metadata"]["completeness"]
    assert completeness["status"] == "partial", "the lowered budget did not truncate the walk"
    assert body["facets"]["severity"]["critical"] == body["total"]
    # The envelope only carries the flag when the total really is approximate.
    assert body.get("total_approximate", False) is False, "the aggregate answered the total exactly"
    assert body["facets_approximate"] is True, "the walk-derived dimensions are still bounded"
    assert any("lower bounds, not totals" in warning for warning in body["warnings"]), body["warnings"]


def test_async_export_uses_the_same_finding_predicates(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    tenant = "default"
    _seed_scan(tenant)
    _seed_resolved_repo_finding(tenant)
    monkeypatch.setenv("AGENT_BOM_REPORT_ARTIFACT_DIR", str(tmp_path))
    monkeypatch.setattr("agent_bom.api.routes.reports.submit_report_job", _run_report_job_sync)
    client = TestClient(app)
    headers = _headers(tenant)

    query = "finding_class=vulnerability&severity=high&domain=aspm&status=open&window_days=0"
    listed = client.get(f"/v1/findings?{query}&limit=100", headers=headers)
    assert listed.status_code == 200, listed.text
    listed_ids = {row["id"] for row in listed.json()["findings"]}

    created = client.post(
        "/v1/reports",
        json={
            "finding_class": "vulnerability",
            "severity": "high",
            "domain": "aspm",
            "status": "open",
            "window_days": 0,
        },
        headers=headers,
    )
    assert created.status_code == 202, created.text
    job = client.get(f"/v1/reports/{created.json()['job_id']}", headers=headers).json()
    assert job["status"] == "done"
    downloaded = client.get(
        job["download_url"],
        headers={**headers, "X-Agent-Bom-Download-Token": job["download_token"]},
    )
    assert downloaded.status_code == 200, downloaded.text
    exported = [json.loads(line) for line in gzip.decompress(downloaded.content).decode().splitlines()]

    assert {row["id"] for row in exported} == listed_ids == {"repo-high"}
    assert all(row["finding_class"] == "vulnerability" for row in exported)


def test_list_and_report_share_safe_observation_metadata(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    tenant = "default"
    monkeypatch.setenv("AGENT_BOM_REPORT_ARTIFACT_DIR", str(tmp_path))
    monkeypatch.setattr("agent_bom.api.routes.reports.submit_report_job", _run_report_job_sync)
    client = TestClient(app)
    headers = _headers(tenant)
    observed_at = "2026-07-25T12:00:00Z"

    ingested = client.post(
        "/v1/findings/bulk",
        json={
            "source": "external_scan",
            "observed_at": observed_at,
            "findings": [
                {
                    "id": "metadata-finding",
                    "finding_type": "CVE",
                    "source": "SBOM",
                    "cve_id": "CVE-2026-4242",
                    "package": "metadata-package",
                    "severity": "high",
                    "cvss_score": 8.8,
                    "cvss_version": "3.1",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    "epss_score": 0.42,
                    "is_kev": True,
                    "fixed_version": "2.0.0",
                    "remediation_versions": ["2.0.0", "2.0.1"],
                    "provenance": {
                        "source": "fixture",
                        "collector": "unit-test",
                        "observed_at": observed_at,
                        "resource_id": "private-resource-id",
                    },
                    "owner": "alice@example.com",
                    "sla_due_at": "2026-08-01T12:00:00Z",
                    "description": "must-not-leave-tier-b",
                }
            ],
        },
        headers=headers,
    )
    assert ingested.status_code == 201, ingested.text

    listed = client.get(
        "/v1/findings?q=metadata-package&window_days=0",
        headers=headers,
    )
    assert listed.status_code == 200, listed.text
    listed_row = listed.json()["findings"][0]
    expected = {
        "first_seen": observed_at,
        "last_observed": observed_at,
        "occurrence_count": 1,
        "lifecycle_status": "open",
        "source": "SBOM",
        "cvss_version": "3.1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.42,
        "is_kev": True,
        "remediation_versions": ["2.0.0", "2.0.1"],
        "owner": "a***@e***.com",
        "sla_due_at": "2026-08-01T12:00:00Z",
        "provenance": {
            "source": "fixture",
            "collector": "unit-test",
            "observed_at": observed_at,
        },
    }
    for key, value in expected.items():
        assert listed_row[key] == value
    assert "description" not in listed_row

    created = client.post(
        "/v1/reports",
        json={"q": "metadata-package", "window_days": 0},
        headers=headers,
    )
    assert created.status_code == 202, created.text
    job = client.get(f"/v1/reports/{created.json()['job_id']}", headers=headers).json()
    downloaded = client.get(
        job["download_url"],
        headers={**headers, "X-Agent-Bom-Download-Token": job["download_token"]},
    )
    exported = [json.loads(line) for line in gzip.decompress(downloaded.content).decode().splitlines()]
    assert len(exported) == 1
    for key, value in expected.items():
        assert exported[0][key] == value
    assert "description" not in exported[0]


def test_server_search_uses_the_same_list_and_report_predicate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    tenant = "default"
    _seed_scan(tenant)
    monkeypatch.setenv("AGENT_BOM_REPORT_ARTIFACT_DIR", str(tmp_path))
    monkeypatch.setattr("agent_bom.api.routes.reports.submit_report_job", _run_report_job_sync)
    client = TestClient(app)
    headers = _headers(tenant)

    listed = client.get(
        "/v1/findings?q=CVE-2026-1002&include_facets=true&window_days=0",
        headers=headers,
    )
    assert listed.status_code == 200, listed.text
    listed_body = listed.json()
    assert {row["id"] for row in listed_body["findings"]} == {"container-high"}
    assert listed_body["total"] == 1
    assert listed_body["filters"]["q"] == "CVE-2026-1002"

    created = client.post(
        "/v1/reports",
        json={"q": "CVE-2026-1002", "window_days": 0},
        headers=headers,
    )
    assert created.status_code == 202, created.text
    job = client.get(f"/v1/reports/{created.json()['job_id']}", headers=headers).json()
    downloaded = client.get(
        job["download_url"],
        headers={**headers, "X-Agent-Bom-Download-Token": job["download_token"]},
    )
    exported = [json.loads(line) for line in gzip.decompress(downloaded.content).decode().splitlines()]
    assert {row["id"] for row in exported} == {"container-high"}


def test_findings_remain_tenant_scoped_when_facets_are_requested() -> None:
    tenant_a = f"facets-a-{uuid4().hex}"
    tenant_b = f"facets-b-{uuid4().hex}"
    _seed_scan(tenant_a)
    from agent_bom.api.routes.scan import _finding_facets

    own_facets, own_total = _finding_facets(tenant_a, severity=None, scan_id=None, since=None, scope={}, status="open")
    other_facets, other_total = _finding_facets(tenant_b, severity=None, scan_id=None, since=None, scope={}, status="open")

    assert own_total == 6
    assert sum(own_facets["finding_class"].values()) == 6
    assert other_total == 0
    assert sum(other_facets["finding_class"].values()) == 0


def test_freshness_never_invents_a_timestamp() -> None:
    from agent_bom.api.routes.scan import _freshness_bucket

    now = datetime(2026, 7, 26, tzinfo=timezone.utc)
    assert _freshness_bucket({}, now=now) == "unavailable"
    assert _freshness_bucket({"last_observed": "not-a-timestamp"}, now=now) == "unavailable"
    assert _freshness_bucket({"last_observed": "2026-07-25T12:00:00Z"}, now=now) == "last_24_hours"


def test_report_rejects_unknown_finding_class() -> None:
    response = TestClient(app).post(
        "/v1/reports",
        json={"finding_class": "not-a-class"},
        headers=_headers("default"),
    )

    assert response.status_code == 422


def test_sast_is_a_vulnerability_and_unknown_runtime_signal_is_unclassified() -> None:
    from agent_bom.finding_scope import finding_class_for_row

    assert finding_class_for_row({"finding_type": "SAST", "source": "SAST"}) == "vulnerability"
    assert finding_class_for_row({"finding_type": "FUTURE_RUNTIME_SIGNAL", "source": "FUTURE_RUNTIME"}) == "unclassified"


def test_list_and_report_share_severity_validation_and_alias_semantics(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    tenant = "default"
    _seed_scan(tenant)
    monkeypatch.setenv("AGENT_BOM_REPORT_ARTIFACT_DIR", str(tmp_path))
    monkeypatch.setattr("agent_bom.api.routes.reports.submit_report_job", _run_report_job_sync)
    client = TestClient(app)
    headers = _headers(tenant)

    rejected_list = client.get("/v1/findings?severity=urgent", headers=headers)
    rejected_report = client.post("/v1/reports", json={"severity": "urgent"}, headers=headers)
    assert rejected_list.status_code == 422
    assert rejected_report.status_code == 422

    listed = client.get("/v1/findings?severity=informational&window_days=0", headers=headers)
    assert listed.status_code == 200, listed.text
    assert {row["id"] for row in listed.json()["findings"]} == {"unknown-runtime"}

    created = client.post(
        "/v1/reports",
        json={"severity": "informational", "window_days": 0},
        headers=headers,
    )
    assert created.status_code == 202, created.text
    assert created.json()["severity"] == "info"
    job = client.get(f"/v1/reports/{created.json()['job_id']}", headers=headers).json()
    downloaded = client.get(
        job["download_url"],
        headers={**headers, "X-Agent-Bom-Download-Token": job["download_token"]},
    )
    exported = [json.loads(line) for line in gzip.decompress(downloaded.content).decode().splitlines()]
    assert {row["id"] for row in exported} == {"unknown-runtime"}
