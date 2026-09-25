"""Server-backed issue grouping preserves asset-scoped finding occurrences."""

from __future__ import annotations

from types import SimpleNamespace

from starlette.testclient import TestClient

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_store
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())


def _finding(asset_identifier: str, *, severity: str = "high", cve_id: str = "CVE-2026-1000") -> dict[str, object]:
    return Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(
            name="requests",
            asset_type="package",
            identifier=asset_identifier,
        ),
        severity=severity,
        cve_id=cve_id,
    ).to_dict()


def test_findings_group_view_preserves_and_expands_asset_occurrences() -> None:
    tenant = "finding-groups"
    set_job_store(InMemoryJobStore())
    job = ScanJob(job_id="scan-groups", tenant_id=tenant, created_at="2026-08-20T12:00:00Z", request=ScanRequest())
    job.status = JobStatus.DONE
    job.completed_at = "2026-08-20T12:01:00Z"
    job.result = {
        "findings": [
            _finding("pkg:pypi/requests@2.0.0?image=api"),
            _finding("pkg:pypi/requests@2.0.0?image=worker"),
        ]
    }
    _get_store().put(job)
    client = TestClient(app)
    headers = proxy_headers(role="analyst", tenant=tenant)

    raw = client.get("/v1/findings?limit=10&window_days=0", headers=headers).json()
    grouped = client.get(
        "/v1/findings?group_occurrences=true&limit=10&window_days=0",
        headers=headers,
    ).json()

    assert raw["count"] == 2
    assert grouped["count"] == 1
    assert grouped["total"] == 1
    assert grouped["filters"]["group_occurrences"] is True
    row = grouped["findings"][0]
    assert row["occurrence_count"] == 2
    assert row["occurrences_truncated"] is False
    assert {item["finding_id"] for item in row["occurrences"]} == {
        raw["findings"][0]["finding_id"],
        raw["findings"][1]["finding_id"],
    }
    # Public responses intentionally omit raw asset identifiers, but the two
    # opaque asset identities remain distinct and joinable.
    assert len({item["asset"]["stable_id"] for item in row["occurrences"]}) == 2


def test_findings_group_view_paginates_groups_without_collapsing_advisories() -> None:
    tenant = "finding-group-pages"
    set_job_store(InMemoryJobStore())
    job = ScanJob(job_id="scan-group-pages", tenant_id=tenant, created_at="2026-08-20T12:00:00Z", request=ScanRequest())
    job.status = JobStatus.DONE
    job.completed_at = "2026-08-20T12:01:00Z"
    rows = []
    for cve in ("CVE-2026-1000", "CVE-2026-2000"):
        finding = Finding(
            finding_type=FindingType.CVE,
            source=FindingSource.MCP_SCAN,
            asset=Asset(name="requests", asset_type="package", identifier=f"pkg:pypi/requests@2.0.0?cve={cve}"),
            severity="high",
            cve_id=cve,
        )
        rows.append(finding.to_dict())
    job.result = {"findings": rows}
    _get_store().put(job)
    client = TestClient(app)
    headers = proxy_headers(role="analyst", tenant=tenant)

    first = client.get(
        "/v1/findings?group_occurrences=true&limit=1&window_days=0",
        headers=headers,
    ).json()
    second = client.get(
        f"/v1/findings?group_occurrences=true&limit=1&window_days=0&cursor={first['next_cursor']}",
        headers=headers,
    ).json()

    assert first["total"] == 2
    assert first["has_more"] is True
    assert first["next_cursor"]
    assert second["has_more"] is False
    assert {first["findings"][0]["cve_id"], second["findings"][0]["cve_id"]} == {
        "CVE-2026-1000",
        "CVE-2026-2000",
    }


def test_findings_group_view_facets_count_issue_groups_not_occurrences() -> None:
    tenant = "finding-group-facets"
    set_job_store(InMemoryJobStore())
    job = ScanJob(job_id="scan-group-facets", tenant_id=tenant, created_at="2026-08-20T12:00:00Z", request=ScanRequest())
    job.status = JobStatus.DONE
    job.completed_at = "2026-08-20T12:01:00Z"
    job.result = {
        "findings": [
            _finding("pkg:pypi/requests@2.0.0?image=api", severity="high"),
            _finding("pkg:pypi/requests@2.0.0?image=worker", severity="high"),
            {
                **_finding("pkg:pypi/requests@2.0.0?image=batch", severity="critical"),
                "cve_id": "CVE-2026-2000",
            },
        ]
    }
    _get_store().put(job)
    client = TestClient(app)
    headers = proxy_headers(role="analyst", tenant=tenant)

    grouped = client.get(
        "/v1/findings?group_occurrences=true&include_facets=true&limit=10&window_days=0",
        headers=headers,
    ).json()
    critical = client.get(
        "/v1/findings?group_occurrences=true&include_facets=true&severity=critical&limit=10&window_days=0",
        headers=headers,
    ).json()

    assert grouped["total"] == 2
    assert grouped["facets"]["severity"] == {
        "critical": 1,
        "high": 1,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
    }
    # Severity facets are self-excluding so changing the active band does not
    # make the other issue counts disappear.
    assert critical["total"] == 1
    assert critical["facets"]["severity"] == grouped["facets"]["severity"]


def test_grouping_projects_graph_reachability_once_after_the_occurrence_walk(monkeypatch) -> None:
    """Internal grouping pages must not re-join the same persisted graph.

    The landing query walks occurrences in 1,000-row chunks. Reachability is a
    property of the returned issue rows, so projecting each internal chunk made
    graph latency multiply with occurrence count and turned Findings into the
    slowest primary screen.
    """
    tenant = "finding-group-reachability-once"
    set_job_store(InMemoryJobStore())
    job = ScanJob(
        job_id="scan-group-reachability-once",
        tenant_id=tenant,
        created_at="2026-08-20T12:00:00Z",
        request=ScanRequest(),
    )
    job.status = JobStatus.DONE
    job.completed_at = "2026-08-20T12:01:00Z"
    job.result = {"findings": [_finding(f"pkg:pypi/requests@2.0.0?image=worker-{index}") for index in range(1_005)]}
    _get_store().put(job)
    calls: list[int] = []
    sanitizations: list[str] = []

    def project_once(rows, **_kwargs):
        calls.append(len(rows))
        return SimpleNamespace(rows=rows, truncated=False)

    monkeypatch.setattr(
        "agent_bom.api.routes.scan.project_persisted_graph_reachability",
        project_once,
    )
    from agent_bom import finding_scope

    real_sanitizer = finding_scope.safe_finding_response_payload

    def count_sanitization(row):
        sanitizations.append(str(row.get("id") or row.get("finding_id") or ""))
        return real_sanitizer(row)

    monkeypatch.setattr(finding_scope, "safe_finding_response_payload", count_sanitization)
    response = TestClient(app).get(
        "/v1/findings?group_occurrences=true&include_facets=true&limit=25&window_days=0",
        headers=proxy_headers(role="analyst", tenant=tenant),
    )

    assert response.status_code == 200, response.text
    assert response.json()["count"] == 1
    assert calls == [1]
    # One representative plus the bounded occurrence sample crosses the public
    # boundary. The other 979 rows are grouped/faceted without public projection.
    assert len(sanitizations) == 26


def _put_group_fixture(tenant: str, job_id: str) -> None:
    from datetime import datetime, timezone

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    job = ScanJob(job_id=job_id, tenant_id=tenant, created_at=stamp, request=ScanRequest())
    job.status = JobStatus.DONE
    job.completed_at = stamp
    job.result = {
        "findings": [
            _finding("pkg:pypi/requests@2.0.0?image=api", severity="critical"),
            _finding("pkg:pypi/requests@2.0.0?image=worker", severity="critical"),
            _finding("pkg:pypi/requests@2.0.0?image=batch", severity="critical"),
            _finding("pkg:pypi/requests@2.0.0?image=api", severity="high", cve_id="CVE-2026-3000"),
            _finding("pkg:pypi/requests@2.0.0?image=worker", severity="high", cve_id="CVE-2026-3000"),
        ]
    }
    _get_store().put(job)


def test_nav_issue_counts_equal_findings_page_default_query() -> None:
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    tenant = "finding-group-nav-contract"
    set_job_store(InMemoryJobStore())
    get_compliance_hub_store().clear(tenant)
    _put_group_fixture(tenant, "scan-nav-contract")
    _put_group_fixture("finding-group-nav-other", "scan-nav-other")
    client = TestClient(app)
    headers = proxy_headers(role="analyst", tenant=tenant)

    page = client.get(
        "/v1/findings?group_occurrences=true&include_facets=true&approximate_total=true&limit=50&window_days=90",
        headers=headers,
    ).json()
    counts = client.get("/v1/posture/counts", headers=headers).json()

    assert page["total"] == 2
    assert page["facets"]["severity"]["critical"] == 1
    assert page["facets"]["severity"]["high"] == 1
    for surface in (counts["issues"],):
        assert surface["basis"] == "issue_groups"
        assert surface["approximate"] is False
        assert surface["total"] == page["total"]
        assert surface["critical"] == page["facets"]["severity"]["critical"]
        assert surface["high"] == page["facets"]["severity"]["high"]
        assert surface["medium"] == surface["low"] == surface["unrated"] == 0
    # Occurrence totals remain available and reconcile with the raw drill.
    raw = client.get("/v1/findings?limit=50&window_days=90", headers=headers).json()
    assert counts["total"] == raw["total"] == 5
    assert counts["critical"] == 3


def test_nav_issue_counts_refresh_immediately_when_a_new_scan_lands() -> None:
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    tenant = "finding-group-nav-refresh"
    set_job_store(InMemoryJobStore())
    get_compliance_hub_store().clear(tenant)
    _put_group_fixture(tenant, "scan-nav-refresh-1")
    client = TestClient(app)
    headers = proxy_headers(role="analyst", tenant=tenant)
    assert client.get("/v1/posture/counts", headers=headers).json()["issues"]["total"] == 2

    from datetime import datetime, timezone

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    job = ScanJob(job_id="scan-nav-refresh-2", tenant_id=tenant, created_at=stamp, request=ScanRequest())
    job.status = JobStatus.DONE
    job.completed_at = stamp
    job.result = {"findings": [_finding("pkg:pypi/requests@2.0.0?image=api", severity="medium", cve_id="CVE-2026-4000")]}
    _get_store().put(job)

    page = client.get("/v1/findings?group_occurrences=true&include_facets=true&limit=50&window_days=90", headers=headers).json()
    issues = client.get("/v1/posture/counts", headers=headers).json()["issues"]
    assert issues["total"] == page["total"]
    assert issues["medium"] == page["facets"]["severity"]["medium"]


def test_nav_issue_counts_reuse_one_grouped_walk_while_evidence_is_unchanged(monkeypatch) -> None:
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store
    from agent_bom.api.routes import scan as scan_routes

    tenant = "finding-group-nav-cache"
    set_job_store(InMemoryJobStore())
    get_compliance_hub_store().clear(tenant)
    _put_group_fixture(tenant, "scan-nav-cache")
    walks: list[str] = []
    real = scan_routes._list_finding_groups_impl

    def counting(*args, **kwargs):
        walks.append("walk")
        return real(*args, **kwargs)

    monkeypatch.setattr(scan_routes, "_list_finding_groups_impl", counting)
    client = TestClient(app)
    first = client.get("/v1/posture/counts", headers=proxy_headers(role="analyst", tenant=tenant)).json()
    second = client.get("/v1/posture/counts", headers=proxy_headers(role="analyst", tenant=tenant)).json()
    other = client.get("/v1/posture/counts", headers=proxy_headers(role="analyst", tenant="finding-group-nav-empty")).json()

    assert {k: v for k, v in first["issues"].items() if k != "window"} == {k: v for k, v in second["issues"].items() if k != "window"}
    assert other["issues"]["total"] == 0
    assert len(walks) == 2
