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


def _finding(asset_identifier: str, *, severity: str = "high") -> dict[str, object]:
    return Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(
            name="requests",
            asset_type="package",
            identifier=asset_identifier,
        ),
        severity=severity,
        cve_id="CVE-2026-1000",
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
