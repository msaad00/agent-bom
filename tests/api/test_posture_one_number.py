"""Overview, posture, and the nav/tile counts report ONE posture number.

The tiles, nav badges and the findings page count open issue groups (#5383).
The exec grade, its summary sentence and ``/v1/posture`` must be computed from
those same counts by the same function, so a reader never sees "428 critical"
in the sentence beside a "325" tile, or an F 15.2 on one page and F 37.0 on
the next.
"""

from __future__ import annotations

from datetime import datetime, timezone

from starlette.testclient import TestClient

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_store
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

TENANT = "posture-one-number"


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())


def _finding(image: str, *, severity: str, cve_id: str) -> dict[str, object]:
    return Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="requests", asset_type="package", identifier=f"pkg:pypi/requests@2.0.0?image={image}"),
        severity=severity,
        cve_id=cve_id,
    ).to_dict()


def _seed() -> None:
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store
    from agent_bom.api.routes import compliance, overview

    set_job_store(InMemoryJobStore())
    get_compliance_hub_store().clear(TENANT)
    compliance._POSTURE_COUNTS_CACHE.clear()
    overview._reset_overview_cache()
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    job = ScanJob(job_id="posture-one-number-scan", tenant_id=TENANT, created_at=stamp, request=ScanRequest())
    job.status = JobStatus.DONE
    job.completed_at = stamp
    job.result = {
        "summary": {"total_packages": 1, "total_findings": 5},
        # Three asset occurrences of one critical advisory, two of one high.
        "findings": [
            _finding("api", severity="critical", cve_id="CVE-2026-1000"),
            _finding("worker", severity="critical", cve_id="CVE-2026-1000"),
            _finding("batch", severity="critical", cve_id="CVE-2026-1000"),
            _finding("api", severity="high", cve_id="CVE-2026-3000"),
            _finding("worker", severity="high", cve_id="CVE-2026-3000"),
        ],
        # A lenient scan-time scorecard: it floors the grade, never lifts it.
        "posture_scorecard": {
            "grade": "A",
            "score": 95.0,
            "summary": "Scan-time scorecard",
            "dimensions": {
                "vulnerability_posture": {"name": "Vulnerability Posture", "score": 90.0, "weight": 0.3, "weighted_score": 27.0}
            },
        },
    }
    _get_store().put(job)


def _surfaces() -> tuple[dict, dict, dict]:
    _seed()
    client = TestClient(app)
    headers = proxy_headers(role="analyst", tenant=TENANT)
    overview = client.get("/v1/overview", headers=headers)
    posture = client.get("/v1/posture", headers=headers)
    counts = client.get("/v1/posture/counts", headers=headers)
    assert overview.status_code == posture.status_code == counts.status_code == 200
    return overview.json(), posture.json(), counts.json()


def test_overview_and_posture_report_the_same_grade_and_score() -> None:
    overview, posture, _counts = _surfaces()

    for key in ("grade", "score", "summary", "display"):
        assert posture[key] == overview["posture"][key], key
    # The scan-time scorecard is still available, explicitly labelled.
    assert posture["scan_scorecard"]["score"] == 95.0
    assert posture["dimensions"]["vulnerability_posture"]["score"] == 90.0


def test_grade_summary_and_tiles_use_the_issue_counts() -> None:
    overview, _posture, counts = _surfaces()

    issues = counts["issues"]
    assert issues["basis"] == "issue_groups"
    assert (issues["critical"], issues["high"], issues["total"]) == (1, 1, 2)
    assert overview["headline"]["critical"] == issues["critical"]
    assert overview["headline"]["high"] == issues["high"]
    assert overview["issue_counts"]["critical"] == issues["critical"]
    breakdown = {row["driver"]: row["count"] for row in overview["posture"]["breakdown"]}
    assert breakdown["critical"] == 1
    assert breakdown["high"] == 1
    assert overview["posture"]["severity_basis"] == "issue_groups"
    summary = overview["posture"]["summary"]
    assert "1 critical" in summary
    assert "3 critical" not in summary
    # Occurrence counts remain available and still reconcile with /v1/findings.
    assert overview["finding_counts"]["critical"] == counts["critical"] == 3

