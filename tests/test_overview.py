"""Tests for the cross-domain /v1/overview aggregation endpoint."""

from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.api.server import JobStatus, _get_store, app, configure_api
from agent_bom.api.store import InMemoryJobStore
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_AUTH_HEADERS = proxy_headers(tenant="default")


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def _clear_jobs() -> None:
    from agent_bom.api.server import set_job_store

    set_job_store(InMemoryJobStore())


def _add_done_job(
    blast_radius: list[dict],
    job_id: str = "test-job",
    *,
    tenant_id: str = "default",
    result_extra: dict | None = None,
) -> None:
    from agent_bom.api.server import ScanJob, ScanRequest

    job = ScanJob(
        job_id=job_id,
        tenant_id=tenant_id,
        created_at="2026-02-22T10:00:00Z",
        request=ScanRequest(),
    )
    job.status = JobStatus.DONE
    job.completed_at = "2026-02-22T10:05:00Z"
    job.result = {
        "agents": [],
        "blast_radius": blast_radius,
        "scan_sources": ["agent_discovery"],
    }
    if result_extra:
        job.result.update(result_extra)
    _get_store().put(job)


_EXPECTED_DOMAINS = {"cloud", "vuln", "code", "runtime", "cost", "identity", "ops"}


def test_overview_empty_shape() -> None:
    """With no scans the endpoint returns the full domain skeleton at zero."""
    _clear_jobs()
    client = TestClient(app)
    resp = client.get("/v1/overview", headers=_AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    assert data["schema_version"] == "overview.v1"
    assert data["tenant_id"] == "default"
    assert set(data["domains"].keys()) == _EXPECTED_DOMAINS
    assert data["headline"]["critical"] == 0
    assert data["headline"]["scans"] == 0
    assert data["top_risks"] == []
    assert data["posture"]["grade"] == "N/A"

    for domain in data["domains"].values():
        assert {"label", "href", "metric", "metric_label", "status", "detail"} <= set(domain)
        assert domain["href"].startswith("/")
        if "graph_href" in domain:
            assert str(domain["graph_href"]).startswith("/graph")


def test_overview_aggregates_findings() -> None:
    """A completed scan with findings populates severity, top risks, and ops."""
    _clear_jobs()
    _add_done_job(
        [
            {
                "vulnerability_id": "CVE-2025-0001",
                "package": "demo",
                "severity": "critical",
                "risk_score": 9.5,
                "cisa_kev": True,
                "exposed_credentials": ["DEMO_TOKEN"],
            },
            {
                "vulnerability_id": "CVE-2025-0002",
                "package": "demo2",
                "severity": "high",
                "blast_score": 70,
            },
        ]
    )
    client = TestClient(app)
    resp = client.get("/v1/overview", headers=_AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    assert data["headline"]["critical"] == 1
    assert data["headline"]["high"] == 1
    assert data["headline"]["critical_high"] == 2
    assert data["headline"]["kev"] == 1
    assert data["headline"]["credential_exposed"] == 1
    assert data["headline"]["scans"] == 1

    cloud = data["domains"]["cloud"]
    assert cloud["metric_label"] == "accounts connected"
    assert cloud["status"] in {"ok", "idle"}

    vuln = data["domains"]["vuln"]
    assert vuln["metric"] == 2  # two unique CVEs
    assert vuln["status"] == "critical"
    assert vuln["detail"]["kev"] == 1

    ops = data["domains"]["ops"]
    assert ops["metric"] == 1  # one completed scan
    assert ops["detail"]["done"] == 1

    assert data["top_risks"][0]["vulnerability_id"] == "CVE-2025-0001"
    assert data["top_risks"][0]["risk_score"] == 9.5
    assert len(data["top_risks"]) == 2


def test_overview_reads_compacted_scan_summary() -> None:
    """Hot-cache compaction must not zero out posture/CVE tiles on /v1/overview."""
    from agent_bom.api.server import ScanJob, ScanRequest
    from agent_bom.api.stores import _compact_terminal_job

    _clear_jobs()
    job = ScanJob(
        job_id="compact-job",
        tenant_id="default",
        created_at="2026-02-22T10:00:00Z",
        request=ScanRequest(),
    )
    job.status = JobStatus.DONE
    job.completed_at = "2026-02-22T10:05:00Z"
    job.result = {
        "summary": {
            "total_vulnerabilities": 87,
            "critical_unified_findings": 3,
            "high_unified_findings": 12,
            "unique_packages": 9,
        },
        "posture_scorecard": {
            "grade": "F",
            "score": 42.0,
            "summary": "Poor posture",
            "dimensions": {},
        },
        "scan_sources": ["agent_discovery"],
        "blast_radius": [
            {
                "vulnerability_id": "CVE-IGNORED",
                "severity": "critical",
                "risk_score": 10,
            }
        ],
    }
    _get_store().put(_compact_terminal_job(job))

    client = TestClient(app)
    resp = client.get("/v1/overview", headers=_AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    assert data["posture"]["grade"] == "F"
    assert data["posture"]["score"] == 42.0
    assert data["headline"]["critical"] == 3
    assert data["headline"]["high"] == 12
    assert data["domains"]["vuln"]["metric"] == 87


def _ingest_hub_findings(findings: list[dict], *, tenant_id: str = "default") -> None:
    """Append normalized findings straight into the compliance-hub ledger.

    Mirrors what POST /v1/findings/bulk persists (hub_store.add) so the overview
    can be exercised against ingested evidence without a full HTTP round-trip.
    """
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    get_compliance_hub_store().add(tenant_id, findings)


def test_overview_counts_bulk_ingested_findings() -> None:
    """Findings ingested via the hub (POST /v1/findings/bulk) move headline + grade."""
    _clear_jobs()
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    get_compliance_hub_store().clear("default")

    client = TestClient(app)
    # Baseline: no scans, no ingest -> N/A posture, zero headline.
    baseline = client.get("/v1/overview", headers=_AUTH_HEADERS).json()
    assert baseline["posture"]["grade"] == "N/A"
    assert baseline["headline"]["critical"] == 0
    assert baseline["headline"]["hub_findings"] == 0

    _ingest_hub_findings(
        [
            {"finding_id": "F-1", "severity": "critical", "title": "boom"},
            {"finding_id": "F-2", "severity": "critical", "title": "boom2"},
            {"finding_id": "F-3", "severity": "high", "title": "warn"},
        ]
    )

    data = client.get("/v1/overview", headers=_AUTH_HEADERS).json()
    assert data["headline"]["critical"] == 2
    assert data["headline"]["high"] == 1
    assert data["headline"]["critical_high"] == 3
    assert data["headline"]["hub_findings"] == 3
    # Two criticals + one high drive the grade off N/A and down to a failing band.
    assert data["posture"]["grade"] not in {"N/A", "A"}
    assert data["posture"]["score"] < 100.0

    get_compliance_hub_store().clear("default")


def test_overview_hub_findings_do_not_upgrade_failing_scan() -> None:
    """Ingested evidence can only move a scan grade down, never launder it up."""
    _clear_jobs()
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    get_compliance_hub_store().clear("default")
    _add_done_job(
        [{"vulnerability_id": "CVE-2025-9999", "severity": "critical", "risk_score": 10}],
        result_extra={
            "posture_scorecard": {"grade": "F", "score": 30.0, "summary": "Failing"},
        },
    )
    _ingest_hub_findings([{"finding_id": "H-1", "severity": "low", "title": "minor"}])

    data = client_get_overview()
    # Low-severity ingest must not raise the F grade / 30.0 score.
    assert data["posture"]["grade"] == "F"
    assert data["posture"]["score"] <= 30.0
    assert data["headline"]["hub_findings"] == 1

    get_compliance_hub_store().clear("default")


def client_get_overview() -> dict:
    return TestClient(app).get("/v1/overview", headers=_AUTH_HEADERS).json()


def test_overview_requires_auth(monkeypatch) -> None:
    """Endpoint is read-only but still behind the standard viewer gate."""
    _clear_jobs()
    # The shared harness enables the anonymous opt-in by default; this contract
    # asserts fail-closed auth, so disable it and rebuild the middleware.
    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)
    configure_api(api_key=None)
    client = TestClient(app)
    resp = client.get("/v1/overview")
    assert resp.status_code in (401, 403)


def test_overview_is_read_only() -> None:
    """No mutating verb reaches a handler.

    Only GET is registered, and the viewer role used by the overview page is
    denied mutating methods by the RBAC middleware (403) before any 405 from
    the router — either status confirms there is no write path here.
    """
    _clear_jobs()
    client = TestClient(app)
    assert client.post("/v1/overview", headers=_AUTH_HEADERS).status_code in (403, 405)
    assert client.delete("/v1/overview", headers=_AUTH_HEADERS).status_code in (403, 405)
