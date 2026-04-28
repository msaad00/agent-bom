"""Tests for the /v1/compliance posture endpoint."""

from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.api.server import JobStatus, _get_store, app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_AUTH_HEADERS = proxy_headers(tenant="default")


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def _clear_jobs():
    """Reset the job store to a fresh in-memory store."""
    from agent_bom.api.server import set_job_store

    set_job_store(InMemoryJobStore())


def _add_done_job(
    blast_radius: list[dict],
    job_id: str = "test-job",
    *,
    tenant_id: str = "default",
    result_extra: dict | None = None,
):
    """Insert a synthetic completed scan job."""
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
        "threat_framework_summary": {},
    }
    if result_extra:
        job.result.update(result_extra)
    _get_store().put(job)


# ─── Tests ───────────────────────────────────────────────────────────────────


def test_compliance_no_scans():
    """With no completed scans, all controls pass and score is 100%."""
    _clear_jobs()
    client = TestClient(app)
    resp = client.get("/v1/compliance", headers=_AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["overall_score"] == 100.0
    assert data["overall_status"] == "pass"
    assert data["scan_count"] == 0
    assert data["latest_scan"] is None
    assert data["aisvs_benchmark"]["framework"] == "aisvs"
    assert data["aisvs_benchmark"]["benchmark"]["checks"] == []
    assert data["summary"]["aisvs_pass"] == 0
    assert data["summary"]["aisvs_fail"] == 0
    # All OWASP controls should be "pass"
    for c in data["owasp_llm_top10"]:
        assert c["status"] == "pass"
        assert c["findings"] == 0
    for metadata in TAG_MAPPED_FRAMEWORKS:
        assert len(data[metadata.output_key]) == metadata.control_count
        assert data["summary"][f"{metadata.summary_prefix}_pass"] == metadata.control_count
        assert data["summary"][f"{metadata.summary_prefix}_warn"] == 0
        assert data["summary"][f"{metadata.summary_prefix}_fail"] == 0
    _clear_jobs()


def test_compliance_includes_latest_aisvs_benchmark():
    """Aggregate compliance includes the latest tenant-scoped AISVS benchmark payload."""
    _clear_jobs()
    _add_done_job(
        [],
        job_id="older-scan",
        result_extra={
            "scan_id": "older-scan",
            "aisvs_benchmark": {
                "benchmark": "OWASP AI Security Verification Standard",
                "benchmark_version": "1.0",
                "passed": 1,
                "failed": 0,
                "total": 1,
                "pass_rate": 100.0,
                "checks": [{"check_id": "AI-4.1", "status": "pass", "severity": "high"}],
                "metadata": {},
            },
        },
    )
    _add_done_job(
        [],
        job_id="newer-scan",
        result_extra={
            "scan_id": "newer-scan",
            "aisvs_benchmark": {
                "benchmark": "OWASP AI Security Verification Standard",
                "benchmark_version": "1.0",
                "passed": 1,
                "failed": 1,
                "total": 3,
                "pass_rate": 50.0,
                "checks": [
                    {"check_id": "AI-4.1", "status": "pass", "severity": "high"},
                    {"check_id": "AI-6.1", "status": "fail", "severity": "critical"},
                    {"check_id": "AI-8.1", "status": "not_applicable", "severity": "medium"},
                ],
                "metadata": {"runner": "test"},
            },
        },
    )

    client = TestClient(app)
    data = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    aisvs = data["aisvs_benchmark"]
    assert aisvs["framework"] == "aisvs"
    assert aisvs["framework_key"] == "aisvs_benchmark"
    assert aisvs["representation"] == "benchmark"
    assert aisvs["scan_id"] == "newer-scan"
    assert aisvs["summary"] == {
        "pass": 1,
        "fail": 1,
        "error": 0,
        "not_applicable": 1,
        "total": 3,
        "score": 50.0,
    }
    assert data["summary"]["aisvs_pass"] == 1
    assert data["summary"]["aisvs_fail"] == 1
    assert data["summary"]["aisvs_not_applicable"] == 1
    assert data["overall_score"] == 100.0

    _clear_jobs()


def test_aisvs_compliance_endpoint_is_tenant_scoped():
    """The dedicated AISVS endpoint returns only the authenticated tenant's benchmark."""
    _clear_jobs()
    _add_done_job(
        [],
        job_id="tenant-alpha-scan",
        tenant_id="tenant-alpha",
        result_extra={
            "scan_id": "tenant-alpha-scan",
            "aisvs_benchmark": {
                "benchmark": "OWASP AI Security Verification Standard",
                "benchmark_version": "1.0",
                "passed": 0,
                "failed": 1,
                "total": 1,
                "pass_rate": 0.0,
                "checks": [{"check_id": "AI-6.1", "status": "fail", "severity": "critical"}],
                "metadata": {},
            },
        },
    )
    _add_done_job(
        [],
        job_id="default-scan",
        result_extra={
            "scan_id": "default-scan",
            "aisvs_benchmark": {
                "benchmark": "OWASP AI Security Verification Standard",
                "benchmark_version": "1.0",
                "passed": 1,
                "failed": 0,
                "total": 1,
                "pass_rate": 100.0,
                "checks": [{"check_id": "AI-4.1", "status": "pass", "severity": "high"}],
                "metadata": {},
            },
        },
    )

    client = TestClient(app)
    data = client.get("/v1/compliance/aisvs", headers=proxy_headers(tenant="tenant-alpha")).json()

    assert data["scan_id"] == "tenant-alpha-scan"
    assert data["summary"]["fail"] == 1
    assert data["benchmark"]["checks"][0]["check_id"] == "AI-6.1"

    _clear_jobs()


def test_compliance_with_findings():
    """Blast radius entries with OWASP tags produce correct per-control status."""
    _clear_jobs()
    _add_done_job(
        [
            {
                "vulnerability_id": "CVE-2025-0001",
                "severity": "high",
                "package": "express",
                "affected_agents": ["claude-desktop"],
                "owasp_tags": ["LLM05", "LLM06"],
                "atlas_tags": ["AML.T0010"],
                "nist_ai_rmf_tags": ["MAP-3.5"],
            },
        ]
    )
    client = TestClient(app)
    resp = client.get("/v1/compliance", headers=_AUTH_HEADERS)
    data = resp.json()

    assert data["scan_count"] == 1
    assert data["overall_status"] == "fail"  # HIGH severity → fail

    # LLM05 should be fail (has HIGH severity finding)
    lmm05 = next(c for c in data["owasp_llm_top10"] if c["code"] == "LLM05")
    assert lmm05["status"] == "fail"
    assert lmm05["findings"] == 1
    assert "express" in lmm05["affected_packages"]
    assert "claude-desktop" in lmm05["affected_agents"]

    # LLM01 should be pass (no findings)
    lmm01 = next(c for c in data["owasp_llm_top10"] if c["code"] == "LLM01")
    assert lmm01["status"] == "pass"
    assert lmm01["findings"] == 0

    _clear_jobs()


def test_compliance_severity_breakdown():
    """CRITICAL findings show in severity_breakdown and produce fail status."""
    _clear_jobs()
    _add_done_job(
        [
            {
                "vulnerability_id": "CVE-2025-9999",
                "severity": "critical",
                "package": "langchain",
                "affected_agents": ["cursor"],
                "owasp_tags": ["LLM05", "LLM04"],
                "atlas_tags": ["AML.T0010", "AML.T0020"],
                "nist_ai_rmf_tags": ["GOVERN-1.7", "MAP-3.5"],
            },
        ]
    )
    client = TestClient(app)
    data = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    lmm04 = next(c for c in data["owasp_llm_top10"] if c["code"] == "LLM04")
    assert lmm04["status"] == "fail"
    assert lmm04["severity_breakdown"]["critical"] == 1
    assert lmm04["severity_breakdown"]["high"] == 0

    _clear_jobs()


def test_compliance_warning_status():
    """MEDIUM-only findings produce warning (not fail) status."""
    _clear_jobs()
    _add_done_job(
        [
            {
                "vulnerability_id": "CVE-2025-5555",
                "severity": "medium",
                "package": "axios",
                "affected_agents": ["windsurf"],
                "owasp_tags": ["LLM05"],
                "atlas_tags": ["AML.T0010"],
                "nist_ai_rmf_tags": ["MAP-3.5"],
            },
        ]
    )
    client = TestClient(app)
    data = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    lmm05 = next(c for c in data["owasp_llm_top10"] if c["code"] == "LLM05")
    assert lmm05["status"] == "warning"
    assert lmm05["severity_breakdown"]["medium"] == 1

    _clear_jobs()


def test_compliance_owasp_catalog_complete():
    """All 10 OWASP LLM Top 10 controls are present."""
    _clear_jobs()
    client = TestClient(app)
    data = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()
    codes = {c["code"] for c in data["owasp_llm_top10"]}
    assert codes == {f"LLM{str(i).zfill(2)}" for i in range(1, 11)}
    _clear_jobs()


def test_compliance_atlas_catalog_complete():
    """MITRE ATLAS catalog is fully populated (74 entries as of March 2026)."""
    _clear_jobs()
    client = TestClient(app)
    data = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()
    assert len(data["mitre_atlas"]) >= 50
    _clear_jobs()


def test_compliance_nist_catalog_complete():
    """All 14 NIST AI RMF subcategories are present."""
    _clear_jobs()
    client = TestClient(app)
    data = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()
    assert len(data["nist_ai_rmf"]) == 14
    _clear_jobs()


def test_compliance_summary_counts():
    """Summary pass/warn/fail counts match control statuses."""
    _clear_jobs()
    _add_done_job(
        [
            {
                "vulnerability_id": "CVE-2025-1111",
                "severity": "high",
                "package": "express",
                "affected_agents": ["claude-desktop"],
                "owasp_tags": ["LLM05"],
                "atlas_tags": ["AML.T0010"],
                "nist_ai_rmf_tags": ["MAP-3.5", "GOVERN-1.7"],
            },
        ]
    )
    client = TestClient(app)
    data = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    s = data["summary"]
    # Verify OWASP: 1 fail (LLM05), 9 pass
    assert s["owasp_fail"] == 1
    assert s["owasp_pass"] == 9
    assert s["owasp_warn"] == 0
    assert s["owasp_pass"] + s["owasp_warn"] + s["owasp_fail"] == 10

    _clear_jobs()
