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
    """With no completed scans, the endpoint reports no_data — not a clean pass.

    An empty tenant has no evidence to evaluate, so reporting
    overall_status="pass"/score=100 would read as "fully compliant" when in
    fact nothing was measured. Mirror the Overview idle pattern instead.
    """
    _clear_jobs()
    client = TestClient(app)
    resp = client.get("/v1/compliance", headers=_AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["overall_score"] == 0.0
    assert data["overall_status"] == "no_data"
    assert data["scan_count"] == 0
    assert data["latest_scan"] is None
    assert data["aisvs_benchmark"]["framework"] == "aisvs"
    assert data["aisvs_benchmark"]["benchmark"]["checks"] == []
    assert data["summary"]["aisvs_pass"] == 0
    assert data["summary"]["aisvs_fail"] == 0
    # With no evidence, every control is not_assessed — not a trivial "pass".
    for c in data["owasp_llm_top10"]:
        assert c["status"] == "not_assessed"
        assert c["findings"] == 0
    for metadata in TAG_MAPPED_FRAMEWORKS:
        assert len(data[metadata.output_key]) == metadata.control_count
        assert data["summary"][f"{metadata.summary_prefix}_pass"] == 0
        assert data["summary"][f"{metadata.summary_prefix}_warn"] == 0
        assert data["summary"][f"{metadata.summary_prefix}_fail"] == 0
        assert data["summary"][f"{metadata.summary_prefix}_not_evaluated"] == metadata.control_count
    _clear_jobs()


def test_compliance_by_framework_no_scans_is_no_data():
    """The single-framework endpoint must not report score 100 / a clean pass on
    a zero-scan tenant — every control trivially "passes" with no evidence, so
    mirror the aggregate no_data guard (regression: this path previously returned
    ``score: 100.0``)."""
    _clear_jobs()
    client = TestClient(app)
    resp = client.get("/v1/compliance/owasp-llm", headers=_AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "no_data"
    assert data["score"] == 0.0
    assert data["summary"] == {"pass": 0, "warning": 0, "fail": 0}
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
    # This scan produced only AISVS-benchmark results, no tag-mapped-framework
    # findings, so the tag-mapped frameworks are not_evaluated — overall_score is
    # 0.0 / no_data (AISVS results are surfaced separately in aisvs_benchmark).
    assert data["overall_score"] == 0.0
    assert data["overall_status"] == "no_data"

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
    # No findings map to this control — it is not_evaluated (no evidence), never a
    # silent pass. Matches the narrative + CLI export.
    assert lmm01["status"] == "not_evaluated"
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
    # The other 9 controls have no mapped findings → not_evaluated, not a silent
    # pass (would otherwise inflate the score toward 100).
    assert s["owasp_pass"] == 0
    assert s["owasp_warn"] == 0
    assert s["owasp_not_evaluated"] == 9
    assert s["owasp_pass"] + s["owasp_warn"] + s["owasp_fail"] + s["owasp_not_evaluated"] == 10

    _clear_jobs()


def test_compliance_summary_no_scans_reports_not_evaluated():
    """With no completed scans /v1/compliance/summary must not report all-pass.

    The *_pass counts and per-framework pass counts equalled the control
    catalogue size even though nothing was evaluated — false full-compliance.
    Mirror /v1/compliance's no_data contract: report 0 pass / not_evaluated.
    """
    _clear_jobs()
    client = TestClient(app)
    data = client.get("/v1/compliance/summary", headers=_AUTH_HEADERS).json()

    assert data["scan_count"] == 0
    assert data["overall_status"] == "no_data"
    assert data["overall_score"] == 0.0

    for metadata in TAG_MAPPED_FRAMEWORKS:
        assert data["summary"][f"{metadata.summary_prefix}_pass"] == 0
        assert data["summary"][f"{metadata.summary_prefix}_not_evaluated"] == metadata.control_count

    for fw in data["frameworks"].values():
        assert fw["pass"] == 0
        assert fw["warning"] == 0
        assert fw["fail"] == 0
        assert fw["not_evaluated"] == fw["controls"]
    _clear_jobs()


def test_compliance_summary_with_scan_counts_evaluated_controls():
    """With a real finding the summary still reports honest pass/fail counts."""
    _clear_jobs()
    _add_done_job(
        [
            {
                "vulnerability_id": "CVE-2025-2222",
                "severity": "high",
                "package": "express",
                "affected_agents": ["claude-desktop"],
                "owasp_tags": ["LLM05"],
            },
        ]
    )
    client = TestClient(app)
    data = client.get("/v1/compliance/summary", headers=_AUTH_HEADERS).json()
    assert data["scan_count"] == 1
    assert data["summary"]["owasp_fail"] == 1
    # Never-triggered controls are not_evaluated, not pass — so the evaluated
    # split is surfaced even on a non-empty scan.
    assert data["summary"]["owasp_pass"] == 0
    assert data["summary"]["owasp_not_evaluated"] == 9
    _clear_jobs()


def _cis_benchmark_result(checks: list[dict], *, cloud_key: str = "cis_benchmark") -> dict:
    """Build a result_extra dict carrying a serialized CIS benchmark blob.

    ``cloud_key`` selects the provider slot used by the JSON output layer
    (``cis_benchmark`` for AWS, ``azure_cis_benchmark`` for Azure, etc.) —
    the exact keys /v1/cis/checks reads via build_cis_benchmark_check_rows.
    """
    return {"scan_id": "cis-scan", cloud_key: {"checks": checks}}


def test_compliance_surfaces_cis_foundations_benchmark_line():
    """A cloud account with CIS Foundations Benchmark PASS/FAIL/ERROR checks must
    surface a dedicated benchmark-backed CIS-Foundations line with an honest
    pass/(pass+fail+error) denominator — the scorecard previously ignored
    ``cis_benchmark_data`` entirely, so a failing CIS account read green."""
    _clear_jobs()
    _add_done_job(
        [],
        result_extra=_cis_benchmark_result(
            [
                {"check_id": "2.1.1", "title": "S3 SSE", "status": "PASS", "severity": "high"},
                {"check_id": "2.1.2", "title": "S3 public", "status": "FAIL", "severity": "high"},
                {"check_id": "1.4", "title": "Root MFA", "status": "ERROR", "severity": "critical"},
                {"check_id": "1.5", "title": "Manual", "status": "NOT_APPLICABLE", "severity": "low"},
            ]
        ),
    )
    client = TestClient(app)
    data = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    line = data["cis_foundations_benchmark"]
    assert line["framework_key"] == "cis_foundations_benchmark"
    assert line["representation"] == "benchmark"
    # evaluated = pass + fail + error (NOT not_applicable); score = pass/evaluated.
    assert line["summary"] == {
        "pass": 1,
        "fail": 1,
        "error": 1,
        "not_applicable": 1,
        "evaluated": 3,
        "score": 33.3,
    }
    assert line["status"] == "fail"
    # ERROR is a distinct bucket — not folded into pass, not folded into fail.
    assert line["summary"]["error"] == 1
    assert line["summary"]["pass"] == 1
    assert line["summary"]["fail"] == 1
    # Summary counters mirror the benchmark line.
    assert data["summary"]["cis_foundations_pass"] == 1
    assert data["summary"]["cis_foundations_fail"] == 1
    assert data["summary"]["cis_foundations_error"] == 1
    assert data["summary"]["cis_foundations_evaluated"] == 3
    _clear_jobs()


def test_failing_cis_account_is_not_green():
    """The core defect: a cloud account failing CIS controls (and with NO
    CVE-derived findings) previously read overall_status=no_data / score 0 as if
    nothing were wrong. It must now read fail."""
    _clear_jobs()
    _add_done_job(
        [],
        result_extra=_cis_benchmark_result(
            [
                {"check_id": "2.1.2", "title": "S3 public", "status": "FAIL", "severity": "high"},
                {"check_id": "2.1.1", "title": "S3 SSE", "status": "PASS", "severity": "high"},
            ]
        ),
    )
    client = TestClient(app)
    data = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    assert data["overall_status"] == "fail"
    assert data["overall_score"] < 100.0
    assert data["cis_foundations_benchmark"]["status"] == "fail"
    _clear_jobs()


def test_cis_foundations_error_only_is_not_a_clean_pass():
    """ERROR (permission-denied / unevaluable) must never read as a clean pass:
    an account whose evaluable checks pass but has an unevaluable control is
    warning, not pass, and error is excluded from the numerator."""
    _clear_jobs()
    _add_done_job(
        [],
        result_extra=_cis_benchmark_result(
            [
                {"check_id": "2.1.1", "title": "S3 SSE", "status": "PASS", "severity": "high"},
                {"check_id": "1.4", "title": "Root MFA", "status": "ERROR", "severity": "critical"},
            ]
        ),
    )
    client = TestClient(app)
    data = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    line = data["cis_foundations_benchmark"]
    assert line["summary"]["error"] == 1
    assert line["summary"]["fail"] == 0
    # score = pass / (pass + fail + error) = 1/2 = 50.0 — unevaluable ≠ pass.
    assert line["summary"]["score"] == 50.0
    assert line["status"] == "warning"
    assert data["overall_status"] == "warning"
    _clear_jobs()


def test_cis_foundations_does_not_double_count_cis_controls_v8():
    """The CIS Foundations Benchmark line (CIS-2.1.1 taxonomy) and the CVE-driven
    CIS Controls v8 line (safeguard CIS-02.1 taxonomy) are distinct surfaces —
    neither counts the other's data, so nothing is conflated."""
    _clear_jobs()
    _add_done_job(
        [
            {
                "vulnerability_id": "CVE-2025-7777",
                "severity": "high",
                "package": "openssl",
                "cis_tags": ["CIS-07.1"],  # Controls v8 safeguard
            }
        ],
        result_extra=_cis_benchmark_result([{"check_id": "2.1.2", "title": "S3 public", "status": "FAIL", "severity": "high"}]),
    )
    client = TestClient(app)
    data = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    # Foundations line reflects the benchmark FAIL only (1 evaluated check).
    assert data["cis_foundations_benchmark"]["summary"]["fail"] == 1
    assert data["cis_foundations_benchmark"]["summary"]["evaluated"] == 1

    # Controls v8 line (cis_controls, cis_tags) reflects the CVE safeguard only —
    # the benchmark FAIL never appears there (different taxonomy / no shared id).
    cis_controls = data["cis_controls"]
    failed_v8 = [c for c in cis_controls if c["status"] == "fail"]
    assert all(c["control_id"] == "CIS-07.1" for c in failed_v8)
    assert all(not c["control_id"].startswith("CIS-2.1") for c in cis_controls)
    _clear_jobs()


def test_cis_foundations_reconciles_with_cis_checks():
    """The benchmark-backed scorecard line's counts must reconcile with
    /v1/cis/checks — both derive from the same build_cis_benchmark_check_rows
    data with the same latest-per-(cloud,check_id) dedup."""
    _clear_jobs()
    checks = [
        {"check_id": "2.1.1", "title": "a", "status": "PASS", "severity": "high"},
        {"check_id": "2.1.2", "title": "b", "status": "FAIL", "severity": "high"},
        {"check_id": "2.1.3", "title": "c", "status": "FAIL", "severity": "medium"},
        {"check_id": "1.4", "title": "d", "status": "ERROR", "severity": "critical"},
    ]
    _add_done_job([], result_extra=_cis_benchmark_result(checks))
    client = TestClient(app)

    scorecard = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()["cis_foundations_benchmark"]["summary"]
    rows = client.get("/v1/cis/checks?limit=500", headers=_AUTH_HEADERS).json()["checks"]

    tally = {"pass": 0, "fail": 0, "error": 0}
    for row in rows:
        st = str(row["status"]).lower()
        if st in tally:
            tally[st] += 1
    assert scorecard["pass"] == tally["pass"]
    assert scorecard["fail"] == tally["fail"]
    assert scorecard["error"] == tally["error"]
    _clear_jobs()


# ─── PR3: NIST 800-53 catalog-backed scoring line ────────────────────────────


def _nist_catalog_scenario() -> None:
    """Seed one estate exercising every NIST-catalog status transition.

    CVE finding tagged SI-10 (curated CWE evidence) -> fail; a second finding
    tagged only RA-5 (a vuln-intrinsic tag with NO curated check -> control
    mapping) -> must stay not_evaluated so the line reconciles with the curated
    evidencing_checks. AWS CIS Foundations checks drive pass/fail/error/N-A.
    """
    _add_done_job(
        [
            {
                "vulnerability_id": "CVE-2025-1000",
                "severity": "high",
                "package": "flask",
                "nist_800_53_tags": ["SI-10"],
            },
            {
                "vulnerability_id": "CVE-2025-2000",
                "severity": "critical",
                "package": "requests",
                "nist_800_53_tags": ["RA-5"],  # not a curated check -> control
            },
        ],
        result_extra=_cis_benchmark_result(
            [
                {"check_id": "2.1.2", "title": "S3 SSE", "status": "PASS", "severity": "high"},  # SC-28 pass
                {"check_id": "2.1.1", "title": "S3 public", "status": "FAIL", "severity": "high"},  # AC-3, SC-7 fail
                {"check_id": "1.12", "title": "Unused creds", "status": "FAIL", "severity": "medium"},  # AC-2, IA-5 fail
                {"check_id": "1.4", "title": "Root key", "status": "ERROR", "severity": "critical"},  # AC-6, IA-5 err
                {"check_id": "1.5", "title": "Manual", "status": "NOT_APPLICABLE", "severity": "low"},  # IA-2 ignored
            ]
        ),
    )


def test_compliance_surfaces_nist_800_53_catalog_line():
    """A NIST-mapped estate surfaces a catalog-backed 800-53 line scored over
    EVALUATED controls only, with an explicit ERROR bucket and a not_evaluated
    remainder against the full vendored catalog."""
    from agent_bom.framework_mapping import FRAMEWORK_CONTROL_CATALOG

    _clear_jobs()
    _nist_catalog_scenario()
    client = TestClient(app)
    data = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    line = data["nist_800_53_catalog"]
    assert line["framework_key"] == "nist_800_53_catalog"
    assert line["representation"] == "catalog"
    assert line["vendor_asserted"] is True

    catalog_size = len(FRAMEWORK_CONTROL_CATALOG["nist-800-53"])
    summary = line["summary"]
    # fail: SI-10, AC-3, SC-7, AC-2, IA-5 (fail beats the 1.4 error) = 5
    # pass: SC-28 = 1 ; error: AC-6 = 1 ; warning: 0
    assert summary["fail"] == 5
    assert summary["pass"] == 1
    assert summary["error"] == 1
    assert summary["warning"] == 0
    assert summary["evaluated"] == 7  # pass + fail + warning + error
    assert summary["catalog_size"] == catalog_size
    assert summary["not_evaluated"] == catalog_size - 7
    # Score is over evaluated controls only: 1 pass / 7 evaluated.
    assert summary["score"] == 14.3
    assert line["score"] == 14.3
    assert line["status"] == "fail"

    by_id = {c["control_id"]: c for c in line["controls"]}
    assert by_id["SI-10"]["status"] == "fail"
    assert by_id["AC-2"]["status"] == "fail"
    assert by_id["SC-28"]["status"] == "pass"
    assert by_id["AC-6"]["status"] == "error"  # unevaluable, not pass/fail
    assert by_id["IA-5"]["status"] == "fail"  # fail (1.12) wins over error (1.4)
    # Reconciliation: controls with no curated check are never on this line.
    assert "RA-5" not in by_id  # vuln-intrinsic tag, not a curated check
    assert "IA-2" not in by_id  # only a NOT_APPLICABLE check touched it
    # Only evaluated controls are listed (no 1000-row not_evaluated tower).
    assert all(c["status"] in ("pass", "fail", "warning", "error") for c in line["controls"])
    _clear_jobs()


def test_nist_catalog_line_iso_attribution_is_derived_by_id_only():
    """A failing NIST control surfaces its ISO 27001 attribution BY ID ONLY,
    labeled as derived from NIST's official SP 800-53 -> ISO crosswalk — never an
    ISO control title (copyrighted)."""
    from agent_bom.framework_mapping import nist_to_iso

    _clear_jobs()
    _nist_catalog_scenario()
    client = TestClient(app)
    line = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()["nist_800_53_catalog"]

    # AC-2 is the canonical example: NIST maps it to A.5.16 / A.5.18 / A.8.2.
    ac2 = next(c for c in line["controls"] if c["control_id"] == "AC-2")
    assert ac2["iso_27001_derived"] == nist_to_iso("AC-2") == ["A.5.16", "A.5.18", "A.8.2"]

    derived = line["iso_27001_derived"]
    assert "crosswalk" in derived["note"].lower()
    assert derived["source"] == "nist_800_53_to_iso_27001_crosswalk"
    # Identifiers only — every entry is an ISO Annex A id, no title text leaks.
    assert all(i.startswith("A.") for i in derived["controls"])
    assert "A.5.16" in derived["controls"]
    # Only failing controls contribute (SC-28 passed -> its ISO ids not implicated
    # unless another failing control shares them).
    assert derived["controls"] == sorted(set(derived["controls"]))
    _clear_jobs()


def test_nist_catalog_line_is_independent_and_does_not_move_overall():
    """The catalog line is scored INDEPENDENTLY: its pass/fail must not be folded
    into overall_score (that would double-count the same CVE/CIS evidence already
    driving the existing lines). The existing CIS Foundations line is unchanged."""
    _clear_jobs()
    # CIS-only estate: no CVE tags. overall is driven by the CIS Foundations fold
    # exactly as before PR3.
    _add_done_job(
        [],
        result_extra=_cis_benchmark_result(
            [
                {"check_id": "2.1.2", "title": "S3 SSE", "status": "PASS", "severity": "high"},
                {"check_id": "2.1.1", "title": "S3 public", "status": "FAIL", "severity": "high"},
                {"check_id": "1.12", "title": "Unused creds", "status": "FAIL", "severity": "medium"},
                {"check_id": "1.4", "title": "Root key", "status": "ERROR", "severity": "critical"},
                {"check_id": "1.5", "title": "Manual", "status": "NOT_APPLICABLE", "severity": "low"},
            ]
        ),
    )
    client = TestClient(app)
    data = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    # cis_foundations fold: pass=1, fail=2, error=1 -> evaluated 4, score 25.0.
    assert data["cis_foundations_benchmark"]["summary"] == {
        "pass": 1,
        "fail": 2,
        "error": 1,
        "not_applicable": 1,
        "evaluated": 4,
        "score": 25.0,
    }
    assert data["overall_status"] == "fail"
    assert data["overall_score"] == 25.0  # NOT dragged further by the NIST line

    # The NIST catalog line still reports its own (independent) failing controls.
    nist_line = data["nist_800_53_catalog"]
    assert nist_line["summary"]["fail"] >= 3  # AC-3, SC-7, AC-2, IA-5
    # Its counts are NOT added into the overall aggregate summary.
    assert "nist_800_53_catalog_fail" in data["summary"]
    _clear_jobs()


def test_nist_catalog_line_no_data_when_nothing_mapped():
    """An estate with a completed scan but no NIST-mapped evidence yields an
    honest no_data line, not a false 100% pass."""
    _clear_jobs()
    _add_done_job([{"vulnerability_id": "CVE-x", "severity": "high", "owasp_tags": ["LLM05"]}])
    client = TestClient(app)
    line = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()["nist_800_53_catalog"]
    assert line["summary"]["evaluated"] == 0
    assert line["status"] == "no_data"
    assert line["score"] == 0.0
    _clear_jobs()


# ─── PR4: NIST 800-53 catalog drill endpoint (surface lock-in) ───────────────


def test_nist_800_53_drill_reconciles_with_compliance_line():
    """GET /v1/compliance/nist-800-53 returns the SAME summary as the
    /v1/compliance nist_800_53_catalog line (one source of truth) and lists the
    evaluated controls with vendor-asserted provenance + ISO-by-id attribution."""
    _clear_jobs()
    _nist_catalog_scenario()
    client = TestClient(app)
    line = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()["nist_800_53_catalog"]
    drill = client.get("/v1/compliance/nist-800-53", headers=_AUTH_HEADERS).json()

    # Reconciliation: the drill's headline numbers equal the aggregate line's.
    assert drill["framework"] == "nist-800-53"
    assert drill["framework_key"] == "nist_800_53_catalog"
    assert drill["vendor_asserted"] is True
    assert drill["summary"] == line["summary"]
    assert drill["score"] == line["score"]
    assert drill["status"] == line["status"]

    by_id = {c["control_id"]: c for c in drill["controls"]}
    assert by_id["SI-10"]["status"] == "fail"
    assert by_id["SC-28"]["status"] == "pass"
    assert by_id["AC-6"]["status"] == "error"
    # Vendor-asserted evidencing checks ride the drill.
    assert by_id["SI-10"]["evidencing_checks"]
    # ISO by ID only, derived, no title text.
    assert by_id["AC-2"]["iso_27001_derived"] == ["A.5.16", "A.5.18", "A.8.2"]
    assert all(i.startswith("A.") for i in drill["iso_27001_derived"]["controls"])

    # Default drill does NOT dump the ~1000-row not_evaluated tower (scale).
    assert all(c["status"] in ("pass", "fail", "warning", "error") for c in drill["controls"])


def test_nist_800_53_drill_family_rollup_reconciles():
    """The family rollup partitions the full catalog and its evaluated counts sum
    back to the line's evaluated total (scale-aware navigation, honest counts)."""
    _clear_jobs()
    _nist_catalog_scenario()
    client = TestClient(app)
    drill = client.get("/v1/compliance/nist-800-53", headers=_AUTH_HEADERS).json()

    families = drill["families"]
    assert families, "family rollup must be present for scale-aware UI grouping"
    # Every evaluated control belongs to exactly one family; totals reconcile.
    assert sum(f["evaluated"] for f in families) == drill["summary"]["evaluated"]
    assert sum(f["total"] for f in families) == drill["summary"]["catalog_size"]
    assert sum(f["fail"] for f in families) == drill["summary"]["fail"]
    # AC family carries the AC-2 / AC-3 / AC-6 evaluated controls.
    ac = next(f for f in families if f["family"] == "AC")
    assert ac["evaluated"] >= 3


def test_nist_800_53_drill_status_filter_and_not_evaluated_opt_in():
    """?status= filters the control list; ?include_not_evaluated=true opts into
    the full catalog listing (still one honest set of counts)."""
    _clear_jobs()
    _nist_catalog_scenario()
    client = TestClient(app)

    only_fail = client.get("/v1/compliance/nist-800-53?status=fail", headers=_AUTH_HEADERS).json()
    assert only_fail["controls"]
    assert all(c["status"] == "fail" for c in only_fail["controls"])
    # Summary is unchanged by the display filter (counts are the source of truth).
    assert only_fail["summary"]["pass"] == 1

    full = client.get("/v1/compliance/nist-800-53?include_not_evaluated=true", headers=_AUTH_HEADERS).json()
    statuses = {c["control_id"]: c["status"] for c in full["controls"]}
    assert len(full["controls"]) == full["summary"]["catalog_size"]
    # A curated-but-unrun control appears as not_evaluated (never a silent pass).
    not_eval = [cid for cid, s in statuses.items() if s == "not_evaluated"]
    assert len(not_eval) == full["summary"]["not_evaluated"]


def test_nist_800_53_drill_no_data_is_honest():
    """A completed scan with no NIST-mapped evidence drills to no_data, never a
    fabricated 100% pass."""
    _clear_jobs()
    _add_done_job([{"vulnerability_id": "CVE-x", "severity": "high", "owasp_tags": ["LLM05"]}])
    client = TestClient(app)
    drill = client.get("/v1/compliance/nist-800-53", headers=_AUTH_HEADERS).json()
    assert drill["status"] == "no_data"
    assert drill["score"] == 0.0
    assert drill["summary"]["evaluated"] == 0
    _clear_jobs()


def test_posture_has_proxy_flips_on_proxy_alert_ingest():
    """audit P1-B: ingesting proxy alerts via /v1/proxy/audit must flip
    the ``has_proxy`` posture flag on /v1/posture/counts.

    Before this fix, ``has_proxy`` only flipped when scan-job results
    carried runtime_correlation/introspection/health_check signals OR
    when the gateway policy_audit log was non-empty. Sites that ingest
    proxy alerts via the dedicated runtime endpoint saw "no proxy data"
    on the dashboard while alerts were sitting in /v1/proxy/status.
    """
    from agent_bom.api.policy_store import InMemoryPolicyStore
    from agent_bom.api.routes.proxy import _proxy_alerts
    from agent_bom.api.server import set_policy_store

    _clear_jobs()
    # ensure the ring buffer is empty for a deterministic before/after,
    # and reset the policy store so a previous test's audit entries don't
    # already flip has_proxy to True via the policy_audit fallback path.
    _proxy_alerts.clear()
    set_policy_store(InMemoryPolicyStore())
    client = TestClient(app)

    before = client.get("/v1/posture/counts", headers=_AUTH_HEADERS).json()
    assert before["has_proxy"] is False

    admin_headers = proxy_headers(role="admin", tenant="default")
    resp = client.post(
        "/v1/proxy/audit",
        headers=admin_headers,
        json={
            "source_id": "proxy-1",
            "session_id": "s1",
            "alerts": [
                {
                    "detector": "secret_exfil",
                    "severity": "high",
                    "message": "AWS key in tool args",
                    "tool_name": "http.post",
                    "ts": 1735000000,
                },
            ],
        },
    )
    assert resp.status_code == 200
    assert resp.json()["alert_count"] == 1

    after = client.get("/v1/posture/counts", headers=_AUTH_HEADERS).json()
    assert after["has_proxy"] is True
    assert after["has_traces"] is True

    # tenant scoping: a different tenant must NOT see this alert
    other_tenant_headers = proxy_headers(tenant="other-tenant")
    other = client.get("/v1/posture/counts", headers=other_tenant_headers).json()
    assert other["has_proxy"] is False

    _proxy_alerts.clear()
    _clear_jobs()
