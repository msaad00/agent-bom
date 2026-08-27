"""Tests for the /v1/compliance posture endpoint."""

from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from agent_bom.api.server import JobStatus, _get_store, app, set_job_store
from agent_bom.api.store import InMemoryJobStore, SQLiteJobStore
from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import BlastRadius
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_AUTH_HEADERS = proxy_headers(tenant="default")


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def _recent_iso(hours: float = 0.0) -> str:
    """A timestamp inside the detective-control evidence-freshness window."""
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


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
        created_at=_recent_iso(hours=1),
        request=ScanRequest(),
    )
    job.status = JobStatus.DONE
    # Detective controls ("monitor and scan for vulnerabilities", "maintain a
    # component inventory") are scored from scan FRESHNESS, so a fixture with a
    # hard-coded past timestamp would read as lapsed monitoring as wall-clock
    # time advances. See agent_bom.evidence.control_modes.
    job.completed_at = _recent_iso()
    job.result = {
        "agents": [],
        "blast_radius": blast_radius,
        "threat_framework_summary": {},
    }
    if result_extra:
        job.result.update(result_extra)
    _get_store().put(job)


def test_compliance_tag_registry_covers_every_blast_radius_tag_field() -> None:
    from agent_bom.compliance_coverage import COMPLIANCE_TAG_FIELDS
    from agent_bom.output.finding_views import compliance_row_dict

    model_fields = {item.name for item in fields(BlastRadius) if item.name.endswith("_tags")}
    finding_fields = {item.name for item in fields(Finding) if item.name.endswith("_tags") and item.name != "compliance_tags"}
    assert set(COMPLIANCE_TAG_FIELDS) == model_fields
    assert set(COMPLIANCE_TAG_FIELDS) == finding_fields
    row = compliance_row_dict(
        Finding(
            finding_type=FindingType.CVE,
            source=FindingSource.SBOM,
            asset=Asset(name="pkg", asset_type="package"),
            severity="low",
            title="test",
        )
    )
    assert set(COMPLIANCE_TAG_FIELDS).issubset(row)


def test_evidence_index_preserves_all_framework_tags() -> None:
    from agent_bom.api.routes import compliance as route
    from agent_bom.compliance_coverage import COMPLIANCE_TAG_FIELDS

    blast = {
        "vulnerability_id": "CVE-2026-TAGS",
        "package": "demo@1.0.0",
        "severity": "high",
        **{field: [f"tag:{field}"] for field in COMPLIANCE_TAG_FIELDS},
    }
    job = SimpleNamespace(
        status=JobStatus.DONE,
        job_id="scan-tags",
        result={"blast_radius": [blast], "summary": {"total_agents": 1, "total_packages": 1}},
        request={},
        created_at="2026-07-29T00:00:00Z",
        completed_at="2026-07-29T00:01:00Z",
    )
    index = route._index_blast_radii_by_tag([job])
    for field in COMPLIANCE_TAG_FIELDS:
        assert f"tag:{field}" in index


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
    # OWASP Top 10 rows are applicability overlays, so no evidence means the
    # risks are not applicable — never a passing control claim.
    for c in data["owasp_llm_top10"]:
        assert c["status"] == "not_applicable"
        assert c["findings"] == 0
    for metadata in TAG_MAPPED_FRAMEWORKS:
        assert len(data[metadata.output_key]) == metadata.control_count
        if not metadata.scored:
            # An applicability overlay has no pass/warn/fail to report at all —
            # zeroed control counters would imply controls it does not have.
            assert data["summary"][f"{metadata.summary_prefix}_applicable"] == 0
            assert data["summary"][f"{metadata.summary_prefix}_not_applicable"] == metadata.control_count
            continue
        assert data["summary"][f"{metadata.summary_prefix}_pass"] == 0
        assert data["summary"][f"{metadata.summary_prefix}_warn"] == 0
        assert data["summary"][f"{metadata.summary_prefix}_fail"] == 0
        assert data["summary"][f"{metadata.summary_prefix}_not_evaluated"] == metadata.control_count
    _clear_jobs()


def test_compliance_can_scope_posture_to_a_selected_scan():
    _clear_jobs()
    _add_done_job(
        [{"vulnerability_id": "CVE-ALPHA", "severity": "critical", "owasp_tags": ["LLM01"]}],
        job_id="scan-alpha",
    )
    _add_done_job(
        [{"vulnerability_id": "CVE-BETA", "severity": "high", "owasp_tags": ["LLM02"]}],
        job_id="scan-beta",
    )

    response = TestClient(app).get("/v1/compliance?scan_id=scan-alpha", headers=_AUTH_HEADERS)

    assert response.status_code == 200
    data = response.json()
    assert data["scan_count"] == 1
    llm01 = next(control for control in data["owasp_llm_top10"] if control["code"] == "LLM01")
    llm02 = next(control for control in data["owasp_llm_top10"] if control["code"] == "LLM02")
    assert llm01["findings"] == 1
    assert llm02["findings"] == 0


def test_agentic_context_is_inferred_from_canonical_agent_evidence_without_mcp() -> None:
    _clear_jobs()
    _add_done_job(
        [
            {
                "vulnerability_id": "CVE-AGENT-ONLY",
                "severity": "high",
                "affected_agents": ["cursor"],
                "affected_servers": [],
                "owasp_agentic_tags": ["ASI04"],
            }
        ],
        result_extra={"has_mcp_context": False, "has_agent_context": False},
    )

    data = TestClient(app).get("/v1/compliance", headers=_AUTH_HEADERS).json()

    assert data["has_mcp_context"] is False
    assert data["has_agent_context"] is True
    agentic = next(control for control in data["owasp_agentic_top10"] if control["code"] == "ASI04")
    assert agentic["status"] == "applicable"
    assert agentic["findings"] == 1
    _clear_jobs()


def test_unified_findings_drive_agentic_and_mcp_applicability_without_blast_duplicates() -> None:
    _clear_jobs()
    _add_done_job(
        [],
        result_extra={
            "has_mcp_context": False,
            "has_agent_context": False,
            "findings": [
                {
                    "id": "agent-occurrence",
                    "severity": "high",
                    "affected_agents": ["cursor"],
                    "owasp_agentic_tags": ["ASI04"],
                },
                {
                    "id": "mcp-occurrence",
                    "severity": "high",
                    "affected_servers": ["payments"],
                    "owasp_mcp_tags": ["MCP04"],
                },
            ],
        },
    )

    data = TestClient(app).get("/v1/compliance", headers=_AUTH_HEADERS).json()

    assert data["has_agent_context"] is True
    assert data["has_mcp_context"] is True
    agentic = next(control for control in data["owasp_agentic_top10"] if control["code"] == "ASI04")
    mcp = next(control for control in data["owasp_mcp_top10"] if control["code"] == "MCP04")
    assert (agentic["status"], agentic["findings"]) == ("applicable", 1)
    assert (mcp["status"], mcp["findings"]) == ("applicable", 1)
    _clear_jobs()


def test_unified_finding_occurrence_is_not_double_counted_across_scans() -> None:
    _clear_jobs()
    finding = {
        "id": "same-occurrence",
        "severity": "high",
        "affected_agents": ["cursor"],
        "owasp_agentic_tags": ["ASI04"],
    }
    _add_done_job([], job_id="scan-a", result_extra={"findings": [finding]})
    _add_done_job([], job_id="scan-b", result_extra={"findings": [dict(finding)]})

    data = TestClient(app).get("/v1/compliance", headers=_AUTH_HEADERS).json()
    agentic = next(control for control in data["owasp_agentic_top10"] if control["code"] == "ASI04")
    assert agentic["findings"] == 1
    _clear_jobs()


@pytest.mark.parametrize("reverse_put_order", [False, True])
def test_newest_unified_finding_occurrence_wins_independent_of_backend_order(
    tmp_path: Path,
    reverse_put_order: bool,
) -> None:
    """The authoritative occurrence is selected by evidence time, not store order.

    In-memory jobs retain insertion order while SQLite returns newest-created
    jobs first. A re-scan that clears a mapped high finding must therefore
    produce the same control posture on both backends.
    """
    from agent_bom.api.server import ScanJob, ScanRequest

    def _job(job_id: str, *, generated_at: str, completed_at: str, finding: dict) -> ScanJob:
        job = ScanJob(
            job_id=job_id,
            tenant_id="default",
            created_at=completed_at,
            request=ScanRequest(),
        )
        job.status = JobStatus.DONE
        job.completed_at = completed_at
        job.result = {"generated_at": generated_at, "findings": [finding]}
        return job

    old = _job(
        "scan-old",
        generated_at="2026-08-20T00:00:00Z",
        # A delayed persistence completion must not outrank fresher evidence.
        completed_at="2026-08-22T00:01:00Z",
        finding={
            "id": "same-occurrence",
            "severity": "critical",
            "soc2_tags": ["CC7.1"],
        },
    )
    newest = _job(
        "scan-new",
        generated_at="2026-08-21T00:00:00Z",
        completed_at="2026-08-21T00:01:00Z",
        finding={
            "id": "same-occurrence",
            "severity": "low",
            "soc2_tags": [],
        },
    )
    jobs = [newest, old] if reverse_put_order else [old, newest]
    results = []
    try:
        for store in (InMemoryJobStore(), SQLiteJobStore(str(tmp_path / f"jobs-{reverse_put_order}.db"))):
            set_job_store(store)
            for job in jobs:
                store.put(job)
            data = TestClient(app).get("/v1/compliance", headers=_AUTH_HEADERS).json()
            cc71 = next(control for control in data["soc2"] if control["code"] == "CC7.1")
            results.append((cc71["status"], cc71["findings"]))
    finally:
        _clear_jobs()

    assert results == [("not_evaluated", 0), ("not_evaluated", 0)]


def test_unified_finding_authority_uses_stable_job_id_tie_break() -> None:
    """Equal evidence/completion timestamps have one deterministic winner."""
    from agent_bom.api.routes import compliance as route

    row = {"id": "same-occurrence"}
    common = {
        "status": JobStatus.DONE,
        "completed_at": "2026-08-21T00:01:00Z",
        "created_at": "2026-08-21T00:00:00Z",
        "result": {"generated_at": "2026-08-21T00:00:30Z"},
    }
    job_a = SimpleNamespace(job_id="scan-a", **common)
    job_z = SimpleNamespace(job_id="scan-z", **common)

    assert route._compliance_evidence_authority_key(job_z, row) > route._compliance_evidence_authority_key(job_a, row)


def test_fedramp_rest_and_narrative_reconcile_namespaced_scanner_tags():
    """The REST score and narrative must join the same emitted FedRAMP tag."""
    _clear_jobs()
    _add_done_job(
        [
            {
                "vulnerability_id": "CVE-2026-FEDRAMP",
                "severity": "critical",
                "package": "demo",
                "fedramp_tags": ["FedRAMP-SI-10"],
            }
        ]
    )
    client = TestClient(app)

    posture = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()
    narrative = client.get("/v1/compliance/narrative/fedramp", headers=_AUTH_HEADERS).json()

    rest_control = next(control for control in posture["fedramp"] if control["code"] == "SI-10")
    narrative_framework = narrative["framework_narratives"][0]
    assert rest_control["findings"] == 1
    assert rest_control["status"] == "fail"
    assert posture["summary"]["fedramp_fail"] == 1
    assert {control["control_id"] for control in narrative_framework["failing_controls"]} == {"SI-10"}
    _clear_jobs()


def test_compliance_serializes_framework_kinds_for_every_framework():
    """Clients must not infer whether a catalog is scored from its display name."""
    _clear_jobs()
    data = TestClient(app).get("/v1/compliance", headers=_AUTH_HEADERS).json()

    assert data["framework_kinds"] == {
        metadata.output_key: ("scored" if metadata.scored else "applicability") for metadata in TAG_MAPPED_FRAMEWORKS
    }
    serialized_fixture = json.loads((Path(__file__).parents[1] / "ui/tests/fixtures/compliance-overlay-response.json").read_text())
    assert serialized_fixture["framework_kinds"] == data["framework_kinds"]
    for output_key in ("owasp_llm_top10", "owasp_mcp_top10", "owasp_agentic_top10", "mitre_atlas"):
        assert data["framework_kinds"][output_key] == "applicability"
    _clear_jobs()
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
    # This scan produced only AISVS-benchmark results and no CVE findings, so
    # every CORRECTIVE control stays not_evaluated. Two things are still real
    # evidence and are scored:
    #   * the 8 DETECTIVE controls — a completed, in-window scan IS the evidence
    #     "we monitor / inventory" operates (pass);
    #   * the AISVS benchmark's directly-evaluated checks (1 pass / 1 fail).
    # 9 pass over 10 evaluated = 90.0, and the failing AISVS check drives the
    # top line to "fail" — a directly-evaluated failure can never read compliant.
    assert data["overall_score"] == 90.0
    assert data["overall_status"] == "fail"
    # The percentage always ships its denominator: 10 evaluated of a much larger
    # catalog, so 90% cannot be misread as "90% of the estate is compliant".
    assert data["evaluated_controls"] == 10
    assert data["total_controls"] > data["evaluated_controls"]

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

    # OWASP Top 10 identifies applicable risks; it does not assert a failed
    # control. Severity remains available as evidence metadata.
    lmm05 = next(c for c in data["owasp_llm_top10"] if c["code"] == "LLM05")
    assert lmm05["status"] == "applicable"
    assert lmm05["findings"] == 1
    assert "express" in lmm05["affected_packages"]
    assert "claude-desktop" in lmm05["affected_agents"]

    # No observed finding means the risk is not applicable, not "passed".
    lmm01 = next(c for c in data["owasp_llm_top10"] if c["code"] == "LLM01")
    assert lmm01["status"] == "not_applicable"
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
    assert lmm04["status"] == "applicable"
    assert lmm04["severity_breakdown"]["critical"] == 1
    assert lmm04["severity_breakdown"]["high"] == 0

    _clear_jobs()


def test_compliance_overlay_preserves_medium_severity_breakdown():
    """An applicable risk keeps severity evidence without becoming a score."""
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
    assert lmm05["status"] == "applicable"
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
    assert s["owasp_applicable"] == 1
    assert s["owasp_not_applicable"] == 9
    assert s["owasp_applicable"] + s["owasp_not_applicable"] == 10

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
        if not metadata.scored:
            assert data["summary"][f"{metadata.summary_prefix}_applicable"] == 0
            continue
        assert data["summary"][f"{metadata.summary_prefix}_pass"] == 0
        assert data["summary"][f"{metadata.summary_prefix}_not_evaluated"] == metadata.control_count

    for fw in data["frameworks"].values():
        if not fw["scored"]:
            assert fw["applicable"] == 0
            assert fw["not_applicable"] == fw["controls"]
            continue
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
    assert data["summary"]["owasp_applicable"] == 1
    assert data["summary"]["owasp_not_applicable"] == 9
    _clear_jobs()


def _cis_benchmark_result(checks: list[dict], *, cloud_key: str = "cis_benchmark") -> dict:
    """Build a result_extra dict carrying a serialized CIS benchmark blob.

    ``cloud_key`` selects the provider slot used by the JSON output layer
    (``cis_benchmark`` for AWS, ``azure_cis_benchmark`` for Azure, etc.) —
    the exact keys /v1/cis/checks reads via build_cis_benchmark_check_rows.
    """
    return {"scan_id": "cis-scan", cloud_key: {"benchmark_version": "3.0", "checks": checks}}


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


def test_cis_checks_fail_closed_for_legacy_remediation_rows():
    _clear_jobs()
    _add_done_job(
        [],
        result_extra=_cis_benchmark_result(
            [
                {
                    "check_id": "3.5",
                    "title": "CloudTrail records management events in all regions",
                    "status": "FAIL",
                    "severity": "high",
                    "remediation": {
                        "fix_cli": "aws kms enable-key-rotation --key-id <KMS_KEY_ID>",
                        "fix_console": "AWS Console → CloudTrail → Trails → Event selectors",
                        "effort": "low",
                        "requires_human_review": False,
                    },
                }
            ]
        ),
    )

    row = TestClient(app).get("/v1/cis/checks", headers=_AUTH_HEADERS).json()["checks"][0]
    assert row["fix_cli"] == ""
    assert row["effort"] == "manual"
    assert row["requires_human_review"] is True
    assert row["remediation"]["fix_cli"] is None
    assert row["remediation"]["requires_human_review"] is True
    assert "Event selectors" in row["fix_console"]
    _clear_jobs()


def test_cis_checks_preserve_exact_provider_verified_remediation():
    command = "az storage account update --name <STORAGE_ACCOUNT_NAME> --resource-group <RESOURCE_GROUP_NAME> --https-only true"
    _clear_jobs()
    _add_done_job(
        [],
        result_extra=_cis_benchmark_result(
            [
                {
                    "check_id": "3.1",
                    "title": "Secure transfer required on storage accounts",
                    "cis_section": "3 - Storage Accounts",
                    "status": "FAIL",
                    "severity": "high",
                    "remediation": {
                        "fix_cli": command,
                        "fix_console": "Azure Portal → Storage accounts → Configuration",
                        "effort": "low",
                        "docs": "https://untrusted.example/old-doc",
                        "requires_human_review": False,
                    },
                }
            ],
            cloud_key="azure_cis_benchmark",
        ),
    )

    row = TestClient(app).get("/v1/cis/checks", headers=_AUTH_HEADERS).json()["checks"][0]
    assert row["fix_cli"] == command
    assert row["effort"] == "low"
    assert row["requires_human_review"] is True
    assert row["remediation"]["fix_cli"] == command
    assert row["remediation"]["docs"] == ("https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer")
    _clear_jobs()


def test_persisted_cis_rows_are_canonicalized_fail_closed():
    from agent_bom.api.routes.compliance import _coerce_cis_row

    row = _coerce_cis_row(
        {
            "fix_cli": "aws kms enable-key-rotation --key-id <KMS_KEY_ID>",
            "fix_console": "",
            "effort": "low",
            "requires_human_review": False,
            "remediation": json.dumps(
                {
                    "fix_cli": "aws kms enable-key-rotation --key-id <KMS_KEY_ID>",
                    "fix_console": "AWS Console → CloudTrail → Trails → Event selectors",
                    "effort": "low",
                    "requires_human_review": False,
                }
            ),
        }
    )

    assert row["fix_cli"] == ""
    assert row["effort"] == "manual"
    assert row["requires_human_review"] is True
    assert row["remediation"]["fix_cli"] is None
    assert row["remediation"]["requires_human_review"] is True
    assert "Event selectors" in row["fix_console"]


def test_persisted_cis_rows_preserve_only_exact_verified_command():
    from agent_bom.api.routes.compliance import _coerce_cis_row

    command = "gcloud storage buckets update gs://<BUCKET_NAME> --uniform-bucket-level-access"
    row = _coerce_cis_row(
        {
            "cloud": "gcp",
            "benchmark_version": "3.0",
            "check_id": "5.2",
            "title": "Uniform bucket-level access enabled on buckets",
            "cis_section": "5 - Cloud Storage",
            "fix_cli": "stale top-level command",
            "effort": "manual",
            "requires_human_review": False,
            "remediation": json.dumps(
                {
                    "fix_cli": command,
                    "fix_console": "GCP Console → Cloud Storage → Permissions",
                    "effort": "high",
                    "docs": "https://untrusted.example/old-doc",
                    "requires_human_review": False,
                }
            ),
        }
    )

    assert row["fix_cli"] == command
    assert row["effort"] == "low"
    assert row["requires_human_review"] is True
    assert row["remediation"]["docs"] == ("https://cloud.google.com/storage/docs/using-uniform-bucket-level-access")


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
    # CIS Foundations contributes pass=1 / fail=2 / error=1; the 8 DETECTIVE
    # controls also pass because a completed in-window scan evidences them.
    # 9 pass over 12 evaluated = 75.0. The NIST catalog line's own failures are
    # still NOT folded in — if they were, aggregate_fail would exceed 2 and the
    # score would drop below 75.
    assert data["overall_score"] == 75.0

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
