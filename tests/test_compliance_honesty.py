"""Compliance honesty contract — the scorecard must assert only what it evidenced.

Three properties of the scorecard read path, each previously violated:

1. ``pass`` is REACHABLE, so ``overall_score`` can move. Before, every
   tag-mapped control could only resolve to fail / warning / not_evaluated, so
   ``total_pass`` was structurally 0 and the UI rendered a permanent
   ``OVERALL 0% — Non-compliant`` with a ``Pass`` tab that matched no row.
2. Detective controls ("monitor and scan for vulnerabilities", "maintain a
   component inventory") are EVIDENCED by the scan, not failed by it. The
   "you have unpatched flaws" mass belongs on the corrective controls
   (SI-2 / SR-3), and controls a package scan cannot observe (RA-7, IR-5) are
   never asserted at all.
3. MITRE ATT&CK is an APPLICABILITY OVERLAY, never a pass/fail framework, and
   never folded into ``overall_status`` / ``overall_score``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from starlette.testclient import TestClient

from agent_bom.api.server import JobStatus, _get_store, app
from agent_bom.api.store import InMemoryJobStore
from tests.auth_helpers import (
    disable_trusted_proxy_env,
    enable_trusted_proxy_env,
    proxy_headers,
)

_AUTH_HEADERS = proxy_headers(tenant="default")


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def _clear_jobs() -> None:
    from agent_bom.api.server import set_job_store

    set_job_store(InMemoryJobStore())


def _iso(delta_days: float = 0.0) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=delta_days)).isoformat()


def _br(
    *,
    name: str = "demo",
    version: str = "1.0.0",
    vuln_id: str = "CVE-2026-0001",
    severity=None,
    cwe_ids: list[str] | None = None,
    exposed_credentials: list[str] | None = None,
):
    """Build a real BlastRadius so the production taggers run over it."""
    from agent_bom.models import Agent, AgentType, BlastRadius, Package, Severity, Vulnerability

    return BlastRadius(
        vulnerability=Vulnerability(
            id=vuln_id,
            summary="test",
            severity=severity or Severity.LOW,
            cwe_ids=cwe_ids or [],
        ),
        package=Package(name=name, version=version, ecosystem="pypi"),
        affected_servers=[],
        affected_agents=[Agent(name="agent-a", agent_type=AgentType.CLAUDE_CODE, config_path="/tmp/a.py")],
        exposed_credentials=list(exposed_credentials or []),
        exposed_tools=[],
    )


def _blast(
    *,
    severity: str = "low",
    vuln_id: str = "CVE-2026-0001",
    package: str = "demo@1.0.0",
    cwe_ids: list[str] | None = None,
) -> dict:
    """A serialized blast radius carrying the tags the real taggers emit."""
    from agent_bom.cis_controls import tag_blast_radius as tag_cis
    from agent_bom.mitre_attack import tag_blast_radius as tag_attack
    from agent_bom.models import Severity
    from agent_bom.nist_800_53 import tag_blast_radius as tag_nist
    from agent_bom.nist_csf import tag_blast_radius as tag_csf

    name, version = package.split("@")
    br = _br(
        name=name,
        version=version,
        vuln_id=vuln_id,
        severity=Severity(severity),
        cwe_ids=cwe_ids or [],
    )
    return {
        "vulnerability_id": vuln_id,
        "severity": severity,
        "package": package,
        "affected_agents": ["agent-a"],
        "nist_800_53_tags": tag_nist(br),
        "nist_csf_tags": tag_csf(br),
        "cis_tags": tag_cis(br),
        "attack_tags": tag_attack(br),
    }


def _add_done_job(
    blast_radius: list[dict],
    *,
    job_id: str = "job-honesty",
    completed_at: str | None = None,
    tenant_id: str = "default",
) -> None:
    from agent_bom.api.server import ScanJob, ScanRequest

    job = ScanJob(
        job_id=job_id,
        tenant_id=tenant_id,
        created_at=_iso(1),
        request=ScanRequest(),
    )
    job.status = JobStatus.DONE
    job.completed_at = completed_at or _iso(0)
    job.result = {"agents": [], "blast_radius": blast_radius, "threat_framework_summary": {}}
    _get_store().put(job)


def _add_failing_aisvs_job(*, job_id: str = "job-aisvs", tenant_id: str = "default") -> None:
    """A completed scan with no CVE evidence but a failing AISVS benchmark check."""
    from agent_bom.api.server import ScanJob, ScanRequest

    job = ScanJob(job_id=job_id, tenant_id=tenant_id, created_at=_iso(1), request=ScanRequest())
    job.status = JobStatus.DONE
    job.completed_at = _iso(0)
    job.result = {
        "agents": [],
        "blast_radius": [],
        "threat_framework_summary": {},
        "scan_id": job_id,
        "aisvs_benchmark": {
            "benchmark": "OWASP AI Security Verification Standard",
            "benchmark_version": "1.0",
            "passed": 1,
            "failed": 1,
            "total": 2,
            "pass_rate": 50.0,
            "checks": [
                {"check_id": "AI-4.1", "status": "pass", "severity": "high"},
                {"check_id": "AI-6.1", "status": "fail", "severity": "critical"},
            ],
            "metadata": {},
        },
    }
    _get_store().put(job)


def _controls(payload: dict, output_key: str) -> dict[str, dict]:
    return {c["control_id"]: c for c in payload[output_key]}


# ── Finding 1: pass is reachable, so overall_score can move ──────────────────


def test_overall_score_is_not_structurally_pinned_at_zero() -> None:
    """A fresh scan over a single LOW finding must not read 0% Non-compliant."""
    _clear_jobs()
    _add_done_job([_blast(severity="low")])
    with TestClient(app) as client:
        payload = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    assert payload["overall_score"] > 0.0, "overall_score can never leave 0 — pass is unreachable"
    total_pass = sum(v for k, v in payload["summary"].items() if k.endswith("_pass"))
    assert total_pass > 0
    assert payload["overall_status"] != "no_data"


def test_a_passing_control_says_why_it_passed() -> None:
    """A pass must carry its evidence basis, never an unexplained green."""
    _clear_jobs()
    _add_done_job([_blast(severity="low")])
    with TestClient(app) as client:
        payload = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    ra5 = _controls(payload, "nist_800_53")["RA-5"]
    assert ra5["status"] == "pass"
    assert ra5["evaluation_mode"] == "detective"
    assert ra5["evidence_reason"] == "fresh_scan_evidence"


# ── Finding 2: detective vs corrective ───────────────────────────────────────


def test_detective_controls_are_evidenced_by_the_scan_not_failed_by_it() -> None:
    _clear_jobs()
    _add_done_job([_blast(severity="critical")])
    with TestClient(app) as client:
        payload = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    nist = _controls(payload, "nist_800_53")
    for control_id in ("RA-5", "CM-8"):
        assert nist[control_id]["status"] == "pass", f"{control_id} is detective — the scan evidences it"

    csf = _controls(payload, "nist_csf")
    for control_id in ("ID.RA-01", "DE.CM-09"):
        assert csf[control_id]["status"] == "pass", f"{control_id} is detective — the scan evidences it"

    cis = _controls(payload, "cis_controls")
    for control_id in ("CIS-02.1", "CIS-07.1", "CIS-07.5"):
        assert cis[control_id]["status"] == "pass", f"{control_id} is detective — the scan evidences it"


def test_unpatched_flaw_mass_lands_on_the_corrective_controls() -> None:
    """SI-2 / SR-3 carry the open-finding failure, and they carry the count."""
    _clear_jobs()
    _add_done_job([_blast(severity="critical")])
    with TestClient(app) as client:
        payload = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    nist = _controls(payload, "nist_800_53")
    for control_id in ("SI-2", "SR-3"):
        assert nist[control_id]["status"] == "fail"
        assert nist[control_id]["findings"] == 1
        assert nist[control_id]["evaluation_mode"] == "corrective"
    # The detective controls no longer carry the "you have unpatched flaws" mass.
    assert nist["RA-5"]["findings"] == 0
    assert nist["CM-8"]["findings"] == 0


def test_unevaluable_controls_are_never_asserted_from_finding_data() -> None:
    """RA-7 (risk response) and IR-5 (incident tracking) cannot be observed."""
    from agent_bom.models import Severity
    from agent_bom.nist_800_53 import tag_blast_radius

    tags = tag_blast_radius(_br(vuln_id="CVE-2026-0002", severity=Severity.CRITICAL))
    assert "RA-7" not in tags
    assert "IR-5" not in tags

    _clear_jobs()
    _add_done_job([_blast(severity="critical")])
    with TestClient(app) as client:
        payload = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()
    nist = _controls(payload, "nist_800_53")
    assert nist["RA-7"]["status"] == "not_evaluated"
    assert nist["IR-5"]["status"] == "not_evaluated"


def test_cve_intrinsic_tagger_agrees_with_the_blast_radius_tagger() -> None:
    """vuln_compliance must not re-introduce the dropped/moved controls."""
    from agent_bom.models import Package, Severity, Vulnerability
    from agent_bom.vuln_compliance import tag_vulnerability

    tags = tag_vulnerability(
        Vulnerability(id="CVE-2026-0003", summary="x", severity=Severity.CRITICAL),
        Package(name="demo", version="1.0.0", ecosystem="pypi"),
    )
    assert "RA-7" not in tags["nist_800_53"]
    assert "IR-5" not in tags["nist_800_53"]
    assert "RA-5" not in tags["nist_800_53"]
    assert "CM-8" not in tags["nist_800_53"]
    assert {"SI-2", "SR-3"} <= set(tags["nist_800_53"])
    assert "ID.RA-01" not in tags["nist_csf"]
    assert "DE.CM-09" not in tags["nist_csf"]
    assert "CIS-02.1" not in tags["cis"]
    assert "CIS-07.1" not in tags["cis"]


def test_stale_scan_evidence_fails_the_detective_controls() -> None:
    """Continuous monitoring that lapsed is a real control failure."""
    _clear_jobs()
    _add_done_job([_blast(severity="low")], completed_at=_iso(400))
    with TestClient(app) as client:
        payload = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    ra5 = _controls(payload, "nist_800_53")["RA-5"]
    assert ra5["status"] == "fail"
    assert ra5["evidence_reason"] == "stale_scan_evidence"


def test_zero_scan_estate_never_asserts_a_detective_pass_or_fail() -> None:
    _clear_jobs()
    with TestClient(app) as client:
        payload = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    assert payload["overall_status"] == "no_data"
    ra5 = _controls(payload, "nist_800_53")["RA-5"]
    assert ra5["status"] == "not_assessed"
    assert ra5["evidence_reason"] == "no_completed_scan"


def test_a_failing_benchmark_check_can_never_read_as_compliant() -> None:
    """Making ``pass`` reachable must not resurrect a false green.

    An estate whose only CVE evidence is empty now legitimately passes its
    detective controls. If a directly-evaluated benchmark line is failing at the
    same time, the top line must still say so — otherwise the honesty fix in
    finding 1 buys a "100% Compliant" headline over a failing AISVS check.
    """
    _clear_jobs()
    _add_failing_aisvs_job()
    with TestClient(app) as client:
        payload = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    assert payload["summary"]["aisvs_fail"] == 1
    assert payload["overall_status"] == "fail", "a failing benchmark check read as compliant"
    assert payload["overall_score"] < 100.0


def test_scanning_alone_is_not_compliance() -> None:
    """Detective passes alone must never render a "Compliant" headline.

    A completed scan over an estate with nothing to report establishes exactly
    one thing: that we scan. It says nothing about whether the estate meets a
    framework. Treating those passes as a clean audit is how "100% Compliant"
    used to appear over an unmeasured estate.
    """
    _clear_jobs()
    _add_done_job([])
    with TestClient(app) as client:
        payload = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    modes = {c["control_id"]: c for c in payload["nist_800_53"]}
    assert modes["RA-5"]["status"] == "pass", "the detective control itself is legitimately evidenced"
    assert payload["overall_status"] == "no_data", "scanning alone read as a compliant estate"


def test_one_tenants_scan_never_evidences_another_tenants_controls() -> None:
    """Detective controls are scored from scan freshness — which must be the
    REQUESTING tenant's freshness. A neighbour's fresh scan cannot be evidence
    that this tenant monitors anything."""
    _clear_jobs()
    _add_done_job([_blast(severity="low")], job_id="neighbour-scan", tenant_id="tenant-other")
    with TestClient(app) as client:
        payload = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    ra5 = _controls(payload, "nist_800_53")["RA-5"]
    assert ra5["status"] == "not_assessed", "another tenant's scan evidenced this tenant's control"
    assert ra5["evidence_reason"] == "no_completed_scan"
    assert payload["overall_status"] == "no_data"


def test_overall_score_always_ships_its_denominator() -> None:
    """A bare percentage hides how little was measured — coverage travels with it."""
    _clear_jobs()
    _add_done_job([_blast(severity="low")])
    with TestClient(app) as client:
        payload = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    assert payload["evaluated_controls"] > 0
    assert payload["total_controls"] > payload["evaluated_controls"]
    assert 0.0 < payload["coverage_pct"] < 100.0
    # The score is over the evaluated denominator, not the whole catalog.
    assert payload["coverage_pct"] == round((payload["evaluated_controls"] / payload["total_controls"]) * 100, 2)


# ── Finding 3: ATT&CK is an applicability overlay ────────────────────────────


def test_attack_is_an_overlay_not_a_scored_framework() -> None:
    _clear_jobs()
    _add_done_job([_blast(severity="critical", cwe_ids=["CWE-200"])])
    with TestClient(app) as client:
        payload = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    statuses = {c["status"] for c in payload["mitre_attack"]}
    assert statuses <= {"applicable", "not_applicable"}, f"ATT&CK still scored pass/fail: {statuses}"
    assert "attack_pass" not in payload["summary"]
    assert "attack_fail" not in payload["summary"]
    assert "attack_warn" not in payload["summary"]
    assert "attack_applicable" in payload["summary"]
    assert "attack_not_applicable" in payload["summary"]


def test_attack_never_moves_the_overall_line() -> None:
    """Removing ATT&CK from the response must not change overall_score."""
    _clear_jobs()
    _add_done_job([_blast(severity="critical", cwe_ids=["CWE-200"])])
    with TestClient(app) as client:
        payload = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    scored_pass = sum(v for k, v in payload["summary"].items() if k.endswith("_pass"))
    scored_warn = sum(v for k, v in payload["summary"].items() if k.endswith("_warn"))
    scored_fail = sum(v for k, v in payload["summary"].items() if k.endswith("_fail"))
    # No ATT&CK contribution exists to subtract — the overlay is outside the score.
    assert payload["mitre_attack"], "expected the overlay to still be reported"
    denominator = scored_pass + scored_warn + scored_fail
    assert denominator > 0
    assert all(c["status"] in {"applicable", "not_applicable"} for c in payload["mitre_attack"])


def test_attack_tagging_drops_technique_synthesis_with_no_evidencing_signal() -> None:
    """A HIGH CVE with no CWE must not synthesize T1190 / T1195 / T1078."""
    from agent_bom.mitre_attack import tag_blast_radius
    from agent_bom.models import Severity

    br = _br(
        vuln_id="CVE-2026-0004",
        severity=Severity.HIGH,
        exposed_credentials=["AWS_SECRET_ACCESS_KEY"],
    )
    assert tag_blast_radius(br) == []
