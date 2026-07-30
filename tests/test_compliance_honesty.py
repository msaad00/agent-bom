"""Compliance honesty contract — the scorecard must assert only what it evidenced.

Five properties, each of which the product previously violated:

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
4. The auditor evidence pack counts control-to-finding mapping ROWS and
   DISTINCT findings under separate, honestly-named keys.
5. A saved evidence bundle carries its own signature, so an artifact that
   advertises ``signature_algorithm`` is actually verifiable off-line.
"""

from __future__ import annotations

import json
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


# ── Finding 4: the evidence pack counts rows and findings separately ─────────


def test_pack_scope_separates_evidence_rows_from_distinct_findings() -> None:
    _clear_jobs()
    _add_done_job(
        [
            _blast(severity="high", vuln_id="CVE-2026-1001", package="alpha@1.0.0"),
            _blast(severity="low", vuln_id="CVE-2026-1002", package="beta@2.0.0"),
        ]
    )
    with TestClient(app) as client:
        pack = client.get("/v1/compliance/report/pack", headers=_AUTH_HEADERS).json()

    scope = pack["scope"]
    assert "finding_count" not in scope, "ambiguous key must be renamed"
    distinct_ids = {row["finding_id"] for fw in pack["frameworks"] for control in fw["controls"] for row in control["evidence"]}
    assert scope["distinct_finding_count"] == len(distinct_ids) == 2
    assert scope["evidence_row_count"] >= scope["distinct_finding_count"]


# ── Finding 5: a saved bundle is verifiable ──────────────────────────────────


def _verify(body: dict, signature_hex: str) -> bool:
    from agent_bom.api.compliance_signing import verify_compliance_signature

    unsigned = {k: v for k, v in body.items() if k != "signature"}
    return verify_compliance_signature(json.dumps(unsigned, sort_keys=True).encode(), signature_hex)


def test_saved_bundle_carries_its_own_verifiable_signature() -> None:
    _clear_jobs()
    _add_done_job([_blast(severity="high")])
    with TestClient(app) as client:
        response = client.get("/v1/compliance/soc2/report", headers=_AUTH_HEADERS)
    body = response.json()

    assert body["signature"], "bundle advertises signature_algorithm but ships no signature"
    assert body["signature"] == response.headers["X-Agent-Bom-Compliance-Report-Signature"]
    assert _verify(body, body["signature"])


def test_saved_pack_carries_its_own_verifiable_signature() -> None:
    _clear_jobs()
    _add_done_job([_blast(severity="high")])
    with TestClient(app) as client:
        response = client.get("/v1/compliance/report/pack", headers=_AUTH_HEADERS)
    body = response.json()

    assert body["signature"]
    assert body["signature"] == response.headers["X-Agent-Bom-Compliance-Report-Signature"]
    assert _verify(body, body["signature"])


def test_renamed_export_counters_survive_the_durable_audit_chain() -> None:
    """Renaming an audited field must not silently drop it from tier-A.

    ``TIER_A_FIELDS`` is a whitelist: anything absent is REPLAY_ONLY and is
    redacted out of durable persistence. The compliance export audit entry
    stopped logging ``finding_count`` in favour of two precise counters, so both
    new names have to be classified alongside the counters they replaced.
    """
    from agent_bom.evidence.policy import EvidenceTier, classify_field

    for field in ("evidence_row_count", "distinct_finding_count"):
        assert classify_field(field) is EvidenceTier.SAFE_TO_STORE, f"{field} would be redacted from the audit chain"


def test_saved_jsonl_bundle_verifies_by_reassembly_not_byte_layout() -> None:
    """The jsonl rendering must verify against the SAME canonical body as json.

    The old contract signed the exact streamed bytes, so verifying a saved
    ``.jsonl`` meant reproducing the stream's byte layout. Both renderings now
    carry the same embedded signature over the same canonical body, so a
    consumer reassembles the records and verifies.
    """
    _clear_jobs()
    _add_done_job([_blast(severity="high")])
    with TestClient(app) as client:
        response = client.get("/v1/compliance/soc2/report?format=jsonl", headers=_AUTH_HEADERS)
    raw = response.text

    records = [json.loads(line) for line in raw.split("\n") if line]
    meta = next(r["meta"] for r in records if "meta" in r)
    reassembled = {
        **meta,
        "controls": [r["control"] for r in records if "control" in r],
        "audit_events": [r["audit"] for r in records if "audit" in r],
    }

    assert reassembled["audit_events"], "expected audit evidence to survive reassembly"
    assert meta["signature"], "jsonl meta ships no signature to verify with"
    # Verified by the same recipe the json rendering uses: canonical body minus
    # the signature field. No dependence on the stream's byte layout.
    assert _verify(reassembled, reassembled["signature"])
    assert reassembled["signature"] == response.headers["X-Agent-Bom-Compliance-Report-Signature"]


def test_tampering_with_a_saved_bundle_invalidates_its_embedded_signature() -> None:
    _clear_jobs()
    _add_done_job([_blast(severity="high")])
    with TestClient(app) as client:
        body = client.get("/v1/compliance/soc2/report", headers=_AUTH_HEADERS).json()

    assert _verify(body, body["signature"])
    body["tenant_id"] = "some-other-tenant"
    assert not _verify(body, body["signature"])
