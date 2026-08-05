"""Enrichment-parity gate: fields computed and carried by most exporters must
not be silently dropped by specific ones.

Covers three "computed but not surfaced" omissions:

1. CycloneDX drops KEV / EPSS / CWE — every other exporter serializes them.
2. AI triage assessments reach only the JSON side-block — join them onto the
   findings they describe in SARIF and the HTML CVE table.
3. Reachability is missing from the HTML findings tables and Markdown — the
   human-facing moat signal, present in JSON/SARIF/CSV.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_bom.ai_schemas import AIFindingAssessment, AIProvenance
from agent_bom.models import (
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    MCPTool,
    Package,
    Severity,
    Vulnerability,
)
from agent_bom.output.cyclonedx_fmt import to_cyclonedx
from agent_bom.output.finding_views import cve_findings
from agent_bom.output.html.sections import _vuln_table
from agent_bom.output.markdown import to_markdown
from agent_bom.output.sarif import to_sarif

_FIXTURES = Path(__file__).parent / "fixtures"


# ── shared fixtures ──────────────────────────────────────────────────────────


def _kev_epss_cwe_vuln() -> Vulnerability:
    return Vulnerability(
        id="CVE-2026-0001",
        summary="Remote code execution in flask",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        fixed_version="2.3.0",
        epss_score=0.94567,
        epss_percentile=99.1,
        is_kev=True,
        kev_date_added="2026-01-02",
        kev_due_date="2026-01-23",
        cwe_ids=["CWE-94", "CWE-502"],
    )


def _report_with_vuln(vuln: Vulnerability) -> AIBOMReport:
    pkg = Package(
        name="flask",
        version="0.12.2",
        ecosystem="pypi",
        purl="pkg:pypi/flask@0.12.2",
        vulnerabilities=[vuln],
        is_direct=True,
    )
    server = MCPServer(
        name="db-server",
        packages=[pkg],
        tools=[MCPTool(name="query", description="run sql")],
    )
    agent = Agent(
        name="claude-desktop",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/claude-desktop.json",
        mcp_servers=[server],
        version="1.0",
    )
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=["AWS_SECRET_ACCESS_KEY"],
        exposed_tools=[],
    )
    br.calculate_risk_score()
    return AIBOMReport(
        agents=[agent],
        blast_radii=[br],
        scan_sources=["agent_discovery"],
        scan_id="3c249b23-4088-4c46-911d-1d4daf950e47",
        tool_version="0.0.0-test",
        generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def _report_with_reachability(reach: str | None) -> AIBOMReport:
    vuln = Vulnerability(
        id="CVE-2026-0002",
        summary="Reachable RCE",
        severity=Severity.HIGH,
        cvss_score=8.1,
        fixed_version="3.0.0",
    )
    report = _report_with_vuln(vuln)
    br = report.blast_radii[0]
    # Code-level reachability (the moat signal) is genuinely absent unless the
    # AST/symbol engine ran; set only that field so "Unknown" stays honest.
    if reach is not None:
        br.symbol_reachability = reach
        if reach == "function_reachable":
            br.reachable_affected_symbols = ["flask.Flask.run"]
    return report


# ── CycloneDX schema helpers (mirror test_interop_schema_conformance) ─────────


def _cyclonedx_registry():
    from referencing import Registry, Resource

    resources = []
    for name in (
        "cyclonedx-1.7.schema.json",
        "spdx.schema.json",
        "jsf-0.82.schema.json",
        "cryptography-defs.schema.json",
    ):
        path = _FIXTURES / name
        if not path.exists():
            continue
        schema = json.loads(path.read_text())
        uri = schema.get("$id") or schema.get("id")
        if uri:
            resources.append((uri, Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def _cdx_vuln(report: AIBOMReport) -> dict:
    cdx = to_cyclonedx(report)
    vulns = cdx.get("vulnerabilities", [])
    return next(v for v in vulns if v["id"] == "CVE-2026-0001")


# ── Instance 1: CycloneDX carries KEV / EPSS / CWE ───────────────────────────


def test_cyclonedx_vulnerability_carries_cwes_native() -> None:
    entry = _cdx_vuln(_report_with_vuln(_kev_epss_cwe_vuln()))
    # CDX 1.7 `cwes` is a native array of integer CWE IDs.
    assert entry.get("cwes") == [94, 502]


def test_cyclonedx_vulnerability_carries_epss_rating() -> None:
    entry = _cdx_vuln(_report_with_vuln(_kev_epss_cwe_vuln()))
    epss_ratings = [r for r in entry.get("ratings", []) if (r.get("source") or {}).get("name") == "EPSS"]
    assert epss_ratings, "EPSS must be surfaced as a CDX rating"
    assert epss_ratings[0]["method"] == "other"
    assert epss_ratings[0]["score"] == pytest.approx(0.94567)


def test_cyclonedx_vulnerability_carries_kev_epss_properties() -> None:
    entry = _cdx_vuln(_report_with_vuln(_kev_epss_cwe_vuln()))
    props = {p["name"]: p["value"] for p in entry.get("properties", [])}
    assert props.get("agent-bom:kev") == "true"
    assert props.get("agent-bom:kev_date_added") == "2026-01-02"
    assert props.get("agent-bom:kev_due_date") == "2026-01-23"
    assert props.get("agent-bom:epss_score") == "0.94567"
    assert props.get("agent-bom:epss_percentile") == "99.1"
    assert props.get("agent-bom:exploit_likelihood") == "actively_exploited"


def test_cyclonedx_no_enrichment_omits_kev_epss_properties() -> None:
    plain = Vulnerability(
        id="CVE-2026-0001",
        summary="plain",
        severity=Severity.MEDIUM,
    )
    entry = _cdx_vuln(_report_with_vuln(plain))
    props = {p["name"] for p in entry.get("properties", [])}
    assert "agent-bom:kev" not in props
    assert "agent-bom:epss_score" not in props
    assert "cwes" not in entry


def test_cyclonedx_kev_epss_cwe_stays_schema_valid() -> None:
    pytest.importorskip("jsonschema")
    from jsonschema import Draft7Validator

    schema_path = _FIXTURES / "cyclonedx-1.7.schema.json"
    if not schema_path.exists():
        pytest.skip("vendored CycloneDX 1.7 schema unavailable")
    cdx = to_cyclonedx(_report_with_vuln(_kev_epss_cwe_vuln()))
    schema = json.loads(schema_path.read_text())
    validator = Draft7Validator(schema, registry=_cyclonedx_registry())
    errors = sorted(validator.iter_errors(cdx), key=lambda e: list(e.path))
    assert not errors, "\n".join(f"  - {'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors[:20])


# ── Instance 2: AI triage assessment joins onto SARIF + HTML ─────────────────


def _report_with_assessment() -> tuple[AIBOMReport, str]:
    report = _report_with_vuln(_kev_epss_cwe_vuln())
    finding = cve_findings(report)[0]
    provenance = AIProvenance(
        run_id="run-1",
        provider="ollama",
        model="qwen2.5",
        prompt_sha256="a" * 64,
        response_sha256="b" * 64,
        generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        deterministic=True,
        redaction_applied=False,
    )
    report.ai_finding_assessments = [
        AIFindingAssessment(
            finding_id=finding.id,
            classification="true_positive",
            confidence="high",
            false_positive_likelihood="low",
            rationale="Reachable RCE in a running server.",
            suggested_controls=["upgrade flask"],
            provenance=provenance,
        )
    ]
    return report, finding.id


def test_sarif_result_carries_ai_assessment() -> None:
    report, finding_id = _report_with_assessment()
    sarif = to_sarif(report)
    results = sarif["runs"][0]["results"]
    target = next(r for r in results if r["ruleId"] == "CVE-2026-0001")
    props = target["properties"]
    assert props.get("agent-bom:ai_classification") == "true_positive"
    assert props.get("agent-bom:ai_false_positive_likelihood") == "low"
    assert props.get("agent-bom:ai_confidence") == "high"


def test_sarif_result_without_assessment_has_no_ai_props() -> None:
    report = _report_with_vuln(_kev_epss_cwe_vuln())  # no assessments
    sarif = to_sarif(report)
    target = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "CVE-2026-0001")
    assert "agent-bom:ai_classification" not in target["properties"]


def test_html_vuln_table_shows_ai_assessment() -> None:
    report, _ = _report_with_assessment()
    html = _vuln_table(report, report.blast_radii)
    assert "true_positive" in html
    # false-positive likelihood must be surfaced on the annotated row.
    assert "FP" in html or "false" in html.lower()


def test_html_vuln_table_without_assessment_has_no_ai_annotation() -> None:
    report = _report_with_vuln(_kev_epss_cwe_vuln())
    html = _vuln_table(report, report.blast_radii)
    assert "ai-triage" not in html


# ── Instance 3: reachability in HTML findings table + Markdown ───────────────


def test_html_vuln_table_shows_reachability_when_reachable() -> None:
    report = _report_with_reachability("function_reachable")
    html = _vuln_table(report, report.blast_radii)
    assert "data-reachability=" in html
    assert "Function" in html


def test_html_vuln_table_shows_reachability_unknown_when_absent() -> None:
    report = _report_with_reachability(None)
    html = _vuln_table(report, report.blast_radii)
    assert 'data-reachability="unknown"' in html
    assert "Unknown" in html


def test_markdown_findings_table_shows_reachability() -> None:
    report = _report_with_reachability("function_reachable")
    md = to_markdown(report, report.blast_radii)
    assert "Reach" in md
    assert "Function" in md


def test_markdown_findings_table_reachability_unknown_when_absent() -> None:
    report = _report_with_reachability(None)
    md = to_markdown(report, report.blast_radii)
    assert "Reach" in md
    assert "Unknown" in md


# ── Instance 4: the KEV remediation deadline survives into EVERY format ──────
#
# ``kev_due_date`` is the CISA BOD 22-01 remediation deadline — the one KEV
# field that carries an obligation. Pinned to the live CISA catalog entry for
# CVE-2023-4863 (added 2023-09-13, due 2023-10-04). SARIF is what lands in
# GitHub Code Scanning, so dropping it there is the costliest omission.


def _kev_vuln(severity: Severity = Severity.CRITICAL) -> Vulnerability:
    """CVE-2023-4863 as CISA actually catalogs it."""
    return Vulnerability(
        id="CVE-2023-4863",
        summary="Heap buffer overflow in libwebp",
        severity=severity,
        cvss_score=8.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        fixed_version="10.0.1",
        epss_score=0.99735,
        epss_percentile=99.953,
        is_kev=True,
        kev_date_added="2023-09-13",
        kev_due_date="2023-10-04",
        cwe_ids=["CWE-787"],
    )


@pytest.mark.parametrize("severity", [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW])
def test_sarif_carries_kev_due_date_at_every_severity(severity: Severity) -> None:
    """SARIF must not reduce a dated BOD 22-01 obligation to ``kev: true``."""
    report = _report_with_vuln(_kev_vuln(severity))
    sarif = to_sarif(report)
    run = sarif["runs"][0]
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "CVE-2023-4863")
    result = next(r for r in run["results"] if r["ruleId"] == "CVE-2023-4863")
    assert rule["properties"].get("kev") is True
    assert rule["properties"].get("kev_due_date") == "2023-10-04"
    assert rule["properties"].get("kev_date_added") == "2023-09-13"
    assert result["properties"].get("kev_due_date") == "2023-10-04"
    assert result["properties"].get("kev_date_added") == "2023-09-13"


def test_sarif_omits_kev_dates_when_not_kev() -> None:
    """Non-vacuous: the dates appear only because the finding really is KEV."""
    plain = Vulnerability(id="CVE-2026-0001", summary="plain", severity=Severity.HIGH, cvss_score=7.0)
    sarif = to_sarif(_report_with_vuln(plain))
    run = sarif["runs"][0]
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "CVE-2026-0001")
    result = next(r for r in run["results"] if r["ruleId"] == "CVE-2026-0001")
    assert "kev_due_date" not in rule["properties"]
    assert "kev_date_added" not in rule["properties"]
    assert result["properties"].get("kev_due_date") is None


@pytest.mark.parametrize("severity", [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW])
def test_markdown_carries_kev_due_date_at_every_severity(severity: Severity) -> None:
    """A MEDIUM KEV has the same deadline as a CRITICAL one.

    The detail block only renders for critical/high findings, so the findings
    table itself has to carry the date or a medium/low KEV loses it entirely.
    """
    md = to_markdown(_report_with_vuln(_kev_vuln(severity)))
    assert "2023-10-04" in md, "KEV remediation deadline dropped from Markdown"


def test_markdown_kev_column_is_plain_dash_when_not_kev() -> None:
    """Non-vacuous: the deadline text appears only for a real KEV finding."""
    from agent_bom.output.finding_views import cve_findings
    from agent_bom.output.markdown import _kev_cell

    plain = Vulnerability(id="CVE-2026-0001", summary="plain", severity=Severity.MEDIUM)
    report = _report_with_vuln(plain)
    md = to_markdown(report)
    assert "2023-10-04" not in md
    assert "Yes (due" not in md
    assert _kev_cell(cve_findings(report)[0]) == "-"


def test_markdown_kev_cell_without_a_due_date_still_says_yes() -> None:
    """CISA has catalogued entries with no due date; KEV status must survive."""
    from agent_bom.output.finding_views import cve_findings
    from agent_bom.output.markdown import _kev_cell

    vuln = _kev_vuln()
    vuln.kev_due_date = None
    report = _report_with_vuln(vuln)
    assert _kev_cell(cve_findings(report)[0]) == "Yes"


@pytest.mark.parametrize("severity", [Severity.CRITICAL, Severity.MEDIUM])
def test_html_vuln_table_carries_kev_due_date(severity: Severity) -> None:
    report = _report_with_vuln(_kev_vuln(severity))
    html = _vuln_table(report, report.blast_radii)
    assert 'data-kev-due="2023-10-04"' in html
    assert "2023-10-04" in html


def test_html_vuln_table_has_no_kev_due_attribute_when_not_kev() -> None:
    plain = Vulnerability(id="CVE-2026-0001", summary="plain", severity=Severity.MEDIUM)
    report = _report_with_vuln(plain)
    html = _vuln_table(report, report.blast_radii)
    assert "data-kev-due=" not in html


def test_cyclonedx_carries_kev_due_date() -> None:
    cdx = to_cyclonedx(_report_with_vuln(_kev_vuln()))
    entry = next(v for v in cdx["vulnerabilities"] if v["id"] == "CVE-2023-4863")
    props = {p["name"]: p["value"] for p in entry.get("properties", [])}
    assert props.get("agent-bom:kev_due_date") == "2023-10-04"


def test_cyclonedx_rating_carries_the_cvss_vector() -> None:
    """CDX 1.7 ``ratings[].vector`` exists; emitting a bare score loses the
    attack metrics every downstream triage tool re-derives from the vector."""
    cdx = to_cyclonedx(_report_with_vuln(_kev_vuln()))
    entry = next(v for v in cdx["vulnerabilities"] if v["id"] == "CVE-2023-4863")
    cvss = next(r for r in entry["ratings"] if str(r.get("method", "")).startswith("CVSS"))
    assert cvss.get("vector") == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
    # A CVSS:3.1 vector is method CVSSv31 — CVSSv3 means 3.0 in the CDX enum.
    assert cvss.get("method") == "CVSSv31"


@pytest.mark.parametrize(
    ("vector", "expected_method"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "CVSSv31"),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSSv3"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CVSSv4"),
        ("AV:N/AC:L/Au:N/C:P/I:P/A:P", "CVSSv2"),
        (None, "CVSSv3"),
    ],
)
def test_cyclonedx_rating_method_follows_the_vector(vector: str | None, expected_method: str) -> None:
    vuln = _kev_vuln()
    vuln.cvss_vector = vector
    cdx = to_cyclonedx(_report_with_vuln(vuln))
    entry = next(v for v in cdx["vulnerabilities"] if v["id"] == "CVE-2023-4863")
    cvss = next(r for r in entry["ratings"] if str(r.get("method", "")).startswith("CVSS"))
    assert cvss["method"] == expected_method
    assert cvss.get("vector") == vector


def test_cyclonedx_with_vector_stays_schema_valid() -> None:
    pytest.importorskip("jsonschema")
    from jsonschema import Draft7Validator

    schema_path = _FIXTURES / "cyclonedx-1.7.schema.json"
    if not schema_path.exists():
        pytest.skip("vendored CycloneDX 1.7 schema unavailable")
    cdx = to_cyclonedx(_report_with_vuln(_kev_vuln()))
    validator = Draft7Validator(json.loads(schema_path.read_text()), registry=_cyclonedx_registry())
    errors = sorted(validator.iter_errors(cdx), key=lambda e: list(e.path))
    assert not errors, "\n".join(f"  - {'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors[:20])


def test_sarif_with_kev_dates_stays_schema_valid() -> None:
    pytest.importorskip("jsonschema")
    from jsonschema import Draft7Validator

    schema_path = _FIXTURES / "sarif-schema-2.1.0.json"
    if not schema_path.exists():
        pytest.skip("vendored SARIF 2.1.0 schema unavailable")
    sarif = to_sarif(_report_with_vuln(_kev_vuln()))
    validator = Draft7Validator(json.loads(schema_path.read_text()))
    errors = sorted(validator.iter_errors(sarif), key=lambda e: list(e.path))
    assert not errors, "\n".join(f"  - {'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors[:20])


def test_kev_due_date_reaches_every_serializing_format() -> None:
    """One assertion per format so a future exporter cannot drop it in silence."""
    from agent_bom.output.csv_fmt import to_csv
    from agent_bom.output.json_fmt import to_json
    from agent_bom.output.spdx_fmt import to_spdx

    report = _report_with_vuln(_kev_vuln())
    rendered = {
        "json": json.dumps(to_json(report)),
        "csv": to_csv(report),
        "markdown": to_markdown(report),
        "sarif": json.dumps(to_sarif(report)),
        "cyclonedx": json.dumps(to_cyclonedx(report)),
        "spdx": json.dumps(to_spdx(report)),
        "html": _vuln_table(report, report.blast_radii),
    }
    missing = sorted(name for name, text in rendered.items() if "2023-10-04" not in text)
    assert not missing, f"kev_due_date dropped by: {missing}"


# ── Instance 5: integrity / provenance verification reaches machine output ───
#
# ``--verify-integrity`` populates ``Package.integrity_verified`` and
# ``Package.provenance_attested`` (plus ``provenance_source``), but the verdict
# was console-only: no SBOM, SARIF, JSON or API consumer could read it. For a
# supply-chain scanner that verdict is the point of the scan, so every
# machine-readable serializer has to carry it — including the negative verdict,
# which is the one a release gate acts on.


def _report_with_integrity(
    *,
    integrity_verified: bool | None,
    provenance_attested: bool | None,
    provenance_source: str | None = None,
    provenance_status: str | None = None,
) -> AIBOMReport:
    report = _report_with_vuln(_kev_epss_cwe_vuln())
    pkg = report.agents[0].mcp_servers[0].packages[0]
    pkg.checksums = {"SHA-512": "c" * 128}
    pkg.integrity_verified = integrity_verified
    pkg.provenance_attested = provenance_attested
    pkg.provenance_source = provenance_source
    pkg.provenance_status = provenance_status
    return report


def _cdx_package_component(report: AIBOMReport) -> dict:
    cdx = to_cyclonedx(report)
    return next(c for c in cdx["components"] if c.get("purl") == "pkg:pypi/flask@0.12.2")


def _spdx3_package_statements(report: AIBOMReport) -> list[str]:
    from agent_bom.output.spdx_fmt import to_spdx

    doc = to_spdx(report)
    pkg = next(node for node in doc["@graph"] if node.get("name") == "flask")
    return [str(a.get("statement") or "") for a in pkg.get("annotation", [])]


def _spdx2_package_comments(report: AIBOMReport) -> list[str]:
    from agent_bom.output.spdx2_fmt import to_spdx2

    doc = to_spdx2(report)
    pkg = next(p for p in doc["packages"] if p["name"] == "flask")
    return [str(a.get("comment") or "") for a in pkg.get("annotations", [])]


def test_json_carries_integrity_and_provenance_verdict() -> None:
    from agent_bom.output.json_fmt import to_json

    payload = to_json(
        _report_with_integrity(integrity_verified=True, provenance_attested=True, provenance_source="npm_slsa")
    )
    pkg = payload["agents"][0]["mcp_servers"][0]["packages"][0]
    assert pkg["integrity_verified"] is True
    assert pkg["provenance_attested"] is True
    assert pkg["provenance_source"] == "npm_slsa"


def test_cyclonedx_component_properties_carry_verdict() -> None:
    component = _cdx_package_component(
        _report_with_integrity(integrity_verified=True, provenance_attested=True, provenance_source="npm_slsa")
    )
    props = {p["name"]: p["value"] for p in component.get("properties", [])}
    assert props.get("agent-bom:integrity-verified") == "true"
    assert props.get("agent-bom:provenance-attested") == "true"
    assert props.get("agent-bom:provenance-source") == "npm_slsa"


def test_cyclonedx_component_uses_native_identity_evidence() -> None:
    """CDX 1.7 models this natively: evidence.identity[].methods[].technique."""
    component = _cdx_package_component(
        _report_with_integrity(integrity_verified=True, provenance_attested=True, provenance_source="npm_slsa")
    )
    identities = component.get("evidence", {}).get("identity", [])
    techniques = {method["technique"]: method for entry in identities for method in entry.get("methods", [])}
    assert "hash-comparison" in techniques, "integrity verification must use the native hash-comparison technique"
    assert techniques["hash-comparison"]["confidence"] == 1.0
    assert "attestation" in techniques, "provenance attestation must use the native attestation technique"
    assert techniques["attestation"]["confidence"] == 1.0
    assert techniques["attestation"]["value"] == "npm_slsa"


def test_cyclonedx_failed_verification_is_confidence_zero_not_absent() -> None:
    component = _cdx_package_component(_report_with_integrity(integrity_verified=False, provenance_attested=False))
    props = {p["name"]: p["value"] for p in component.get("properties", [])}
    assert props.get("agent-bom:integrity-verified") == "false"
    assert props.get("agent-bom:provenance-attested") == "false"
    identities = component.get("evidence", {}).get("identity", [])
    techniques = {method["technique"]: method for entry in identities for method in entry.get("methods", [])}
    assert techniques["hash-comparison"]["confidence"] == 0.0
    assert techniques["attestation"]["confidence"] == 0.0


def test_cyclonedx_unverified_package_emits_no_verdict() -> None:
    """Non-vacuous: absent means "never checked", not "checked and failed"."""
    component = _cdx_package_component(_report_with_integrity(integrity_verified=None, provenance_attested=None))
    props = {p["name"] for p in component.get("properties", [])}
    assert "agent-bom:integrity-verified" not in props
    assert "agent-bom:provenance-attested" not in props
    assert "evidence" not in component


def test_cyclonedx_with_verdict_stays_schema_valid() -> None:
    pytest.importorskip("jsonschema")
    from jsonschema import Draft7Validator

    schema_path = _FIXTURES / "cyclonedx-1.7.schema.json"
    if not schema_path.exists():
        pytest.skip("vendored CycloneDX 1.7 schema unavailable")
    cdx = to_cyclonedx(
        _report_with_integrity(integrity_verified=True, provenance_attested=False, provenance_source="npm_slsa")
    )
    validator = Draft7Validator(json.loads(schema_path.read_text()), registry=_cyclonedx_registry())
    errors = sorted(validator.iter_errors(cdx), key=lambda e: list(e.path))
    assert not errors, "\n".join(f"  - {'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors[:20])


def test_spdx3_package_annotation_carries_verdict() -> None:
    statements = _spdx3_package_statements(
        _report_with_integrity(integrity_verified=True, provenance_attested=True, provenance_source="pypi_pep740")
    )
    assert "agent-bom:integrity-verified=true" in statements
    assert "agent-bom:provenance-attested=true source=pypi_pep740" in statements


def test_spdx3_package_annotation_carries_negative_verdict() -> None:
    statements = _spdx3_package_statements(_report_with_integrity(integrity_verified=False, provenance_attested=False))
    assert "agent-bom:integrity-verified=false" in statements
    assert "agent-bom:provenance-attested=false" in statements


def test_spdx3_unverified_package_has_no_verdict_annotation() -> None:
    statements = _spdx3_package_statements(_report_with_integrity(integrity_verified=None, provenance_attested=None))
    assert not [s for s in statements if "integrity-verified" in s or "provenance-attested" in s]


def test_spdx2_package_annotation_carries_verdict() -> None:
    comments = _spdx2_package_comments(
        _report_with_integrity(integrity_verified=True, provenance_attested=True, provenance_source="go_sumdb")
    )
    assert "agent-bom:integrity-verified=true" in comments
    assert "agent-bom:provenance-attested=true source=go_sumdb" in comments


def test_spdx2_unverified_package_has_no_verdict_annotation() -> None:
    comments = _spdx2_package_comments(_report_with_integrity(integrity_verified=None, provenance_attested=None))
    assert not [c for c in comments if "integrity-verified" in c or "provenance-attested" in c]


def test_spdx2_with_verdict_stays_schema_valid() -> None:
    pytest.importorskip("jsonschema")
    from jsonschema import Draft7Validator

    from agent_bom.output.spdx2_fmt import to_spdx2

    schema_path = _FIXTURES / "spdx-2.3.schema.json"
    if not schema_path.exists():
        pytest.skip("vendored SPDX 2.3 schema unavailable")
    doc = to_spdx2(
        _report_with_integrity(integrity_verified=True, provenance_attested=False, provenance_source="npm_slsa")
    )
    validator = Draft7Validator(json.loads(schema_path.read_text()))
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    assert not errors, "\n".join(f"  - {'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors[:20])


def test_sarif_result_carries_integrity_and_provenance_verdict() -> None:
    report = _report_with_integrity(integrity_verified=False, provenance_attested=True, provenance_source="npm_slsa")
    sarif = to_sarif(report)
    result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "CVE-2026-0001")
    props = result["properties"]
    assert props.get("package_integrity_verified") is False
    assert props.get("package_provenance_attested") is True
    assert props.get("package_provenance_source") == "npm_slsa"


def test_sarif_result_omits_verdict_when_not_verified() -> None:
    report = _report_with_integrity(integrity_verified=None, provenance_attested=None)
    sarif = to_sarif(report)
    result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "CVE-2026-0001")
    assert "package_integrity_verified" not in result["properties"]
    assert "package_provenance_attested" not in result["properties"]


def test_finding_evidence_carries_integrity_and_provenance_verdict() -> None:
    report = _report_with_integrity(integrity_verified=True, provenance_attested=False, provenance_source=None)
    finding = cve_findings(report)[0]
    assert finding.evidence.get("package_integrity_verified") is True
    assert finding.evidence.get("package_provenance_attested") is False


def test_integrity_verdict_reaches_every_serializing_format() -> None:
    """One assertion per format so a future exporter cannot drop it in silence."""
    from agent_bom.output.csv_fmt import to_csv
    from agent_bom.output.json_fmt import to_json
    from agent_bom.output.spdx2_fmt import to_spdx2
    from agent_bom.output.spdx_fmt import to_spdx

    report = _report_with_integrity(integrity_verified=True, provenance_attested=True, provenance_source="npm_slsa")
    rendered = {
        "json": json.dumps(to_json(report)),
        "csv": to_csv(report),
        "sarif": json.dumps(to_sarif(report)),
        "cyclonedx": json.dumps(to_cyclonedx(report)),
        "spdx3": json.dumps(to_spdx(report)),
        "spdx2": json.dumps(to_spdx2(report)),
    }
    missing = sorted(name for name, text in rendered.items() if "npm_slsa" not in text)
    assert not missing, f"provenance verdict dropped by: {missing}"


# ── Instance 6: a registry outage is not a negative attestation ─────────────
#
# ``check_package_provenance`` returns ``status: unavailable`` for a timeout, a
# 5xx or an unparseable body. The verdict then has to stay unknown AND say why,
# or a consumer reads an outage as "this package ships no attestation" — the
# verdict a release gate blocks on.


def _outage_report() -> AIBOMReport:
    return _report_with_integrity(
        integrity_verified=True,
        provenance_attested=None,
        provenance_status="unavailable",
    )


def test_json_distinguishes_an_unreachable_registry_from_a_missing_attestation() -> None:
    from agent_bom.output.json_fmt import to_json

    pkg = to_json(_outage_report())["agents"][0]["mcp_servers"][0]["packages"][0]
    assert pkg["provenance_attested"] is None
    assert pkg["provenance_status"] == "unavailable"


def test_cyclonedx_carries_the_provenance_status() -> None:
    component = _cdx_package_component(_outage_report())
    props = {p["name"]: p["value"] for p in component.get("properties", [])}
    assert props.get("agent-bom:provenance-status") == "unavailable"
    assert "agent-bom:provenance-attested" not in props, "an unanswered registry must not be published as a boolean verdict"
    # A 0.0-confidence attestation method means "documented failure" in CDX 1.7;
    # an unanswered question earns no identity evidence at all.
    identities = component.get("evidence", {}).get("identity", [])
    techniques = {m["technique"] for entry in identities for m in entry.get("methods", [])}
    assert "attestation" not in techniques


def test_spdx_annotations_carry_the_provenance_status() -> None:
    assert any("agent-bom:provenance-status=unavailable" in s for s in _spdx3_package_statements(_outage_report()))
    assert any("agent-bom:provenance-status=unavailable" in c for c in _spdx2_package_comments(_outage_report()))


def test_sarif_and_csv_and_findings_carry_the_provenance_status() -> None:
    from agent_bom.output.csv_fmt import to_csv

    report = _outage_report()
    result = next(r for r in to_sarif(report)["runs"][0]["results"] if r["ruleId"] == "CVE-2026-0001")
    assert result["properties"].get("package_provenance_status") == "unavailable"
    assert "package_provenance_attested" not in result["properties"]

    csv_text = to_csv(report)
    header, *rows = csv_text.splitlines()
    columns = header.split(",")
    assert "provenance_status" in columns
    cell = rows[0].split(",")[columns.index("provenance_status")]
    assert cell == "unavailable"
    assert rows[0].split(",")[columns.index("provenance_attested")] == "", (
        "an unanswered registry must leave the boolean column empty, not 'no'"
    )

    finding = cve_findings(report)[0]
    assert finding.evidence.get("package_provenance_status") == "unavailable"
    assert "package_provenance_attested" not in finding.evidence


def test_findings_api_payload_carries_the_provenance_status() -> None:
    """``/v1/findings`` redacts by default; this field has to survive that."""
    from agent_bom.finding_scope import safe_finding_response_payload

    payload = safe_finding_response_payload(
        {
            "id": "f-1",
            "finding_type": "cve",
            "evidence": {
                "package_integrity_verified": True,
                "package_provenance_status": "unavailable",
            },
        }
    )
    assert payload["package_integrity_verified"] is True
    assert payload["package_provenance_status"] == "unavailable"
    # The response model carries every field explicitly, so the unknown verdict
    # is an explicit null beside the status that explains it.
    assert payload["package_provenance_attested"] is None
