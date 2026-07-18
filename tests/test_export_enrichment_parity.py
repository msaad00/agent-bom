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
