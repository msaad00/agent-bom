"""Regression coverage for the JSON remediation projection hot path."""

from __future__ import annotations

from agent_bom.finding import blast_radius_to_finding
from agent_bom.models import AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability


def _report_with_materialized_cve() -> AIBOMReport:
    package = Package(name="requests", version="2.0.0", ecosystem="pypi")
    server = MCPServer(name="test-server", command="npx test-server")
    blast = BlastRadius(
        vulnerability=Vulnerability(
            id="CVE-2026-0001",
            summary="test vulnerability",
            severity=Severity.HIGH,
            fixed_version="2.0.1",
        ),
        package=package,
        affected_servers=[server],
        affected_agents=[],
        exposed_credentials=["OPENAI_API_KEY"],
        exposed_tools=[],
        risk_score=7.0,
    )
    return AIBOMReport(
        blast_radii=[blast],
        findings=[blast_radius_to_finding(blast)],
    )


def test_json_remediation_reuses_materialized_cve_projection(monkeypatch):
    """JSON remediation must not reconvert nested BlastRadius dataclasses."""
    report = _report_with_materialized_cve()

    def fail_if_reconverted(_blast):
        raise AssertionError("remediation JSON reconverted a materialized BlastRadius")

    monkeypatch.setattr("agent_bom.finding.blast_radius_to_finding", fail_if_reconverted)

    from agent_bom.output.json_fmt import _build_remediation_json

    payload = _build_remediation_json(report)

    assert payload and payload[0]["package"] == "requests"
