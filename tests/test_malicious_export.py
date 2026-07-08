"""Regression: vuln-less malicious packages reach gates and machine exports (#3682)."""

from __future__ import annotations

import pytest

from agent_bom.finding import FindingType
from agent_bom.models import Agent, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.output.csv_fmt import to_csv
from agent_bom.output.finding_views import machine_export_findings
from agent_bom.output.parquet_fmt import _row_dict
from agent_bom.policy import evaluate_policy


def _malicious_report() -> AIBOMReport:
    pkg = Package(
        name="evil-requests",
        version="9.9.9",
        ecosystem="pypi",
        is_malicious=True,
        malicious_reason="Typosquat of requests",
    )
    server = MCPServer(name="tools", command="npx", packages=[pkg])
    agent = Agent(name="dev-agent", agent_type="cli", config_path="/tmp/agent", mcp_servers=[server])
    return AIBOMReport(agents=[agent], blast_radii=[])


def test_malicious_package_synthesized_in_to_findings() -> None:
    report = _malicious_report()
    findings = report.to_findings()
    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_type == FindingType.MALICIOUS_PACKAGE
    assert finding.is_malicious is True
    assert finding.evidence.get("package_is_malicious") is True


def test_malicious_package_in_csv_export() -> None:
    report = _malicious_report()
    csv_text = to_csv(report)
    assert "evil-requests" in csv_text
    assert "yes" in csv_text.splitlines()[1]  # is_malicious column


def test_malicious_package_policy_gate() -> None:
    report = _malicious_report()
    policy = {
        "name": "malicious-gate",
        "rules": [{"id": "block-malicious", "is_malicious": True, "action": "fail"}],
    }
    result = evaluate_policy(policy, [], report=report)
    assert result["passed"] is False
    assert len(result["failures"]) == 1


def test_malicious_parquet_row_has_compliance_tags() -> None:
    report = _malicious_report()
    finding = report.to_findings()[0]
    row = _row_dict(finding)
    assert row["is_malicious"] is True
    assert row["malicious_reason"]


def _report_with_cve_and_malicious() -> AIBOMReport:
    """A report carrying a CVE BlastRadius *and* a vuln-less malicious package.

    This is the regression case: once a CVE BlastRadius exists the flat exporters
    used to return only BlastRadius rows, silently dropping the typosquat package.
    """
    vulnerable = Package(name="flask", version="0.12.2", ecosystem="pypi")
    vuln = Vulnerability(id="CVE-2018-1000656", summary="x", severity=Severity.HIGH, fixed_version="0.12.3")
    vulnerable.vulnerabilities = [vuln]
    evil = Package(name="reqeusts", version="1.0.0", ecosystem="pypi", is_malicious=True, malicious_reason="Typosquat of requests")
    server = MCPServer(name="tools", command="npx", packages=[vulnerable, evil])
    agent = Agent(name="dev-agent", agent_type="cli", config_path="/tmp/agent", mcp_servers=[server])
    br = BlastRadius(
        vulnerability=vuln,
        package=vulnerable,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
    return AIBOMReport(agents=[agent], blast_radii=[br])


def test_machine_export_includes_malicious_alongside_cve() -> None:
    report = _report_with_cve_and_malicious()
    findings = machine_export_findings(report, report.blast_radii)
    kinds = {f.finding_type for f in findings}
    assert FindingType.CVE in kinds
    assert FindingType.MALICIOUS_PACKAGE in kinds


def test_malicious_package_in_csv_when_cve_present() -> None:
    report = _report_with_cve_and_malicious()
    csv_text = to_csv(report)
    lines = csv_text.splitlines()
    header = lines[0].lstrip("﻿").split(",")
    mal_idx = header.index("is_malicious")
    evil_rows = [line.split(",") for line in lines[1:] if line.split(",")[1] == "reqeusts"]
    assert len(evil_rows) == 1, "typosquat package missing from CSV export"
    assert evil_rows[0][mal_idx] == "yes"


def test_malicious_package_in_parquet_when_cve_present() -> None:
    pytest.importorskip("pyarrow")
    from agent_bom.output.parquet_fmt import to_arrow_table

    report = _report_with_cve_and_malicious()
    rows = to_arrow_table(report).to_pylist()
    evil = [r for r in rows if r["package"] == "reqeusts"]
    assert len(evil) == 1, "typosquat package missing from Parquet export"
    assert evil[0]["is_malicious"] is True
    assert evil[0]["malicious_reason"]
