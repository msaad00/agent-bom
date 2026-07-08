"""Regression: vuln-less malicious packages reach gates and machine exports (#3682)."""

from __future__ import annotations

from agent_bom.finding import FindingType
from agent_bom.models import Agent, AIBOMReport, MCPServer, Package
from agent_bom.output.csv_fmt import to_csv
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
