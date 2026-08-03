"""One SARIF document must state one severity per finding severity.

``to_sarif`` builds five result streams. The CVE stream uses the module-level
``_SARIF_SEVERITY_MAP`` / ``_SECURITY_SEVERITY_SCORE`` tables; the unified
finding, IaC, AI and CIS streams each carried their own inline copy keyed by
severity *string*. Those copies had no ``none`` and no ``unknown`` key and fell
back to ``warning`` / ``security-severity 4.0``, so a finding the scanner
explicitly rated ``none`` — or one it could not rate at all — was published to
GitHub code scanning as **Medium**, while the CVE stream in the same file
published the identical severity as ``note`` / ``0.0``.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import AIBOMReport, BlastRadius, Package, Severity, Vulnerability
from agent_bom.output.sarif import to_sarif

SEVERITIES = ["critical", "high", "medium", "low", "none", "unknown"]


def _asset() -> Asset:
    return Asset(name="warehouse", asset_type="file", location="infra/main.tf")


def _rules_by_id(severity: str) -> dict[str, dict[str, Any]]:
    """SARIF rules for a report carrying the same severity on every stream."""
    report = AIBOMReport()
    report.findings = [
        Finding(
            finding_type=FindingType.CIS_ERROR,
            source=FindingSource.CLOUD_SECURITY,
            asset=_asset(),
            severity=severity,
            title="Check could not be evaluated",
            description="The provider API returned no data for this control.",
            id=f"unified-{severity}",
        )
    ]
    report.iac_findings_data = {
        "findings": [
            {
                "rule_id": f"TF-{severity}",
                "severity": severity,
                "title": "Storage bucket is public",
                "message": "Bucket grants public read.",
                "file_path": "infra/main.tf",
                "line_number": 12,
            }
        ]
    }

    # No CVSS score, so the CVE stream falls back to its severity table rather
    # than echoing a numeric score.
    vuln = Vulnerability(id=f"GHSA-0000-0000-{severity}", summary="s", severity=Severity(severity), cvss_score=None)
    pkg = Package(name="left-pad", version="1.0.0", ecosystem="npm", vulnerabilities=[vuln], is_direct=True)
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )
    br.calculate_risk_score()

    doc = to_sarif(report, blast_radii=[br])
    return {rule["id"]: rule for rule in doc["runs"][0]["tool"]["driver"]["rules"]}


def _verdict(rule: dict[str, Any]) -> tuple[str, str]:
    return rule["defaultConfiguration"]["level"], rule["properties"]["security-severity"]


@pytest.mark.parametrize("severity", SEVERITIES)
def test_every_result_stream_agrees_on_one_severity(severity: str) -> None:
    rules = _rules_by_id(severity)
    cve = rules[f"GHSA-0000-0000-{severity}"]
    unified = rules["finding/CIS_ERROR"]
    iac = rules[f"iac/TF-{severity}"]

    verdicts = {"cve": _verdict(cve), "unified": _verdict(unified), "iac": _verdict(iac)}

    assert len(set(verdicts.values())) == 1, verdicts


@pytest.mark.parametrize("severity", ["none", "unknown"])
def test_unrated_findings_are_never_published_as_medium(severity: str) -> None:
    """GitHub reads security-severity 4.0–6.9 as Medium; unrated is not Medium."""
    rules = _rules_by_id(severity)

    for rule_id in ("finding/CIS_ERROR", f"iac/TF-{severity}"):
        level, score = _verdict(rules[rule_id])
        assert float(score) < 4.0, (rule_id, level, score)
        assert level != "warning", (rule_id, level, score)
