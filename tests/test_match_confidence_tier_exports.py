"""match_confidence_tier + canonical cve_ids must surface across every report
export, not just the unified ``finding.py`` JSON. A buyer filtering on the
``nvd_cpe_candidate`` (review-grade) tier needs it in SARIF, the JSON report,
and the HTML dashboard alike.
"""

from __future__ import annotations

import json

from agent_bom.models import (
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    Package,
    Severity,
    Vulnerability,
)
from agent_bom.output.html import to_html
from agent_bom.output.json_fmt import to_json
from agent_bom.output.sarif import to_sarif


def _report_with_tier() -> AIBOMReport:
    vuln = Vulnerability(
        id="GHSA-xxxx-yyyy-zzzz",
        summary="Candidate match via NVD CPE",
        severity=Severity.HIGH,
        cvss_score=7.5,
        fixed_version="2.0.0",
        aliases=["CVE-2026-12345", "CVE-2026-99999"],
        match_confidence_tier="nvd_cpe_candidate",
    )
    pkg = Package(
        name="acme-lib",
        version="1.4.2",
        ecosystem="pypi",
        purl="pkg:pypi/acme-lib@1.4.2",
        vulnerabilities=[vuln],
        is_direct=True,
    )
    agent = Agent(
        name="claude-desktop",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/claude-desktop.json",
        mcp_servers=[],
        version="1.0",
    )
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
    br.calculate_risk_score()
    return AIBOMReport(
        agents=[agent],
        blast_radii=[br],
        findings=[],
        scan_sources=["agent_discovery"],
        scan_id="tier-test-001",
    )


def test_sarif_carries_tier_and_canonical_cve_ids() -> None:
    doc = to_sarif(_report_with_tier())
    result = doc["runs"][0]["results"][0]
    props = result["properties"]
    assert props["match_confidence_tier"] == "nvd_cpe_candidate"
    # Canonical CVE list derives from id + aliases, deduped/sorted, CVE-only.
    assert props["cve_ids"] == ["CVE-2026-12345", "CVE-2026-99999"]


def test_json_report_carries_tier() -> None:
    payload = to_json(_report_with_tier())  # to_json returns a dict
    blob = json.dumps(payload)
    assert "nvd_cpe_candidate" in blob
    assert '"match_confidence_tier"' in blob


def test_html_dashboard_renders_tier() -> None:
    report = _report_with_tier()
    html = to_html(report, report.blast_radii)
    assert "nvd_cpe_candidate" in html
    assert "match-tier" in html
