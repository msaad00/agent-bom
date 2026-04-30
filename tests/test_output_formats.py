"""Tests for JUnit XML, CSV, and Markdown output reporters."""

from __future__ import annotations

import csv
import io
import xml.etree.ElementTree as ET
from datetime import datetime

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import (
    Agent,
    AgentStatus,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    TransportType,
    Vulnerability,
)
from agent_bom.output import to_csv, to_json, to_junit, to_markdown
from agent_bom.output.html import to_html

# ── Fixtures ─────────────────────────────────────────────────────────────────


def _make_report(
    agents: list[Agent] | None = None,
    blast_radii: list[BlastRadius] | None = None,
) -> AIBOMReport:
    return AIBOMReport(
        agents=agents or [],
        blast_radii=blast_radii or [],
        generated_at=datetime(2026, 1, 1, 12, 0, 0),
        tool_version="0.70.6",
    )


def _make_agent(
    name: str = "claude",
    servers: list[MCPServer] | None = None,
) -> Agent:
    return Agent(
        name=name,
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/test.json",
        mcp_servers=servers or [],
        status=AgentStatus.CONFIGURED,
    )


def _make_server(
    name: str = "test-server",
    packages: list[Package] | None = None,
) -> MCPServer:
    return MCPServer(
        name=name,
        command="npx",
        args=[name],
        transport=TransportType.STDIO,
        packages=packages or [],
        env={},
    )


def _make_pkg(
    name: str = "lodash",
    version: str = "4.17.20",
    ecosystem: str = "npm",
) -> Package:
    return Package(name=name, version=version, ecosystem=ecosystem)


def _make_vuln(
    cve_id: str = "CVE-2024-0001",
    severity: Severity = Severity.CRITICAL,
    cvss_score: float | None = 9.8,
    fixed_version: str | None = "4.17.21",
    cwe_ids: list[str] | None = None,
) -> Vulnerability:
    return Vulnerability(
        id=cve_id,
        severity=severity,
        summary="Test vulnerability",
        cvss_score=cvss_score,
        fixed_version=fixed_version,
        cwe_ids=cwe_ids or [],
    )


def _make_blast_radius(
    pkg: Package | None = None,
    vuln: Vulnerability | None = None,
    agents: list[Agent] | None = None,
) -> BlastRadius:
    return BlastRadius(
        package=pkg or _make_pkg(),
        vulnerability=vuln or _make_vuln(),
        affected_agents=agents or [_make_agent()],
        affected_servers=[],
        exposed_credentials=[],
        exposed_tools=[],
    )


def _report_with_vulns() -> tuple[AIBOMReport, list[BlastRadius]]:
    """Report with mixed-severity findings across ecosystems."""
    agent = _make_agent(servers=[_make_server(packages=[_make_pkg()])])
    brs = [
        _make_blast_radius(
            pkg=_make_pkg("lodash", "4.17.20", "npm"),
            vuln=_make_vuln("CVE-2024-0001", Severity.CRITICAL, 9.8, "4.17.21", ["CWE-1321"]),
            agents=[agent],
        ),
        _make_blast_radius(
            pkg=_make_pkg("requests", "2.28.0", "pypi"),
            vuln=_make_vuln("CVE-2024-0002", Severity.HIGH, 7.5, "2.31.0"),
            agents=[agent],
        ),
        _make_blast_radius(
            pkg=_make_pkg("express", "4.18.0", "npm"),
            vuln=_make_vuln("CVE-2024-0003", Severity.MEDIUM, 5.3),
            agents=[agent],
        ),
        _make_blast_radius(
            pkg=_make_pkg("debug", "4.3.0", "npm"),
            vuln=_make_vuln("CVE-2024-0004", Severity.LOW, 2.1),
            agents=[agent],
        ),
    ]
    report = _make_report(agents=[agent], blast_radii=brs)
    return report, brs


def _report_with_policy_finding() -> AIBOMReport:
    """Report with a unified non-CVE finding and no vulnerable packages."""
    report = _make_report(agents=[_make_agent(servers=[_make_server()])])
    report.findings = [
        Finding(
            finding_type=FindingType.MCP_BLOCKLIST,
            source=FindingSource.MCP_SCAN,
            asset=Asset(name="credential-stealer", asset_type="mcp_server", location="/tmp/mcp.json"),
            severity="high",
            title="Suspicious credential exfiltration MCP server",
            description="Matched the MCP intelligence blocklist.",
            remediation_guidance="Remove this server or replace it with a trusted MCP server.",
            evidence={"match_type": "pattern", "confidence": "suspicious"},
        ),
        Finding(
            finding_type=FindingType.CIS_FAIL,
            source=FindingSource.CLOUD_CIS,
            asset=Asset(
                name="snowflake-cortex-service",
                asset_type="cloud_resource",
                identifier="snowflake://acct/cortex/svc",
                location="snowflake:us-west-2",
            ),
            severity="medium",
            title="Cloud AI service missing hardened policy",
            description="Snowflake Cortex service policy needs review.",
            remediation_guidance="Review provider contract and tighten the service policy.",
            evidence={"scan_mode": "operator_pushed_inventory", "permissions_used": "read-only"},
        ),
    ]
    return report


# ── JUnit XML ────────────────────────────────────────────────────────────────


class TestJUnit:
    def test_empty_report(self):
        report = _make_report()
        xml_str = to_junit(report)
        assert xml_str.startswith("<?xml")
        root = ET.fromstring(xml_str)
        assert root.tag == "testsuites"

    def test_valid_xml_structure(self):
        report, brs = _report_with_vulns()
        xml_str = to_junit(report, brs)
        root = ET.fromstring(xml_str)
        assert root.tag == "testsuites"
        suites = root.findall("testsuite")
        assert len(suites) >= 1

    def test_ecosystems_become_suites(self):
        report, brs = _report_with_vulns()
        xml_str = to_junit(report, brs)
        root = ET.fromstring(xml_str)
        suite_names = {s.get("name") for s in root.findall("testsuite")}
        assert "npm" in suite_names
        assert "pypi" in suite_names

    def test_critical_becomes_failure(self):
        report, brs = _report_with_vulns()
        xml_str = to_junit(report, brs)
        root = ET.fromstring(xml_str)
        # Find the npm suite and look for a failure element
        for suite in root.findall("testsuite"):
            for tc in suite.findall("testcase"):
                if "CVE-2024-0001" in (tc.get("name") or ""):
                    assert tc.find("failure") is not None

    def test_medium_becomes_error(self):
        report, brs = _report_with_vulns()
        xml_str = to_junit(report, brs)
        root = ET.fromstring(xml_str)
        for suite in root.findall("testsuite"):
            for tc in suite.findall("testcase"):
                if "CVE-2024-0003" in (tc.get("name") or ""):
                    assert tc.find("error") is not None

    def test_low_becomes_skipped(self):
        report, brs = _report_with_vulns()
        xml_str = to_junit(report, brs)
        root = ET.fromstring(xml_str)
        for suite in root.findall("testsuite"):
            for tc in suite.findall("testcase"):
                if "CVE-2024-0004" in (tc.get("name") or ""):
                    assert tc.find("skipped") is not None

    def test_testcase_has_classname(self):
        report, brs = _report_with_vulns()
        xml_str = to_junit(report, brs)
        root = ET.fromstring(xml_str)
        for suite in root.findall("testsuite"):
            for tc in suite.findall("testcase"):
                assert tc.get("classname")


# ── CSV ──────────────────────────────────────────────────────────────────────


class TestCSV:
    def test_empty_report(self):
        report = _make_report()
        csv_str = to_csv(report)
        # Should have header row only (after BOM)
        content = csv_str.lstrip("\ufeff")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
        assert len(rows) == 1  # header only
        assert "cve_id" in rows[0]

    def test_utf8_bom(self):
        report = _make_report()
        csv_str = to_csv(report)
        assert csv_str.startswith("\ufeff")

    def test_column_count(self):
        report, brs = _report_with_vulns()
        csv_str = to_csv(report, brs)
        content = csv_str.lstrip("\ufeff")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
        header = rows[0]
        assert len(header) >= 10  # at least core columns
        # All data rows have same column count
        for row in rows[1:]:
            assert len(row) == len(header)

    def test_data_rows(self):
        report, brs = _report_with_vulns()
        csv_str = to_csv(report, brs)
        content = csv_str.lstrip("\ufeff")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
        assert len(rows) == 5  # 1 header + 4 vulns

    def test_severity_values(self):
        report, brs = _report_with_vulns()
        csv_str = to_csv(report, brs)
        content = csv_str.lstrip("\ufeff")
        reader = csv.DictReader(io.StringIO(content))
        severities = {row["severity"] for row in reader}
        assert "critical" in severities
        assert "high" in severities

    def test_cve_ids_present(self):
        report, brs = _report_with_vulns()
        csv_str = to_csv(report, brs)
        assert "CVE-2024-0001" in csv_str
        assert "CVE-2024-0002" in csv_str

    def test_published_dates_present(self):
        report, brs = _report_with_vulns()
        brs[0].vulnerability.published_at = "2026-03-21T12:00:00Z"
        brs[0].vulnerability.modified_at = "2026-03-23T09:00:00Z"
        csv_str = to_csv(report, brs)
        content = csv_str.lstrip("\ufeff")
        reader = csv.DictReader(io.StringIO(content))
        rows = list(reader)
        assert "published_at" in reader.fieldnames
        assert "modified_at" in reader.fieldnames
        assert rows[0]["published_at"] == "2026-03-21T12:00:00Z"
        assert rows[0]["modified_at"] == "2026-03-23T09:00:00Z"


class TestJSON:
    def test_nested_package_vulnerability_count_present(self):
        pkg = _make_pkg("ncurses-bin", "6.5+20250216-2", "deb")
        pkg.vulnerabilities = [
            _make_vuln("DEBIAN-CVE-2025-6141", Severity.CRITICAL, 9.8),
            _make_vuln("DEBIAN-CVE-2025-69720", Severity.CRITICAL, 9.8),
        ]
        server = _make_server("image-server", packages=[pkg])
        report = _make_report(agents=[_make_agent(name="image:test", servers=[server])])

        result = to_json(report)
        nested_pkg = result["agents"][0]["mcp_servers"][0]["packages"][0]

        assert nested_pkg["vulnerability_count"] == 2
        assert len(nested_pkg["vulnerabilities"]) == 2

    def test_scan_performance_passthrough_present(self):
        report = _make_report()
        report.scan_performance_data = {
            "osv": {"cache_hits": 5, "cache_misses": 2, "cache_hit_rate_pct": 71},
            "registry": {"cache_hits": 4, "cache_misses": 1, "cache_hit_rate_pct": 80},
        }

        result = to_json(report)

        assert result["scan_performance"]["osv"]["cache_hits"] == 5
        assert result["scan_performance"]["registry"]["cache_hit_rate_pct"] == 80


def test_json_runtime_session_graph_passthrough():
    report = _make_report()
    report.runtime_session_graph = {
        "node_count": 1,
        "edge_count": 0,
        "nodes": [{"id": "tool:read_file", "kind": "tool"}],
        "edges": [],
    }
    data = to_json(report)
    assert "runtime_session_graph" in data
    assert data["runtime_session_graph"]["node_count"] == 1


def test_json_includes_ai_bom_entities():
    report = _make_report(agents=[_make_agent(servers=[_make_server(packages=[_make_pkg()])])])
    data = to_json(report)
    assert "ai_bom_entities" in data
    assert data["ai_bom_entities"]["schema_version"] == "1.0"
    assert data["ai_bom_entities"]["summary"]["agents"] == 1


# ── Markdown ─────────────────────────────────────────────────────────────────


class TestMarkdown:
    def test_empty_report(self):
        report = _make_report()
        md = to_markdown(report)
        assert "# agent-bom Scan Report" in md
        assert "No vulnerabilities found" in md

    def test_summary_table(self):
        report, brs = _report_with_vulns()
        md = to_markdown(report, brs)
        assert "| Metric | Count |" in md
        assert "Vulnerabilities" in md

    def test_findings_table(self):
        report, brs = _report_with_vulns()
        md = to_markdown(report, brs)
        assert "## Findings" in md
        assert "CVE-2024-0001" in md
        assert "CVE-2024-0002" in md

    def test_critical_high_details(self):
        report, brs = _report_with_vulns()
        md = to_markdown(report, brs)
        assert "## Critical & High Findings" in md
        assert "### CVE-2024-0001" in md

    def test_severity_badges(self):
        report, brs = _report_with_vulns()
        md = to_markdown(report, brs)
        assert "**CRITICAL**" in md
        assert "**HIGH**" in md

    def test_fix_version_shown(self):
        report, brs = _report_with_vulns()
        md = to_markdown(report, brs)
        assert "4.17.21" in md
        assert "2.31.0" in md

    def test_footer(self):
        report, brs = _report_with_vulns()
        md = to_markdown(report, brs)
        assert "agent-bom" in md.split("---")[-1]

    def test_version_in_header(self):
        report = _make_report()
        md = to_markdown(report)
        assert "0.70.6" in md

    def test_unified_non_cve_findings_are_rendered(self):
        report = _report_with_policy_finding()
        md = to_markdown(report)

        assert "## Policy & Security Findings" in md
        assert "MCP_BLOCKLIST" in md
        assert "CIS_FAIL" in md
        assert "credential-stealer" in md
        assert "snowflake-cortex-service" in md
        assert "Suspicious credential exfiltration MCP server" in md
        assert "No vulnerabilities found" not in md


def test_html_renders_unified_non_cve_findings_with_asset_context():
    report = _report_with_policy_finding()
    html = to_html(report, [])

    assert "SECURITY FINDINGS" in html
    assert "Policy &amp; Security Findings" in html
    assert 'id="policyFindingsTable"' in html
    assert 'class="policy-sev-filter"' in html
    assert 'id="policyTypeFilter"' in html
    assert 'id="policyAssetFilter"' in html
    assert 'id="policySearch"' in html
    assert "filterPolicyFindingsTable" in html
    assert "MCP_BLOCKLIST" in html
    assert "CIS_FAIL" in html
    assert "credential-stealer" in html
    assert "snowflake-cortex-service" in html
    assert "cloud_resource" in html
    assert "operator_pushed_inventory" in html
    assert "/tmp/mcp.json" in html
    assert "Matched the MCP intelligence blocklist." in html
    assert "Unified non-CVE findings" in html
