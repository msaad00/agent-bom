"""Tests for JUnit XML, CSV, and Markdown output reporters."""

from __future__ import annotations

import csv
import io
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import (
    Agent,
    AgentStatus,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    MCPTool,
    Package,
    Severity,
    TransportType,
    Vulnerability,
)
from agent_bom.output import to_csv, to_json, to_junit, to_markdown, to_spdx
from agent_bom.output.html import to_html
from agent_bom.output.sarif import to_sarif

FIXTURES = Path(__file__).resolve().parent / "fixtures"

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
    tools: list[MCPTool] | None = None,
    env: dict[str, str] | None = None,
) -> MCPServer:
    return MCPServer(
        name=name,
        command="npx",
        args=[name],
        transport=TransportType.STDIO,
        packages=packages or [],
        tools=tools or [],
        env=env or {},
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


def _make_enriched_vuln() -> Vulnerability:
    return Vulnerability(
        id="CVE-2026-4242",
        severity=Severity.HIGH,
        severity_source="nvd:cvss_v3",
        summary="Enriched vulnerability",
        cvss_score=8.8,
        epss_score=0.812345,
        epss_percentile=99.1234,
        fixed_version="2.0.0",
        is_kev=True,
        kev_date_added="2026-01-15",
        kev_due_date="2026-02-05",
        cwe_ids=["CWE-79", "CWE-352"],
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

    def test_enrichment_and_compliance_metadata_are_appended(self):
        br = _make_blast_radius(pkg=_make_pkg("web-lib", "1.0.0"), vuln=_make_enriched_vuln())
        br.owasp_tags = ["LLM05"]
        br.soc2_tags = ["CC7.1"]
        report = _make_report(blast_radii=[br])

        csv_str = to_csv(report, [br])
        reader = csv.DictReader(io.StringIO(csv_str.lstrip("\ufeff")))
        row = next(reader)

        assert row["cwe_ids"] == "CWE-79;CWE-352"
        assert row["epss_score"] == "0.8123"
        assert row["is_kev"] == "yes"
        assert row["severity_source"] == "nvd:cvss_v3"
        assert row["epss_percentile"] == "99.1234"
        assert row["kev_date_added"] == "2026-01-15"
        assert row["kev_due_date"] == "2026-02-05"
        assert "owasp_llm:LLM05" in row["compliance_tags"]
        assert "soc2:CC7.1" in row["compliance_tags"]


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
    assert data["packages"] == data["ai_bom_entities"]["packages"]


def test_json_summary_distinguishes_total_vs_unique_packages():
    """Same package on two servers counts twice in `total_packages` (occurrences)
    but once in `unique_packages` (deduped by stable_id), matching
    `ai_bom_entities.packages`.

    v0.84.6 audit flagged operators reading `total_packages` and finding
    fewer entries in `ai_bom_entities.packages` than expected. Surfacing
    `unique_packages` makes the occurrence-vs-unique split self-documenting
    so the asymmetry can't read as a bug.
    """
    pkg = _make_pkg(name="lodash", version="4.17.20")
    pkg_other = _make_pkg(name="lodash", version="4.17.20")
    agent = _make_agent(
        servers=[
            _make_server(name="srv-a", packages=[pkg]),
            _make_server(name="srv-b", packages=[pkg_other]),
        ]
    )
    data = to_json(_make_report(agents=[agent]))

    assert data["summary"]["total_packages"] == 2, "occurrence count across servers"
    assert data["summary"]["unique_packages"] == 1, "deduped by stable_id"
    assert len(data["ai_bom_entities"]["packages"]) == data["summary"]["unique_packages"]


def test_json_inventory_snapshot_round_trips_through_inventory_schema(tmp_path):
    from agent_bom.inventory import _inventory_validator, load_inventory

    pkg = _make_pkg(name="openssl", version="3.0.16", ecosystem="deb")
    server = _make_server(name="image-scan", packages=[pkg])
    from agent_bom.models import ServerSurface

    server.surface = ServerSurface.CONTAINER_IMAGE
    agent = _make_agent(name="image:agent-bom", servers=[server])
    data = to_json(_make_report(agents=[agent]))
    snapshot = data["inventory_snapshot"]

    errors = sorted(_inventory_validator().iter_errors(snapshot), key=lambda error: list(error.path))
    assert errors == []
    assert snapshot["agents"][0]["mcp_servers"][0]["packages"][0]["ecosystem"] == "unknown"

    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    loaded = load_inventory(str(path))
    assert loaded["agents"][0]["name"] == "image:agent-bom"


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

    def test_demo_markdown_export_matches_golden_fixture(self):
        report, brs = _report_with_vulns()
        golden = (FIXTURES / "output" / "demo-markdown-golden.md").read_text(encoding="utf-8")
        rendered = to_markdown(report, brs).replace("  \n", "\n")

        assert rendered == golden

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

    def test_findings_table_preserves_enrichment_and_compliance_metadata(self):
        br = _make_blast_radius(pkg=_make_pkg("web-lib", "1.0.0"), vuln=_make_enriched_vuln())
        br.owasp_tags = ["LLM05"]
        br.soc2_tags = ["CC7.1"]
        report = _make_report(blast_radii=[br])

        md = to_markdown(report, [br])

        assert "| Severity | CVE | Package | Version | Fix | CVSS | EPSS | KEV | CWE | Tags | Source | Agents |" in md
        assert "0.8123" in md
        assert "Yes" in md
        assert "CWE-79, CWE-352" in md
        assert "owasp_llm:LLM05" in md
        assert "soc2:CC7.1" in md
        assert "nvd:cvss_v3" in md
        assert "- **EPSS percentile**: 99.1234" in md
        assert "- **KEV date added**: 2026-01-15" in md

    def test_exposure_paths_render_in_markdown(self):
        tool = MCPTool(name="deploy", description="Deploy workloads")
        server = _make_server(name="prod-mcp", tools=[tool], env={"AWS_SECRET_ACCESS_KEY": "redacted"})
        agent = _make_agent(name="prod-agent", servers=[server])
        br = _make_blast_radius(agents=[agent])
        br.affected_servers = [server]
        br.exposed_tools = [tool]
        br.exposed_credentials = ["AWS_SECRET_ACCESS_KEY"]
        br.risk_score = 9.4
        report = _make_report(agents=[agent], blast_radii=[br])

        md = to_markdown(report, [br])

        assert "## Exposure Paths" in md
        assert "| #1 | 9.4 | CRITICAL | lodash@4.17.20 -> CVE-2024-0001 |" in md
        assert "1 affected agent(s), 1 affected server(s), 1 reachable tool(s), 1 exposed credential reference(s)" in md
        assert "Upgrade lodash to 4.17.21" in md

    def test_skill_trust_axes_render_in_markdown(self):
        report = _make_report()
        report.trust_assessment_data = {
            "skill_name": "scan",
            "source_file": "SKILL.md",
            "verdict": "benign",
            "content_verdict": "benign",
            "provenance_verdict": "unverified",
            "review_verdict": "review",
            "overall_recommendation": "review",
            "confidence": "medium",
            "categories": [],
            "recommendations": [],
        }

        md = to_markdown(report)

        assert "## Skill Trust Assessment" in md
        assert "| Content verdict | `benign` |" in md
        assert "| Provenance verdict | `unverified` |" in md
        assert "| Recommendation | `review` |" in md


def test_exposure_path_is_embedded_in_sarif_properties():
    tool = MCPTool(name="deploy", description="Deploy workloads")
    server = _make_server(name="prod-mcp", tools=[tool], env={"AWS_SECRET_ACCESS_KEY": "redacted"})
    agent = _make_agent(name="prod-agent", servers=[server])
    br = _make_blast_radius(agents=[agent])
    br.affected_servers = [server]
    br.exposed_tools = [tool]
    br.exposed_credentials = ["AWS_SECRET_ACCESS_KEY"]
    br.risk_score = 9.4
    report = _make_report(agents=[agent], blast_radii=[br])

    sarif = to_sarif(report)
    exposure_path = sarif["runs"][0]["results"][0]["properties"]["exposure_path"]

    assert exposure_path["label"] == "lodash@4.17.20 -> CVE-2024-0001"
    assert exposure_path["affectedAgents"] == ["prod-agent"]
    assert exposure_path["affectedServers"] == ["prod-mcp"]
    assert exposure_path["reachableTools"] == ["deploy"]
    assert exposure_path["exposedCredentials"] == ["AWS_SECRET_ACCESS_KEY"]
    assert {
        "id": "agent:prod-agent->uses->server:prod-mcp",
        "type": "uses",
        "source": "agent:prod-agent",
        "target": "server:prod-mcp",
    } in exposure_path["relationships"]


def test_skill_trust_axes_are_embedded_in_sarif_properties():
    report = _make_report()
    report.trust_assessment_data = {
        "skill_name": "scan",
        "source_file": "SKILL.md",
        "verdict": "benign",
        "content_verdict": "benign",
        "provenance_verdict": "unverified",
        "review_verdict": "review",
        "overall_recommendation": "review",
        "confidence": "medium",
        "categories": [],
        "recommendations": [],
    }

    sarif = to_sarif(report)
    trust = sarif["runs"][0]["properties"]["trust_assessment"]

    assert trust["verdict"] == "benign"
    assert trust["content_verdict"] == "benign"
    assert trust["provenance_verdict"] == "unverified"
    assert trust["overall_recommendation"] == "review"


def test_html_renders_exposure_path_investigation_briefs():
    tool = MCPTool(name="deploy", description="Deploy workloads")
    server = _make_server(name="prod-mcp", tools=[tool], env={"AWS_SECRET_ACCESS_KEY": "redacted"})
    agent = _make_agent(name="prod-agent", servers=[server])
    br = _make_blast_radius(agents=[agent])
    br.affected_servers = [server]
    br.exposed_tools = [tool]
    br.exposed_credentials = ["AWS_SECRET_ACCESS_KEY"]
    br.risk_score = 9.4
    report = _make_report(agents=[agent], blast_radii=[br])

    html = to_html(report, [br])

    assert 'id="exposure-paths"' in html
    assert "Exposure Paths" in html
    assert "lodash@4.17.20 -&gt; CVE-2024-0001" in html
    assert "1 affected agent(s), 1 affected server(s), 1 reachable tool(s), 1 exposed credential reference(s)" in html
    assert "Upgrade lodash to 4.17.21" in html


def test_spdx_vulnerability_annotations_preserve_enrichment_and_compliance_metadata():
    vuln = _make_enriched_vuln()
    pkg = _make_pkg("web-lib", "1.0.0")
    pkg.vulnerabilities = [vuln]
    br = _make_blast_radius(pkg=pkg, vuln=vuln)
    br.owasp_tags = ["LLM05"]
    br.soc2_tags = ["CC7.1"]
    report = _make_report(agents=[_make_agent(servers=[_make_server(packages=[pkg])])], blast_radii=[br])

    spdx = to_spdx(report)
    vuln_element = next(element for element in spdx["elements"] if element.get("type") == "security/Vulnerability")
    statements = {annotation["statement"] for annotation in vuln_element["annotation"]}

    assert "agent-bom:severity-source=nvd:cvss_v3" in statements
    assert "agent-bom:epss-score=0.8123" in statements
    assert "agent-bom:epss-percentile=99.1234" in statements
    assert "agent-bom:kev=true" in statements
    assert "agent-bom:kev-date-added=2026-01-15" in statements
    assert "agent-bom:cwe=CWE-79" in statements
    assert "agent-bom:cwe=CWE-352" in statements
    assert "agent-bom:compliance-tag=owasp_llm:LLM05" in statements
    assert "agent-bom:compliance-tag=soc2:CC7.1" in statements


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


def test_cytoscape_graph_includes_credential_to_tool_reachability_evidence():
    from agent_bom.output.graph import build_graph_elements

    server = _make_server(
        "github",
        tools=[MCPTool(name="create_issue", description="Create issue"), MCPTool(name="delete_repo", description="Delete repo")],
        env={"GITHUB_TOKEN": "***"},
    )
    report = _make_report(agents=[_make_agent(servers=[server])])

    elements = build_graph_elements(report, [])
    reaches_edges = [
        element["data"]
        for element in elements
        if element.get("data", {}).get("type") == "reaches_tool" and element["data"].get("credential_env_var") == "GITHUB_TOKEN"
    ]

    assert reaches_edges
    assert reaches_edges[0]["mapping_method"] == "server_scope_conservative"
    assert reaches_edges[0]["confidence"] == "medium"


def test_cytoscape_package_nodes_include_version_provenance():
    from agent_bom.output.graph import build_graph_elements

    pkg = _make_pkg("axios", "1.4.0", "npm")
    pkg.version_source = "lockfile"
    server = _make_server("github", packages=[pkg])
    agent = _make_agent(servers=[server])
    report = _make_report(agents=[agent])
    blast_radius = _make_blast_radius(pkg=pkg, agents=[agent])

    elements = build_graph_elements(report, [blast_radius])
    package = next(element["data"] for element in elements if element.get("data", {}).get("type") == "pkg_vuln")

    assert package["versionSource"] == "lockfile"
    assert package["versionConfidence"] == "exact"
    assert '"version_source": "lockfile"' in package["versionProvenance"]
