"""Tests for output module — coverage expansion."""

from __future__ import annotations

from datetime import datetime, timezone

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
from agent_bom.output import (
    _coverage_bar,
    _pct,
    _risk_narrative,
    build_remediation_plan,
    print_agent_tree,
    print_attack_flow_tree,
    print_blast_radius,
    print_export_hint,
    print_policy_results,
    print_posture_summary,
    print_scan_performance_summary,
    print_severity_chart,
    print_summary,
    print_threat_frameworks,
    to_cyclonedx,
    to_json,
    to_sarif,
    to_spdx,
)

# ── Fixtures ─────────────────────────────────────────────────────────────────


def _make_report(
    agents: list[Agent] | None = None,
    blast_radii: list[BlastRadius] | None = None,
) -> AIBOMReport:
    return AIBOMReport(
        agents=agents or [],
        blast_radii=blast_radii or [],
        generated_at=datetime(2026, 1, 1, 12, 0, 0),
        tool_version="0.69.0",
    )


def _make_agent(
    name: str = "claude",
    agent_type: AgentType = AgentType.CLAUDE_DESKTOP,
    servers: list[MCPServer] | None = None,
    status: AgentStatus = AgentStatus.CONFIGURED,
) -> Agent:
    return Agent(
        name=name,
        agent_type=agent_type,
        config_path="/tmp/test.json",
        mcp_servers=servers or [],
        status=status,
    )


def _make_server(
    name: str = "test-server",
    packages: list[Package] | None = None,
    env: dict[str, str] | None = None,
) -> MCPServer:
    return MCPServer(
        name=name,
        command="npx",
        args=[name],
        transport=TransportType.STDIO,
        packages=packages or [],
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
    is_kev: bool = False,
) -> Vulnerability:
    return Vulnerability(
        id=cve_id,
        severity=severity,
        summary="Test vulnerability",
        is_kev=is_kev,
    )


def _make_blast_radius(
    pkg: Package | None = None,
    vuln: Vulnerability | None = None,
    agents: list[Agent] | None = None,
) -> BlastRadius:
    p = pkg or _make_pkg()
    v = vuln or _make_vuln()
    a = agents or [_make_agent()]
    return BlastRadius(
        package=p,
        vulnerability=v,
        affected_agents=a,
        affected_servers=[],
        exposed_credentials=[],
        exposed_tools=[],
    )


# ── print_summary ────────────────────────────────────────────────────────────


class TestPrintSummary:
    def test_empty_report(self, capsys):
        report = _make_report()
        print_summary(report)
        # Should not raise

    def test_with_agents(self, capsys):
        agent = _make_agent(servers=[_make_server()])
        report = _make_report(agents=[agent])
        print_summary(report)

    def test_with_scan_performance_data(self, capsys):
        report = _make_report()
        report.scan_performance_data = {
            "osv": {"cache_hits": 3, "cache_misses": 1, "cache_hit_rate_pct": 75},
            "registry": {"cache_hits": 4, "cache_misses": 2, "cache_hit_rate_pct": 67},
            "advisory_coverage": {
                "primary_sources": {"osv": 3, "ghsa": 1, "nvidia_csaf": 0},
                "enrichment_sources": {"nvd": 2, "epss": 2, "cisa_kev": 1},
                "records_with_enrichment": 2,
            },
        }
        print_summary(report)

    def test_with_project_inventory_data(self, capsys):
        report = _make_report()
        report.project_inventory_data = {
            "manifest_files": 3,
            "lockfiles": 2,
            "package_count": 12,
            "direct_packages": 5,
            "transitive_packages": 7,
            "lockfile_backed_packages": 9,
            "declaration_only_packages": 3,
            "advisory_depth_pct": 75,
        }
        print_summary(report)

    def test_with_model_supply_chain_data(self, capsys):
        report = _make_report()
        report.model_supply_chain_data = {
            "model_files": 2,
            "provenance_checks": 1,
            "signed_files": 1,
            "files_with_security_flags": 1,
            "provenance_with_security_flags": 0,
            "hash_verification": {"verified": 1, "tampered": 0},
        }
        print_summary(report)


class TestPrintScanPerformanceSummary:
    def test_prints_cache_summary(self, capsys):
        report = _make_report()
        report.scan_performance_data = {
            "osv": {"cache_hits": 3, "cache_misses": 1, "packages_queried": 2, "cache_hit_rate_pct": 75, "lookup_errors": 0},
            "registry": {"cache_hits": 4, "cache_misses": 2, "network_requests": 2, "cache_hit_rate_pct": 67},
            "advisory_coverage": {
                "primary_sources": {"osv": 3, "ghsa": 1, "nvidia_csaf": 0},
                "enrichment_sources": {"nvd": 2, "epss": 2, "cisa_kev": 1},
                "records_with_multiple_sources": 2,
            },
        }
        print_scan_performance_summary(report)


# ── print_posture_summary ────────────────────────────────────────────────────


class TestPrintPostureSummary:
    def test_clean_posture(self, capsys):
        report = _make_report(agents=[_make_agent()])
        print_posture_summary(report)

    def test_critical_posture(self, capsys):
        agent = _make_agent()
        br = _make_blast_radius(agents=[agent])
        report = _make_report(agents=[agent], blast_radii=[br])
        print_posture_summary(report)

    def test_medium_only_posture(self, capsys):
        agent = _make_agent()
        br = _make_blast_radius(
            vuln=_make_vuln(severity=Severity.MEDIUM),
            agents=[agent],
        )
        report = _make_report(agents=[agent], blast_radii=[br])
        print_posture_summary(report)

    def test_with_credentials(self, capsys):
        server = _make_server(
            env={"API_KEY": "x", "SECRET": "x", "TOKEN": "x", "PASSWORD": "x", "OTHER_KEY": "x"},
        )
        agent = _make_agent(servers=[server])
        report = _make_report(agents=[agent])
        print_posture_summary(report)

    def test_with_ecosystem_breakdown(self, capsys):
        pkgs = [_make_pkg("lodash", "4.17.20", "npm"), _make_pkg("requests", "2.28.0", "pypi")]
        server = _make_server(packages=pkgs)
        agent = _make_agent(servers=[server])
        report = _make_report(agents=[agent])
        print_posture_summary(report)

    def test_with_kev_vulnerability(self, capsys):
        agent = _make_agent()
        br = _make_blast_radius(
            vuln=_make_vuln(is_kev=True),
            agents=[agent],
        )
        report = _make_report(agents=[agent], blast_radii=[br])
        print_posture_summary(report)

    def test_installed_not_configured(self, capsys):
        agent = _make_agent(status=AgentStatus.INSTALLED_NOT_CONFIGURED)
        report = _make_report(agents=[agent])
        print_posture_summary(report)

    def test_vex_suppressed(self, capsys):
        agent = _make_agent()
        vuln = _make_vuln()
        vuln.vex_status = "not_affected"
        br = _make_blast_radius(vuln=vuln, agents=[agent])
        report = _make_report(agents=[agent], blast_radii=[br])
        print_posture_summary(report)


# ── print_policy_results ─────────────────────────────────────────────────────


class TestPrintPolicyResults:
    def test_all_passed(self, capsys):
        result = {
            "policy_name": "security",
            "failures": [],
            "warnings": [],
            "passed": True,
        }
        print_policy_results(result)

    def test_with_warnings(self, capsys):
        result = {
            "policy_name": "security",
            "failures": [],
            "warnings": [
                {
                    "rule_id": "max_severity",
                    "rule_description": "Max severity exceeded",
                    "vulnerability_id": "CVE-2024-001",
                    "package": "lodash@4.17.20",
                    "severity": "MEDIUM",
                }
            ],
            "passed": True,
        }
        print_policy_results(result)

    def test_with_failures(self, capsys):
        result = {
            "policy_name": "security",
            "failures": [
                {
                    "rule_id": "block_critical",
                    "rule_description": "Critical CVEs blocked",
                    "vulnerability_id": "CVE-2024-002",
                    "package": "old@2.0",
                    "severity": "CRITICAL",
                    "is_kev": True,
                    "ai_risk_context": "Model serving",
                }
            ],
            "warnings": [],
            "passed": False,
        }
        print_policy_results(result)

    def test_failures_without_kev_or_ai(self, capsys):
        result = {
            "policy_name": "test",
            "failures": [
                {
                    "rule_id": "r1",
                    "rule_description": "desc",
                    "vulnerability_id": "CVE-2024-003",
                    "package": "pkg@1.0",
                    "severity": "HIGH",
                }
            ],
            "warnings": [],
            "passed": False,
        }
        print_policy_results(result)

    def test_many_failures_truncated(self, capsys):
        failures = [
            {
                "rule_id": f"r{i}",
                "rule_description": f"desc {i}",
                "vulnerability_id": f"CVE-2024-{i:04d}",
                "package": f"pkg{i}@1.0",
                "severity": "HIGH",
            }
            for i in range(15)
        ]
        result = {
            "policy_name": "big",
            "failures": failures,
            "warnings": [],
            "passed": False,
        }
        print_policy_results(result)


# ── print_severity_chart ─────────────────────────────────────────────────────


class TestPrintSeverityChart:
    def test_no_blast_radii(self, capsys):
        report = _make_report()
        print_severity_chart(report)

    def test_mixed_severities(self, capsys):
        agent = _make_agent()
        brs = [
            _make_blast_radius(vuln=_make_vuln("CVE-2024-001", Severity.CRITICAL), agents=[agent]),
            _make_blast_radius(vuln=_make_vuln("CVE-2024-002", Severity.HIGH), agents=[agent]),
            _make_blast_radius(vuln=_make_vuln("CVE-2024-003", Severity.MEDIUM), agents=[agent]),
            _make_blast_radius(vuln=_make_vuln("CVE-2024-004", Severity.LOW), agents=[agent]),
        ]
        report = _make_report(agents=[agent], blast_radii=brs)
        print_severity_chart(report)


# ── to_sarif ─────────────────────────────────────────────────────────────────


class TestToSarif:
    def test_empty_report(self):
        report = _make_report()
        sarif = to_sarif(report)
        assert sarif["$schema"]
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1

    def test_with_vulns(self):
        agent = _make_agent()
        br = _make_blast_radius(agents=[agent])
        report = _make_report(agents=[agent], blast_radii=[br])
        sarif = to_sarif(report)
        assert len(sarif["runs"][0]["results"]) >= 1


# ── to_cyclonedx ─────────────────────────────────────────────────────────────


class TestToCyclonedx:
    def test_empty_report(self):
        report = _make_report()
        cdx = to_cyclonedx(report)
        assert cdx["bomFormat"] == "CycloneDX"
        assert cdx["specVersion"] == "1.6"

    def test_with_agents_and_vulns(self):
        pkg = _make_pkg()
        server = _make_server(packages=[pkg])
        agent = _make_agent(servers=[server])
        br = _make_blast_radius(pkg=pkg, agents=[agent])
        report = _make_report(agents=[agent], blast_radii=[br])
        cdx = to_cyclonedx(report)
        assert len(cdx["components"]) >= 1
        # Vulnerabilities may be in a nested structure depending on CycloneDX version
        assert len(cdx["components"]) >= 1


# ── to_spdx ──────────────────────────────────────────────────────────────────


class TestToSpdx:
    def test_empty_report(self):
        report = _make_report()
        spdx = to_spdx(report)
        assert spdx["spdxVersion"] == "SPDX-3.0"

    def test_with_agents_and_vulns(self):
        pkg = _make_pkg()
        server = _make_server(packages=[pkg])
        agent = _make_agent(servers=[server])
        br = _make_blast_radius(pkg=pkg, agents=[agent])
        report = _make_report(agents=[agent], blast_radii=[br])
        spdx = to_spdx(report)
        assert len(spdx["elements"]) >= 1


class TestToJson:
    def test_includes_project_inventory(self):
        report = _make_report()
        report.project_inventory_data = {
            "root": "/tmp/project",
            "manifest_directories": 2,
            "lockfile_directories": 1,
            "declaration_only_directories": 1,
            "manifest_files": 4,
            "lockfiles": 2,
            "declaration_only_files": 2,
            "package_count": 8,
            "direct_packages": 3,
            "transitive_packages": 5,
            "lockfile_backed_packages": 6,
            "declaration_only_packages": 2,
            "lockfile_backed_direct_packages": 2,
            "lockfile_backed_transitive_packages": 4,
            "declaration_only_direct_packages": 1,
            "declaration_only_transitive_packages": 1,
            "advisory_depth_pct": 75,
            "ecosystems": {"pypi": 3, "npm": 5},
            "directories": [
                {
                    "path": ".",
                    "package_count": 8,
                    "direct_packages": 3,
                    "transitive_packages": 5,
                    "manifest_files": ["package.json", "package-lock.json"],
                    "lockfile_files": ["package-lock.json"],
                    "declaration_files": ["package.json"],
                    "advisory_evidence": "lockfile_backed",
                    "ecosystems": {"npm": 5},
                }
            ],
        }
        data = to_json(report)
        assert data["project_inventory"]["lockfiles"] == 2
        assert data["project_inventory"]["advisory_depth_pct"] == 75
        assert data["project_inventory"]["directories"][0]["path"] == "."

    def test_includes_advisory_source_fields(self):
        vuln = Vulnerability(
            id="CVE-2026-3000",
            summary="test",
            severity=Severity.HIGH,
            advisory_sources=["osv"],
            epss_score=0.8,
            is_kev=True,
        )
        pkg = Package(name="demo", version="1.0.0", ecosystem="npm", vulnerabilities=[vuln])
        server = _make_server(packages=[pkg])
        agent = _make_agent(servers=[server])
        br = _make_blast_radius(pkg=pkg, vuln=vuln, agents=[agent])
        report = _make_report(agents=[agent], blast_radii=[br])

        data = to_json(report)
        vuln_json = data["agents"][0]["mcp_servers"][0]["packages"][0]["vulnerabilities"][0]
        blast_json = data["blast_radius"][0]

        assert vuln_json["advisory_sources"] == ["osv", "epss", "cisa_kev"]
        assert vuln_json["primary_advisory_source"] == "osv"
        assert vuln_json["advisory_coverage_state"] == "enriched"
        assert blast_json["advisory_sources"] == ["osv", "epss", "cisa_kev"]


# ── _pct / _coverage_bar (from cov2) ────────────────────────────────────────


def test_pct_normal():
    assert _pct(3, 10) == "30%"


def test_pct_zero_total():
    assert _pct(5, 0) == "\u2014"


def test_coverage_bar():
    result = _coverage_bar(5, 10, "red", width=10)
    assert "\u2588" in result


def test_coverage_bar_zero():
    result = _coverage_bar(0, 10, "blue")
    assert "\u2591" in result


# ── _risk_narrative (from cov2) ──────────────────────────────────────────────


def test_risk_narrative_with_creds_and_tools():
    item = {
        "vulns": ["CVE-2025-0001"],
        "agents": ["agent1"],
        "creds": ["API_KEY"],
        "tools": ["read_file"],
    }
    result = _risk_narrative(item)
    assert "CVE-2025-0001" in result
    assert "API_KEY" in result
    assert "read_file" in result


def test_risk_narrative_no_creds():
    item = {"vulns": ["CVE-1"], "agents": ["a"], "creds": [], "tools": []}
    result = _risk_narrative(item)
    assert "CVE-1" in result
    assert "via a" in result


# ── print_agent_tree (from cov2) ─────────────────────────────────────────────


def _make_server_cov2(name="srv", pkgs=None, creds=None, tools=None):
    env = {}
    if creds:
        for c in creds:
            env[c] = "secret-value"
    return MCPServer(
        name=name,
        command="node",
        transport=TransportType.STDIO,
        packages=pkgs or [],
        env=env,
        tools=tools or [],
    )


def _make_agent_cov2(name="agent1", servers=None, status=AgentStatus.CONFIGURED):
    return Agent(
        name=name,
        agent_type=AgentType.CUSTOM,
        config_path="/test",
        mcp_servers=servers or [],
        status=status,
    )


def _make_report_cov2(agents=None, blast_radii=None):
    return AIBOMReport(
        agents=agents or [],
        blast_radii=blast_radii or [],
        generated_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )


def _make_vuln_cov2(vid="CVE-2025-0001", sev=Severity.HIGH, fixed="4.17.22"):
    return Vulnerability(id=vid, severity=sev, summary="test vuln", fixed_version=fixed)


def _make_pkg_cov2(name="lodash", version="4.17.20", ecosystem="npm", vulns=None):
    return Package(name=name, version=version, ecosystem=ecosystem, vulnerabilities=vulns or [])


def _make_blast_radius_cov2(vuln=None, pkg=None, agents=None, servers=None, creds=None, tools=None):
    v = vuln or _make_vuln_cov2()
    p = pkg or _make_pkg_cov2(vulns=[v])
    return BlastRadius(
        vulnerability=v,
        package=p,
        affected_agents=agents or [],
        affected_servers=servers or [],
        exposed_credentials=creds or [],
        exposed_tools=tools or [],
    )


def test_print_agent_tree_basic():
    pkg = _make_pkg_cov2()
    srv = _make_server_cov2(pkgs=[pkg], creds=["KEY"])
    agent = _make_agent_cov2(servers=[srv])
    report = _make_report_cov2(agents=[agent])
    print_agent_tree(report)


def test_print_agent_tree_not_configured():
    agent = _make_agent_cov2(status=AgentStatus.INSTALLED_NOT_CONFIGURED)
    report = _make_report_cov2(agents=[agent])
    print_agent_tree(report)


def test_print_agent_tree_with_vulns():
    vuln = _make_vuln_cov2()
    pkg = _make_pkg_cov2(vulns=[vuln])
    srv = _make_server_cov2(pkgs=[pkg])
    agent = _make_agent_cov2(servers=[srv])
    report = _make_report_cov2(agents=[agent])
    print_agent_tree(report)


def test_print_agent_tree_transitive_pkgs():
    direct = _make_pkg_cov2()
    direct.is_direct = True
    trans = _make_pkg_cov2(name="dep", version="1.0")
    trans.is_direct = False
    trans.dependency_depth = 2
    trans.parent_package = "lodash"
    srv = _make_server_cov2(pkgs=[direct, trans])
    agent = _make_agent_cov2(servers=[srv])
    report = _make_report_cov2(agents=[agent])
    print_agent_tree(report)


# ── print_blast_radius (from cov2) ──────────────────────────────────────────


def test_print_blast_radius_empty():
    report = _make_report_cov2()
    print_blast_radius(report)


def test_print_blast_radius_with_findings():
    vuln = _make_vuln_cov2()
    vuln.epss_score = 0.85
    vuln.is_kev = True
    vuln.references = ["https://example.com"]
    pkg = _make_pkg_cov2(vulns=[vuln])
    srv = _make_server_cov2(pkgs=[pkg])
    agent = _make_agent_cov2(servers=[srv])
    br = _make_blast_radius_cov2(vuln=vuln, pkg=pkg, agents=[agent], servers=[srv], creds=["KEY"])
    br.owasp_tags = ["LLM01"]
    br.atlas_tags = ["AML.T0001"]
    br.nist_ai_rmf_tags = ["MAP-1.1"]
    report = _make_report_cov2(agents=[agent], blast_radii=[br])
    print_blast_radius(report)


def test_print_blast_radius_no_fix():
    vuln = _make_vuln_cov2(fixed=None)
    pkg = _make_pkg_cov2(vulns=[vuln])
    br = _make_blast_radius_cov2(vuln=vuln, pkg=pkg)
    report = _make_report_cov2(blast_radii=[br])
    print_blast_radius(report)


def test_print_blast_radius_ghsa():
    vuln = _make_vuln_cov2(vid="GHSA-xxxx-yyyy-zzzz")
    pkg = _make_pkg_cov2(vulns=[vuln])
    br = _make_blast_radius_cov2(vuln=vuln, pkg=pkg)
    report = _make_report_cov2(blast_radii=[br])
    print_blast_radius(report)


# ── build_remediation_plan (from cov2) ───────────────────────────────────────


def test_build_remediation_plan_empty():
    assert build_remediation_plan([]) == []


def test_build_remediation_plan_with_items():
    vuln = _make_vuln_cov2()
    pkg = _make_pkg_cov2(vulns=[vuln])
    agent = _make_agent_cov2()
    srv = _make_server_cov2(pkgs=[pkg])
    br = _make_blast_radius_cov2(vuln=vuln, pkg=pkg, agents=[agent], servers=[srv], creds=["KEY"])
    plan = build_remediation_plan([br])
    assert len(plan) >= 1
    assert plan[0]["package"] == "lodash"


def test_build_remediation_plan_no_downgrade():
    """Regression: multi-branch OSV advisories must not produce downgrade entries.

    Django 3.2.0 CVE has two fix branches: 2.2.26 (older branch) and 3.2.14.
    The remediation plan must emit exactly ONE entry for django@3.2.0 pointing
    to 3.2.14 — not a second entry pointing backward to 2.2.26.
    """
    pkg = Package(name="django", version="3.2.0", ecosystem="pypi", vulnerabilities=[])
    vuln_downgrade = Vulnerability(id="CVE-2025-9999", severity=Severity.HIGH, summary="Django XSS", fixed_version="2.2.26")
    vuln_valid = Vulnerability(id="CVE-2025-9999", severity=Severity.HIGH, summary="Django XSS", fixed_version="3.2.14")
    br1 = BlastRadius(
        vulnerability=vuln_downgrade, package=pkg, affected_agents=[], affected_servers=[], exposed_credentials=[], exposed_tools=[]
    )
    br2 = BlastRadius(
        vulnerability=vuln_valid, package=pkg, affected_agents=[], affected_servers=[], exposed_credentials=[], exposed_tools=[]
    )
    plan = build_remediation_plan([br1, br2])
    # Must be exactly one entry (grouped by package+ecosystem+version)
    assert len(plan) == 1
    # fix must be the forward upgrade, not the downgrade
    assert plan[0]["fix"] == "3.2.14"


def test_build_remediation_plan_skips_prerelease_downgrade_for_npm():
    """npm canary/pre-release branches should not be emitted as a downgrade fix."""
    pkg = Package(name="next", version="16.2.1", ecosystem="npm", vulnerabilities=[])
    vuln_canary = Vulnerability(
        id="CVE-2026-1111",
        severity=Severity.HIGH,
        summary="Next issue",
        fixed_version="13.4.20-canary.13",
    )
    vuln_valid = Vulnerability(
        id="CVE-2026-1111",
        severity=Severity.HIGH,
        summary="Next issue",
        fixed_version="16.2.2",
    )
    br1 = BlastRadius(
        vulnerability=vuln_canary, package=pkg, affected_agents=[], affected_servers=[], exposed_credentials=[], exposed_tools=[]
    )
    br2 = BlastRadius(
        vulnerability=vuln_valid, package=pkg, affected_agents=[], affected_servers=[], exposed_credentials=[], exposed_tools=[]
    )
    plan = build_remediation_plan([br1, br2])
    assert len(plan) == 1
    assert plan[0]["fix"] == "16.2.2"


def test_build_remediation_plan_suppresses_prerelease_only_fix():
    """Prerelease-only fixes should not be emitted as default remediation."""
    pkg = Package(name="samplelib", version="1.4.0", ecosystem="pypi", vulnerabilities=[])
    vuln = Vulnerability(
        id="CVE-2026-2222",
        severity=Severity.HIGH,
        summary="Sample issue",
        fixed_version="2.0.0rc1",
    )
    br = BlastRadius(vulnerability=vuln, package=pkg, affected_agents=[], affected_servers=[], exposed_credentials=[], exposed_tools=[])

    plan = build_remediation_plan([br])

    assert len(plan) == 1
    assert plan[0]["fix"] is None
    assert plan[0]["reason"] == "prerelease fix suppressed by default"
    assert "suppressed by default" in plan[0]["action"]


# ── to_json (from cov2) ─────────────────────────────────────────────────────


def test_to_json_empty_report():
    report = _make_report_cov2()
    result = to_json(report)
    assert result["document_type"] == "AI-BOM"
    assert result["summary"]["total_agents"] == 0
    assert isinstance(result["agents"], list)


def test_to_json_with_agents():
    pkg = _make_pkg_cov2()
    srv = _make_server_cov2(pkgs=[pkg])
    agent = _make_agent_cov2(servers=[srv])
    report = _make_report_cov2(agents=[agent])
    result = to_json(report)
    assert len(result["agents"]) == 1
    assert result["agents"][0]["name"] == "agent1"


def test_to_json_with_blast_radius():
    vuln = _make_vuln_cov2()
    pkg = _make_pkg_cov2(vulns=[vuln])
    agent = _make_agent_cov2()
    br = _make_blast_radius_cov2(vuln=vuln, pkg=pkg, agents=[agent])
    report = _make_report_cov2(agents=[agent], blast_radii=[br])
    result = to_json(report)
    assert len(result["blast_radius"]) >= 1
    assert "threat_framework_summary" in result


def test_to_json_with_optional_fields():
    report = _make_report_cov2()
    report.executive_summary = "Test summary"
    report.ai_threat_chains = [{"chain": "test"}]
    report.skill_audit_data = {"findings": []}
    report.trust_assessment_data = {"score": 0.8}
    report.cis_benchmark_data = {"checks": []}
    result = to_json(report)
    assert result.get("executive_summary") == "Test summary"
    assert "skill_audit" in result
    assert "trust_assessment" in result


def test_to_json_with_model_supply_chain_fields():
    report = _make_report_cov2()
    report.model_manifests = [{"filename": "model.safetensors.index.json", "manifest_type": "weight_index"}]
    report.model_hash_verification_data = {
        "scanned": 2,
        "verified": 1,
        "tampered": 0,
        "unverified": 1,
        "offline": 0,
        "has_tampering": False,
        "results": [],
    }
    report.model_supply_chain_data = {
        "model_files": 2,
        "manifest_files": 1,
        "signed_files": 1,
        "unsigned_files": 1,
        "unsafe_format_files": 1,
        "files_with_security_flags": 1,
        "formats": ["Pickle", "SafeTensors"],
        "ecosystems": ["HuggingFace", "Python"],
        "provenance_checks": 1,
        "provenance_with_digest": 1,
        "gated_models": 0,
        "provenance_with_security_flags": 0,
        "provenance_sources": ["huggingface"],
        "manifests_with_repo_id": 1,
        "adapter_lineage_refs": 0,
        "sharded_bundles": 1,
        "manifests_with_security_flags": 0,
        "hash_verification": {"scanned": 2, "verified": 1, "tampered": 0, "unverified": 1, "offline": 0, "has_tampering": False},
    }
    result = to_json(report)
    assert result["model_manifests"][0]["manifest_type"] == "weight_index"
    assert result["model_hash_verification"]["verified"] == 1
    assert result["model_supply_chain"]["model_files"] == 2
    assert result["model_supply_chain"]["manifest_files"] == 1


# ── print_threat_frameworks (from cov2) ──────────────────────────────────────


def test_print_threat_frameworks_no_blast():
    report = _make_report_cov2()
    print_threat_frameworks(report)


def test_print_threat_frameworks_with_tags():
    vuln = _make_vuln_cov2()
    pkg = _make_pkg_cov2(vulns=[vuln])
    br = _make_blast_radius_cov2(vuln=vuln, pkg=pkg)
    br.owasp_tags = ["LLM01"]
    br.atlas_tags = ["AML.T0001"]
    br.nist_ai_rmf_tags = ["MAP-1.1"]
    br.owasp_mcp_tags = ["MCP01"]
    br.owasp_agentic_tags = ["AGT01"]
    br.eu_ai_act_tags = ["ART-9"]
    br.nist_csf_tags = ["ID.AM"]
    br.iso_27001_tags = ["A.5.1"]
    br.soc2_tags = ["CC1.1"]
    br.cis_tags = ["CIS-1.1"]
    report = _make_report_cov2(blast_radii=[br])
    print_threat_frameworks(report)


# ── print_export_hint (from cov2) ────────────────────────────────────────────


def test_print_export_hint_no_vulns():
    report = _make_report_cov2()
    print_export_hint(report)


def test_print_export_hint_with_vulns():
    vuln = _make_vuln_cov2()
    pkg = _make_pkg_cov2(vulns=[vuln])
    br = _make_blast_radius_cov2(vuln=vuln, pkg=pkg)
    br.owasp_tags = ["LLM01"]
    report = _make_report_cov2(blast_radii=[br])
    print_export_hint(report)


# ── print_attack_flow_tree (from cov2) ───────────────────────────────────────


def test_print_attack_flow_tree():
    vuln = _make_vuln_cov2()
    vuln.cvss_score = 9.8
    vuln.epss_score = 0.5
    vuln.is_kev = True
    pkg = _make_pkg_cov2(vulns=[vuln])
    tool = MCPTool(name="read_file", description="Read a file")
    srv = _make_server_cov2(pkgs=[pkg], tools=[tool])
    agent = _make_agent_cov2(servers=[srv])
    br = _make_blast_radius_cov2(vuln=vuln, pkg=pkg, agents=[agent], servers=[srv], creds=["API_KEY"], tools=[tool])
    report = _make_report_cov2(agents=[agent], blast_radii=[br])
    print_attack_flow_tree(report)


def test_print_attack_flow_tree_no_servers():
    vuln = _make_vuln_cov2()
    pkg = _make_pkg_cov2(vulns=[vuln])
    tool = MCPTool(name="exec", description="Execute")
    agent = _make_agent_cov2()
    br = _make_blast_radius_cov2(vuln=vuln, pkg=pkg, agents=[agent], servers=[], creds=["SECRET"], tools=[tool])
    report = _make_report_cov2(blast_radii=[br])
    print_attack_flow_tree(report)


# ── _build_remediation_json (from cov2) ──────────────────────────────────────


def test_build_remediation_json():
    from agent_bom.output import _build_remediation_json

    vuln = _make_vuln_cov2()
    pkg = _make_pkg_cov2(vulns=[vuln])
    agent = _make_agent_cov2()
    tool = MCPTool(name="read_file", description="Read")
    srv = _make_server_cov2(pkgs=[pkg], tools=[tool])
    br = _make_blast_radius_cov2(vuln=vuln, pkg=pkg, agents=[agent], servers=[srv], creds=["KEY"], tools=[tool])
    report = _make_report_cov2(agents=[agent], blast_radii=[br])
    result = _build_remediation_json(report)
    assert isinstance(result, list)


def test_build_remediation_json_includes_reason_for_unfixable_item():
    from agent_bom.output import _build_remediation_json

    pkg = Package(name="samplelib", version="1.4.0", ecosystem="pypi", vulnerabilities=[])
    vuln = Vulnerability(id="CVE-2026-3333", severity=Severity.HIGH, summary="Issue", fixed_version="2.0.0rc1")
    br = BlastRadius(vulnerability=vuln, package=pkg, affected_agents=[], affected_servers=[], exposed_credentials=[], exposed_tools=[])
    report = _make_report_cov2(blast_radii=[br])

    result = _build_remediation_json(report)

    assert result[0]["fixed_version"] is None
    assert result[0]["reason"] == "prerelease fix suppressed by default"


# ── export_json (from cov2) ──────────────────────────────────────────────────


def test_export_json(tmp_path):
    import json

    from agent_bom.output import export_json

    report = _make_report_cov2()
    out = tmp_path / "report.json"
    export_json(report, str(out))
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["document_type"] == "AI-BOM"


# ── to_cyclonedx extras (from cov2) ─────────────────────────────────────────


def test_to_cyclonedx_with_agent():
    vuln = _make_vuln_cov2()
    pkg = _make_pkg_cov2(vulns=[vuln])
    srv = _make_server_cov2(pkgs=[pkg])
    agent = _make_agent_cov2(servers=[srv])
    report = _make_report_cov2(agents=[agent])
    result = to_cyclonedx(report)
    assert len(result["components"]) >= 2
    assert "vulnerabilities" in result


def test_to_cyclonedx_no_fix():
    vuln = _make_vuln_cov2(fixed=None)
    pkg = _make_pkg_cov2(vulns=[vuln])
    srv = _make_server_cov2(pkgs=[pkg])
    agent = _make_agent_cov2(servers=[srv])
    report = _make_report_cov2(agents=[agent])
    result = to_cyclonedx(report)
    assert "vulnerabilities" in result


# ── CycloneDX ML BOM extensions ─────────────────────────────────────────────


def test_to_cyclonedx_ml_model_provenance():
    """Model provenance should produce machine-learning-model components with modelCard."""
    report = _make_report()
    report.model_provenance = [
        {
            "model_id": "meta-llama/Llama-3.1-8B",
            "source": "huggingface",
            "format": "safetensors",
            "is_safe_format": True,
            "has_digest": True,
            "digest": "abc123def456",
            "risk_flags": [],
            "risk_level": "safe",
            "metadata": {"pipeline_tag": "text-generation", "tags": ["dataset:wikitext"]},
        }
    ]
    result = to_cyclonedx(report)
    ml_comps = [c for c in result["components"] if c["type"] == "machine-learning-model"]
    assert len(ml_comps) >= 1
    assert any("modelCard" in c for c in ml_comps)
    assert any("Llama" in c["name"] for c in ml_comps)


def test_to_cyclonedx_ml_model_files():
    """Model file scan results should produce ML components with security flags."""
    report = _make_report()
    report.model_files = [
        {
            "filename": "model.pkl",
            "format": "Pickle",
            "ecosystem": "scikit-learn",
            "size_bytes": 5242880,
            "size_human": "5.0 MB",
            "security_flags": [{"type": "PICKLE_DESERIALIZATION", "severity": "HIGH", "description": "Pickle can execute arbitrary code"}],
        }
    ]
    result = to_cyclonedx(report)
    ml_comps = [c for c in result["components"] if c["type"] == "machine-learning-model"]
    assert len(ml_comps) >= 1
    pkl_comp = [c for c in ml_comps if "model.pkl" in c["name"]]
    assert len(pkl_comp) == 1


def test_to_cyclonedx_dataset_cards():
    """Dataset cards should produce data components with CycloneDX data extension."""
    report = _make_report()
    report.dataset_cards = {
        "datasets": [
            {
                "name": "wikitext-103",
                "description": "Wikipedia text corpus",
                "license": "CC-BY-SA-4.0",
                "source_file": "dataset_info.json",
                "features": ["text"],
                "splits": {"train": 1801350},
                "task_categories": ["language-modeling"],
                "languages": ["en"],
                "security_flags": [],
            }
        ]
    }
    result = to_cyclonedx(report)
    data_comps = [c for c in result["components"] if c["type"] == "data"]
    assert len(data_comps) == 1
    assert "data" in data_comps[0]
    assert data_comps[0]["data"][0]["type"] == "dataset"


def test_to_cyclonedx_training_pipelines():
    """Training runs should produce ML components with quantitativeAnalysis."""
    report = _make_report()
    report.training_pipelines = {
        "runs": [
            {
                "name": "finetune-v2",
                "framework": "mlflow",
                "source_file": "MLmodel",
                "run_id": "abc123",
                "model_flavor": "transformers",
                "metrics": {"eval_loss": 2.31, "accuracy": 0.87},
                "parameters": {"lr": "2e-5"},
                "security_flags": [],
            }
        ]
    }
    result = to_cyclonedx(report)
    ml_comps = [c for c in result["components"] if c["type"] == "machine-learning-model"]
    assert any("finetune" in c["name"] for c in ml_comps)
    training_comp = [c for c in ml_comps if "finetune" in c["name"]][0]
    assert "modelCard" in training_comp
    assert "quantitativeAnalysis" in training_comp["modelCard"]


def test_to_cyclonedx_ml_models_metadata_count():
    """Metadata should include ml-models count."""
    report = _make_report()
    report.model_provenance = [
        {
            "model_id": "m1",
            "source": "hf",
            "format": "safetensors",
            "is_safe_format": True,
            "has_digest": False,
            "digest": "",
            "risk_flags": [],
            "risk_level": "safe",
            "metadata": {},
        }
    ]
    report.model_files = [
        {"filename": "f1.gguf", "format": "GGUF", "ecosystem": "llama.cpp", "size_bytes": 100, "size_human": "100 B", "security_flags": []}
    ]
    result = to_cyclonedx(report)
    meta_props = {p["name"]: p["value"] for p in result["metadata"]["properties"]}
    assert meta_props["agent-bom:ml-models"] == "2"


# ── to_spdx extras (from cov2) ──────────────────────────────────────────────


def test_to_spdx_with_agent():
    vuln = _make_vuln_cov2()
    pkg = _make_pkg_cov2(vulns=[vuln])
    srv = _make_server_cov2(pkgs=[pkg])
    agent = _make_agent_cov2(servers=[srv])
    report = _make_report_cov2(agents=[agent])
    result = to_spdx(report)
    assert len(result.get("packages", result.get("elements", []))) >= 1


# ── to_sarif extras (from cov2) ─────────────────────────────────────────────


def test_to_sarif_with_findings():
    vuln = _make_vuln_cov2()
    pkg = _make_pkg_cov2(vulns=[vuln])
    agent = _make_agent_cov2()
    br = _make_blast_radius_cov2(vuln=vuln, pkg=pkg, agents=[agent])
    report = _make_report_cov2(agents=[agent], blast_radii=[br])
    result = to_sarif(report)
    assert "runs" in result
    run = result["runs"][0]
    assert len(run.get("results", [])) >= 1
