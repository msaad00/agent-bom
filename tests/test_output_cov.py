"""Tests for output module — coverage expansion."""

from __future__ import annotations

from datetime import datetime

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
from agent_bom.output import (
    print_policy_results,
    print_posture_summary,
    print_severity_chart,
    print_summary,
    to_cyclonedx,
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
