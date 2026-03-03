"""Tests for license policy engine — categorization, evaluation, and reporting."""

from __future__ import annotations

from agent_bom.license_policy import (
    DEFAULT_LICENSE_POLICY,
    LicenseReport,
    categorize_license,
    evaluate_license_policy,
    to_serializable,
)
from agent_bom.models import Agent, MCPServer, Package

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pkg(
    name: str = "test-pkg",
    version: str = "1.0.0",
    ecosystem: str = "npm",
    license: str | None = None,
    license_expression: str | None = None,
) -> Package:
    return Package(name=name, version=version, ecosystem=ecosystem, license=license, license_expression=license_expression)


def _server(name: str = "test-server", packages: list | None = None) -> MCPServer:
    return MCPServer(name=name, command="npx", packages=packages or [])


def _agent(name: str = "agent-a", servers: list | None = None) -> Agent:
    return Agent(name=name, agent_type="claude-desktop", config_path="/tmp/test", mcp_servers=servers or [])


# ---------------------------------------------------------------------------
# TestCategorizeLicense
# ---------------------------------------------------------------------------


class TestCategorizeLicense:
    def test_permissive_licenses(self):
        for lic in ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "0BSD", "Unlicense"]:
            cat, risk = categorize_license(lic)
            assert cat == "permissive", f"{lic} should be permissive"
            assert risk == "low"

    def test_weak_copyleft_licenses(self):
        for lic in ["LGPL-2.1-only", "LGPL-3.0-or-later", "MPL-2.0", "EPL-2.0"]:
            cat, risk = categorize_license(lic)
            assert cat == "weak_copyleft", f"{lic} should be weak copyleft"
            assert risk == "medium"

    def test_strong_copyleft_licenses(self):
        for lic in ["GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only", "GPL-3.0-or-later"]:
            cat, risk = categorize_license(lic)
            assert cat == "strong_copyleft", f"{lic} should be strong copyleft"
            assert risk == "high"

    def test_commercial_risk_licenses(self):
        for lic in ["SSPL-1.0", "BSL-1.1", "Elastic-2.0"]:
            cat, risk = categorize_license(lic)
            assert cat == "commercial_risk", f"{lic} should be commercial risk"
            assert risk == "critical"

    def test_unknown_license(self):
        cat, risk = categorize_license("CustomLicense-1.0")
        assert cat == "unknown"
        assert risk == "medium"

    def test_empty_license(self):
        cat, risk = categorize_license("")
        assert cat == "unknown"
        assert risk == "medium"

    def test_or_expression_picks_most_permissive(self):
        cat, risk = categorize_license("Apache-2.0 OR GPL-3.0-only")
        assert cat == "permissive"
        assert risk == "low"

    def test_and_expression_picks_most_restrictive(self):
        cat, risk = categorize_license("MIT AND GPL-3.0-only")
        assert cat == "strong_copyleft"
        assert risk == "high"

    def test_or_with_all_copyleft(self):
        cat, risk = categorize_license("LGPL-2.1-only OR GPL-3.0-only")
        assert cat == "weak_copyleft"
        assert risk == "medium"

    def test_and_with_all_permissive(self):
        cat, risk = categorize_license("MIT AND Apache-2.0")
        assert cat == "permissive"
        assert risk == "low"

    def test_whitespace_handling(self):
        cat, risk = categorize_license("  MIT  ")
        assert cat == "permissive"


# ---------------------------------------------------------------------------
# TestEvaluatePolicy
# ---------------------------------------------------------------------------


class TestEvaluatePolicy:
    def test_all_permissive_compliant(self):
        agents = [_agent(servers=[_server(packages=[_pkg(license="MIT"), _pkg(name="other", license="Apache-2.0")])])]
        report = evaluate_license_policy(agents)
        assert report.compliant is True
        assert len(report.findings) == 0

    def test_gpl_blocked_by_default(self):
        agents = [_agent(servers=[_server(packages=[_pkg(license="GPL-3.0-only")])])]
        report = evaluate_license_policy(agents)
        assert report.compliant is False
        blocked = [f for f in report.findings if f.risk_level == "critical"]
        assert len(blocked) == 1
        assert "blocked by policy" in blocked[0].reason

    def test_agpl_blocked_by_default(self):
        agents = [_agent(servers=[_server(packages=[_pkg(license="AGPL-3.0-only")])])]
        report = evaluate_license_policy(agents)
        assert report.compliant is False

    def test_lgpl_warned_by_default(self):
        agents = [_agent(servers=[_server(packages=[_pkg(license="LGPL-3.0-only")])])]
        report = evaluate_license_policy(agents)
        assert report.compliant is True  # warnings don't break compliance
        warned = [f for f in report.findings if f.risk_level == "high"]
        assert len(warned) == 1
        assert "review" in warned[0].reason

    def test_unknown_license_finding(self):
        agents = [_agent(servers=[_server(packages=[_pkg(license=None)])])]
        report = evaluate_license_policy(agents)
        assert report.unknown_count == 1
        assert len(report.findings) == 1
        assert report.findings[0].license_id == "UNKNOWN"

    def test_custom_policy(self):
        policy = {"license_block": ["MIT"], "license_warn": []}
        agents = [_agent(servers=[_server(packages=[_pkg(license="MIT")])])]
        report = evaluate_license_policy(agents, policy=policy)
        assert report.compliant is False

    def test_empty_agents(self):
        report = evaluate_license_policy([])
        assert report.compliant is True
        assert report.total_packages == 0

    def test_multiple_agents_same_package(self):
        """Same package in multiple agents should list all agent names."""
        pkg = _pkg(license="GPL-3.0-only")
        agents = [
            _agent("agent-a", servers=[_server(packages=[pkg])]),
            _agent(
                "agent-b",
                servers=[_server(packages=[Package(name=pkg.name, version=pkg.version, ecosystem=pkg.ecosystem, license=pkg.license)])],
            ),
        ]
        report = evaluate_license_policy(agents)
        blocked = [f for f in report.findings if f.risk_level == "critical"]
        assert len(blocked) == 1
        assert "agent-a" in blocked[0].agents
        assert "agent-b" in blocked[0].agents

    def test_summary_counts(self):
        agents = [
            _agent(
                servers=[
                    _server(
                        packages=[
                            _pkg(name="a", license="MIT"),
                            _pkg(name="b", license="GPL-3.0-only"),
                            _pkg(name="c", license="LGPL-3.0-only"),
                            _pkg(name="d", license=None),
                        ]
                    )
                ]
            )
        ]
        report = evaluate_license_policy(agents)
        assert report.total_packages == 4
        assert report.unknown_count == 1
        assert report.summary["findings_count"] == 3  # GPL blocked, LGPL warned, unknown
        assert report.summary["compliant"] is False

    def test_sspl_blocked_by_default(self):
        agents = [_agent(servers=[_server(packages=[_pkg(license="SSPL-1.0")])])]
        report = evaluate_license_policy(agents)
        assert report.compliant is False

    def test_license_expression_in_finding(self):
        agents = [_agent(servers=[_server(packages=[_pkg(license="GPL-3.0-only", license_expression="GPL-3.0-only OR Apache-2.0")])])]
        report = evaluate_license_policy(agents)
        finding = report.findings[0]
        assert finding.license_expression == "GPL-3.0-only OR Apache-2.0"

    def test_commercial_risk_detected(self):
        agents = [_agent(servers=[_server(packages=[_pkg(license="Elastic-2.0")])])]
        report = evaluate_license_policy(agents)
        finding = [f for f in report.findings if f.category == "commercial_risk"]
        assert len(finding) == 1


# ---------------------------------------------------------------------------
# TestSerialization
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_roundtrip(self):
        agents = [_agent(servers=[_server(packages=[_pkg(license="GPL-3.0-only")])])]
        report = evaluate_license_policy(agents)
        data = to_serializable(report)
        assert data["compliant"] is False
        assert len(data["findings"]) == 1
        assert data["findings"][0]["license_id"] == "GPL-3.0-only"

    def test_empty_report(self):
        report = LicenseReport()
        data = to_serializable(report)
        assert data["compliant"] is True
        assert data["findings"] == []

    def test_summary_included(self):
        agents = [_agent(servers=[_server(packages=[_pkg(license="MIT"), _pkg(name="b", license=None)])])]
        report = evaluate_license_policy(agents)
        data = to_serializable(report)
        assert "summary" in data
        assert data["total_packages"] == 2
        assert data["unknown_count"] == 1


# ---------------------------------------------------------------------------
# TestPrintReport
# ---------------------------------------------------------------------------


class TestPrintReport:
    def test_no_findings_output(self, capsys):
        from rich.console import Console

        report = LicenseReport()
        from agent_bom.license_policy import print_license_report

        console = Console(force_terminal=True, width=120)
        print_license_report(report, console)
        # Should not raise

    def test_with_findings_output(self, capsys):
        from rich.console import Console

        agents = [_agent(servers=[_server(packages=[_pkg(license="GPL-3.0-only")])])]
        report = evaluate_license_policy(agents)
        from agent_bom.license_policy import print_license_report

        console = Console(force_terminal=True, width=120)
        print_license_report(report, console)
        # Should not raise


# ---------------------------------------------------------------------------
# TestDefaultPolicy
# ---------------------------------------------------------------------------


class TestDefaultPolicy:
    def test_default_blocks_gpl_variants(self):
        from agent_bom.license_policy import _matches_pattern

        for lic in ["GPL-2.0-only", "GPL-3.0-only", "GPL-3.0-or-later"]:
            assert _matches_pattern(lic, DEFAULT_LICENSE_POLICY["license_block"]), f"{lic} should be blocked"

    def test_default_blocks_agpl(self):
        from agent_bom.license_policy import _matches_pattern

        assert _matches_pattern("AGPL-3.0-only", DEFAULT_LICENSE_POLICY["license_block"])

    def test_default_warns_lgpl(self):
        from agent_bom.license_policy import _matches_pattern

        assert _matches_pattern("LGPL-3.0-only", DEFAULT_LICENSE_POLICY["license_warn"])

    def test_default_warns_mpl(self):
        from agent_bom.license_policy import _matches_pattern

        assert _matches_pattern("MPL-2.0", DEFAULT_LICENSE_POLICY["license_warn"])

    def test_default_allows_mit(self):
        from agent_bom.license_policy import _matches_pattern

        assert not _matches_pattern("MIT", DEFAULT_LICENSE_POLICY["license_block"])
        assert not _matches_pattern("MIT", DEFAULT_LICENSE_POLICY["license_warn"])
