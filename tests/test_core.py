"""Tests for agent-bom core functionality."""

import json
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.discovery import parse_mcp_config
from agent_bom.models import (
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    TransportType,
    Vulnerability,
)
from agent_bom.output import export_sarif, to_cyclonedx, to_json, to_sarif
from agent_bom.parsers import parse_npm_packages, parse_pip_packages

# ─── Model Tests ────────────────────────────────────────────────────────────


def test_package_no_vulns():
    pkg = Package(name="express", version="4.19.0", ecosystem="npm")
    assert not pkg.has_vulnerabilities
    assert pkg.max_severity == Severity.NONE


def test_package_with_vulns():
    pkg = Package(
        name="express",
        version="4.18.2",
        ecosystem="npm",
        vulnerabilities=[
            Vulnerability(id="CVE-2024-1234", summary="XSS", severity=Severity.HIGH),
            Vulnerability(id="CVE-2024-5678", summary="RCE", severity=Severity.CRITICAL),
        ],
    )
    assert pkg.has_vulnerabilities
    assert pkg.max_severity == Severity.CRITICAL


def test_mcp_server_credential_detection():
    server = MCPServer(
        name="test",
        command="node",
        env={"API_KEY": "abc123", "NORMAL_VAR": "hello"},
    )
    assert server.has_credentials
    assert "API_KEY" in server.credential_names
    assert "NORMAL_VAR" not in server.credential_names


def test_mcp_server_no_credentials():
    server = MCPServer(
        name="test",
        command="node",
        env={"PORT": "3000", "HOST": "localhost"},
    )
    assert not server.has_credentials


def test_blast_radius_scoring():
    vuln = Vulnerability(id="CVE-2024-1234", summary="RCE", severity=Severity.CRITICAL)
    pkg = Package(name="express", version="4.18.2", ecosystem="npm")
    server = MCPServer(name="db-server", command="node", env={"DB_PASSWORD": "secret"})
    agent = Agent(name="claude", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/test")

    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=["DB_PASSWORD"],
        exposed_tools=[],
    )
    score = br.calculate_risk_score()
    assert score > 8.0  # Critical + credential = high score


# ─── Discovery Tests ────────────────────────────────────────────────────────


def test_parse_claude_desktop_config():
    config = {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            },
            "database": {
                "command": "python",
                "args": ["db_server.py"],
                "env": {"DB_TOKEN": "secret123"},
            },
        }
    }
    servers = parse_mcp_config(config, "/test/config.json")
    assert len(servers) == 2
    assert servers[0].name == "filesystem"
    assert servers[0].command == "npx"
    assert servers[1].name == "database"
    assert servers[1].has_credentials


def test_parse_sse_transport():
    config = {
        "mcpServers": {
            "remote": {
                "command": "",
                "url": "https://api.example.com/sse",
            }
        }
    }
    servers = parse_mcp_config(config, "/test/config.json")
    assert len(servers) == 1
    assert servers[0].transport == TransportType.SSE


def test_parse_empty_config():
    config = {}
    servers = parse_mcp_config(config, "/test/config.json")
    assert len(servers) == 0


# ─── Parser Tests ───────────────────────────────────────────────────────────


def test_parse_npm_package_json():
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg_json = Path(tmpdir) / "package.json"
        pkg_json.write_text(json.dumps({
            "dependencies": {
                "express": "^4.18.2",
                "axios": "~1.6.0",
            },
            "devDependencies": {
                "jest": "^29.0.0",
            }
        }))

        packages = parse_npm_packages(Path(tmpdir))
        assert len(packages) == 3
        names = {p.name for p in packages}
        assert "express" in names
        assert "axios" in names
        assert "jest" in names
        assert all(p.ecosystem == "npm" for p in packages)


def test_parse_pip_requirements():
    with tempfile.TemporaryDirectory() as tmpdir:
        req_file = Path(tmpdir) / "requirements.txt"
        req_file.write_text(
            "flask==3.0.0\n"
            "requests>=2.31.0\n"
            "# comment\n"
            "numpy==1.26.0\n"
            "-r other.txt\n"
        )

        packages = parse_pip_packages(Path(tmpdir))
        assert len(packages) == 3
        names = {p.name for p in packages}
        assert "flask" in names
        assert "requests" in names
        assert "numpy" in names


def test_npx_package_detection():
    server = MCPServer(
        name="filesystem",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    )
    from agent_bom.parsers import detect_npx_package
    packages = detect_npx_package(server)
    assert len(packages) == 1
    assert packages[0].name == "@modelcontextprotocol/server-filesystem"
    assert packages[0].ecosystem == "npm"


def test_uvx_package_detection():
    server = MCPServer(
        name="mcp-server-fetch",
        command="uvx",
        args=["mcp-server-fetch"],
    )
    from agent_bom.parsers import detect_uvx_package
    packages = detect_uvx_package(server)
    assert len(packages) == 1
    assert packages[0].name == "mcp-server-fetch"
    assert packages[0].ecosystem == "pypi"


# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def sample_report():
    """Build a minimal AIBOMReport with one vulnerability."""
    vuln = Vulnerability(
        id="CVE-2024-1234",
        summary="Test RCE vulnerability",
        severity=Severity.HIGH,
        cvss_score=8.5,
        fixed_version="1.2.3",
        cwe_ids=["CWE-79"],
    )
    pkg = Package(
        name="test-pkg",
        version="1.0.0",
        ecosystem="npm",
        vulnerabilities=[vuln],
    )
    server = MCPServer(
        name="test-server",
        command="npx",
        args=["-y", "test-pkg"],
        env={"API_KEY": "secret"},
        packages=[pkg],
    )
    agent = Agent(
        name="test-agent",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/test-config.json",
        mcp_servers=[server],
    )
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=["API_KEY"],
        exposed_tools=[],
    )
    br.calculate_risk_score()
    return AIBOMReport(agents=[agent], blast_radii=[br])


@pytest.fixture
def empty_report():
    """Report with no agents or vulnerabilities."""
    return AIBOMReport(agents=[], blast_radii=[])


# ─── Version Tests ───────────────────────────────────────────────────────────


def test_version_sync():
    from agent_bom import __version__
    assert __version__ == "0.3.0"


def test_report_version_matches():
    report = AIBOMReport()
    from agent_bom import __version__
    assert report.tool_version == __version__


# ─── SARIF Output Tests ──────────────────────────────────────────────────────


def test_sarif_schema_structure(sample_report):
    sarif = to_sarif(sample_report)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "agent-bom"
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 1


def test_sarif_rule_ids_match_results(sample_report):
    sarif = to_sarif(sample_report)
    run = sarif["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    result_rule_ids = {r["ruleId"] for r in run["results"]}
    assert result_rule_ids.issubset(rule_ids)


def test_sarif_severity_mapping(sample_report):
    sarif = to_sarif(sample_report)
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "error"  # HIGH maps to error


def test_sarif_empty_report(empty_report):
    sarif = to_sarif(empty_report)
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_export_file(sample_report, tmp_path):
    out = tmp_path / "test.sarif"
    export_sarif(sample_report, str(out))
    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 1


# ─── JSON / CycloneDX Output Tests ───────────────────────────────────────────


def test_json_output_structure(sample_report):
    data = to_json(sample_report)
    assert "agents" in data
    assert "blast_radius" in data
    assert data["summary"]["total_vulnerabilities"] == 1
    assert data["ai_bom_version"] == sample_report.tool_version


def test_cyclonedx_output_structure(sample_report):
    data = to_cyclonedx(sample_report)
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.6"
    assert len(data["components"]) > 0
    assert "vulnerabilities" in data


# ─── CLI Tests ───────────────────────────────────────────────────────────────


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "agent-bom" in result.output


def test_cli_scan_empty_dir_exits_0():
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        result = runner.invoke(main, ["scan", "--project", tmpdir])
        assert result.exit_code == 0


def test_cli_help_shows_exit_codes():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert "Exit codes" in result.output
    assert "0" in result.output
    assert "1" in result.output


# ─── History / Diff Tests ─────────────────────────────────────────────────────


def test_history_save_and_load(tmp_path, monkeypatch):
    from agent_bom.history import load_report, save_report
    monkeypatch.setattr("agent_bom.history.HISTORY_DIR", tmp_path)

    data = {"ai_bom_version": "0.3.0", "generated_at": "2025-01-01T00:00:00", "summary": {}, "agents": [], "blast_radius": []}
    saved = save_report(data, label="test")
    assert saved.exists()
    loaded = load_report(saved)
    assert loaded["ai_bom_version"] == "0.3.0"


def test_diff_no_changes():
    from agent_bom.history import diff_reports

    report = {
        "generated_at": "2025-01-01T00:00:00",
        "agents": [{"name": "a", "mcp_servers": [{"packages": [{"name": "express", "version": "4.18.2", "ecosystem": "npm"}]}]}],
        "blast_radius": [{"vulnerability_id": "CVE-2024-1", "package": "express@4.18.2", "ecosystem": "npm", "severity": "HIGH"}],
    }
    diff = diff_reports(report, report)
    assert diff["summary"]["new_findings"] == 0
    assert diff["summary"]["resolved_findings"] == 0
    assert diff["summary"]["unchanged_findings"] == 1


def test_diff_new_finding():
    from agent_bom.history import diff_reports

    baseline = {
        "generated_at": "2025-01-01T00:00:00",
        "agents": [],
        "blast_radius": [],
    }
    current = {
        "generated_at": "2025-01-02T00:00:00",
        "agents": [],
        "blast_radius": [
            {"vulnerability_id": "CVE-2024-99", "package": "lodash@4.17.20", "ecosystem": "npm", "severity": "CRITICAL"},
        ],
    }
    diff = diff_reports(baseline, current)
    assert diff["summary"]["new_findings"] == 1
    assert diff["summary"]["resolved_findings"] == 0
    assert len(diff["new"]) == 1
    assert diff["new"][0]["vulnerability_id"] == "CVE-2024-99"


def test_diff_resolved_finding():
    from agent_bom.history import diff_reports

    baseline = {
        "generated_at": "2025-01-01T00:00:00",
        "agents": [],
        "blast_radius": [
            {"vulnerability_id": "CVE-2023-10", "package": "axios@1.6.0", "ecosystem": "npm", "severity": "HIGH"},
        ],
    }
    current = {"generated_at": "2025-01-02T00:00:00", "agents": [], "blast_radius": []}
    diff = diff_reports(baseline, current)
    assert diff["summary"]["resolved_findings"] == 1
    assert len(diff["resolved"]) == 1


def test_cli_check_help():
    runner = CliRunner()
    result = runner.invoke(main, ["check", "--help"])
    assert result.exit_code == 0
    assert "ecosystem" in result.output.lower()


def test_cli_history_help():
    runner = CliRunner()
    result = runner.invoke(main, ["history", "--help"])
    assert result.exit_code == 0


def test_cli_diff_help():
    runner = CliRunner()
    result = runner.invoke(main, ["diff", "--help"])
    assert result.exit_code == 0
    assert "baseline" in result.output.lower()


def test_cli_scan_new_flags():
    """New policy flags appear in --help."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert "--fail-on-kev" in result.output
    assert "--fail-if-ai-risk" in result.output
    assert "--save" in result.output
    assert "--baseline" in result.output


def test_json_output_has_enriched_vuln_fields(sample_report):
    data = to_json(sample_report)
    agents = data["agents"]
    assert len(agents) > 0
    server = agents[0]["mcp_servers"][0]
    assert "mcp_version" in server
    vuln = server["packages"][0]["vulnerabilities"][0]
    assert "epss_score" in vuln
    assert "is_kev" in vuln
    assert "cwe_ids" in vuln


def test_json_output_blast_radius_has_new_fields(sample_report):
    data = to_json(sample_report)
    br = data["blast_radius"][0]
    assert "ai_risk_context" in br
    assert "epss_score" in br
    assert "is_kev" in br
    assert "cvss_score" in br


# ─── Policy Engine Tests ──────────────────────────────────────────────────────


def test_policy_pass_no_vulns():
    from agent_bom.policy import evaluate_policy

    policy = {
        "name": "test",
        "rules": [{"id": "no-critical", "severity_gte": "CRITICAL", "action": "fail"}],
    }
    result = evaluate_policy(policy, [])
    assert result["passed"]
    assert result["failures"] == []
    assert result["warnings"] == []


def test_policy_fail_critical(sample_report):
    from agent_bom.policy import evaluate_policy

    policy = {
        "name": "test",
        "rules": [{"id": "no-high", "severity_gte": "HIGH", "action": "fail"}],
    }
    result = evaluate_policy(policy, sample_report.blast_radii)
    # sample_report has a HIGH vuln — should fail
    assert not result["passed"]
    assert len(result["failures"]) >= 1
    assert result["failures"][0]["rule_id"] == "no-high"


def test_policy_warn_medium():
    from agent_bom.models import Agent, AgentType, BlastRadius, MCPServer, Package, Severity, Vulnerability
    from agent_bom.policy import evaluate_policy

    vuln = Vulnerability(id="CVE-2024-9999", summary="Medium issue", severity=Severity.MEDIUM)
    pkg = Package(name="requests", version="2.27.0", ecosystem="pypi")
    server = MCPServer(name="api", command="uvx", env={})
    agent = Agent(name="bot", agent_type=AgentType.CUSTOM, config_path="/tmp/test")
    br = BlastRadius(
        vulnerability=vuln, package=pkg,
        affected_servers=[server], affected_agents=[agent],
        exposed_credentials=[], exposed_tools=[],
    )
    br.calculate_risk_score()

    policy = {
        "name": "test",
        "rules": [{"id": "warn-medium", "severity_gte": "MEDIUM", "action": "warn"}],
    }
    result = evaluate_policy(policy, [br])
    assert result["passed"]  # warnings don't fail
    assert len(result["warnings"]) == 1


def test_policy_template_command():
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = str(Path(tmpdir) / "policy.json")
        result = runner.invoke(main, ["policy-template", "-o", out_file])
        assert result.exit_code == 0
        data = json.loads(Path(out_file).read_text())
        assert "rules" in data
        assert len(data["rules"]) > 0
        assert all("id" in r and "action" in r for r in data["rules"])


def test_policy_has_credentials_filter():
    from agent_bom.models import (
        Agent,
        AgentType,
        BlastRadius,
        MCPServer,
        Package,
        Severity,
        Vulnerability,
    )
    from agent_bom.policy import evaluate_policy

    vuln = Vulnerability(id="CVE-2024-1111", summary="Critical", severity=Severity.CRITICAL)
    pkg = Package(name="express", version="4.18.2", ecosystem="npm")
    server = MCPServer(name="no-creds-server", command="node", env={})
    agent = Agent(name="agent", agent_type=AgentType.CUSTOM, config_path="/tmp")
    br = BlastRadius(
        vulnerability=vuln, package=pkg,
        affected_servers=[server], affected_agents=[agent],
        exposed_credentials=[],  # no credentials
        exposed_tools=[],
    )
    br.calculate_risk_score()

    # Rule requires has_credentials — should NOT match since no creds
    policy = {
        "name": "test",
        "rules": [{"id": "cred-only", "severity_gte": "CRITICAL", "has_credentials": True, "action": "fail"}],
    }
    result = evaluate_policy(policy, [br])
    assert result["passed"]  # no match because no credentials


# ─── SPDX 3.0 Tests ──────────────────────────────────────────────────────────


def test_spdx_output_structure(sample_report):
    from agent_bom.output import to_spdx

    data = to_spdx(sample_report)
    assert data["spdxVersion"] == "SPDX-3.0"
    assert data["dataLicense"] == "CC0-1.0"
    assert "elements" in data
    assert "relationships" in data
    assert "creationInfo" in data
    assert len(data["elements"]) > 0


def test_spdx_has_vulnerability_elements(sample_report):
    from agent_bom.output import to_spdx

    data = to_spdx(sample_report)
    vuln_elements = [e for e in data["elements"] if e.get("type") == "security/Vulnerability"]
    assert len(vuln_elements) >= 1
    assert vuln_elements[0]["name"] == "CVE-2024-1234"


def test_spdx_export_file(sample_report, tmp_path):
    from agent_bom.output import export_spdx

    out = tmp_path / "test.spdx.json"
    export_spdx(sample_report, str(out))
    data = json.loads(out.read_text())
    assert data["spdxVersion"] == "SPDX-3.0"


def test_cli_scan_has_spdx_format():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert "spdx" in result.output


def test_cli_scan_has_policy_flag():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert "--policy" in result.output


# ─── Scanner Mock Test ───────────────────────────────────────────────────────


def test_osv_empty_response_yields_no_blast_radii(monkeypatch):
    """OSV query returning empty results should produce zero blast radii."""

    from agent_bom.models import Agent, AgentType, MCPServer, Package
    from agent_bom.scanners import scan_agents_sync

    async def _empty_osv(packages):
        return {}

    monkeypatch.setattr("agent_bom.scanners.query_osv_batch", _empty_osv)

    pkg = Package(name="express", version="4.18.2", ecosystem="npm")
    server = MCPServer(name="srv", command="node", env={}, packages=[pkg])
    agent = Agent(name="agt", agent_type=AgentType.CUSTOM, config_path="/tmp", mcp_servers=[server])

    blast_radii = scan_agents_sync([agent])
    assert blast_radii == []
