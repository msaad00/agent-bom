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
    assert __version__ == "0.24.0"


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


# ─── Cortex Code + Registry Tests ────────────────────────────────────────────


def test_cortex_code_agent_type_exists():
    from agent_bom.models import AgentType
    assert AgentType.CORTEX_CODE == "cortex-code"
    assert AgentType.ZED == "zed"
    assert AgentType.CONTINUE == "continue"


def test_cortex_code_in_discovery_locations():
    from agent_bom.discovery import CONFIG_LOCATIONS
    from agent_bom.models import AgentType
    assert AgentType.CORTEX_CODE in CONFIG_LOCATIONS
    paths = CONFIG_LOCATIONS[AgentType.CORTEX_CODE]
    # All platforms should point to ~/.snowflake/cortex/mcp.json
    for platform_paths in paths.values():
        assert any("snowflake/cortex/mcp.json" in p for p in platform_paths)


def test_vscode_copilot_in_discovery_locations():
    from agent_bom.discovery import CONFIG_LOCATIONS
    from agent_bom.models import AgentType
    assert AgentType.VSCODE_COPILOT in CONFIG_LOCATIONS


def test_mcp_registry_loads():
    from agent_bom.parsers import _load_registry
    registry = _load_registry()
    assert len(registry) > 0
    assert "@modelcontextprotocol/server-filesystem" in registry
    assert "@modelcontextprotocol/server-github" in registry


def test_mcp_registry_lookup_by_arg(tmp_path):
    from agent_bom.models import MCPServer
    from agent_bom.parsers import lookup_mcp_registry

    server = MCPServer(
        name="filesystem",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem"],
        env={},
    )
    packages = lookup_mcp_registry(server)
    assert len(packages) == 1
    assert packages[0].name == "@modelcontextprotocol/server-filesystem"
    assert packages[0].ecosystem == "npm"
    assert packages[0].resolved_from_registry is True


def test_mcp_registry_lookup_unknown_server():
    from agent_bom.models import MCPServer
    from agent_bom.parsers import lookup_mcp_registry

    server = MCPServer(name="totally-unknown-server-xyz", command="node", env={})
    packages = lookup_mcp_registry(server)
    assert packages == []


def test_continue_format_parsed(tmp_path):
    """Continue.dev uses array format for mcpServers."""
    from agent_bom.discovery import parse_mcp_config

    config = {
        "mcpServers": [
            {"name": "filesystem", "command": "npx",
             "args": ["-y", "@modelcontextprotocol/server-filesystem"]}
        ]
    }
    servers = parse_mcp_config(config, str(tmp_path))
    assert len(servers) == 1
    assert servers[0].name == "filesystem"
    assert servers[0].command == "npx"


def test_zed_format_parsed(tmp_path):
    """Zed uses context_servers with nested command object."""
    from agent_bom.discovery import parse_mcp_config

    config = {
        "context_servers": {
            "postgres": {
                "command": {
                    "path": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-postgres"]
                }
            }
        }
    }
    servers = parse_mcp_config(config, str(tmp_path))
    assert len(servers) == 1
    assert servers[0].name == "postgres"
    assert servers[0].command == "npx"


# ─── SBOM Ingestion Tests ─────────────────────────────────────────────────────


def test_parse_cyclonedx_components():
    from agent_bom.sbom import parse_cyclonedx

    data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {"name": "express", "version": "4.18.2",
             "purl": "pkg:npm/express@4.18.2", "type": "library"},
            {"name": "requests", "version": "2.28.0",
             "purl": "pkg:pypi/requests@2.28.0", "type": "library"},
        ],
    }
    packages = parse_cyclonedx(data)
    assert len(packages) == 2
    assert packages[0].name == "express"
    assert packages[0].ecosystem == "npm"
    assert packages[1].name == "requests"
    assert packages[1].ecosystem == "pypi"


def test_parse_spdx2_packages():
    from agent_bom.sbom import parse_spdx

    data = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "lodash",
                "versionInfo": "4.17.21",
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.21"},
                ],
            }
        ],
    }
    packages = parse_spdx(data)
    assert len(packages) == 1
    assert packages[0].name == "lodash"
    assert packages[0].version == "4.17.21"
    assert packages[0].ecosystem == "npm"


def test_load_sbom_cyclonedx(tmp_path):
    import json as _json

    from agent_bom.sbom import load_sbom

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {"name": "flask", "version": "2.3.0",
             "purl": "pkg:pypi/flask@2.3.0", "type": "library"},
        ],
    }
    p = tmp_path / "sbom.json"
    p.write_text(_json.dumps(sbom))
    packages, fmt = load_sbom(str(p))
    assert fmt == "cyclonedx"
    assert len(packages) == 1
    assert packages[0].name == "flask"


def test_load_sbom_unknown_format(tmp_path):
    import json as _json

    from agent_bom.sbom import load_sbom

    p = tmp_path / "bad.json"
    p.write_text(_json.dumps({"random": "data"}))
    try:
        load_sbom(str(p))
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Unrecognised" in str(e)


def test_cli_scan_has_sbom_flag():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert "--sbom" in result.output


# ─── Image scanning tests ────────────────────────────────────────────────────


def test_image_to_purl_simple():
    from agent_bom.image import image_to_purl

    assert image_to_purl("nginx:1.25") == "pkg:oci/nginx:1.25"


def test_image_to_purl_with_registry():
    from agent_bom.image import image_to_purl

    purl = image_to_purl("ghcr.io/org/app:v1.0.0")
    assert purl == "pkg:oci/org/app:v1.0.0?repository_url=ghcr.io"


def test_image_scan_no_tools(monkeypatch):
    """scan_image raises ImageScanError when neither syft nor docker is available."""
    import shutil

    from agent_bom.image import ImageScanError, scan_image

    monkeypatch.setattr(shutil, "which", lambda _: None)
    with pytest.raises(ImageScanError, match="Neither"):
        scan_image("nginx:latest")


def test_scan_with_syft_preferred(monkeypatch):
    """scan_image uses syft when grype is absent but syft is present."""
    import shutil
    import subprocess

    from agent_bom.image import scan_image

    # Grype not available → falls through to syft
    monkeypatch.setattr(shutil, "which", lambda cmd: None if cmd == "grype" else "/usr/bin/" + cmd)

    # Return a minimal CycloneDX JSON from syft
    fake_cdx = json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0", "type": "library"}
        ],
    })

    def fake_run(cmd, **kwargs):
        class R:
            returncode = 0
            stdout = fake_cdx
            stderr = ""
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    packages, strategy = scan_image("myapp:latest")
    assert strategy == "syft"
    assert len(packages) == 1
    assert packages[0].name == "requests"
    assert packages[0].ecosystem == "pypi"


def test_scan_with_syft_error(monkeypatch):
    """scan_image raises ImageScanError when syft exits non-zero."""
    import shutil
    import subprocess

    from agent_bom.image import ImageScanError, scan_image

    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/syft" if cmd == "syft" else None)

    def fake_run(cmd, **kwargs):
        class R:
            returncode = 1
            stdout = ""
            stderr = "image not found"
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ImageScanError, match="syft exited"):
        scan_image("nonexistent:latest")


def test_cli_scan_has_image_flag():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert "--image" in result.output


def test_cli_scan_has_k8s_flags():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert "--k8s" in result.output
    assert "--namespace" in result.output


# ─── K8s discovery tests ──────────────────────────────────────────────────────


def test_k8s_discover_no_kubectl(monkeypatch):
    """discover_images raises K8sDiscoveryError when kubectl is not available."""
    import shutil

    from agent_bom.k8s import K8sDiscoveryError, discover_images

    monkeypatch.setattr(shutil, "which", lambda _: None)
    with pytest.raises(K8sDiscoveryError, match="kubectl"):
        discover_images()


def test_k8s_discover_parses_pods(monkeypatch):
    """discover_images extracts unique image refs from kubectl JSON output."""
    import shutil
    import subprocess

    from agent_bom.k8s import discover_images

    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/" + cmd)

    fake_pods = {
        "items": [
            {
                "metadata": {"name": "web-pod", "namespace": "default"},
                "spec": {
                    "containers": [
                        {"name": "web", "image": "nginx:1.25"},
                        {"name": "sidecar", "image": "busybox:latest"},
                    ],
                    "initContainers": [
                        {"name": "init", "image": "nginx:1.25"},  # duplicate — should be skipped
                    ],
                },
            }
        ]
    }

    def fake_run(cmd, **kwargs):
        class R:
            returncode = 0
            stdout = json.dumps(fake_pods)
            stderr = ""
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    records = discover_images(namespace="default")
    images = [r[0] for r in records]
    assert "nginx:1.25" in images
    assert "busybox:latest" in images
    assert images.count("nginx:1.25") == 1  # deduplication


def test_k8s_discover_kubectl_error(monkeypatch):
    """discover_images raises K8sDiscoveryError on non-zero kubectl exit."""
    import shutil
    import subprocess

    from agent_bom.k8s import K8sDiscoveryError, discover_images

    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/" + cmd)

    def fake_run(cmd, **kwargs):
        class R:
            returncode = 1
            stdout = ""
            stderr = "Error from server: connection refused"
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(K8sDiscoveryError, match="kubectl exited"):
        discover_images()


def test_k8s_all_namespaces_flag(monkeypatch):
    """discover_images includes namespace in pod name when --all-namespaces."""
    import shutil
    import subprocess

    from agent_bom.k8s import discover_images

    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/" + cmd)

    fake_pods = {
        "items": [
            {
                "metadata": {"name": "my-pod", "namespace": "prod"},
                "spec": {
                    "containers": [{"name": "app", "image": "myapp:v2"}],
                },
            }
        ]
    }

    captured_cmd = []

    def fake_run(cmd, **kwargs):
        captured_cmd.extend(cmd)

        class R:
            returncode = 0
            stdout = json.dumps(fake_pods)
            stderr = ""
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    records = discover_images(all_namespaces=True)
    assert "-A" in captured_cmd
    assert records[0][1] == "prod/my-pod"  # qualified pod name includes namespace


# ─── HTML report tests ───────────────────────────────────────────────────────


def _make_report_with_vuln() -> tuple:
    """Build a minimal AIBOMReport with one vulnerability for HTML tests."""
    vuln = Vulnerability(
        id="CVE-2024-9999",
        summary="Test vuln",
        severity=Severity.HIGH,
        cvss_score=7.5,
        fixed_version="2.0.0",
    )
    pkg = Package(
        name="testpkg", version="1.0.0", ecosystem="npm",
        vulnerabilities=[vuln],
    )
    server = MCPServer(
        name="test-server", command="npx",
        args=["testpkg"],
        env={"API_KEY": "secret"},
        packages=[pkg],
    )
    agent = Agent(
        name="test-agent", agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/config.json", mcp_servers=[server],
    )
    report = AIBOMReport(agents=[agent])
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_agents=[agent],
        affected_servers=[server],
        exposed_credentials=["API_KEY"],
        exposed_tools=[],
    )
    return report, [br]


def test_html_output_is_valid_html():
    from agent_bom.output.html import to_html

    report, blast_radii = _make_report_with_vuln()
    html = to_html(report, blast_radii)
    assert "<!DOCTYPE html>" in html
    assert "<title>" in html
    assert "agent-bom" in html


def test_html_contains_summary_data():
    from agent_bom.output.html import to_html

    report, blast_radii = _make_report_with_vuln()
    html = to_html(report, blast_radii)
    assert "test-agent" in html
    assert "test-server" in html
    assert "testpkg" in html
    assert "1.0.0" in html


def test_html_contains_vuln_table():
    from agent_bom.output.html import to_html

    report, blast_radii = _make_report_with_vuln()
    html = to_html(report, blast_radii)
    assert "CVE-2024-9999" in html
    assert "HIGH" in html
    assert "2.0.0" in html  # fix version


def test_html_contains_credential_warning():
    from agent_bom.output.html import to_html

    report, blast_radii = _make_report_with_vuln()
    html = to_html(report, blast_radii)
    assert "API_KEY" in html


def test_html_contains_cytoscape_graph():
    from agent_bom.output.html import to_html

    report, blast_radii = _make_report_with_vuln()
    html = to_html(report, blast_radii)
    assert "cytoscape" in html.lower()
    assert "cy.nodes" in html or "cytoscape(" in html


def test_html_clean_report_shows_clean_status():
    from agent_bom.output.html import to_html

    pkg = Package(name="safe-pkg", version="1.0.0", ecosystem="npm")
    server = MCPServer(name="safe-server", command="npx", args=["safe-pkg"], packages=[pkg])
    agent = Agent(
        name="safe-agent", agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/config.json", mcp_servers=[server],
    )
    report = AIBOMReport(agents=[agent])
    html = to_html(report, [])
    assert "CLEAN" in html
    # Vuln section should be absent when no blast_radii passed
    assert "CVE-" not in html


def test_html_export_writes_file(tmp_path):
    from agent_bom.output.html import export_html

    report, blast_radii = _make_report_with_vuln()
    out = tmp_path / "report.html"
    export_html(report, str(out), blast_radii)
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert len(content) > 5000  # sanity check — should be a real file


def test_cli_scan_has_html_format():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert "html" in result.output


# ─── Prometheus output tests ──────────────────────────────────────────────────


def test_prometheus_output_has_required_metrics():
    from agent_bom.output.prometheus import to_prometheus

    report, blast_radii = _make_report_with_vuln()
    prom = to_prometheus(report, blast_radii)

    # Core metrics must be present
    assert "agent_bom_agents_total" in prom
    assert "agent_bom_mcp_servers_total" in prom
    assert "agent_bom_packages_total" in prom
    assert "agent_bom_vulnerabilities_total" in prom
    assert "agent_bom_kev_findings_total" in prom
    assert "agent_bom_fixable_vulnerabilities_total" in prom
    assert "agent_bom_blast_radius_score" in prom
    assert "agent_bom_credentials_exposed_total" in prom
    assert "agent_bom_agent_vulnerabilities_total" in prom
    assert "agent_bom_scan_timestamp_seconds" in prom
    assert "agent_bom_info" in prom


def test_prometheus_output_has_help_and_type_lines():
    from agent_bom.output.prometheus import to_prometheus

    report, blast_radii = _make_report_with_vuln()
    prom = to_prometheus(report, blast_radii)

    assert "# HELP agent_bom_agents_total" in prom
    assert "# TYPE agent_bom_agents_total gauge" in prom
    assert "# HELP agent_bom_blast_radius_score" in prom
    assert "# TYPE agent_bom_blast_radius_score gauge" in prom


def test_prometheus_severity_labels():
    from agent_bom.output.prometheus import to_prometheus

    report, blast_radii = _make_report_with_vuln()
    prom = to_prometheus(report, blast_radii)

    # All four severity labels should appear
    assert 'severity="critical"' in prom
    assert 'severity="high"' in prom
    assert 'severity="medium"' in prom
    assert 'severity="low"' in prom


def test_prometheus_blast_radius_labels():
    from agent_bom.output.prometheus import to_prometheus

    report, blast_radii = _make_report_with_vuln()
    prom = to_prometheus(report, blast_radii)

    # Check that blast_radius_score has required labels
    assert 'vuln_id="CVE-2024-9999"' in prom
    assert 'package="testpkg"' in prom
    assert 'severity="high"' in prom
    # fixable should be "1" since there is a fixed_version
    assert 'fixable="1"' in prom


def test_prometheus_export_writes_file(tmp_path):
    from agent_bom.output.prometheus import export_prometheus

    report, blast_radii = _make_report_with_vuln()
    out = tmp_path / "metrics.prom"
    export_prometheus(report, str(out), blast_radii)
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "agent_bom_agents_total" in content
    assert len(content) > 200


def test_prometheus_clean_report_zero_vulns():
    from agent_bom.output.prometheus import to_prometheus

    pkg = Package(name="safe-pkg", version="1.0.0", ecosystem="npm")
    server = MCPServer(name="safe-server", command="npx", args=["safe-pkg"], packages=[pkg])
    agent = Agent(
        name="safe-agent", agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/config.json", mcp_servers=[server],
    )
    report = AIBOMReport(agents=[agent])
    prom = to_prometheus(report, [])

    assert 'agent_bom_vulnerabilities_total{severity="critical"} 0' in prom
    assert 'agent_bom_vulnerabilities_total{severity="high"} 0' in prom
    assert "agent_bom_kev_findings_total 0" in prom
    assert "agent_bom_agents_total 1" in prom


def test_cli_scan_has_prometheus_format():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert "prometheus" in result.output
    assert "--push-gateway" in result.output


# ─── Terraform scanner tests ──────────────────────────────────────────────────


def test_terraform_provider_extraction(tmp_path):
    """_extract_providers finds provider source and version from required_providers block."""
    from agent_bom.terraform import _extract_providers

    tf = tmp_path / "main.tf"
    tf.write_text("""
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.30"
    }
    google = {
      source  = "hashicorp/google"
      version = "6.0.0"
    }
  }
}
""")
    providers = _extract_providers([(tf, tf.read_text())])
    assert "hashicorp/aws" in providers
    assert providers["hashicorp/aws"] == "5.30"
    assert "hashicorp/google" in providers
    assert providers["hashicorp/google"] == "6.0.0"


def test_terraform_ai_resource_detection(tmp_path):
    """_extract_ai_resources finds AI-specific resource types."""
    from agent_bom.terraform import _extract_ai_resources

    tf = tmp_path / "bedrock.tf"
    tf.write_text("""
resource "aws_bedrockagent_agent" "my_agent" {
  agent_name = "my-bedrock-agent"
  foundation_model = "anthropic.claude-3-sonnet-20240229-v1:0"
}

resource "aws_s3_bucket" "artifacts" {
  bucket = "my-artifacts"
}
""")
    resources = _extract_ai_resources([(tf, tf.read_text())])
    assert len(resources) == 1
    rtype, rname, fname = resources[0]
    assert rtype == "aws_bedrockagent_agent"
    assert rname == "my_agent"


def test_terraform_hardcoded_secret_detection(tmp_path):
    """_detect_hardcoded_secrets flags API key default values."""
    from agent_bom.terraform import _detect_hardcoded_secrets

    tf = tmp_path / "vars.tf"
    tf.write_text("""
variable "openai_api_key" {
  type    = string
  default = "sk-abc123realkey456789012345678901234"
}

variable "normal_var" {
  type    = string
  default = "hello"
}
""")
    secrets = _detect_hardcoded_secrets([(tf, tf.read_text())])
    assert len(secrets) == 1
    assert "openai_api_key".upper() in secrets[0].variable_name.upper()


def test_terraform_placeholder_not_flagged(tmp_path):
    """_detect_hardcoded_secrets should NOT flag obvious placeholder values."""
    from agent_bom.terraform import _detect_hardcoded_secrets

    tf = tmp_path / "vars.tf"
    tf.write_text("""
variable "openai_api_key" {
  type    = string
  default = "placeholder"
}
""")
    secrets = _detect_hardcoded_secrets([(tf, tf.read_text())])
    assert len(secrets) == 0


def test_terraform_scan_creates_agents(tmp_path):
    """scan_terraform_dir creates Agent entries for AI resources found."""
    from agent_bom.terraform import scan_terraform_dir

    tf = tmp_path / "main.tf"
    tf.write_text("""
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.30.0"
    }
  }
}

resource "aws_bedrockagent_agent" "analyst" {
  agent_name       = "analyst"
  foundation_model = "anthropic.claude-v2"
}
""")
    agents, warnings = scan_terraform_dir(str(tmp_path))
    assert len(agents) >= 1
    agent = agents[0]
    assert "terraform" in agent.name or "tf:" in agent.name
    assert agent.source == "terraform"
    # Provider package should be Go ecosystem
    pkgs = [p for srv in agent.mcp_servers for p in srv.packages]
    assert any(p.ecosystem == "Go" for p in pkgs)


def test_terraform_scan_empty_dir(tmp_path):
    """scan_terraform_dir returns empty list with a warning for directories with no .tf files."""
    from agent_bom.terraform import scan_terraform_dir

    agents, warnings = scan_terraform_dir(str(tmp_path))
    assert agents == []
    assert len(warnings) == 1
    assert "No .tf files" in warnings[0]


def test_terraform_secret_goes_to_env(tmp_path):
    """Hardcoded secrets appear as env keys (not values) in MCPServer.env."""
    from agent_bom.terraform import scan_terraform_dir

    tf = tmp_path / "main.tf"
    tf.write_text("""
variable "anthropic_api_key" {
  type    = string
  default = "sk-ant-realkey1234567890123456789012345"
}
""")
    agents, warnings = scan_terraform_dir(str(tmp_path))
    # Should have at least one agent with the credential in env
    assert len(agents) >= 1
    server = agents[0].mcp_servers[0]
    assert server.has_credentials
    assert any("ANTHROPIC" in k.upper() for k in server.env)
    # The value should be redacted — not the actual key
    for v in server.env.values():
        assert "sk-ant" not in v


def test_cli_scan_has_tf_dir_flag():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert "--tf-dir" in result.output


# ─── GitHub Actions scanner tests ─────────────────────────────────────────────


def test_gha_detects_ai_env_vars(tmp_path):
    """scan_github_actions flags workflows with AI API key env vars."""
    from agent_bom.github_actions import scan_github_actions

    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text("""
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    env:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
      NORMAL_VAR: "hello"
    steps:
      - uses: actions/checkout@v4
""")
    agents, warnings = scan_github_actions(str(tmp_path))
    assert len(agents) == 1
    agent = agents[0]
    assert agent.source == "github-actions"
    server = agent.mcp_servers[0]
    assert server.has_credentials
    assert "OPENAI_API_KEY" in server.env
    assert len(warnings) == 1


def test_gha_no_ai_workflow_not_flagged(tmp_path):
    """scan_github_actions ignores workflows with no AI usage."""
    from agent_bom.github_actions import scan_github_actions

    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text("""
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pytest tests/
""")
    agents, warnings = scan_github_actions(str(tmp_path))
    assert agents == []
    assert warnings == []


def test_gha_detects_ai_sdk_in_run_step(tmp_path):
    """scan_github_actions detects openai/anthropic SDK usage in run: steps."""
    from agent_bom.github_actions import scan_github_actions

    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ai.yml").write_text("""
name: AI Pipeline
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          pip install openai anthropic
          python generate.py
""")
    agents, warnings = scan_github_actions(str(tmp_path))
    assert len(agents) == 1
    server = agents[0].mcp_servers[0]
    # openai and/or anthropic should appear as packages
    pkg_names = {p.name for p in server.packages}
    assert "openai" in pkg_names or "anthropic" in pkg_names


def test_gha_no_workflows_dir(tmp_path):
    """scan_github_actions returns empty when .github/workflows doesn't exist."""
    from agent_bom.github_actions import scan_github_actions

    agents, warnings = scan_github_actions(str(tmp_path))
    assert agents == []
    assert warnings == []


def test_cli_scan_has_gha_flag():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert "--gha" in result.output


# ─── Streamlit serve CLI test ─────────────────────────────────────────────────


def test_cli_serve_command_exists():
    runner = CliRunner()
    result = runner.invoke(main, ["serve", "--help"])
    assert result.exit_code == 0
    assert "--port" in result.output
    assert "--host" in result.output


def test_cli_serve_fails_without_streamlit(monkeypatch):
    """agent-bom serve exits with error when streamlit is not installed."""
    import builtins

    runner = CliRunner()

    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "streamlit":
            raise ImportError("No module named 'streamlit'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)
    result = runner.invoke(main, ["serve"])
    assert result.exit_code != 0 or "streamlit" in (result.output + str(result.exception)).lower()


# ─── Python agent framework scanner tests ─────────────────────────────────────

def test_python_agents_detects_openai_agents_sdk(tmp_path):
    """Detects openai-agents from requirements.txt and Agent() definition."""
    (tmp_path / "requirements.txt").write_text("openai-agents==0.0.11\nopenai>=1.0\n")
    (tmp_path / "agent.py").write_text(
        "from agents import Agent, function_tool\n\n"
        "@function_tool\ndef search_web(query: str): ...\n\n"
        "agent = Agent(name='support-bot', tools=[search_web], model='gpt-4o')\n"
    )
    from agent_bom.python_agents import scan_python_agents
    agents, warnings = scan_python_agents(str(tmp_path))
    assert any(a.name == "openai-agents:support-bot" for a in agents)
    agent = next(a for a in agents if "support-bot" in a.name)
    server = agent.mcp_servers[0]
    tool_names = [t.name for t in server.tools]
    assert "search_web" in tool_names or "gpt-4o" in tool_names
    assert any(p.name == "openai-agents" for p in server.packages)


def test_python_agents_detects_google_adk(tmp_path):
    """Detects google-adk from pyproject.toml."""
    (tmp_path / "pyproject.toml").write_text(
        "[project]\ndependencies = [\n  \"google-adk>=0.3.0\",\n]\n"
    )
    (tmp_path / "main.py").write_text(
        "from google.adk.agents import Agent\n"
        "agent = Agent(name='researcher', tools=[])\n"
    )
    from agent_bom.python_agents import scan_python_agents
    agents, warnings = scan_python_agents(str(tmp_path))
    assert len(agents) >= 1
    assert any("google-adk" in a.name or "researcher" in a.name for a in agents)


def test_python_agents_detects_langchain(tmp_path):
    """Detects langchain from requirements and import."""
    (tmp_path / "requirements.txt").write_text("langchain==0.2.16\nlangchain-openai==0.1.9\n")
    (tmp_path / "chain.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "from langchain.agents import create_openai_tools_agent\n"
        "agent = AgentExecutor(name='qa-agent', tools=[], agent=None)\n"
    )
    from agent_bom.python_agents import scan_python_agents
    agents, warnings = scan_python_agents(str(tmp_path))
    assert len(agents) >= 1
    pkgs = [p.name for a in agents for s in a.mcp_servers for p in s.packages]
    assert "langchain" in pkgs


def test_python_agents_extracts_credential_refs(tmp_path):
    """Flags env var references that look like credentials."""
    (tmp_path / "requirements.txt").write_text("openai-agents==0.0.11\n")
    (tmp_path / "agent.py").write_text(
        "import os\nfrom agents import Agent\n"
        "key = os.environ.get('OPENAI_API_KEY')\n"
        "agent = Agent(name='my-bot', tools=[])\n"
    )
    from agent_bom.python_agents import scan_python_agents
    agents, warnings = scan_python_agents(str(tmp_path))
    assert len(agents) >= 1
    creds = {k for a in agents for s in a.mcp_servers for k in s.env}
    assert "OPENAI_API_KEY" in creds
    assert any("OPENAI_API_KEY" in w for w in warnings)


def test_python_agents_no_framework_returns_empty(tmp_path):
    """Returns empty when no agent framework is present."""
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask==3.0.0\n")
    (tmp_path / "app.py").write_text("import requests\nprint('hello')\n")
    from agent_bom.python_agents import scan_python_agents
    agents, warnings = scan_python_agents(str(tmp_path))
    assert agents == []


def test_python_agents_invalid_dir():
    """Returns error warning for nonexistent directory."""
    from agent_bom.python_agents import scan_python_agents
    agents, warnings = scan_python_agents("/nonexistent/path/xyz")
    assert agents == []
    assert len(warnings) == 1
    assert "Not a directory" in warnings[0]


def test_python_agents_synthetic_entry_when_no_def(tmp_path):
    """Creates synthetic agent entry when framework in requirements but no Agent() found."""
    (tmp_path / "requirements.txt").write_text("crewai==0.51.0\n")
    (tmp_path / "tasks.py").write_text(
        "from crewai import Task\ntask = Task(description='do research')\n"
    )
    from agent_bom.python_agents import scan_python_agents
    agents, warnings = scan_python_agents(str(tmp_path))
    # Should create a synthetic entry for crewai
    assert len(agents) >= 1
    pkgs = [p.name for a in agents for s in a.mcp_servers for p in s.packages]
    assert "crewai" in pkgs


def test_cli_scan_has_agent_project_flag():
    """CLI scan command exposes --agent-project flag."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--agent-project" in result.output


# ─── API tests ──────────────────────────────────────────────────────────────


def test_cli_api_help():
    """CLI exposes 'api' subcommand with expected options."""
    runner = CliRunner()
    result = runner.invoke(main, ["api", "--help"])
    assert result.exit_code == 0
    assert "--host" in result.output
    assert "--port" in result.output
    assert "--reload" in result.output
    assert "8422" in result.output  # default port shown


def test_cli_completions_help():
    """CLI exposes 'completions' subcommand for bash/zsh/fish."""
    runner = CliRunner()
    result = runner.invoke(main, ["completions", "--help"])
    assert result.exit_code == 0
    assert "bash" in result.output
    assert "zsh" in result.output
    assert "fish" in result.output


def test_api_import():
    """FastAPI server module imports cleanly when fastapi is available."""
    pytest.importorskip("fastapi", reason="fastapi not installed")
    from agent_bom.api.server import app  # noqa: F401
    assert app.title == "agent-bom API"


def test_api_health_endpoint():
    """GET /health returns {status: ok}."""
    pytest.importorskip("fastapi", reason="fastapi not installed")
    from fastapi.testclient import TestClient

    from agent_bom.api.server import app
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_api_version_endpoint():
    """GET /version returns current version string."""
    pytest.importorskip("fastapi", reason="fastapi not installed")
    from fastapi.testclient import TestClient

    from agent_bom import __version__
    from agent_bom.api.server import app
    client = TestClient(app)
    resp = client.get("/version")
    assert resp.status_code == 200
    assert resp.json()["version"] == __version__


def test_api_scan_submit_and_poll():
    """POST /v1/scan returns 202 with job_id; GET /v1/scan/{id} returns the job."""
    pytest.importorskip("fastapi", reason="fastapi not installed")
    from fastapi.testclient import TestClient

    from agent_bom.api.server import app
    client = TestClient(app)
    # Submit a scan with no targets — completes quickly (done or failed: no agents on CI)
    resp = client.post("/v1/scan", json={})
    assert resp.status_code == 202
    body = resp.json()
    assert "job_id" in body
    # All terminal states are valid: TestClient runs tasks synchronously so the job
    # may already be done/failed by the time we receive the response.
    assert body["status"] in ("pending", "running", "done", "failed")

    job_id = body["job_id"]
    poll = client.get(f"/v1/scan/{job_id}")
    assert poll.status_code == 200
    assert poll.json()["job_id"] == job_id


def test_api_scan_not_found():
    """GET /v1/scan/{id} with unknown id returns 404."""
    pytest.importorskip("fastapi", reason="fastapi not installed")
    from fastapi.testclient import TestClient

    from agent_bom.api.server import app
    client = TestClient(app)
    resp = client.get("/v1/scan/does-not-exist-12345")
    assert resp.status_code == 404


def test_api_jobs_list():
    """GET /v1/jobs returns a jobs list."""
    pytest.importorskip("fastapi", reason="fastapi not installed")
    from fastapi.testclient import TestClient

    from agent_bom.api.server import app
    client = TestClient(app)
    resp = client.get("/v1/jobs")
    assert resp.status_code == 200
    assert "jobs" in resp.json()


def test_cli_main_help_has_api_in_listing():
    """Main --help lists the api subcommand."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "api" in result.output


# ─── v0.7.0 tests: Grype, OWASP, trust signals, registry ─────────────────────


def test_grype_scan_mock(monkeypatch, tmp_path):
    """Grype scanner parses JSON output into Package objects with pre-populated vulns."""
    import json
    import shutil
    import subprocess

    from agent_bom.image import _scan_with_grype

    grype_output = {
        "matches": [
            {
                "artifact": {"name": "requests", "version": "2.28.0", "type": "python"},
                "vulnerability": {
                    "id": "CVE-2023-32681",
                    "severity": "Medium",
                    "description": "Proxy auth header leak",
                    "cvss": [{"metrics": {"baseScore": 6.1}}],
                    "fix": {"versions": ["2.31.0"]},
                },
            }
        ]
    }

    def fake_run(cmd, **kwargs):
        class R:
            returncode = 0
            stdout = json.dumps(grype_output)
            stderr = ""
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(shutil, "which", lambda x: "/usr/bin/grype" if x == "grype" else None)

    pkgs = _scan_with_grype("python:3.11")
    assert len(pkgs) == 1
    assert pkgs[0].name == "requests"
    assert pkgs[0].ecosystem == "pypi"
    assert len(pkgs[0].vulnerabilities) == 1
    vuln = pkgs[0].vulnerabilities[0]
    assert vuln.id == "CVE-2023-32681"
    assert vuln.cvss_score == 6.1
    assert vuln.fixed_version == "2.31.0"


def test_owasp_lm05_always_present(sample_report):
    """Any blast radius entry must always include LLM05 (Supply Chain)."""
    from agent_bom.owasp import tag_blast_radius
    br = sample_report.blast_radii[0]
    br.owasp_tags = tag_blast_radius(br)
    assert "LLM05" in br.owasp_tags


def test_owasp_lm06_credential_exposure(sample_report):
    """Credential exposure triggers LLM06 tagging."""
    from agent_bom.owasp import tag_blast_radius
    br = sample_report.blast_radii[0]
    br.exposed_credentials = ["OPENAI_API_KEY"]
    br.owasp_tags = tag_blast_radius(br)
    assert "LLM06" in br.owasp_tags


def test_owasp_lm08_excessive_agency(sample_report):
    """More than 5 exposed tools + HIGH/CRITICAL severity triggers LLM08."""
    from agent_bom.models import MCPTool, Severity
    from agent_bom.owasp import tag_blast_radius
    br = sample_report.blast_radii[0]
    br.vulnerability.severity = Severity.CRITICAL
    br.exposed_tools = [MCPTool(name=f"tool_{i}", description="") for i in range(6)]
    br.owasp_tags = tag_blast_radius(br)
    assert "LLM08" in br.owasp_tags


def test_owasp_tags_in_json_output(sample_report):
    """to_json() includes 'owasp_tags' field in each blast radius entry."""
    from agent_bom.output import to_json
    from agent_bom.owasp import tag_blast_radius
    # Populate tags first (normally done by scanner)
    for br in sample_report.blast_radii:
        br.owasp_tags = tag_blast_radius(br)
    data = to_json(sample_report)
    assert "blast_radius" in data
    for entry in data["blast_radius"]:
        assert "owasp_tags" in entry
        assert isinstance(entry["owasp_tags"], list)


def test_dry_run_exits_zero(tmp_path):
    """--dry-run prints access plan and exits 0 without scanning."""
    runner = CliRunner()
    inv = tmp_path / "inv.json"
    inv.write_text('{"agents": []}')
    result = runner.invoke(main, ["scan", "--dry-run", "--inventory", str(inv)])
    assert result.exit_code == 0
    assert "Dry-run" in result.output or "dry-run" in result.output or "Would" in result.output


def test_api_trust_headers():
    """Every API response includes X-Agent-Bom-Read-Only trust header."""
    pytest.importorskip("fastapi", reason="fastapi not installed")
    from fastapi.testclient import TestClient

    from agent_bom.api.server import app
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers.get("x-agent-bom-read-only") == "true"
    assert response.headers.get("x-agent-bom-no-credential-storage") == "true"


def test_api_agents_endpoint():
    """GET /v1/agents returns agents with count field."""
    pytest.importorskip("fastapi", reason="fastapi not installed")
    from fastapi.testclient import TestClient

    from agent_bom.api.server import app
    client = TestClient(app)
    resp = client.get("/v1/agents")
    assert resp.status_code == 200
    body = resp.json()
    assert "agents" in body
    assert "count" in body
    assert isinstance(body["agents"], list)
    assert body["count"] == len(body["agents"])


def test_api_scan_completes_successfully():
    """POST /v1/scan → GET poll returns status done with result."""
    pytest.importorskip("fastapi", reason="fastapi not installed")
    from fastapi.testclient import TestClient

    from agent_bom.api.server import app
    client = TestClient(app)
    resp = client.post("/v1/scan", json={})
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]

    # TestClient runs executor tasks synchronously, so poll should have result
    import time
    time.sleep(1)
    poll = client.get(f"/v1/scan/{job_id}")
    assert poll.status_code == 200
    data = poll.json()
    # Job should complete (done) or fail gracefully (no crash)
    assert data["status"] in ("done", "failed", "running")
    if data["status"] == "done":
        assert data["result"] is not None
        assert "agents" in data["result"]


def test_registry_endpoint():
    """GET /v1/registry returns a non-empty list of MCP servers."""
    pytest.importorskip("fastapi", reason="fastapi not installed")
    from fastapi.testclient import TestClient

    from agent_bom.api.server import _load_registry, app
    _load_registry.cache_clear()  # clear cache so fresh load from disk
    client = TestClient(app)
    response = client.get("/v1/registry")
    assert response.status_code == 200
    body = response.json()
    assert "servers" in body
    assert body["count"] == len(body["servers"])
    # Registry has at least the official modelcontextprotocol servers
    ids = [s["id"] for s in body["servers"]]
    assert "@modelcontextprotocol/server-filesystem" in ids


def test_api_skill_audit_endpoint():
    """GET /v1/scan/{id}/skill-audit returns skill audit data when available."""
    pytest.importorskip("fastapi", reason="fastapi not installed")
    from fastapi.testclient import TestClient

    from agent_bom.api.server import JobStatus, ScanJob, ScanRequest, _jobs, app
    client = TestClient(app)

    # Create a fake completed job with skill_audit data
    job = ScanJob(
        job_id="skill-audit-test",
        status=JobStatus.DONE,
        created_at="2026-01-01T00:00:00Z",
        request=ScanRequest(),
        result={
            "skill_audit": {
                "findings": [{"severity": "high", "category": "shell_access", "title": "Shell access"}],
                "packages_checked": 2,
                "servers_checked": 1,
                "credentials_checked": 0,
                "passed": False,
            }
        },
    )
    _jobs["skill-audit-test"] = job
    try:
        resp = client.get("/v1/scan/skill-audit-test/skill-audit")
        assert resp.status_code == 200
        body = resp.json()
        assert body["passed"] is False
        assert len(body["findings"]) == 1
        assert body["findings"][0]["category"] == "shell_access"
    finally:
        _jobs.pop("skill-audit-test", None)


def test_api_skill_audit_empty():
    """GET /v1/scan/{id}/skill-audit returns empty default when no skill audit ran."""
    pytest.importorskip("fastapi", reason="fastapi not installed")
    from fastapi.testclient import TestClient

    from agent_bom.api.server import JobStatus, ScanJob, ScanRequest, _jobs, app
    client = TestClient(app)

    job = ScanJob(
        job_id="no-skill-audit-test",
        status=JobStatus.DONE,
        created_at="2026-01-01T00:00:00Z",
        request=ScanRequest(),
        result={"agents": []},
    )
    _jobs["no-skill-audit-test"] = job
    try:
        resp = client.get("/v1/scan/no-skill-audit-test/skill-audit")
        assert resp.status_code == 200
        body = resp.json()
        assert body["passed"] is True
        assert body["findings"] == []
    finally:
        _jobs.pop("no-skill-audit-test", None)


# ── Resilient HTTP client tests ──────────────────────────────────────

def test_http_client_create():
    """create_client returns an httpx.AsyncClient with retry transport."""
    import httpx

    from agent_bom.http_client import create_client
    client = create_client(timeout=10.0)
    assert isinstance(client, httpx.AsyncClient)
    # Cleanup
    import asyncio
    asyncio.get_event_loop_policy().new_event_loop().run_until_complete(client.aclose())


def test_http_client_retry_constants():
    """Retry configuration constants are sensible."""
    from agent_bom.http_client import INITIAL_BACKOFF, MAX_RETRIES, RETRYABLE_STATUS_CODES
    assert MAX_RETRIES >= 2
    assert INITIAL_BACKOFF >= 0.5
    assert 429 in RETRYABLE_STATUS_CODES
    assert 503 in RETRYABLE_STATUS_CODES


# ── Integrity module tests ──────────────────────────────────────

def test_integrity_module_imports():
    """integrity.py module imports without error and exposes expected API."""
    # All should be async functions
    import asyncio

    from agent_bom.integrity import (
        check_package_provenance,
        verify_package_integrity,
    )
    assert asyncio.iscoroutinefunction(verify_package_integrity)
    assert asyncio.iscoroutinefunction(check_package_provenance)


def test_cli_scan_has_verify_integrity_flag():
    """The scan command accepts --verify-integrity."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--verify-integrity" in result.output


def test_credential_redaction_in_discovery():
    """sanitize_env_vars is applied when parsing MCP configs — secrets are redacted."""
    from agent_bom.discovery import parse_mcp_config
    config = {
        "mcpServers": {
            "test-server": {
                "command": "npx",
                "args": ["-y", "@test/server"],
                "env": {
                    "API_KEY": "sk-super-secret-value",
                    "OPENAI_API_TOKEN": "sk-proj-abc123",
                    "NORMAL_VAR": "not-a-secret",
                }
            }
        }
    }
    servers = parse_mcp_config(config, "/tmp/test.json")
    assert len(servers) == 1
    env = servers[0].env
    assert env["API_KEY"] == "***REDACTED***"
    assert env["OPENAI_API_TOKEN"] == "***REDACTED***"
    assert env["NORMAL_VAR"] == "not-a-secret"


# ─── MITRE ATLAS Tests ──────────────────────────────────────────────────────


def test_atlas_module_imports():
    """ATLAS module can be imported and has the expected catalog."""
    from agent_bom.atlas import ATLAS_TECHNIQUES
    assert "AML.T0010" in ATLAS_TECHNIQUES
    assert "AML.T0051" in ATLAS_TECHNIQUES
    assert "AML.T0062" in ATLAS_TECHNIQUES
    assert len(ATLAS_TECHNIQUES) >= 10


def test_atlas_supply_chain_always_present():
    """AML.T0010 (ML Supply Chain Compromise) is always tagged on every blast radius."""
    from agent_bom.atlas import tag_blast_radius as tag_atlas
    br = BlastRadius(
        vulnerability=Vulnerability(id="CVE-2024-1234", summary="test", severity=Severity.LOW),
        package=Package(name="express", version="4.18.0", ecosystem="npm"),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )
    tags = tag_atlas(br)
    assert "AML.T0010" in tags


def test_atlas_exfiltration_via_agent_tool():
    """AML.T0062 is tagged when credentials are exposed."""
    from agent_bom.atlas import tag_blast_radius as tag_atlas
    br = BlastRadius(
        vulnerability=Vulnerability(id="CVE-2024-5678", summary="test", severity=Severity.HIGH),
        package=Package(name="lodash", version="4.17.0", ecosystem="npm"),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=["OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY"],
        exposed_tools=[],
    )
    tags = tag_atlas(br)
    assert "AML.T0062" in tags


def test_atlas_agent_tools_broad_surface():
    """AML.T0061 is tagged when >3 tools are reachable."""
    from agent_bom.atlas import tag_blast_radius as tag_atlas
    from agent_bom.models import MCPTool
    tools = [MCPTool(name=f"tool_{i}", description="test") for i in range(5)]
    br = BlastRadius(
        vulnerability=Vulnerability(id="CVE-2024-9999", summary="test", severity=Severity.MEDIUM),
        package=Package(name="axios", version="1.0.0", ecosystem="npm"),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=tools,
    )
    tags = tag_atlas(br)
    assert "AML.T0061" in tags


def test_atlas_prompt_injection_surface():
    """AML.T0051 is tagged when tools can access prompts/context."""
    from agent_bom.atlas import tag_blast_radius as tag_atlas
    from agent_bom.models import MCPTool
    br = BlastRadius(
        vulnerability=Vulnerability(id="CVE-2024-1111", summary="test", severity=Severity.HIGH),
        package=Package(name="test-pkg", version="1.0.0", ecosystem="npm"),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[MCPTool(name="get_system_prompt", description="Read system prompt")],
    )
    tags = tag_atlas(br)
    assert "AML.T0051" in tags


def test_atlas_craft_adversarial_data():
    """AML.T0043 is tagged when shell/exec tools are reachable."""
    from agent_bom.atlas import tag_blast_radius as tag_atlas
    from agent_bom.models import MCPTool
    br = BlastRadius(
        vulnerability=Vulnerability(id="CVE-2024-2222", summary="test", severity=Severity.CRITICAL),
        package=Package(name="vulnerable-pkg", version="0.1.0", ecosystem="npm"),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[MCPTool(name="run_shell", description="Execute shell commands")],
    )
    tags = tag_atlas(br)
    assert "AML.T0043" in tags


def test_atlas_meta_prompt_extraction():
    """AML.T0056 is tagged when file/data read tools are reachable."""
    from agent_bom.atlas import tag_blast_radius as tag_atlas
    from agent_bom.models import MCPTool
    br = BlastRadius(
        vulnerability=Vulnerability(id="CVE-2024-3333", summary="test", severity=Severity.MEDIUM),
        package=Package(name="some-pkg", version="2.0.0", ecosystem="npm"),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[MCPTool(name="read_file", description="Read file contents")],
    )
    tags = tag_atlas(br)
    assert "AML.T0056" in tags


def test_atlas_poison_training_data():
    """AML.T0020 is tagged when AI framework has HIGH+ CVE."""
    from agent_bom.atlas import tag_blast_radius as tag_atlas
    br = BlastRadius(
        vulnerability=Vulnerability(id="CVE-2024-4444", summary="RCE in torch", severity=Severity.CRITICAL),
        package=Package(name="torch", version="2.0.0", ecosystem="pypi"),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )
    tags = tag_atlas(br)
    assert "AML.T0020" in tags


def test_atlas_context_poisoning():
    """AML.T0058 is tagged when AI framework + creds + HIGH+ severity."""
    from agent_bom.atlas import tag_blast_radius as tag_atlas
    br = BlastRadius(
        vulnerability=Vulnerability(id="CVE-2024-5555", summary="RCE in langchain", severity=Severity.HIGH),
        package=Package(name="langchain", version="0.1.0", ecosystem="pypi"),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=["OPENAI_API_KEY"],
        exposed_tools=[],
    )
    tags = tag_atlas(br)
    assert "AML.T0058" in tags
    assert "AML.T0024" in tags  # also exfil via inference API


def test_atlas_label_formatting():
    """atlas_label() and atlas_labels() return human-readable strings."""
    from agent_bom.atlas import atlas_label, atlas_labels
    label = atlas_label("AML.T0010")
    assert "AML.T0010" in label
    assert "Supply Chain" in label

    labels = atlas_labels(["AML.T0010", "AML.T0051"])
    assert len(labels) == 2
    assert "Prompt Injection" in labels[1]


def test_atlas_tags_in_blast_radius_model():
    """BlastRadius model has atlas_tags field."""
    br = BlastRadius(
        vulnerability=Vulnerability(id="CVE-2024-0001", summary="test", severity=Severity.LOW),
        package=Package(name="test", version="1.0.0", ecosystem="npm"),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )
    assert hasattr(br, "atlas_tags")
    assert br.atlas_tags == []
    br.atlas_tags = ["AML.T0010", "AML.T0051"]
    assert len(br.atlas_tags) == 2


# ─── End-to-End Scenario Tests ──────────────────────────────────────────────


def test_scenario_enterprise_multi_agent():
    """Enterprise scenario: 3 agents, each with multiple servers and credentials.

    Validates that blast radius correctly maps CVEs across agents.
    """
    from agent_bom.atlas import tag_blast_radius as tag_atlas
    from agent_bom.models import MCPTool
    from agent_bom.owasp import tag_blast_radius as tag_owasp

    # Agent 1: Claude Desktop with filesystem + sqlite servers
    srv1 = MCPServer(
        name="filesystem",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem"],
        packages=[Package(
            name="glob",
            version="7.1.6",
            ecosystem="npm",
            vulnerabilities=[Vulnerability(id="CVE-2024-GLOB", summary="ReDoS", severity=Severity.HIGH)],
        )],
        tools=[MCPTool(name="read_file", description="Read file"), MCPTool(name="write_file", description="Write file")],
        env={"OPENAI_API_KEY": "***REDACTED***"},
    )
    srv2 = MCPServer(
        name="sqlite-mcp",
        command="uvx",
        packages=[Package(
            name="better-sqlite3",
            version="9.0.0",
            ecosystem="npm",
            vulnerabilities=[Vulnerability(id="CVE-2024-SQL", summary="SQL injection", severity=Severity.CRITICAL)],
        )],
        tools=[MCPTool(name="query_db", description="Execute SQL query")],
    )
    agent1 = Agent(name="Claude Desktop", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/test.json", mcp_servers=[srv1, srv2])

    # Agent 2: Cursor with different server
    srv3 = MCPServer(
        name="puppeteer",
        command="npx",
        packages=[Package(name="puppeteer", version="21.0.0", ecosystem="npm", vulnerabilities=[])],
        tools=[MCPTool(name="navigate", description="Navigate browser"), MCPTool(name="screenshot", description="Take screenshot")],
    )
    agent2 = Agent(name="Cursor", agent_type=AgentType.CURSOR, config_path="/tmp/cursor.json", mcp_servers=[srv3])

    # Build blast radii for Agent 1's vulnerable packages
    br1 = BlastRadius(
        vulnerability=srv1.packages[0].vulnerabilities[0],
        package=srv1.packages[0],
        affected_servers=[srv1],
        affected_agents=[agent1],
        exposed_credentials=["OPENAI_API_KEY"],
        exposed_tools=srv1.tools,
    )
    br1.calculate_risk_score()
    br1.owasp_tags = tag_owasp(br1)
    br1.atlas_tags = tag_atlas(br1)

    br2 = BlastRadius(
        vulnerability=srv2.packages[0].vulnerabilities[0],
        package=srv2.packages[0],
        affected_servers=[srv2],
        affected_agents=[agent1],
        exposed_credentials=[],
        exposed_tools=srv2.tools,
    )
    br2.calculate_risk_score()
    br2.owasp_tags = tag_owasp(br2)
    br2.atlas_tags = tag_atlas(br2)

    # Assertions
    assert br1.risk_score > 0
    assert br2.risk_score > br1.risk_score  # CRITICAL > HIGH

    # OWASP: supply chain + credential + file tools
    assert "LLM05" in br1.owasp_tags
    assert "LLM06" in br1.owasp_tags  # credentials exposed
    assert "LLM07" in br1.owasp_tags  # read_file tool

    # ATLAS: supply chain + exfil + prompt extraction
    assert "AML.T0010" in br1.atlas_tags
    assert "AML.T0062" in br1.atlas_tags  # cred exposure
    assert "AML.T0056" in br1.atlas_tags  # read_file = data access

    # Agent 2 has no CVEs, no blast radius
    assert len(srv3.packages[0].vulnerabilities) == 0

    # Report construction
    report = AIBOMReport(agents=[agent1, agent2], blast_radii=[br1, br2])
    assert report.total_agents == 2
    assert report.total_servers == 3
    assert len(report.blast_radii) == 2


def test_scenario_individual_developer():
    """Individual developer scenario: single agent, few servers, basic scan.

    No enrichment, no credentials — just package CVEs.
    """
    srv = MCPServer(
        name="weather-api",
        command="npx",
        packages=[
            Package(name="axios", version="0.21.0", ecosystem="npm",
                    vulnerabilities=[Vulnerability(id="CVE-2024-AXIOS", summary="SSRF", severity=Severity.MEDIUM)]),
            Package(name="express", version="4.19.0", ecosystem="npm", vulnerabilities=[]),
        ],
    )
    agent = Agent(name="Claude Desktop", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/dev.json", mcp_servers=[srv])

    # Only 1 CVE, no credentials, no tools
    br = BlastRadius(
        vulnerability=srv.packages[0].vulnerabilities[0],
        package=srv.packages[0],
        affected_servers=[srv],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
    br.calculate_risk_score()

    assert br.risk_score > 0
    assert br.risk_score < 6.0  # MEDIUM severity, no amplifiers

    report = AIBOMReport(agents=[agent], blast_radii=[br])
    data = to_json(report)
    assert len(data["blast_radius"]) == 1
    assert data["blast_radius"][0]["vulnerability_id"] == "CVE-2024-AXIOS"


def test_scenario_docker_image_packages():
    """Scenario: Docker image scan produces packages from multiple ecosystems."""

    # Simulating a Docker image with packages from npm + pypi + go
    packages = [
        Package(name="express", version="4.17.0", ecosystem="npm",
                vulnerabilities=[Vulnerability(id="CVE-2024-NPM1", summary="XSS", severity=Severity.HIGH)]),
        Package(name="flask", version="2.3.0", ecosystem="pypi",
                vulnerabilities=[Vulnerability(id="CVE-2024-PY1", summary="Path traversal", severity=Severity.MEDIUM)]),
        Package(name="gin", version="1.9.0", ecosystem="go", vulnerabilities=[]),
    ]

    srv = MCPServer(name="image-scan", command="grype", packages=packages)
    agent = Agent(name="Docker Image", agent_type=AgentType.CUSTOM, config_path="python:3.11-slim", mcp_servers=[srv])

    blast_radii = []
    for pkg in packages:
        for vuln in pkg.vulnerabilities:
            br = BlastRadius(
                vulnerability=vuln,
                package=pkg,
                affected_servers=[srv],
                affected_agents=[agent],
                exposed_credentials=[],
                exposed_tools=[],
            )
            br.calculate_risk_score()
            blast_radii.append(br)

    assert len(blast_radii) == 2
    assert blast_radii[0].package.ecosystem == "npm"
    assert blast_radii[1].package.ecosystem == "pypi"

    report = AIBOMReport(agents=[agent], blast_radii=blast_radii)
    data = to_sarif(report)
    assert len(data["runs"][0]["results"]) == 2


def test_scenario_high_privilege_mcp_server():
    """Scenario: MCP server with shell access + many tools + credentials = maximum risk."""
    from agent_bom.atlas import tag_blast_radius as tag_atlas
    from agent_bom.models import MCPTool
    from agent_bom.owasp import tag_blast_radius as tag_owasp

    tools = [
        MCPTool(name="run_shell", description="Execute bash commands"),
        MCPTool(name="read_file", description="Read any file"),
        MCPTool(name="write_file", description="Write to any file"),
        MCPTool(name="query_database", description="Execute SQL"),
        MCPTool(name="deploy", description="Deploy to production"),
        MCPTool(name="get_prompt_history", description="Get prompt history"),
    ]

    srv = MCPServer(
        name="super-server",
        command="npx",
        packages=[Package(
            name="langchain",
            version="0.1.0",
            ecosystem="pypi",
            vulnerabilities=[Vulnerability(id="CVE-2024-LANG", summary="RCE in chains", severity=Severity.CRITICAL)],
        )],
        tools=tools,
        env={"OPENAI_API_KEY": "***REDACTED***", "AWS_SECRET_ACCESS_KEY": "***REDACTED***", "DATABASE_URL": "***REDACTED***"},
    )
    agent = Agent(name="Claude Desktop", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/danger.json", mcp_servers=[srv])

    br = BlastRadius(
        vulnerability=srv.packages[0].vulnerabilities[0],
        package=srv.packages[0],
        affected_servers=[srv],
        affected_agents=[agent],
        exposed_credentials=["OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "DATABASE_URL"],
        exposed_tools=tools,
    )
    br.calculate_risk_score()
    br.owasp_tags = tag_owasp(br)
    br.atlas_tags = tag_atlas(br)

    # Maximum risk — should be close to 10.0
    assert br.risk_score >= 9.0

    # OWASP: every relevant tag should fire
    assert "LLM05" in br.owasp_tags  # supply chain
    assert "LLM06" in br.owasp_tags  # credential exposure
    assert "LLM02" in br.owasp_tags  # shell exec
    assert "LLM07" in br.owasp_tags  # file/prompt read
    assert "LLM08" in br.owasp_tags  # excessive agency (>5 tools + CRITICAL)
    assert "LLM04" in br.owasp_tags  # AI framework + CRITICAL

    # ATLAS: maximum threat surface
    assert "AML.T0010" in br.atlas_tags  # supply chain
    assert "AML.T0062" in br.atlas_tags  # exfil via tools
    assert "AML.T0061" in br.atlas_tags  # broad tool surface (6 tools)
    assert "AML.T0043" in br.atlas_tags  # shell = craft adversarial data
    assert "AML.T0051" in br.atlas_tags  # prompt access
    assert "AML.T0056" in br.atlas_tags  # file read = meta prompt extraction
    assert "AML.T0020" in br.atlas_tags  # AI + CRITICAL = poisoning
    assert "AML.T0058" in br.atlas_tags  # AI + creds + CRITICAL = context poisoning
    assert "AML.T0024" in br.atlas_tags  # AI + creds = exfil via inference


def test_scenario_clean_scan():
    """Scenario: scan finds agents but no CVEs — should produce empty blast radius."""
    srv = MCPServer(
        name="safe-server",
        command="npx",
        packages=[
            Package(name="express", version="4.19.0", ecosystem="npm", vulnerabilities=[]),
            Package(name="react", version="18.2.0", ecosystem="npm", vulnerabilities=[]),
        ],
    )
    agent = Agent(name="Claude Desktop", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/safe.json", mcp_servers=[srv])

    report = AIBOMReport(agents=[agent], blast_radii=[])
    assert report.total_agents == 1
    assert report.total_packages == 2
    assert report.total_vulnerabilities == 0
    assert len(report.blast_radii) == 0
    assert len(report.critical_vulns) == 0

    data = to_json(report)
    assert data["summary"]["total_vulnerabilities"] == 0
    assert len(data["blast_radius"]) == 0


def test_scenario_json_output_has_atlas_tags():
    """JSON output includes atlas_tags field in blast_radius entries."""
    from agent_bom.atlas import tag_blast_radius as tag_atlas
    vuln = Vulnerability(id="CVE-2024-0001", summary="test", severity=Severity.HIGH)
    pkg = Package(name="lodash", version="4.17.0", ecosystem="npm", vulnerabilities=[vuln])
    srv = MCPServer(name="test", command="npx", packages=[pkg])
    agent = Agent(name="TestAgent", agent_type=AgentType.CUSTOM, config_path="/tmp/test.json", mcp_servers=[srv])

    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[srv],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
    br.calculate_risk_score()
    br.atlas_tags = tag_atlas(br)

    report = AIBOMReport(agents=[agent], blast_radii=[br])
    data = to_json(report)

    assert "atlas_tags" in data["blast_radius"][0]
    assert "AML.T0010" in data["blast_radius"][0]["atlas_tags"]


def test_scenario_sarif_output_has_atlas_tags():
    """SARIF output includes atlas_tags in result properties."""
    from agent_bom.atlas import tag_blast_radius as tag_atlas
    from agent_bom.owasp import tag_blast_radius as tag_owasp

    vuln = Vulnerability(id="CVE-2024-0002", summary="test", severity=Severity.CRITICAL)
    pkg = Package(name="express", version="4.17.0", ecosystem="npm", vulnerabilities=[vuln])
    srv = MCPServer(name="test", command="npx", packages=[pkg], config_path="/tmp/test.json")
    agent = Agent(name="TestAgent", agent_type=AgentType.CUSTOM, config_path="/tmp/test.json", mcp_servers=[srv])

    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[srv],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
    br.calculate_risk_score()
    br.owasp_tags = tag_owasp(br)
    br.atlas_tags = tag_atlas(br)

    report = AIBOMReport(agents=[agent], blast_radii=[br])
    data = to_sarif(report)

    result = data["runs"][0]["results"][0]
    assert "properties" in result
    assert "atlas_tags" in result["properties"]
    assert "AML.T0010" in result["properties"]["atlas_tags"]


# ─── Threat Framework Summary Tests ─────────────────────────────────────────


def test_print_threat_frameworks_import():
    """print_threat_frameworks can be imported from output module."""
    from agent_bom.output import print_threat_frameworks
    assert callable(print_threat_frameworks)


def test_json_threat_framework_summary(sample_report):
    """to_json() includes threat_framework_summary with OWASP + ATLAS data."""
    from agent_bom.atlas import tag_blast_radius as tag_atlas
    from agent_bom.owasp import tag_blast_radius as tag_owasp

    for br in sample_report.blast_radii:
        br.owasp_tags = tag_owasp(br)
        br.atlas_tags = tag_atlas(br)

    data = to_json(sample_report)
    assert "threat_framework_summary" in data
    summary = data["threat_framework_summary"]

    # OWASP section
    assert "owasp_llm_top10" in summary
    assert len(summary["owasp_llm_top10"]) == 10  # Full catalog
    assert "total_owasp_triggered" in summary
    assert summary["total_owasp_triggered"] > 0

    # ATLAS section
    assert "mitre_atlas" in summary
    assert len(summary["mitre_atlas"]) == 13  # Full catalog
    assert "total_atlas_triggered" in summary
    assert summary["total_atlas_triggered"] > 0


def test_json_framework_summary_structure(sample_report):
    """Each framework entry has code, name, findings, and triggered fields."""
    from agent_bom.atlas import tag_blast_radius as tag_atlas
    from agent_bom.owasp import tag_blast_radius as tag_owasp

    for br in sample_report.blast_radii:
        br.owasp_tags = tag_owasp(br)
        br.atlas_tags = tag_atlas(br)

    data = to_json(sample_report)
    summary = data["threat_framework_summary"]

    # Check OWASP entries
    for entry in summary["owasp_llm_top10"]:
        assert "code" in entry
        assert "name" in entry
        assert "findings" in entry
        assert "triggered" in entry
        assert isinstance(entry["findings"], int)
        assert isinstance(entry["triggered"], bool)

    # Check ATLAS entries
    for entry in summary["mitre_atlas"]:
        assert "technique_id" in entry
        assert "name" in entry
        assert "findings" in entry
        assert "triggered" in entry


def test_json_framework_lm05_always_triggered(sample_report):
    """LLM05 (Supply Chain Vulnerabilities) is always triggered when there are findings."""
    from agent_bom.owasp import tag_blast_radius as tag_owasp

    for br in sample_report.blast_radii:
        br.owasp_tags = tag_owasp(br)
        br.atlas_tags = []

    data = to_json(sample_report)
    owasp_entries = {e["code"]: e for e in data["threat_framework_summary"]["owasp_llm_top10"]}
    assert owasp_entries["LLM05"]["triggered"] is True
    assert owasp_entries["LLM05"]["findings"] > 0


def test_json_framework_lm06_with_credentials(sample_report):
    """LLM06 (Sensitive Information Disclosure) triggers when credentials are exposed."""
    from agent_bom.owasp import tag_blast_radius as tag_owasp

    # sample_report has exposed_credentials=["API_KEY"]
    for br in sample_report.blast_radii:
        br.owasp_tags = tag_owasp(br)
        br.atlas_tags = []

    data = to_json(sample_report)
    owasp_entries = {e["code"]: e for e in data["threat_framework_summary"]["owasp_llm_top10"]}
    assert owasp_entries["LLM06"]["triggered"] is True


def test_json_framework_atlas_t0010_always(sample_report):
    """AML.T0010 (ML Supply Chain Compromise) is always triggered."""
    from agent_bom.atlas import tag_blast_radius as tag_atlas

    for br in sample_report.blast_radii:
        br.owasp_tags = []
        br.atlas_tags = tag_atlas(br)

    data = to_json(sample_report)
    atlas_entries = {e["technique_id"]: e for e in data["threat_framework_summary"]["mitre_atlas"]}
    assert atlas_entries["AML.T0010"]["triggered"] is True
    assert atlas_entries["AML.T0010"]["findings"] > 0


def test_json_framework_empty_when_no_findings():
    """Framework summary shows zero triggered when no blast radii."""
    report = AIBOMReport(agents=[], blast_radii=[])
    data = to_json(report)
    summary = data["threat_framework_summary"]
    assert summary["total_owasp_triggered"] == 0
    assert summary["total_atlas_triggered"] == 0
    assert all(e["triggered"] is False for e in summary["owasp_llm_top10"])
    assert all(e["triggered"] is False for e in summary["mitre_atlas"])


def test_print_threat_frameworks_no_crash(sample_report):
    """print_threat_frameworks() runs without crashing on a real report."""
    from agent_bom.atlas import tag_blast_radius as tag_atlas
    from agent_bom.output import print_threat_frameworks
    from agent_bom.owasp import tag_blast_radius as tag_owasp

    for br in sample_report.blast_radii:
        br.owasp_tags = tag_owasp(br)
        br.atlas_tags = tag_atlas(br)

    # Should not raise
    print_threat_frameworks(sample_report)


def test_print_threat_frameworks_empty_report():
    """print_threat_frameworks() handles empty reports gracefully."""
    from agent_bom.output import print_threat_frameworks

    report = AIBOMReport(agents=[], blast_radii=[])
    # Should not raise
    print_threat_frameworks(report)


# ─── Remediation Plan Tests ──────────────────────────────────────────────────


def test_remediation_plan_named_assets(sample_report):
    """Remediation plan includes named agents and credentials."""
    from agent_bom.output import build_remediation_plan

    plan = build_remediation_plan(sample_report.blast_radii)
    assert len(plan) == 1
    item = plan[0]
    assert "test-agent" in item["agents"]
    assert "API_KEY" in item["creds"]
    assert item["package"] == "test-pkg"
    assert item["fix"] == "1.2.3"


def test_remediation_plan_impact_score(sample_report):
    """Impact score accounts for agents, creds, and vulns."""
    from agent_bom.output import build_remediation_plan

    plan = build_remediation_plan(sample_report.blast_radii)
    item = plan[0]
    # 1 agent * 10 + 1 cred * 3 + 1 vuln = 14
    assert item["impact"] == 14


def test_remediation_json_in_output(sample_report):
    """JSON output includes remediation_plan with named assets and percentages."""
    data = to_json(sample_report)
    assert "remediation_plan" in data
    plan = data["remediation_plan"]
    assert len(plan) >= 1
    item = plan[0]
    assert item["package"] == "test-pkg"
    assert item["fixed_version"] == "1.2.3"
    assert "test-agent" in item["affected_agents"]
    assert "API_KEY" in item["exposed_credentials"]
    assert isinstance(item["agents_pct"], int)
    assert isinstance(item["risk_narrative"], str)
    assert len(item["risk_narrative"]) > 10


def test_remediation_json_percentages(sample_report):
    """Percentage calculations are valid."""
    data = to_json(sample_report)
    item = data["remediation_plan"][0]
    # 1 agent out of 1 total = 100%
    assert item["agents_pct"] == 100
    # 1 credential out of 1 total = 100%
    assert item["credentials_pct"] == 100


def test_remediation_plan_owasp_atlas_tags():
    """Remediation plan includes OWASP and ATLAS tags from blast radii."""
    from agent_bom.models import MCPTool
    from agent_bom.output import build_remediation_plan

    vuln = Vulnerability(id="CVE-2024-9999", summary="test", severity=Severity.HIGH, fixed_version="2.0.0")
    pkg = Package(name="vuln-pkg", version="1.0.0", ecosystem="pypi", vulnerabilities=[vuln])
    server = MCPServer(name="srv", command="python")
    agent = Agent(name="my-agent", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/test.json", mcp_servers=[server])
    tool = MCPTool(name="run_shell", description="Execute commands")
    br = BlastRadius(
        vulnerability=vuln, package=pkg,
        affected_servers=[server], affected_agents=[agent],
        exposed_credentials=["AWS_KEY"], exposed_tools=[tool],
        owasp_tags=["LLM02", "LLM05"], atlas_tags=["AML.T0010"],
    )
    plan = build_remediation_plan([br])
    item = plan[0]
    assert "LLM02" in item["owasp"]
    assert "LLM05" in item["owasp"]
    assert "AML.T0010" in item["atlas"]
    assert "run_shell" in item["tools"]


def test_remediation_risk_narrative():
    """Risk narrative mentions CVE, credentials, and agents."""
    from agent_bom.output import _risk_narrative

    item = {
        "vulns": ["CVE-2024-1234"],
        "agents": ["claude-desktop"],
        "creds": ["OPENAI_KEY"],
        "tools": ["read_file"],
    }
    narrative = _risk_narrative(item)
    assert "CVE-2024-1234" in narrative
    assert "OPENAI_KEY" in narrative
    assert "claude-desktop" in narrative
    assert "read_file" in narrative


def test_remediation_empty_blast_radii():
    """Empty blast radii produces empty remediation plan."""
    from agent_bom.output import build_remediation_plan

    plan = build_remediation_plan([])
    assert plan == []


def test_print_remediation_no_crash(sample_report):
    """print_remediation_plan() doesn't crash with valid report."""
    from agent_bom.output import print_remediation_plan

    # Should not raise
    print_remediation_plan(sample_report)


def test_json_ai_bom_identity(sample_report):
    """JSON output declares document_type and spec_version for AI-BOM identity."""
    data = to_json(sample_report)
    assert data["document_type"] == "AI-BOM"
    assert data["spec_version"] == "1.0"
    assert "ai_bom_version" in data


def test_print_export_hint_no_crash(sample_report):
    """print_export_hint() doesn't crash with valid report."""
    from agent_bom.output import print_export_hint

    # Should not raise
    print_export_hint(sample_report)


# ---------------------------------------------------------------------------
# Integration file validation
# ---------------------------------------------------------------------------


def test_toolhive_server_json_valid():
    """ToolHive server.json should be valid JSON with required fields."""
    import json as _json
    from pathlib import Path
    p = Path(__file__).parent.parent / "integrations" / "toolhive" / "server.json"
    data = _json.loads(p.read_text())
    assert data["name"] == "io.github.agent-bom/agent-bom"
    assert data["version"] == "0.24.0"
    assert "packages" in data
    assert data["packages"][0]["registryType"] == "oci"


def test_mcp_registry_server_json_valid():
    """MCP registry server.json should be valid JSON with required fields."""
    import json as _json
    from pathlib import Path
    p = Path(__file__).parent.parent / "integrations" / "mcp-registry" / "server.json"
    data = _json.loads(p.read_text())
    assert data["name"] == "io.github.agent-bom/agent-bom"
    assert any(pkg["registryType"] == "pypi" for pkg in data["packages"])


def test_openclaw_skill_exists():
    """OpenClaw SKILL.md should exist with agent-bom content."""
    from pathlib import Path
    p = Path(__file__).parent.parent / "integrations" / "openclaw" / "SKILL.md"
    assert p.exists()
    content = p.read_text()
    assert "agent-bom" in content
    assert "name: agent-bom" in content


def test_mcp_registry_has_awm_entries():
    """MCP registry should include AWM ecosystem entries."""
    from agent_bom.parsers import _load_registry
    registry = _load_registry()
    # fastapi-mcp: auto-exposes FastAPI endpoints as MCP tools
    assert "fastapi-mcp" in registry
    assert registry["fastapi-mcp"]["ecosystem"] == "pypi"
    assert registry["fastapi-mcp"]["risk_level"] == "high"
    # mcp-agent: MCP client SDK used in AWM
    assert "mcp-agent" in registry
    assert registry["mcp-agent"]["ecosystem"] == "pypi"
    # agent-world-model: Snowflake's RL environment generator
    assert "agent-world-model" in registry
    assert registry["agent-world-model"]["risk_level"] == "high"


# ─── --no-skill / --skill-only CLI flag tests ────────────────────────────────


def test_no_skill_flag_dry_run():
    """--no-skill flag is accepted and shows 'disabled' in dry-run output."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--dry-run", "--no-skill"])
    assert result.exit_code == 0
    assert "disabled" in result.output


def test_skill_only_flag_dry_run():
    """--skill-only flag is accepted and shows 'skill-only' in dry-run output."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--dry-run", "--skill-only"])
    assert result.exit_code == 0
    assert "skill-only" in result.output


def test_no_skill_and_skill_only_mutually_exclusive():
    """--no-skill and --skill-only cannot be used together."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--no-skill", "--skill-only"])
    assert result.exit_code == 2
    assert "mutually exclusive" in result.output


# ─── HTML visualization filter tests ─────────────────────────────────────────


def test_html_vuln_filter_controls():
    """HTML report includes vulnerability filter controls."""
    from agent_bom.output.html import to_html

    report, blast_radii = _make_report_with_vuln()
    html = to_html(report, blast_radii)
    assert 'class="vuln-sev-filter"' in html
    assert 'id="vulnSearch"' in html
    assert 'id="kevToggle"' in html


def test_html_graph_filter_controls():
    """HTML report includes graph severity filter and search."""
    from agent_bom.output.html import to_html

    report, blast_radii = _make_report_with_vuln()
    html = to_html(report, blast_radii)
    assert 'class="graph-sev-filter"' in html
    assert 'id="graphSearch"' in html


def test_html_vuln_rows_have_data_attributes():
    """Vulnerability table rows include data-severity, data-kev, data-cvss."""
    from agent_bom.output.html import to_html

    report, blast_radii = _make_report_with_vuln()
    html = to_html(report, blast_radii)
    assert 'data-severity="high"' in html
    assert 'data-kev=' in html
    assert 'data-cvss=' in html
