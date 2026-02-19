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
    assert __version__ == "0.5.0"


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
    """scan_image uses syft when available, even if docker is also present."""
    import shutil
    import subprocess

    from agent_bom.image import scan_image

    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/" + cmd)

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
