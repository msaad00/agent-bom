"""Tests for agent-bom core functionality."""

import json
import tempfile
from pathlib import Path

from agent_bom.discovery import parse_mcp_config
from agent_bom.models import (
    Agent,
    AgentType,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    TransportType,
    Vulnerability,
)
from agent_bom.parsers import extract_packages, parse_npm_packages, parse_pip_packages


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
