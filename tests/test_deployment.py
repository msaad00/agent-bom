"""Tests for deployment configs and MCP server metadata."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Deployment file existence + content validation
# ---------------------------------------------------------------------------


def test_dockerfile_sse_exists():
    """Dockerfile.sse should exist with SSE transport config."""
    f = ROOT / "Dockerfile.sse"
    assert f.exists(), "Dockerfile.sse is missing"
    content = f.read_text()
    assert "mcp-server" in content
    assert "--transport" in content
    assert "sse" in content
    assert "EXPOSE" in content


def test_railway_json_valid():
    """railway.json should be valid JSON with correct deploy config."""
    f = ROOT / "railway.json"
    assert f.exists(), "railway.json is missing"
    data = json.loads(f.read_text())
    assert "build" in data
    assert "deploy" in data
    assert "Dockerfile.sse" in data["build"]["dockerfilePath"]
    assert data["deploy"]["restartPolicyType"] == "ON_FAILURE"


def test_render_yaml_valid():
    """render.yaml should be valid YAML with service config."""
    import yaml

    f = ROOT / "render.yaml"
    assert f.exists(), "render.yaml is missing"
    data = yaml.safe_load(f.read_text())
    assert "services" in data
    assert len(data["services"]) >= 1
    svc = data["services"][0]
    assert svc["type"] == "web"
    assert "Dockerfile.sse" in svc["dockerfilePath"]


def test_fly_toml_valid():
    """fly.toml should be valid TOML with http_service config."""
    import toml

    f = ROOT / "fly.toml"
    assert f.exists(), "fly.toml is missing"
    data = toml.loads(f.read_text())
    assert "build" in data
    assert "http_service" in data
    assert data["http_service"]["internal_port"] == 8423
    assert data["http_service"]["force_https"] is True


def test_procfile_exists():
    """Procfile should have web process with SSE transport."""
    f = ROOT / "Procfile"
    assert f.exists(), "Procfile is missing"
    content = f.read_text().strip()
    assert content.startswith("web:")
    assert "mcp-server" in content
    assert "sse" in content


# ---------------------------------------------------------------------------
# Integration files version consistency
# ---------------------------------------------------------------------------


def test_mcp_registry_entry_valid():
    """MCP registry entry should be valid JSON with current version."""
    f = ROOT / "integrations" / "mcp-registry" / "server.json"
    assert f.exists()
    data = json.loads(f.read_text())
    assert data["name"] == "io.github.agent-bom/agent-bom"
    assert "version" in data
    # Should have at least one package entry
    assert len(data["packages"]) >= 1
    pkg = data["packages"][0]
    assert pkg["registryType"] == "pypi"
    assert pkg["transport"]["type"] == "stdio"


def test_toolhive_entry_valid():
    """ToolHive entry should be valid JSON with OCI transport."""
    f = ROOT / "integrations" / "toolhive" / "server.json"
    assert f.exists()
    data = json.loads(f.read_text())
    assert data["name"] == "io.github.agent-bom/agent-bom"
    pkg = data["packages"][0]
    assert pkg["registryType"] == "oci"
    assert pkg["identifier"].startswith("ghcr.io/msaad00/agent-bom:")


def test_smithery_yaml_exists():
    """smithery.yaml should exist with stdio config."""
    import yaml

    f = ROOT / "smithery.yaml"
    assert f.exists()
    data = yaml.safe_load(f.read_text())
    assert data["runtime"] == "python"
    assert data["startCommand"]["type"] == "stdio"


# ---------------------------------------------------------------------------
# MCP server card metadata
# ---------------------------------------------------------------------------


def test_server_card_has_all_tools():
    """Server card should list all 7 MCP tools."""
    from agent_bom.mcp_server import build_server_card

    card = build_server_card()
    assert card["name"] == "agent-bom"
    assert "version" in card
    tool_names = [t["name"] for t in card["tools"]]
    assert len(tool_names) == 7
    assert "scan" in tool_names
    assert "blast_radius" in tool_names
    assert "policy_check" in tool_names
    assert "registry_lookup" in tool_names
    assert "generate_sbom" in tool_names
    assert "compliance" in tool_names
    assert "remediate" in tool_names


def test_server_card_capabilities():
    """Server card should include frameworks and data sources."""
    from agent_bom.mcp_server import build_server_card

    card = build_server_card()
    caps = card["capabilities"]
    assert "OWASP LLM Top 10" in caps["frameworks"]
    assert "MITRE ATLAS" in caps["frameworks"]
    assert "NIST AI RMF" in caps["frameworks"]
    assert caps["read_only"] is True
    assert "OSV.dev" in caps["data_sources"]


def test_server_card_metadata():
    """Server card should have correct package metadata."""
    from agent_bom.mcp_server import build_server_card

    card = build_server_card()
    assert card["license"] == "Apache-2.0"
    assert card["pypi"] == "agent-bom"
    assert "stdio" in card["transport"]
    assert "sse" in card["transport"]
    assert "github.com/msaad00/agent-bom" in card["repository"]


# ---------------------------------------------------------------------------
# CLI help text
# ---------------------------------------------------------------------------


def test_mcp_server_help_shows_7_tools():
    """MCP server help should mention 7 tools."""
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["mcp-server", "--help"])
    assert "7 security tools" in result.output
    assert "compliance" in result.output
    assert "remediate" in result.output


# ---------------------------------------------------------------------------
# CI workflow files
# ---------------------------------------------------------------------------


def test_publish_mcp_workflow_has_sse_job():
    """publish-mcp.yml should have both stdio and SSE jobs."""
    import yaml

    f = ROOT / ".github" / "workflows" / "publish-mcp.yml"
    assert f.exists()
    data = yaml.safe_load(f.read_text())
    jobs = data.get("jobs", {})
    assert "publish-stdio" in jobs, "Missing publish-stdio job"
    assert "publish-sse" in jobs, "Missing publish-sse job"


def test_deploy_sse_workflow_exists():
    """deploy-mcp-sse.yml should exist."""
    f = ROOT / ".github" / "workflows" / "deploy-mcp-sse.yml"
    assert f.exists()
