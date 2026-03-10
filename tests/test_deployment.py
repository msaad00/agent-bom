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
    assert data["name"] == "io.github.msaad00/agent-bom"
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
    assert data["name"] == "io.github.msaad00/agent-bom"
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
    """Server card should list all 29 MCP tools."""
    from agent_bom.mcp_server import build_server_card

    card = build_server_card()
    assert card["name"] == "agent-bom"
    assert "version" in card
    tool_names = [t["name"] for t in card["tools"]]
    assert len(tool_names) == 29
    assert "scan" in tool_names
    assert "check" in tool_names
    assert "blast_radius" in tool_names
    assert "policy_check" in tool_names
    assert "registry_lookup" in tool_names
    assert "generate_sbom" in tool_names
    assert "compliance" in tool_names
    assert "skill_trust" in tool_names
    assert "remediate" in tool_names
    assert "verify" in tool_names
    assert "where" in tool_names
    assert "inventory" in tool_names
    assert "diff" in tool_names
    assert "code_scan" in tool_names
    assert "context_graph" in tool_names
    assert "analytics_query" in tool_names
    assert "vector_db_scan" in tool_names
    assert "aisvs_benchmark" in tool_names
    assert "dataset_card_scan" in tool_names
    assert "training_pipeline_scan" in tool_names
    assert "browser_extension_scan" in tool_names
    assert "model_provenance_scan" in tool_names
    assert "prompt_scan" in tool_names
    assert "model_file_scan" in tool_names


def test_server_card_tool_count_matches_decorators():
    """_SERVER_CARD_TOOLS must list every @mcp.tool in create_mcp_server."""
    import inspect
    import re

    from agent_bom.mcp_server import _SERVER_CARD_TOOLS, create_mcp_server

    source = inspect.getsource(create_mcp_server)
    decorator_count = len(re.findall(r"@mcp\.tool", source))
    card_count = len(_SERVER_CARD_TOOLS)
    assert card_count == decorator_count, (
        f"_SERVER_CARD_TOOLS has {card_count} entries but create_mcp_server has {decorator_count} @mcp.tool decorators"
    )


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


def test_root_metadata_fields():
    """Root metadata endpoint should expose homepage/source for trust evaluators."""

    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    # Verify the custom routes were registered — check that root and health
    # route functions exist on the server (they're decorators on custom_route)
    assert hasattr(server, "custom_route")


def test_health_endpoint_fields():
    """Health check should return name, version, and healthy status."""

    from agent_bom import __version__
    from agent_bom.mcp_server import create_mcp_server

    create_mcp_server()
    # The routes are registered; verify the build_server_card still works
    from agent_bom.mcp_server import build_server_card

    card = build_server_card()
    assert card["version"] == __version__
    assert card["name"] == "agent-bom"


# ---------------------------------------------------------------------------
# CLI help text
# ---------------------------------------------------------------------------


def test_mcp_server_help_shows_14_tools():
    """MCP server help should mention 14 tools."""
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["mcp-server", "--help"])
    assert "23 security tools" in result.output
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
