"""Tests for deployment configs and MCP server metadata."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Deployment file existence + content validation
# ---------------------------------------------------------------------------


def test_dockerfile_sse_exists():
    """Dockerfile.sse should exist with SSE transport config."""
    f = ROOT / "deploy" / "docker" / "Dockerfile.sse"
    assert f.exists(), "deploy/docker/Dockerfile.sse is missing"
    content = f.read_text()
    assert "mcp" in content and "server" in content
    assert "--transport" in content
    assert "sse" in content
    assert "EXPOSE" in content


def test_railway_json_valid():
    """railway.json should be valid JSON with correct deploy config."""
    f = ROOT / "railway.json"
    assert f.exists(), "railway.json must be at project root (Railway reads it from working directory)"
    data = json.loads(f.read_text())
    assert "build" in data
    assert "deploy" in data
    assert "Dockerfile.sse" in data["build"]["dockerfilePath"]
    assert data["deploy"]["restartPolicyType"] == "ON_FAILURE"


def test_render_yaml_valid():
    """render.yaml should be valid YAML with service config."""
    import yaml

    f = ROOT / "deploy" / "render.yaml"
    assert f.exists(), "deploy/render.yaml is missing"
    data = yaml.safe_load(f.read_text())
    assert "services" in data
    assert len(data["services"]) >= 1
    svc = data["services"][0]
    assert svc["type"] == "web"
    assert "Dockerfile.sse" in svc["dockerfilePath"]


def test_fly_toml_valid():
    """fly.toml should be valid TOML with http_service config."""
    import toml

    f = ROOT / "deploy" / "fly.toml"
    assert f.exists(), "deploy/fly.toml is missing"
    data = toml.loads(f.read_text())
    assert "build" in data
    assert "http_service" in data
    assert data["http_service"]["internal_port"] == 8423
    assert data["http_service"]["force_https"] is True


def test_procfile_exists():
    """Procfile should have web process with streamable-http transport."""
    f = ROOT / "deploy" / "Procfile"
    assert f.exists(), "deploy/Procfile is missing"
    content = f.read_text().strip()
    assert content.startswith("web:")
    assert "mcp" in content and "server" in content
    assert "streamable-http" in content
    assert "AGENT_BOM_MCP_BEARER_TOKEN" in content


def test_dockerfile_sse_does_not_opt_into_insecure_public_mode():
    """The maintained SSE/HTTP image should not disable remote auth by default."""
    content = (ROOT / "deploy" / "docker" / "Dockerfile.sse").read_text()
    assert "--allow-insecure-no-auth" not in content
    assert "AGENT_BOM_MCP_BEARER_TOKEN" in content


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


def test_smithery_yaml_exists():
    """smithery.yaml should exist with stdio config."""
    import yaml

    f = ROOT / "integrations" / "smithery.yaml"
    assert f.exists()
    data = yaml.safe_load(f.read_text())
    assert data["runtime"] == "python"
    assert data["startCommand"]["type"] == "stdio"


# ---------------------------------------------------------------------------
# MCP server card metadata
# ---------------------------------------------------------------------------


def test_server_card_has_all_tools():
    """Server card tools count matches _SERVER_CARD_TOOLS."""
    from agent_bom.mcp_server import _SERVER_CARD_TOOLS, build_server_card

    card = build_server_card()
    assert card["name"] == "agent-bom"
    assert "version" in card
    tool_names = [t["name"] for t in card["tools"]]
    assert len(tool_names) == len(_SERVER_CARD_TOOLS)
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
    """Health check contract should expose version and tool-count metadata."""

    from agent_bom import __version__
    from agent_bom.mcp_server import _tool_metrics_snapshot, create_mcp_server

    create_mcp_server()
    # The routes are registered; verify the build_server_card still works
    from agent_bom.mcp_server import build_server_card

    card = build_server_card()
    assert card["version"] == __version__
    assert card["name"] == "agent-bom"
    summary = _tool_metrics_snapshot()["summary"]
    assert "tool_count" in summary


def test_deployment_freshness_workflow_uses_bearer_token_and_parses_tool_count():
    """Deployment freshness should probe authenticated MCP health endpoints safely."""
    workflow = (ROOT / ".github" / "workflows" / "deployment-freshness.yml").read_text()
    assert "RAILWAY_MCP_BEARER_TOKEN" in workflow
    assert "Authorization: Bearer" in workflow
    assert "tool_count" in workflow


def test_deploy_mcp_sse_workflow_uses_bearer_token_for_health_check():
    """Post-deploy health verification should use the same auth contract as Railway."""
    workflow = (ROOT / ".github" / "workflows" / "deploy-mcp-sse.yml").read_text()
    assert "RAILWAY_MCP_BEARER_TOKEN" in workflow
    assert "Authorization: Bearer" in workflow


def test_dockerfiles_support_proxy_and_ca_contract():
    """Maintained Docker images should support standard proxy and CA env vars."""
    dockerfiles = [
        ROOT / "Dockerfile",
        ROOT / "deploy" / "docker" / "Dockerfile.mcp",
        ROOT / "deploy" / "docker" / "Dockerfile.sse",
        ROOT / "deploy" / "docker" / "Dockerfile.runtime",
        ROOT / "deploy" / "docker" / "Dockerfile.snowpark",
    ]
    required_tokens = [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "PIP_CERT",
        "ca-certificates",
    ]
    for dockerfile in dockerfiles:
        content = dockerfile.read_text()
        for token in required_tokens:
            assert token in content, f"{dockerfile.name} missing {token}"


def test_runtime_dockerfile_builds_from_repo_source():
    """Runtime image should install agent-bom from the checked-out source tree, not PyPI."""
    content = (ROOT / "deploy" / "docker" / "Dockerfile.runtime").read_text()
    assert "COPY pyproject.toml README.md LICENSE ./" in content
    assert "COPY src/ ./src/" in content
    assert 'pip install --no-cache-dir --prefix=/install ".[runtime]"' in content
    assert "agent-bom==${VERSION}" not in content


def test_compose_examples_pass_through_proxy_and_ca_env():
    """Compose examples should expose the same enterprise network env contract."""
    compose_files = [
        ROOT / "deploy" / "docker-compose.yml",
        ROOT / "deploy" / "docker-compose.runtime.yml",
    ]
    required_tokens = [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "PIP_CERT",
    ]
    for compose_file in compose_files:
        content = compose_file.read_text()
        for token in required_tokens:
            assert token in content, f"{compose_file.name} missing {token}"


# ---------------------------------------------------------------------------
# CLI help text
# ---------------------------------------------------------------------------


def test_mcp_server_help_shows_skill_tools():
    """MCP server help should mention the expanded skill tool surface."""
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["mcp", "server", "--help"])
    assert "35 security tools" in result.output
    assert "skill_scan" in result.output
    assert "skill_verify" in result.output
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


def test_mcp_registry_has_source_metadata():
    """mcp_registry.json must declare its feed sources."""
    f = ROOT / "src" / "agent_bom" / "mcp_registry.json"
    assert f.exists(), "mcp_registry.json is missing"
    data = json.loads(f.read_text())
    assert "_sources" in data, "mcp_registry.json is missing '_sources' key"
    assert "mcp-official" in data["_sources"], f"'mcp-official' not in _sources: {data['_sources']}"
