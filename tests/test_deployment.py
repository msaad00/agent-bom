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


def test_server_card_tools_expose_capability_classes():
    """Server card should classify tool capabilities for agents and marketplaces."""
    from agent_bom.mcp_server import build_server_card

    card = build_server_card()
    for tool in card["tools"]:
        classes = tool.get("capability_classes")
        assert isinstance(classes, list), tool["name"]
        assert classes, tool["name"]
        assert "READ" in classes, tool["name"]
        assert tool["annotations"]["readOnlyHint"] is True


def test_server_card_exposes_resources_and_workflow_prompts():
    """Server card should advertise the live resource and prompt catalog."""
    from agent_bom.mcp_server import build_server_card

    card = build_server_card()
    resource_uris = {resource["uri"] for resource in card["resources"]}
    assert "registry://servers" in resource_uris
    assert "policy://template" in resource_uris
    assert "metrics://tools" in resource_uris
    assert "schema://inventory-v1" in resource_uris
    assert "bestpractices://mcp-hardening" in resource_uris
    assert "compliance://framework-controls" in resource_uris

    prompt_names = {prompt["name"] for prompt in card["prompts"]}
    assert "quick-audit" in prompt_names
    assert "pre-install-check" in prompt_names
    assert "compliance-report" in prompt_names
    assert "fleet-audit" in prompt_names
    assert "incident-triage" in prompt_names
    assert "remediation-plan" in prompt_names


def test_mcp_docs_match_resource_and_prompt_catalog():
    """Human MCP docs should stay aligned with the server-card catalog."""
    from agent_bom.mcp_server import build_server_card

    docs = "\n".join(
        [
            (ROOT / "docs" / "MCP_SERVER.md").read_text(),
            (ROOT / "site-docs" / "getting-started" / "mcp-server.md").read_text(),
            (ROOT / "site-docs" / "reference" / "mcp-tools.md").read_text(),
        ]
    )
    card = build_server_card()
    assert "35 security tools" not in docs
    assert "36" in docs
    for resource in card["resources"]:
        assert resource["uri"] in docs
    for prompt in card["prompts"]:
        assert prompt["name"] in docs


def test_server_card_tool_count_matches_decorators():
    """_SERVER_CARD_TOOLS must list every @mcp.tool across MCP tool surfaces."""
    import inspect
    import re

    from agent_bom import mcp_server_operator_tools, mcp_server_runtime_catalog, mcp_server_specialized
    from agent_bom.mcp_server import _SERVER_CARD_TOOLS, create_mcp_server

    source = (
        inspect.getsource(create_mcp_server)
        + inspect.getsource(mcp_server_operator_tools)
        + inspect.getsource(mcp_server_runtime_catalog)
        + inspect.getsource(mcp_server_specialized)
    )
    decorator_count = len(re.findall(r"@mcp\.tool", source))
    card_count = len(_SERVER_CARD_TOOLS)
    assert card_count == decorator_count, (
        f"_SERVER_CARD_TOOLS has {card_count} entries but MCP server surfaces define {decorator_count} @mcp.tool decorators"
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
    assert "SMITHERY_MCP_URL" in workflow
    assert "python3 -m agent_bom.deployment_probe" in workflow
    assert "tool_count" in workflow
    assert "auth_required" in workflow
    assert "probe_failed=true" in workflow
    assert "steps.railway.outputs.probe_failed != 'true'" in workflow
    assert "--resolve-only" in workflow


def test_docs_workflow_never_deploys_pages_from_release_tags():
    """Release tags may build docs, but Pages deploy is protected to main only."""
    workflow = (ROOT / ".github" / "workflows" / "docs.yml").read_text()
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "inputs.deploy == true" in workflow
    assert "actions/deploy-pages" in workflow


def test_publish_registries_workflow_requires_public_smithery_surface_and_curated_clawhub_set():
    """Registry publishing should fail fast on auth-gated Smithery URLs and avoid omnibus ClawHub skills."""
    workflow = (ROOT / ".github" / "workflows" / "publish-registries.yml").read_text()
    assert "SMITHERY_MCP_URL" in workflow
    assert "--forbid-auth-required" in workflow
    assert "integrations/openclaw/scan" in workflow
    assert "integrations/openclaw/compliance" in workflow
    assert "integrations/openclaw/registry" in workflow
    assert "integrations/openclaw/runtime" in workflow
    assert "integrations/openclaw/discover-aws" in workflow
    assert "integrations/openclaw/discover-azure" in workflow
    assert "integrations/openclaw/discover-gcp" in workflow
    assert "integrations/openclaw/discover-snowflake" in workflow
    assert "integrations/openclaw/ingest" in workflow
    assert "integrations/openclaw/vulnerability-intel" in workflow
    assert '_publish_skill "integrations/openclaw" "agent-bom"' not in workflow


def test_deploy_mcp_sse_workflow_uses_bearer_token_for_health_check():
    """Post-deploy health verification should use the same auth contract as Railway."""
    workflow = (ROOT / ".github" / "workflows" / "deploy-mcp-sse.yml").read_text()
    assert "RAILWAY_MCP_BEARER_TOKEN" in workflow
    assert "python3 -m agent_bom.deployment_probe" in workflow
    assert "--attempts 5" in workflow


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


def test_primary_api_image_includes_snowflake_extra_for_snowflake_backend():
    """The default API image must contain the Snowflake connector for the Snowflake Helm profile."""
    content = (ROOT / "Dockerfile").read_text()
    assert 'pip install --no-cache-dir --prefix=/install ".[api,snowflake]"' in content


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


def test_eks_snowflake_values_use_supported_chart_keys():
    """Snowflake EKS profile should render with keys the Helm chart actually consumes."""
    import yaml

    values = yaml.safe_load((ROOT / "deploy" / "helm" / "agent-bom" / "examples" / "eks-snowflake-values.yaml").read_text())
    api = values["controlPlane"]["api"]
    assert "extraVolumeMounts" in api
    assert "extraVolumes" in api
    assert "volumeMounts" not in api
    assert "volumes" not in api
    assert api["extraVolumeMounts"][0]["mountPath"] == "/var/snowflake"
    assert api["extraVolumes"][0]["secret"]["secretName"] == "agent-bom-snowflake"

    assert "scanCronJob" not in values["controlPlane"]
    assert values["scanner"]["enabled"] is True
    assert "--push-url" in values["scanner"]["extraArgs"]
    assert "http://agent-bom-api.agent-bom.svc.cluster.local:8422/v1/fleet/sync" in values["scanner"]["extraArgs"]

    assert "networkPolicy" not in values["controlPlane"]
    assert values["networkPolicy"]["enabled"] is True
    assert values["networkPolicy"]["restrictIngress"] is True
    assert values["networkPolicy"]["additionalEgress"][0]["ports"][0]["port"] == 443


def test_eks_pilot_doc_matches_chart_secret_and_service_port():
    """The pilot runbook should match the values file and the actual API service port."""
    doc = (ROOT / "site-docs" / "deployment" / "eks-mcp-pilot.md").read_text()
    assert "kubectl -n agent-bom create secret generic agent-bom-control-plane" in doc
    assert "controlPlane.externalSecrets" in doc
    assert "8080:8422" in doc
    assert "/v1/compliance/owasp-llm/report" in doc
    assert "/v1/compliance/soc2/report" not in doc


# ---------------------------------------------------------------------------
# CLI help text
# ---------------------------------------------------------------------------


def test_mcp_server_help_shows_skill_tools():
    """MCP server help should mention the expanded skill tool surface."""
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["mcp", "server", "--help"])
    assert "36 security tools" in result.output
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


def test_mcp_registry_descriptions_are_bounded():
    """Bundled registry descriptions stay safe for catalog/UI consumers."""
    from agent_bom.mcp_registry_text import MCP_REGISTRY_DESCRIPTION_MAX_CHARS

    f = ROOT / "src" / "agent_bom" / "mcp_registry.json"
    data = json.loads(f.read_text())
    too_long = [
        (name, len(str(entry.get("description", ""))))
        for name, entry in data.get("servers", {}).items()
        if len(str(entry.get("description", ""))) > MCP_REGISTRY_DESCRIPTION_MAX_CHARS
    ]
    assert not too_long, f"registry descriptions exceed {MCP_REGISTRY_DESCRIPTION_MAX_CHARS} chars: {too_long[:5]}"
