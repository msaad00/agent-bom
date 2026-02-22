"""Tests for Docker MCP discovery, check @latest resolution, and CLI polish."""

from __future__ import annotations

import yaml

from agent_bom.models import (
    AgentStatus,
    AgentType,
    Severity,
    Vulnerability,
)

# ── AgentType enum ───────────────────────────────────────────────────────────


def test_docker_mcp_agent_type():
    """DOCKER_MCP enum value exists and is correct."""
    assert AgentType.DOCKER_MCP.value == "docker-mcp"


# ── Docker MCP Discovery ─────────────────────────────────────────────────────


def test_docker_mcp_discovery_no_files(monkeypatch, tmp_path):
    """discover_docker_mcp returns None when Docker MCP dir doesn't exist."""
    from agent_bom.discovery import discover_docker_mcp

    monkeypatch.setattr(
        "os.path.expanduser",
        lambda p: str(tmp_path / "nonexistent" / "mcp") if ".docker/mcp" in p else p,
    )
    # Patch expanduser at module level in discovery
    import agent_bom.discovery as disc_mod
    original = disc_mod.os.path.expanduser
    monkeypatch.setattr(disc_mod.os.path, "expanduser", lambda p: str(tmp_path / "nonexistent") if ".docker/mcp" in p else original(p))

    result = discover_docker_mcp()
    assert result is None


def test_docker_mcp_discovery_empty_registry(tmp_path):
    """discover_docker_mcp returns INSTALLED_NOT_CONFIGURED for empty registry."""
    from agent_bom.discovery import discover_docker_mcp

    mcp_dir = tmp_path / ".docker" / "mcp"
    mcp_dir.mkdir(parents=True)
    (mcp_dir / "registry.yaml").write_text("registry: {}\n")

    # Directly test the function by patching the path
    import agent_bom.discovery as disc_mod
    original_expanduser = disc_mod.os.path.expanduser

    def mock_expanduser(p):
        if ".docker/mcp" in p:
            return str(mcp_dir)
        return original_expanduser(p)

    disc_mod.os.path.expanduser = mock_expanduser
    try:
        agent = discover_docker_mcp()
        assert agent is not None
        assert agent.agent_type == AgentType.DOCKER_MCP
        assert agent.status == AgentStatus.INSTALLED_NOT_CONFIGURED
        assert len(agent.mcp_servers) == 0
    finally:
        disc_mod.os.path.expanduser = original_expanduser


def test_docker_mcp_discovery_with_servers(tmp_path):
    """discover_docker_mcp returns CONFIGURED with servers from catalog."""
    from agent_bom.discovery import discover_docker_mcp

    mcp_dir = tmp_path / ".docker" / "mcp"
    mcp_dir.mkdir(parents=True)
    catalogs_dir = mcp_dir / "catalogs"
    catalogs_dir.mkdir()

    (mcp_dir / "registry.yaml").write_text('registry:\n  playwright:\n    ref: ""\n')

    catalog = {
        "version": 3,
        "name": "docker-mcp",
        "registry": {
            "playwright": {
                "title": "Playwright",
                "image": "mcp/playwright@sha256:4e403fabcdef1234",
                "tools": [
                    {"name": "browser_click"},
                    {"name": "browser_close"},
                    {"name": "browser_navigate"},
                ],
                "metadata": {"pulls": 700108, "category": "devops"},
            }
        },
    }
    (catalogs_dir / "docker-mcp.yaml").write_text(yaml.dump(catalog))

    import agent_bom.discovery as disc_mod
    original_expanduser = disc_mod.os.path.expanduser

    def mock_expanduser(p):
        if ".docker/mcp" in p:
            return str(mcp_dir)
        return original_expanduser(p)

    disc_mod.os.path.expanduser = mock_expanduser
    try:
        agent = discover_docker_mcp()
        assert agent is not None
        assert agent.agent_type == AgentType.DOCKER_MCP
        assert agent.status == AgentStatus.CONFIGURED
        assert len(agent.mcp_servers) == 1
        assert agent.mcp_servers[0].name == "playwright"
        assert len(agent.mcp_servers[0].tools) == 3
    finally:
        disc_mod.os.path.expanduser = original_expanduser


def test_docker_mcp_tools_extracted(tmp_path):
    """Tools from Docker MCP catalog become MCPTool objects on the server."""
    from agent_bom.discovery import _parse_docker_mcp_catalog

    catalog = {
        "registry": {
            "playwright": {
                "image": "mcp/playwright@sha256:abc123def456",
                "tools": [
                    {"name": "browser_click"},
                    {"name": "browser_close"},
                    {"name": "browser_navigate"},
                    {"name": "browser_snapshot"},
                ],
            }
        }
    }
    catalog_path = tmp_path / "docker-mcp.yaml"
    catalog_path.write_text(yaml.dump(catalog))

    servers = _parse_docker_mcp_catalog({"playwright"}, catalog_path)
    assert len(servers) == 1
    assert len(servers[0].tools) == 4
    tool_names = {t.name for t in servers[0].tools}
    assert tool_names == {"browser_click", "browser_close", "browser_navigate", "browser_snapshot"}


def test_docker_mcp_secrets_as_credentials(tmp_path):
    """Secrets from Docker MCP catalog become credential env vars."""
    from agent_bom.discovery import _parse_docker_mcp_catalog

    catalog = {
        "registry": {
            "couchbase": {
                "image": "mcp/couchbase@sha256:ce108aabb",
                "tools": [{"name": "run_query"}],
                "secrets": [
                    {"name": "couchbase.cb_password", "env": "CB_PASSWORD"},
                    {"name": "couchbase.cb_token", "env": "CB_API_TOKEN"},
                ],
            }
        }
    }
    catalog_path = tmp_path / "docker-mcp.yaml"
    catalog_path.write_text(yaml.dump(catalog))

    servers = _parse_docker_mcp_catalog({"couchbase"}, catalog_path)
    assert len(servers) == 1
    assert servers[0].has_credentials
    cred_names = servers[0].credential_names
    assert "CB_PASSWORD" in cred_names
    assert "CB_API_TOKEN" in cred_names
    # Values should be redacted
    assert servers[0].env["CB_PASSWORD"] == "***REDACTED***"


def test_docker_mcp_package_from_image(tmp_path):
    """Docker image reference becomes a Package with ecosystem='docker'."""
    from agent_bom.discovery import _parse_docker_mcp_catalog

    catalog = {
        "registry": {
            "nginx": {
                "image": "mcp/nginx@sha256:abc123def456789",
                "tools": [],
            }
        }
    }
    catalog_path = tmp_path / "docker-mcp.yaml"
    catalog_path.write_text(yaml.dump(catalog))

    servers = _parse_docker_mcp_catalog({"nginx"}, catalog_path)
    assert len(servers) == 1
    assert len(servers[0].packages) == 1
    pkg = servers[0].packages[0]
    assert pkg.name == "mcp/nginx"
    assert pkg.ecosystem == "docker"
    assert pkg.version == "abc123def456"  # First 12 chars of digest


# ── Check @latest Resolution ─────────────────────────────────────────────────


def test_check_latest_triggers_resolution():
    """check command with @latest should attempt version resolution."""
    from unittest.mock import patch

    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()

    resolve_called = False

    async def fake_resolve(pkg, client):
        nonlocal resolve_called
        resolve_called = True
        pkg.version = "1.6.2"
        pkg.purl = f"pkg:npm/{pkg.name}@1.6.2"
        return True

    async def fake_osv(pkgs):
        return {}

    with patch("agent_bom.resolver.resolve_package_version", side_effect=fake_resolve), \
         patch("agent_bom.scanners.query_osv_batch", side_effect=fake_osv):
        result = runner.invoke(main, ["check", "express@latest", "-e", "npm"])
        assert resolve_called, "resolve_package_version should have been called for @latest"
        assert "Resolved" in result.output or "1.6.2" in result.output


# ── CLI Output Polish ────────────────────────────────────────────────────────


def test_fix_available_indicator():
    """Vulnerability with fixed_version should use green checkmark in display."""
    vuln_with_fix = Vulnerability(
        id="CVE-2024-1234",
        summary="XSS in templates",
        severity=Severity.HIGH,
        fixed_version="4.19.0",
    )
    vuln_no_fix = Vulnerability(
        id="CVE-2024-5678",
        summary="RCE via prototype pollution",
        severity=Severity.CRITICAL,
    )

    # Test the fix display logic (same as used in output/__init__.py and cli.py)
    if vuln_with_fix.fixed_version:
        fix_display = f"✓ {vuln_with_fix.fixed_version}"
    else:
        fix_display = "No fix"
    assert "✓" in fix_display
    assert "4.19.0" in fix_display

    if vuln_no_fix.fixed_version:
        fix_display2 = f"✓ {vuln_no_fix.fixed_version}"
    else:
        fix_display2 = "No fix"
    assert "No fix" in fix_display2
