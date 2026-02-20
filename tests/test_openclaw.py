"""Tests for OpenClaw discovery and MCP registry integration."""


from agent_bom.discovery import CONFIG_LOCATIONS, PROJECT_CONFIG_FILES, parse_mcp_config
from agent_bom.models import AgentType, TransportType

# ── Enum Tests ─────────────────────────────────────────────────────────────


def test_openclaw_agent_type_exists():
    """OpenClaw should be a valid AgentType."""
    assert AgentType.OPENCLAW == "openclaw"
    assert AgentType.OPENCLAW.value == "openclaw"


def test_openclaw_agent_type_in_enum_values():
    """Ensure OPENCLAW is in the AgentType enum values."""
    assert "openclaw" in [at.value for at in AgentType]


# ── Discovery Config Path Tests ────────────────────────────────────────────


def test_openclaw_in_config_locations():
    """OpenClaw should have entries in CONFIG_LOCATIONS for all platforms."""
    assert AgentType.OPENCLAW in CONFIG_LOCATIONS
    paths = CONFIG_LOCATIONS[AgentType.OPENCLAW]
    assert "Darwin" in paths
    assert "Linux" in paths
    assert "Windows" in paths


def test_openclaw_darwin_paths():
    """macOS should search both ~/.openclaw/ and ~/Library/Application Support/."""
    paths = CONFIG_LOCATIONS[AgentType.OPENCLAW]["Darwin"]
    assert any("openclaw/config.json" in p for p in paths)
    assert any("Application Support/OpenClaw" in p for p in paths)


def test_openclaw_linux_paths():
    """Linux should search ~/.openclaw/ and ~/.config/openclaw/."""
    paths = CONFIG_LOCATIONS[AgentType.OPENCLAW]["Linux"]
    assert any("openclaw/config.json" in p for p in paths)
    assert any(".config/openclaw" in p for p in paths)


def test_openclaw_windows_paths():
    """Windows should search ~/.openclaw/ and ~/AppData/Roaming/OpenClaw/."""
    paths = CONFIG_LOCATIONS[AgentType.OPENCLAW]["Windows"]
    assert any("openclaw/config.json" in p for p in paths)
    assert any("AppData/Roaming/OpenClaw" in p for p in paths)


def test_openclaw_project_config_in_list():
    """Project-level .openclaw/openclaw.json should be in PROJECT_CONFIG_FILES."""
    assert ".openclaw/openclaw.json" in PROJECT_CONFIG_FILES


# ── Config Parsing Tests ───────────────────────────────────────────────────


def test_parse_openclaw_standard_config():
    """OpenClaw standard mcpServers format should parse correctly."""
    config = {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "openclaw-mcp-filesystem", "/home/user"],
            },
            "browser": {
                "command": "npx",
                "args": ["-y", "openclaw-mcp-browser"],
                "env": {"OPENCLAW_API_KEY": "oc-key-123"},
            },
        }
    }
    servers = parse_mcp_config(config, "~/.openclaw/config.json")
    assert len(servers) == 2
    names = {s.name for s in servers}
    assert "filesystem" in names
    assert "browser" in names
    browser = next(s for s in servers if s.name == "browser")
    assert browser.has_credentials


def test_parse_openclaw_empty_config():
    """Empty OpenClaw config should return no servers."""
    servers = parse_mcp_config({}, "~/.openclaw/config.json")
    assert len(servers) == 0


def test_parse_openclaw_with_sse_transport():
    """OpenClaw servers can use SSE transport."""
    config = {
        "mcpServers": {
            "remote-tool": {
                "url": "https://api.openclaw.dev/sse",
            }
        }
    }
    servers = parse_mcp_config(config, "~/.openclaw/config.json")
    assert len(servers) == 1
    assert servers[0].transport == TransportType.SSE


# ── MCP Registry Tests ────────────────────────────────────────────────────


def test_openclaw_in_mcp_registry():
    """OpenClaw core package should be in the MCP registry."""
    import json
    from pathlib import Path

    registry_path = Path(__file__).parent.parent / "src" / "agent_bom" / "mcp_registry.json"
    data = json.loads(registry_path.read_text())
    assert "openclaw" in data["servers"]
    entry = data["servers"]["openclaw"]
    assert entry["ecosystem"] == "npm"
    assert entry["risk_level"] == "high"
    assert "OPENCLAW_API_KEY" in entry["credential_env_vars"]


def test_openclaw_mcp_filesystem_in_registry():
    """OpenClaw filesystem MCP server should be in the registry."""
    import json
    from pathlib import Path

    registry_path = Path(__file__).parent.parent / "src" / "agent_bom" / "mcp_registry.json"
    data = json.loads(registry_path.read_text())
    assert "openclaw-mcp-filesystem" in data["servers"]


def test_openclaw_mcp_browser_in_registry():
    """OpenClaw browser MCP server should be in the registry."""
    import json
    from pathlib import Path

    registry_path = Path(__file__).parent.parent / "src" / "agent_bom" / "mcp_registry.json"
    data = json.loads(registry_path.read_text())
    assert "openclaw-mcp-browser" in data["servers"]


def test_openclaw_known_cves_in_registry():
    """Registry entry should list known CVEs for threat intelligence."""
    import json
    from pathlib import Path

    registry_path = Path(__file__).parent.parent / "src" / "agent_bom" / "mcp_registry.json"
    data = json.loads(registry_path.read_text())
    entry = data["servers"]["openclaw"]
    known_cves = entry.get("known_cves", [])
    assert "CVE-2026-25253" in known_cves
    assert len(known_cves) >= 7
