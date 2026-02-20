"""Tests for OpenClaw discovery and MCP registry integration.

Based on the real OpenClaw project: https://github.com/openclaw/openclaw
- 214k+ GitHub stars, TypeScript/Node.js, MIT license
- Config dir: ~/.openclaw/ on all platforms (resolveConfigDir in src/utils.ts)
- Override via OPENCLAW_STATE_DIR env var
- Config file: ~/.openclaw/openclaw.json
- npm package: openclaw
- 12 real CVEs from GitHub Security Advisories
"""


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


def test_openclaw_config_path_all_platforms():
    """All platforms use ~/.openclaw/openclaw.json (resolveConfigDir uses ~/.openclaw/)."""
    for platform in ("Darwin", "Linux", "Windows"):
        paths = CONFIG_LOCATIONS[AgentType.OPENCLAW][platform]
        assert any("/.openclaw/openclaw.json" in p for p in paths), f"Missing ~/.openclaw/openclaw.json on {platform}"


def test_openclaw_no_fake_platform_paths():
    """OpenClaw does NOT use ~/Library/Application Support/ or ~/.config/ — only ~/.openclaw/."""
    for platform in ("Darwin", "Linux", "Windows"):
        paths = CONFIG_LOCATIONS[AgentType.OPENCLAW][platform]
        for p in paths:
            assert "Application Support" not in p, f"Fake path found: {p}"
            assert "AppData/Roaming" not in p, f"Fake path found: {p}"


def test_openclaw_project_config_in_list():
    """Project-level .openclaw/openclaw.json should be in PROJECT_CONFIG_FILES."""
    assert ".openclaw/openclaw.json" in PROJECT_CONFIG_FILES


# ── Config Parsing Tests ───────────────────────────────────────────────────


def test_parse_openclaw_standard_config():
    """OpenClaw openclaw.json with mcpServers should parse correctly."""
    config = {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user"],
            },
            "github": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"],
                "env": {"GITHUB_TOKEN": "ghp_xxx"},
            },
        }
    }
    servers = parse_mcp_config(config, "~/.openclaw/openclaw.json")
    assert len(servers) == 2
    names = {s.name for s in servers}
    assert "filesystem" in names
    assert "github" in names
    github = next(s for s in servers if s.name == "github")
    assert github.has_credentials


def test_parse_openclaw_empty_config():
    """Empty OpenClaw config should return no servers."""
    servers = parse_mcp_config({}, "~/.openclaw/openclaw.json")
    assert len(servers) == 0


def test_parse_openclaw_agent_config_only():
    """OpenClaw config with only agent settings (no mcpServers) returns no MCP servers."""
    config = {
        "agent": {
            "model": "anthropic/claude-opus-4-6"
        }
    }
    servers = parse_mcp_config(config, "~/.openclaw/openclaw.json")
    assert len(servers) == 0


def test_parse_openclaw_with_sse_transport():
    """OpenClaw servers can use SSE transport."""
    config = {
        "mcpServers": {
            "remote-tool": {
                "url": "https://mcp.example.com/sse",
            }
        }
    }
    servers = parse_mcp_config(config, "~/.openclaw/openclaw.json")
    assert len(servers) == 1
    assert servers[0].transport == TransportType.SSE


# ── MCP Registry Tests ────────────────────────────────────────────────────


def test_openclaw_in_mcp_registry():
    """OpenClaw core package should be in the MCP registry with real data."""
    import json
    from pathlib import Path

    registry_path = Path(__file__).parent.parent / "src" / "agent_bom" / "mcp_registry.json"
    data = json.loads(registry_path.read_text())
    assert "openclaw" in data["servers"]
    entry = data["servers"]["openclaw"]
    assert entry["ecosystem"] == "npm"
    assert entry["risk_level"] == "high"
    assert entry["license"] == "MIT"
    assert entry["source_url"] == "https://github.com/openclaw/openclaw"


def test_openclaw_registry_has_real_tools():
    """Registry tools should match OpenClaw's actual tool groups from tool-policy.ts."""
    import json
    from pathlib import Path

    registry_path = Path(__file__).parent.parent / "src" / "agent_bom" / "mcp_registry.json"
    data = json.loads(registry_path.read_text())
    tools = data["servers"]["openclaw"]["tools"]
    # Real tools from OpenClaw's tool-policy.ts
    for real_tool in ["web_search", "web_fetch", "read", "write", "edit", "exec", "browser", "memory_search"]:
        assert real_tool in tools, f"Missing real tool: {real_tool}"


def test_openclaw_registry_has_real_cves():
    """Registry should list real CVEs from OpenClaw's GitHub Security Advisories."""
    import json
    from pathlib import Path

    registry_path = Path(__file__).parent.parent / "src" / "agent_bom" / "mcp_registry.json"
    data = json.loads(registry_path.read_text())
    entry = data["servers"]["openclaw"]
    known_cves = entry.get("known_cves", [])
    # Real CVEs from https://github.com/openclaw/openclaw/security/advisories
    assert "CVE-2026-27001" in known_cves  # CWD path injection into LLM prompts (HIGH)
    assert "CVE-2026-27002" in known_cves  # Docker container escape via bind mount (MEDIUM)
    assert "CVE-2026-27487" in known_cves  # Shell injection in macOS keychain (HIGH)
    assert "CVE-2026-26321" in known_cves  # Local file disclosure in Feishu extension (HIGH)
    assert len(known_cves) >= 12


def test_openclaw_registry_no_fake_cves():
    """Registry must NOT contain fabricated CVEs."""
    import json
    from pathlib import Path

    registry_path = Path(__file__).parent.parent / "src" / "agent_bom" / "mcp_registry.json"
    data = json.loads(registry_path.read_text())
    known_cves = data["servers"]["openclaw"].get("known_cves", [])
    fake_cves = ["CVE-2026-25253", "CVE-2026-24764", "CVE-2026-26322", "CVE-2026-26324", "CVE-2026-26326", "CVE-2026-26327"]
    for fake in fake_cves:
        assert fake not in known_cves, f"Fake CVE still present: {fake}"


def test_openclaw_registry_no_fake_packages():
    """Fake openclaw-mcp-filesystem and openclaw-mcp-browser should NOT exist."""
    import json
    from pathlib import Path

    registry_path = Path(__file__).parent.parent / "src" / "agent_bom" / "mcp_registry.json"
    data = json.loads(registry_path.read_text())
    assert "openclaw-mcp-filesystem" not in data["servers"]
    assert "openclaw-mcp-browser" not in data["servers"]


def test_openclaw_registry_real_credential_vars():
    """Credential env vars should match what OpenClaw actually uses."""
    import json
    from pathlib import Path

    registry_path = Path(__file__).parent.parent / "src" / "agent_bom" / "mcp_registry.json"
    data = json.loads(registry_path.read_text())
    creds = data["servers"]["openclaw"]["credential_env_vars"]
    assert "OPENAI_API_KEY" in creds
    assert "ANTHROPIC_API_KEY" in creds
    # OPENCLAW_API_KEY is not a real env var
    assert "OPENCLAW_API_KEY" not in creds
