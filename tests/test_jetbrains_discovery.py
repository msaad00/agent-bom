"""Tests for JetBrains AI Assistant + Junie MCP client discovery."""

from __future__ import annotations

import json

from agent_bom.models import Agent, AgentStatus, AgentType

# ── AgentType enum values ────────────────────────────────────────────────────


def test_jetbrains_ai_agent_type():
    assert AgentType.JETBRAINS_AI.value == "jetbrains-ai"


def test_junie_agent_type():
    assert AgentType.JUNIE.value == "junie"


# ── CONFIG_LOCATIONS entries ─────────────────────────────────────────────────


def test_jetbrains_ai_in_config_locations():
    from agent_bom.discovery import CONFIG_LOCATIONS

    assert AgentType.JETBRAINS_AI in CONFIG_LOCATIONS
    locs = CONFIG_LOCATIONS[AgentType.JETBRAINS_AI]
    # All three platforms must be present
    for plat in ("Darwin", "Linux", "Windows"):
        assert plat in locs
        assert len(locs[plat]) >= 1


def test_junie_in_config_locations():
    from agent_bom.discovery import CONFIG_LOCATIONS

    assert AgentType.JUNIE in CONFIG_LOCATIONS
    locs = CONFIG_LOCATIONS[AgentType.JUNIE]
    for plat in ("Darwin", "Linux", "Windows"):
        assert plat in locs
        paths = locs[plat]
        assert any("junie" in p for p in paths)


def test_jetbrains_ai_darwin_paths():
    from agent_bom.discovery import CONFIG_LOCATIONS

    paths = CONFIG_LOCATIONS[AgentType.JETBRAINS_AI]["Darwin"]
    # Should have JetBrains glob path + Copilot path
    assert any("JetBrains" in p and "*" in p for p in paths)
    assert any("github-copilot/intellij" in p for p in paths)


def test_jetbrains_ai_linux_paths():
    from agent_bom.discovery import CONFIG_LOCATIONS

    paths = CONFIG_LOCATIONS[AgentType.JETBRAINS_AI]["Linux"]
    assert any("JetBrains" in p and "*" in p for p in paths)


def test_junie_path_stable():
    from agent_bom.discovery import CONFIG_LOCATIONS

    for plat in ("Darwin", "Linux", "Windows"):
        paths = CONFIG_LOCATIONS[AgentType.JUNIE][plat]
        assert "~/.junie/mcp/mcp.json" in paths


# ── AGENT_BINARIES ───────────────────────────────────────────────────────────


def test_junie_binary_in_agent_binaries():
    from agent_bom.discovery import AGENT_BINARIES

    assert AgentType.JUNIE in AGENT_BINARIES
    assert AGENT_BINARIES[AgentType.JUNIE] == "junie"


# ── PROJECT_CONFIG_FILES ─────────────────────────────────────────────────────


def test_junie_project_config():
    from agent_bom.discovery import PROJECT_CONFIG_FILES

    assert ".junie/mcp/mcp.json" in PROJECT_CONFIG_FILES


# ── Discovery integration ────────────────────────────────────────────────────


def test_discover_junie_config(tmp_path, monkeypatch):
    """Discover Junie when its config file exists with MCP servers."""
    from agent_bom.discovery import discover_global_configs

    config = {"mcpServers": {"test-server": {"command": "node", "args": ["server.js"]}}}
    junie_dir = tmp_path / ".junie" / "mcp"
    junie_dir.mkdir(parents=True)
    config_file = junie_dir / "mcp.json"
    config_file.write_text(json.dumps(config))

    monkeypatch.setattr(
        "agent_bom.discovery.CONFIG_LOCATIONS",
        {AgentType.JUNIE: {"Darwin": [str(config_file)], "Linux": [str(config_file)], "Windows": [str(config_file)]}},
    )
    monkeypatch.setattr("agent_bom.discovery.get_platform", lambda: "Darwin")

    agents = discover_global_configs([AgentType.JUNIE])
    assert len(agents) == 1
    assert agents[0].agent_type == AgentType.JUNIE
    assert len(agents[0].mcp_servers) == 1
    assert agents[0].mcp_servers[0].name == "test-server"


def test_discover_jetbrains_ai_config(tmp_path, monkeypatch):
    """Discover JetBrains AI Assistant when its config file exists."""
    from agent_bom.discovery import discover_global_configs

    config = {"mcpServers": {"db-tool": {"command": "python", "args": ["-m", "db_mcp"]}}}
    jb_dir = tmp_path / "JetBrains" / "PyCharm2025.2"
    jb_dir.mkdir(parents=True)
    config_file = jb_dir / "mcp.json"
    config_file.write_text(json.dumps(config))

    monkeypatch.setattr(
        "agent_bom.discovery.CONFIG_LOCATIONS",
        {AgentType.JETBRAINS_AI: {"Darwin": [str(config_file)], "Linux": [], "Windows": []}},
    )
    monkeypatch.setattr("agent_bom.discovery.get_platform", lambda: "Darwin")

    agents = discover_global_configs([AgentType.JETBRAINS_AI])
    assert len(agents) == 1
    assert agents[0].agent_type == AgentType.JETBRAINS_AI
    assert agents[0].mcp_servers[0].name == "db-tool"


def test_discover_jetbrains_glob_pattern(tmp_path, monkeypatch):
    """Glob pattern expands to find JetBrains IDE configs across versions."""
    from agent_bom.discovery import discover_global_configs

    config = {"mcpServers": {"mcp-server": {"command": "node", "args": ["server.js"]}}}

    # Create two versioned JetBrains dirs
    for ide in ("IntelliJIdea2025.2", "PyCharm2025.1"):
        ide_dir = tmp_path / "JetBrains" / ide
        ide_dir.mkdir(parents=True)
        (ide_dir / "mcp.json").write_text(json.dumps(config))

    glob_pattern = str(tmp_path / "JetBrains" / "*" / "mcp.json")
    monkeypatch.setattr(
        "agent_bom.discovery.CONFIG_LOCATIONS",
        {AgentType.JETBRAINS_AI: {"Darwin": [glob_pattern], "Linux": [], "Windows": []}},
    )
    monkeypatch.setattr("agent_bom.discovery.get_platform", lambda: "Darwin")

    agents = discover_global_configs([AgentType.JETBRAINS_AI])
    # Should find both IDE configs (may merge or create 2 agents)
    assert len(agents) >= 1
    total_servers = sum(len(a.mcp_servers) for a in agents)
    assert total_servers >= 2


def test_discover_junie_no_config(monkeypatch):
    """No agents returned when Junie config does not exist."""
    from agent_bom.discovery import discover_global_configs

    monkeypatch.setattr(
        "agent_bom.discovery.CONFIG_LOCATIONS",
        {AgentType.JUNIE: {"Darwin": ["/nonexistent/path/.junie/mcp/mcp.json"], "Linux": [], "Windows": []}},
    )
    monkeypatch.setattr("agent_bom.discovery.get_platform", lambda: "Darwin")

    agents = discover_global_configs([AgentType.JUNIE])
    assert len(agents) == 0


def test_junie_agent_model():
    """Junie agent can be instantiated with standard Agent model."""
    agent = Agent(
        name="junie",
        agent_type=AgentType.JUNIE,
        config_path="~/.junie/mcp/mcp.json",
    )
    assert agent.agent_type == AgentType.JUNIE
    assert agent.status == AgentStatus.CONFIGURED


def test_jetbrains_ai_agent_model():
    """JetBrains AI agent can be instantiated with standard Agent model."""
    agent = Agent(
        name="jetbrains-ai",
        agent_type=AgentType.JETBRAINS_AI,
        config_path="~/Library/Application Support/JetBrains/PyCharm2025.2/mcp.json",
    )
    assert agent.agent_type == AgentType.JETBRAINS_AI
    assert agent.status == AgentStatus.CONFIGURED


# ── get_all_discovery_paths includes JetBrains ───────────────────────────────


def test_discovery_paths_include_jetbrains():
    from agent_bom.discovery import get_all_discovery_paths

    paths = get_all_discovery_paths("Darwin")
    clients = {c for c, _ in paths}
    assert "jetbrains-ai" in clients
    assert "junie" in clients


def test_client_count_is_29():
    """Verify we now have 29 config-backed MCP client types after ToolHive removal."""
    from agent_bom.discovery import CONFIG_LOCATIONS

    # CUSTOM is not in CONFIG_LOCATIONS, and ToolHive was removed.
    assert len(CONFIG_LOCATIONS) == 29
