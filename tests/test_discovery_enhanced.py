"""Tests for v0.15.0 discovery enhancements: agent status, ToolHive, Claude Code projects."""

from __future__ import annotations

import json
import subprocess

from agent_bom.models import Agent, AgentStatus, AgentType, TransportType

# ── AgentStatus model tests ──────────────────────────────────────────────────


def test_agent_status_enum_values():
    assert AgentStatus.CONFIGURED.value == "configured"
    assert AgentStatus.INSTALLED_NOT_CONFIGURED.value == "installed-not-configured"


def test_agent_default_status():
    agent = Agent(name="test", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/test")
    assert agent.status == AgentStatus.CONFIGURED


def test_agent_installed_not_configured():
    agent = Agent(
        name="openclaw",
        agent_type=AgentType.OPENCLAW,
        config_path="openclaw (binary on PATH)",
        status=AgentStatus.INSTALLED_NOT_CONFIGURED,
    )
    assert agent.status == AgentStatus.INSTALLED_NOT_CONFIGURED
    assert len(agent.mcp_servers) == 0


def test_toolhive_agent_type():
    assert AgentType.TOOLHIVE.value == "toolhive"


# ── Claude Code project parsing ──────────────────────────────────────────────


def test_parse_claude_json_projects_empty():
    from agent_bom.discovery import parse_claude_json_projects

    servers = parse_claude_json_projects({}, "~/.claude.json")
    assert servers == []


def test_parse_claude_json_projects_with_servers():
    from agent_bom.discovery import parse_claude_json_projects

    config = {
        "projects": {
            "/Users/user/myproject": {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    }
                },
                "allowedTools": [],
            }
        }
    }
    servers = parse_claude_json_projects(config, "~/.claude.json")
    assert len(servers) == 1
    assert servers[0].name == "filesystem"
    assert servers[0].working_dir == "/Users/user/myproject"


def test_parse_claude_json_projects_multiple():
    from agent_bom.discovery import parse_claude_json_projects

    config = {
        "projects": {
            "/project1": {
                "mcpServers": {
                    "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]},
                }
            },
            "/project2": {
                "mcpServers": {
                    "db": {"command": "python", "args": ["db.py"]},
                }
            },
        }
    }
    servers = parse_claude_json_projects(config, "~/.claude.json")
    assert len(servers) == 2
    names = {s.name for s in servers}
    assert "fs" in names
    assert "db" in names


def test_parse_claude_json_projects_empty_mcpservers():
    from agent_bom.discovery import parse_claude_json_projects

    config = {
        "projects": {
            "/project1": {
                "mcpServers": {},
                "enabledMcpjsonServers": [],
            }
        }
    }
    servers = parse_claude_json_projects(config, "~/.claude.json")
    assert servers == []


def test_parse_claude_json_projects_no_key():
    from agent_bom.discovery import parse_claude_json_projects

    config = {
        "projects": {
            "/project1": {
                "allowedTools": ["tool1"],
            }
        }
    }
    servers = parse_claude_json_projects(config, "~/.claude.json")
    assert servers == []


# ── ToolHive server parsing ──────────────────────────────────────────────────


def test_parse_toolhive_servers_list():
    from agent_bom.discovery import _parse_toolhive_servers

    data = [
        {"name": "fetch", "image": "ghcr.io/stacklok/mcp-fetch:latest"},
        {"name": "github", "image": "ghcr.io/stacklok/mcp-github:latest", "url": "http://localhost:9090/sse"},
    ]
    servers = _parse_toolhive_servers(data)
    assert len(servers) == 2
    assert servers[0].name == "fetch"
    assert servers[0].transport == TransportType.STDIO
    assert servers[1].name == "github"
    assert servers[1].transport == TransportType.SSE


def test_parse_toolhive_servers_dict():
    from agent_bom.discovery import _parse_toolhive_servers

    data = {"servers": [{"name": "test", "image": "test:latest"}]}
    servers = _parse_toolhive_servers(data)
    assert len(servers) == 1
    assert servers[0].name == "test"


def test_parse_toolhive_servers_empty():
    from agent_bom.discovery import _parse_toolhive_servers

    assert _parse_toolhive_servers([]) == []
    assert _parse_toolhive_servers({"servers": []}) == []


def test_parse_toolhive_servers_streamable_http():
    from agent_bom.discovery import _parse_toolhive_servers

    data = [{"name": "api", "image": "test:latest", "url": "http://localhost:8080/mcp"}]
    servers = _parse_toolhive_servers(data)
    assert len(servers) == 1
    assert servers[0].transport == TransportType.STREAMABLE_HTTP


# ── ToolHive discovery ───────────────────────────────────────────────────────


def test_toolhive_no_thv(monkeypatch):
    """discover_toolhive returns None when thv is not on PATH."""
    import shutil

    from agent_bom.discovery import discover_toolhive

    monkeypatch.setattr(shutil, "which", lambda _: None)
    assert discover_toolhive() is None


def test_toolhive_thv_no_servers(monkeypatch):
    """discover_toolhive returns installed-not-configured when thv list returns empty."""
    import shutil

    from agent_bom.discovery import discover_toolhive

    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/local/bin/" + cmd)

    def fake_run(cmd, **kwargs):
        class R:
            returncode = 0
            stdout = "[]"
            stderr = ""
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    agent = discover_toolhive()
    assert agent is not None
    assert agent.agent_type == AgentType.TOOLHIVE
    assert agent.status == AgentStatus.INSTALLED_NOT_CONFIGURED


def test_toolhive_thv_with_servers(monkeypatch):
    """discover_toolhive returns configured agent when thv list returns servers."""
    import shutil

    from agent_bom.discovery import discover_toolhive

    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/local/bin/" + cmd)

    fake_data = [
        {"name": "fetch-server", "image": "ghcr.io/stacklok/mcp-fetch:latest", "url": "http://localhost:8080/sse"},
        {"name": "github-server", "image": "ghcr.io/stacklok/mcp-github:latest"},
    ]

    def fake_run(cmd, **kwargs):
        class R:
            returncode = 0
            stdout = json.dumps(fake_data)
            stderr = ""
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    agent = discover_toolhive()
    assert agent is not None
    assert agent.status == AgentStatus.CONFIGURED
    assert len(agent.mcp_servers) == 2
    names = {s.name for s in agent.mcp_servers}
    assert "fetch-server" in names
    assert "github-server" in names


def test_toolhive_thv_error(monkeypatch):
    """discover_toolhive returns installed-not-configured when thv list fails."""
    import shutil

    from agent_bom.discovery import discover_toolhive

    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/local/bin/" + cmd)

    def fake_run(cmd, **kwargs):
        class R:
            returncode = 1
            stdout = ""
            stderr = "daemon not running"
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    agent = discover_toolhive()
    assert agent is not None
    assert agent.status == AgentStatus.INSTALLED_NOT_CONFIGURED


def test_toolhive_thv_timeout(monkeypatch):
    """discover_toolhive handles subprocess timeout gracefully."""
    import shutil

    from agent_bom.discovery import discover_toolhive

    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/local/bin/" + cmd)

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=15)

    monkeypatch.setattr(subprocess, "run", fake_run)
    agent = discover_toolhive()
    assert agent is not None
    assert agent.status == AgentStatus.INSTALLED_NOT_CONFIGURED


# ── Binary detection ─────────────────────────────────────────────────────────


def test_detect_installed_openclaw(monkeypatch):
    """detect_installed_agents finds openclaw binary when config is missing."""
    import shutil

    from agent_bom.discovery import detect_installed_agents

    monkeypatch.setattr(shutil, "which", lambda cmd: "/opt/homebrew/bin/openclaw" if cmd == "openclaw" else None)

    installed = detect_installed_agents(discovered_types=set())
    agent_types = {a.agent_type for a in installed}
    assert AgentType.OPENCLAW in agent_types

    openclaw = next(a for a in installed if a.agent_type == AgentType.OPENCLAW)
    assert openclaw.status == AgentStatus.INSTALLED_NOT_CONFIGURED
    assert len(openclaw.mcp_servers) == 0


def test_detect_skips_already_discovered(monkeypatch):
    """detect_installed_agents doesn't duplicate agents already found via config."""
    import shutil

    from agent_bom.discovery import detect_installed_agents

    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/" + cmd)

    installed = detect_installed_agents(discovered_types={AgentType.OPENCLAW})
    agent_types = {a.agent_type for a in installed}
    assert AgentType.OPENCLAW not in agent_types


def test_detect_no_binaries(monkeypatch):
    """detect_installed_agents returns empty when no agent binaries are on PATH."""
    import shutil

    from agent_bom.discovery import detect_installed_agents

    monkeypatch.setattr(shutil, "which", lambda _: None)
    installed = detect_installed_agents(discovered_types=set())
    assert installed == []


def test_detect_skips_toolhive(monkeypatch):
    """detect_installed_agents skips ToolHive (handled separately)."""
    import shutil

    from agent_bom.discovery import detect_installed_agents

    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/local/bin/thv" if cmd == "thv" else None)
    installed = detect_installed_agents(discovered_types=set())
    agent_types = {a.agent_type for a in installed}
    assert AgentType.TOOLHIVE not in agent_types


# ── JSON output includes status ──────────────────────────────────────────────


def test_json_includes_status():
    from agent_bom.models import AIBOMReport
    from agent_bom.output import to_json

    agent = Agent(
        name="openclaw",
        agent_type=AgentType.OPENCLAW,
        config_path="openclaw (binary on PATH)",
        status=AgentStatus.INSTALLED_NOT_CONFIGURED,
    )
    report = AIBOMReport(agents=[agent])
    data = to_json(report)
    assert data["agents"][0]["status"] == "installed-not-configured"


def test_json_configured_default():
    from agent_bom.models import AIBOMReport
    from agent_bom.output import to_json

    agent = Agent(
        name="claude-desktop",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/test/config.json",
    )
    report = AIBOMReport(agents=[agent])
    data = to_json(report)
    assert data["agents"][0]["status"] == "configured"


# ── CycloneDX output includes status ────────────────────────────────────────


def test_cyclonedx_includes_status():
    from agent_bom.models import AIBOMReport
    from agent_bom.output import to_cyclonedx

    agent = Agent(
        name="test",
        agent_type=AgentType.CUSTOM,
        config_path="/test",
        status=AgentStatus.INSTALLED_NOT_CONFIGURED,
    )
    report = AIBOMReport(agents=[agent])
    cdx = to_cyclonedx(report)
    agent_comp = cdx["components"][0]
    status_props = [p for p in agent_comp["properties"] if p["name"] == "agent-bom:status"]
    assert len(status_props) == 1
    assert status_props[0]["value"] == "installed-not-configured"


# ── ToolHive in CONFIG_LOCATIONS ─────────────────────────────────────────────


def test_toolhive_in_config_locations():
    from agent_bom.discovery import CONFIG_LOCATIONS

    assert AgentType.TOOLHIVE in CONFIG_LOCATIONS
    # ToolHive uses CLI-based discovery, so paths are empty
    for platform_paths in CONFIG_LOCATIONS[AgentType.TOOLHIVE].values():
        assert platform_paths == []


# ── AGENT_BINARIES constant ─────────────────────────────────────────────────


def test_agent_binaries_has_expected_entries():
    from agent_bom.discovery import AGENT_BINARIES

    assert AGENT_BINARIES[AgentType.OPENCLAW] == "openclaw"
    assert AGENT_BINARIES[AgentType.TOOLHIVE] == "thv"
    assert AGENT_BINARIES[AgentType.CLAUDE_CODE] == "claude"


# ── CLI where command ────────────────────────────────────────────────────────


def test_where_shows_binary_info():
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["where"])
    assert result.exit_code == 0
    # Should mention binary detection
    assert "binary:" in result.output or "toolhive" in result.output.lower()


def test_get_all_discovery_paths_returns_all_clients():
    from agent_bom.discovery import get_all_discovery_paths

    paths = get_all_discovery_paths("Darwin")
    clients = {c for c, _ in paths}
    # Must include key clients
    for expected in ["claude-desktop", "claude-code", "cursor", "windsurf",
                     "Docker MCP Toolkit", "Project config", "Docker Compose"]:
        assert expected in clients, f"Missing client: {expected}"
    # Must have a reasonable number of paths
    assert len(paths) >= 20


def test_get_all_discovery_paths_linux():
    from agent_bom.discovery import get_all_discovery_paths

    paths = get_all_discovery_paths("Linux")
    path_strs = [p for _, p in paths]
    # Linux should use ~/.config paths, not ~/Library
    assert any("/.config/" in p for p in path_strs)
    assert not any("Library/Application Support" in p for p in path_strs)


def test_where_json_output():
    import json

    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["where", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "platform" in data
    assert "paths" in data
    assert len(data["paths"]) >= 20
    # Each entry has required fields
    for entry in data["paths"]:
        assert "client" in entry
        assert "path" in entry
        assert "exists" in entry


def test_where_shows_totals():
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["where"])
    assert result.exit_code == 0
    assert "Total:" in result.output
    assert "paths checked" in result.output
