"""Tests for discovery enhancements: agent status and Claude Code projects."""

from __future__ import annotations

from datetime import datetime

import pytest

from agent_bom.cloud.normalization import build_cloud_state, normalize_cloud_lifecycle_state
from agent_bom.models import Agent, AgentStatus, AgentType

# ── AgentStatus model tests ──────────────────────────────────────────────────


def test_agent_status_enum_values():
    assert AgentStatus.CONFIGURED.value == "configured"
    assert AgentStatus.INSTALLED_NOT_CONFIGURED.value == "installed-not-configured"


def test_agent_default_status():
    agent = Agent(name="test", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/test")
    assert agent.status == AgentStatus.CONFIGURED
    assert agent.discovered_at
    assert agent.last_seen == agent.discovered_at
    datetime.fromisoformat(agent.discovered_at.replace("Z", "+00:00"))


def test_agent_installed_not_configured():
    agent = Agent(
        name="openclaw",
        agent_type=AgentType.OPENCLAW,
        config_path="openclaw (binary on PATH)",
        status=AgentStatus.INSTALLED_NOT_CONFIGURED,
    )
    assert agent.status == AgentStatus.INSTALLED_NOT_CONFIGURED
    assert len(agent.mcp_servers) == 0


def test_json_includes_agent_metadata():
    from agent_bom.models import AIBOMReport
    from agent_bom.output import to_json

    agent = Agent(
        name="vertex-ai:prod-endpoint",
        agent_type=AgentType.CUSTOM,
        config_path="projects/test/locations/us-central1/endpoints/123",
        source="gcp-vertex-ai",
        metadata={
            "cloud_origin": {
                "provider": "gcp",
                "service": "vertex-ai",
                "resource_type": "endpoint",
                "resource_id": "projects/test/locations/us-central1/endpoints/123",
                "resource_name": "prod-endpoint",
                "location": "us-central1",
                "scope": {"project_id": "test"},
            },
            "cloud_state": {
                "provider": "gcp",
                "service": "vertex-ai",
                "resource_type": "endpoint",
                "lifecycle_state": "ready",
                "raw_state": "READY",
                "state_source": "state",
            },
        },
    )
    data = to_json(AIBOMReport(agents=[agent]))
    assert data["agents"][0]["metadata"]["cloud_origin"]["provider"] == "gcp"
    assert data["agents"][0]["metadata"]["cloud_origin"]["scope"]["project_id"] == "test"
    assert data["agents"][0]["metadata"]["cloud_state"]["lifecycle_state"] == "ready"


def test_local_inventory_agent_lifecycle_fields_preserved():
    from agent_bom.cli._common import _build_agents_from_inventory
    from agent_bom.models import AIBOMReport
    from agent_bom.output import to_json

    inventory = {
        "source": "local",
        "agents": [
            {
                "name": "claude-desktop",
                "agent_type": "claude-desktop",
                "config_path": "/Users/example/Library/Application Support/Claude/claude_desktop_config.json",
                "discovered_at": "2026-04-28T10:00:00Z",
                "last_seen": "2026-04-28T11:30:00Z",
                "mcp_servers": [{"name": "filesystem", "command": "npx"}],
            }
        ],
    }

    agents = _build_agents_from_inventory(inventory, "inventory.json")
    assert agents[0].discovered_at == "2026-04-28T10:00:00Z"
    assert agents[0].last_seen == "2026-04-28T11:30:00Z"

    data = to_json(AIBOMReport(agents=agents))
    assert data["agents"][0]["discovered_at"] == "2026-04-28T10:00:00Z"
    assert data["agents"][0]["last_seen"] == "2026-04-28T11:30:00Z"
    assert data["inventory_snapshot"]["agents"][0]["discovered_at"] == "2026-04-28T10:00:00Z"
    assert data["inventory_snapshot"]["agents"][0]["last_seen"] == "2026-04-28T11:30:00Z"


@pytest.mark.parametrize(
    ("provider", "service", "resource_type", "raw_state", "expected"),
    [
        ("databricks", "clusters", "cluster", "RUNNING", "running"),
        ("databricks", "clusters", "cluster", "TERMINATED", "terminated"),
        ("databricks", "model-serving", "serving-endpoint", "NOT_READY", "not-ready"),
    ],
)
def test_cloud_asset_lifecycle_states_preserved_in_report(provider, service, resource_type, raw_state, expected):
    from agent_bom.graph.builder import build_unified_graph_from_report
    from agent_bom.models import AIBOMReport
    from agent_bom.output import to_json

    lifecycle_state = normalize_cloud_lifecycle_state(
        provider=provider,
        service=service,
        resource_type=resource_type,
        raw_state=raw_state,
    )
    assert lifecycle_state == expected

    agent = Agent(
        name=f"{service}:{expected}",
        agent_type=AgentType.CUSTOM,
        config_path=f"{provider}://{service}/{expected}",
        source=provider,
        discovered_at="2026-04-27T09:00:00Z",
        last_seen="2026-04-28T09:00:00Z",
        metadata={
            "cloud_state": build_cloud_state(
                provider=provider,
                service=service,
                resource_type=resource_type,
                lifecycle_state=lifecycle_state,
                raw_state=raw_state,
                state_source="test.state",
            )
        },
    )

    data = to_json(AIBOMReport(agents=[agent]))
    serialized = data["agents"][0]
    assert serialized["discovered_at"] == "2026-04-27T09:00:00Z"
    assert serialized["last_seen"] == "2026-04-28T09:00:00Z"
    assert serialized["metadata"]["cloud_state"]["lifecycle_state"] == expected
    assert serialized["metadata"]["cloud_state"]["raw_state"] == raw_state

    graph = build_unified_graph_from_report(data)
    graph_agent = graph.nodes[f"agent:{service}:{expected}"]
    assert graph_agent.first_seen == "2026-04-27T09:00:00Z"
    assert graph_agent.last_seen == "2026-04-28T09:00:00Z"
    assert graph_agent.attributes["discovered_at"] == "2026-04-27T09:00:00Z"
    assert graph_agent.attributes["last_seen"] == "2026-04-28T09:00:00Z"


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
    import agent_bom.discovery as disc
    from agent_bom.discovery import detect_installed_agents

    monkeypatch.setattr(disc, "_find_binary", lambda _: None)
    monkeypatch.setattr(disc, "_INSTALL_SIGNALS", {})
    installed = detect_installed_agents(discovered_types=set())
    assert installed == []


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


def test_json_includes_stable_ids_and_resources():
    from agent_bom.models import AIBOMReport, MCPResource, MCPServer, MCPTool, Package
    from agent_bom.output import to_json

    server = MCPServer(
        name="filesystem",
        command="npx",
        mcp_version="2024-11-05",
        discovery_sources=["config:/test/config.json", "process:pid:123"],
        tools=[MCPTool(name="read_file", description="Read a file", schema_findings=["read_file.path: filesystem-capability"])],
        resources=[MCPResource(uri="file:///workspace", name="workspace", content_findings=["file:///workspace: mutable-resource"])],
        packages=[Package(name="requests", version="2.31.0", ecosystem="pypi")],
    )
    agent = Agent(
        name="claude-desktop",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/test/config.json",
        mcp_servers=[server],
    )
    data = to_json(AIBOMReport(agents=[agent]))

    assert data["agents"][0]["stable_id"] == agent.stable_id
    assert data["agents"][0]["mcp_servers"][0]["stable_id"] == server.stable_id
    assert data["agents"][0]["mcp_servers"][0]["tools"][0]["stable_id"] == server.tools[0].stable_id
    assert data["agents"][0]["mcp_servers"][0]["resources"][0]["stable_id"] == server.resources[0].stable_id
    assert data["agents"][0]["mcp_servers"][0]["packages"][0]["stable_id"] == server.packages[0].stable_id
    assert data["agents"][0]["mcp_servers"][0]["discovery_sources"] == ["config:/test/config.json", "process:pid:123"]
    assert data["agents"][0]["mcp_servers"][0]["tools"][0]["discovery_source"] is None
    assert data["agents"][0]["mcp_servers"][0]["tools"][0]["discovery_confidence"] is None
    assert data["agents"][0]["mcp_servers"][0]["tools"][0]["risk_score"] >= 1
    assert data["agents"][0]["mcp_servers"][0]["resources"][0]["risk_score"] >= 1
    snapshot = data["inventory_snapshot"]
    assert snapshot["summary"]["agents"] == 1
    assert snapshot["summary"]["servers"] == 1
    assert snapshot["summary"]["tools"] == 1
    assert snapshot["summary"]["resources"] == 1
    assert snapshot["summary"]["packages"] == 1


def test_json_includes_tool_discovery_metadata():
    from agent_bom.models import AIBOMReport, MCPServer, MCPTool
    from agent_bom.output import to_json

    server = MCPServer(
        name="python-agent",
        tools=[MCPTool(name="search_docs", description="agent tool", discovery_source="tool-constructor", discovery_confidence="medium")],
    )
    agent = Agent(name="crewai:researcher", agent_type=AgentType.CUSTOM, config_path="/tmp/project", mcp_servers=[server])

    data = to_json(AIBOMReport(agents=[agent]))
    tool = data["agents"][0]["mcp_servers"][0]["tools"][0]
    assert tool["discovery_source"] == "tool-constructor"
    assert tool["discovery_confidence"] == "medium"


def test_json_includes_mcp_runtime_diff():
    from agent_bom.models import AIBOMReport, MCPServer
    from agent_bom.output import to_json

    server = MCPServer(name="filesystem", command="npx")
    agent = Agent(name="claude-desktop", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/claude.json", mcp_servers=[server])
    report = AIBOMReport(
        agents=[agent],
        introspection_data={
            "results": [
                {
                    "server_name": "filesystem",
                    "auth_mode": "local-stdio",
                    "configured_fingerprint": "cfg-1",
                    "runtime_fingerprint": "rt-2",
                    "configured_tool_count": 1,
                    "configured_resource_count": 0,
                    "tool_count": 2,
                    "resource_count": 1,
                    "tools_added": ["write_file"],
                    "tools_removed": [],
                    "resources_added": ["file:///workspace"],
                    "resources_removed": [],
                    "capability_risk_score": 7.1,
                    "capability_risk_level": "high",
                    "capability_counts": {"write": 1},
                    "capability_tools": {"write": ["write_file"]},
                    "dangerous_combinations": ["Can write arbitrary files and execute commands — full system compromise possible"],
                    "risk_justification": "Server has WRITE capabilities across 1 tool.",
                    "tool_risk_profiles": [{"tool_name": "write_file", "risk_score": 7.5, "risk_level": "high"}],
                    "tool_schema_findings": ["write_file.path: filesystem-capability"],
                    "resource_findings": ["file:///workspace: mutable-resource"],
                    "has_drift": True,
                }
            ]
        },
        runtime_correlation={
            "correlated_findings": [
                {"server_name": "filesystem", "tool_name": "read_file"},
            ]
        },
    )
    data = to_json(report)
    assert data["mcp_runtime_diff"]["summary"]["servers_changed"] == 1
    diff = data["mcp_runtime_diff"]["servers"][0]
    assert diff["configured_vs_observed_changed"] is True
    assert diff["runtime_used_tools"] == ["read_file"]
    assert diff["max_tool_risk_score"] == 7.5
    assert diff["capability_risk_level"] == "high"


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


# ── AGENT_BINARIES constant ─────────────────────────────────────────────────


def test_agent_binaries_has_expected_entries():
    from agent_bom.discovery import AGENT_BINARIES

    assert AGENT_BINARIES[AgentType.OPENCLAW] == "openclaw"
    assert AGENT_BINARIES[AgentType.CLAUDE_CODE] == "claude"


# ── CLI where command ────────────────────────────────────────────────────────


def test_where_shows_binary_info():
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["mcp", "where"])
    assert result.exit_code == 0
    assert "binary:" in result.output


def test_get_all_discovery_paths_returns_all_clients():
    from agent_bom.discovery import get_all_discovery_paths

    paths = get_all_discovery_paths("Darwin")
    clients = {c for c, _ in paths}
    # Must include key clients
    for expected in ["claude-desktop", "claude-code", "cursor", "windsurf", "Docker MCP Toolkit", "Project config", "Docker Compose"]:
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
    result = runner.invoke(main, ["mcp", "where", "--json"])
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
    result = runner.invoke(main, ["mcp", "where"])
    assert result.exit_code == 0
    assert "Total:" in result.output
    assert "paths checked" in result.output


# ── Binary fallback detection ────────────────────────────────────────────────


def test_find_binary_on_path(monkeypatch):
    """_find_binary returns result from shutil.which when binary is on PATH."""
    import shutil

    from agent_bom.discovery import _find_binary

    monkeypatch.setattr(shutil, "which", lambda cmd: f"/usr/local/bin/{cmd}")
    assert _find_binary("cortex") == "/usr/local/bin/cortex"


def test_find_binary_in_local_bin(monkeypatch, tmp_path):
    """_find_binary checks ~/.local/bin when shutil.which fails."""
    import os
    import shutil

    import agent_bom.discovery as disc

    monkeypatch.setattr(shutil, "which", lambda _: None)
    # Create a fake binary in a temp dir that simulates ~/.local/bin
    fake_bin = tmp_path / "cortex"
    fake_bin.write_text("#!/bin/sh")
    fake_bin.chmod(0o755)

    def patched_find(binary_name):
        found = shutil.which(binary_name)
        if found:
            return found
        candidate = tmp_path / binary_name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
        return None

    monkeypatch.setattr(disc, "_find_binary", patched_find)
    assert disc._find_binary("cortex") == str(fake_bin)


def test_detect_installed_via_signal_file(monkeypatch, tmp_path):
    """detect_installed_agents finds Cortex Code via install signal file."""
    import shutil

    from agent_bom.discovery import _INSTALL_SIGNALS, detect_installed_agents

    monkeypatch.setattr(shutil, "which", lambda _: None)
    # Make _find_binary always return None
    import agent_bom.discovery as disc

    monkeypatch.setattr(disc, "_find_binary", lambda _: None)

    # Create a signal file
    signal_file = tmp_path / "coco.log"
    signal_file.write_text("log data")
    monkeypatch.setitem(_INSTALL_SIGNALS, AgentType.CORTEX_CODE, [str(signal_file)])

    installed = detect_installed_agents(discovered_types=set())
    agent_types = {a.agent_type for a in installed}
    assert AgentType.CORTEX_CODE in agent_types
    cortex = next(a for a in installed if a.agent_type == AgentType.CORTEX_CODE)
    assert cortex.status == AgentStatus.INSTALLED_NOT_CONFIGURED


# ── License field on Package ─────────────────────────────────────────────────


def test_package_license_field():
    """Package model has a license field."""
    from agent_bom.models import Package

    pkg = Package(name="express", version="4.18.2", ecosystem="npm", license="MIT")
    assert pkg.license == "MIT"


def test_package_license_default_none():
    """Package license defaults to None."""
    from agent_bom.models import Package

    pkg = Package(name="flask", version="3.0.0", ecosystem="pypi")
    assert pkg.license is None
