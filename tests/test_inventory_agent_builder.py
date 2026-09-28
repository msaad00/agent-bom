"""Characterization of inventory → Agent construction shared by the CLI and API."""

from __future__ import annotations

import pytest

from agent_bom.models import AgentType, TransportType

_INVENTORY = {
    "source": "cmdb-export",
    "discovery_provenance": {"source_type": "operator_pushed_inventory", "collector": "inventory"},
    "agents": [
        {
            "name": "fleet-agent",
            "type": "internal-lab-agent",
            "version": "1.2.3",
            "source_id": "cmdb-42",
            "device_fingerprint": "fp-1",
            "first_seen": "2026-01-01T00:00:00Z",
            "last_seen_at": "2026-02-01T00:00:00Z",
            "metadata": {"owner": "platform", "api_key": "sk-" + "live-abcdefghijklmnopqrstuvwxyz0123"},
            "mcp_servers": [
                {
                    "name": "remote",
                    "transport": "sse",
                    "url": "https://mcp.example.test/sse",
                    "command": "",
                    "env": {"OPENAI_API_KEY": "sk-real-secret-value-123456", "LOG_LEVEL": "debug"},
                    "security_blocked": 1,
                    "security_warnings": ["pinned"],
                    "security_intelligence": [{"source": "feed", "matched_value": "remote"}, "not-a-dict"],
                    "mcp_version": "2025-06-18",
                    "working_dir": "/srv",
                    "tools": ["plain", {"name": "rich", "description": "d", "input_schema": {"type": "object"}}, 7],
                    "packages": [
                        "left-pad@1.3.0",
                        "@scope/pkg@2.0.0",
                        "bare",
                        {"name": "requests", "version": "2.31.0", "ecosystem": "pypi", "purl": "pkg:pypi/requests@2.31.0"},
                        {"name": "noversion"},
                        42,
                    ],
                }
            ],
        },
        {"name": "minimal", "agent_type": "claude-desktop", "mcp_servers": []},
    ],
}


def _builders():
    from agent_bom.cli import _build_agents_from_inventory as package_alias
    from agent_bom.cli._common import _build_agents_from_inventory as cli_alias
    from agent_bom.inventory import build_agents_from_inventory

    return [build_agents_from_inventory, cli_alias, package_alias]


@pytest.mark.parametrize("builder", _builders())
def test_inventory_builder_characterization(builder):
    agents = builder(_INVENTORY, "/fleet.json")

    assert [agent.name for agent in agents] == ["fleet-agent", "minimal"]
    fleet, minimal = agents
    assert fleet.agent_type is AgentType.CUSTOM
    assert minimal.agent_type is AgentType("claude-desktop")
    assert fleet.config_path == "/fleet.json"
    assert fleet.version == "1.2.3"
    assert fleet.source == "cmdb-export"
    assert fleet.source_id == "cmdb-42"
    assert fleet.device_fingerprint == "fp-1"
    assert fleet.discovered_at == "2026-01-01T00:00:00Z"
    assert fleet.last_seen == "2026-02-01T00:00:00Z"
    assert minimal.discovered_at  # model default fills an unset timestamp
    assert fleet.metadata["owner"] == "platform"
    assert "sk-live-abcdefghijklmnopqrstuvwxyz0123" not in str(fleet.metadata)
    assert fleet.discovery_provenance["source_type"] == "operator_pushed_inventory"

    server = fleet.mcp_servers[0]
    assert server.transport is TransportType.SSE
    assert server.url == "https://mcp.example.test/sse"
    assert server.config_path is None
    assert server.working_dir == "/srv"
    assert server.mcp_version == "2025-06-18"
    assert server.security_blocked is True
    assert server.security_warnings == ["pinned"]
    assert len(server.security_intelligence) == 1
    assert server.env["LOG_LEVEL"] == "debug"
    assert server.env["OPENAI_API_KEY"] != "sk-real-secret-value-123456"
    assert [(tool.name, tool.description, tool.input_schema) for tool in server.tools] == [
        ("plain", "", None),
        ("rich", "d", {"type": "object"}),
    ]
    assert [(pkg.name, pkg.version, pkg.ecosystem, pkg.purl) for pkg in server.packages] == [
        ("left-pad", "1.3.0", "unknown", None),
        ("@scope/pkg", "2.0.0", "unknown", None),
        ("bare", "unknown", "unknown", None),
        ("requests", "2.31.0", "pypi", "pkg:pypi/requests@2.31.0"),
        ("noversion", "unknown", "unknown", None),
    ]
    assert server.packages[0].discovery_provenance == server.discovery_provenance


def test_cli_and_api_share_one_inventory_builder():
    import agent_bom.cli._common as cli_common
    from agent_bom.inventory import build_agents_from_inventory, coerce_agent_type_for_inventory

    assert cli_common._build_agents_from_inventory is build_agents_from_inventory
    assert cli_common._coerce_agent_type_for_inventory is coerce_agent_type_for_inventory


def test_api_inventory_paths_use_the_neutral_builder(monkeypatch):
    from agent_bom.api.routes import discovery

    monkeypatch.setattr("agent_bom.demo_estate.bootstrap.demo_estate_enabled", lambda: True)
    agents = discovery._discover_agents_with_demo_fallback()
    assert agents
    assert all(agent.config_path for agent in agents)
