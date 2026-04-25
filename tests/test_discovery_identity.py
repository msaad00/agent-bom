from __future__ import annotations

from agent_bom.discovery.identity import deduplicate_discovered_agents, server_identity_key
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, TransportType


def _agent(name: str, source: str, server: MCPServer) -> Agent:
    return Agent(
        name=name,
        agent_type=AgentType.CUSTOM,
        config_path=f"{source}://agent",
        source=source,
        mcp_servers=[server],
    )


def test_process_and_config_server_collapse_by_command_identity() -> None:
    configured = MCPServer(
        name="filesystem",
        command="npx",
        args=["@modelcontextprotocol/server-filesystem", "/workspace"],
        config_path="/home/user/.config/claude/mcp.json",
        tools=[MCPTool(name="read_file", description="Read files")],
    )
    process = MCPServer(
        name="server-filesystem",
        command="/usr/local/bin/npx",
        args=["@modelcontextprotocol/server-filesystem", "/workspace"],
        config_path="pid:4242",
        tools=[MCPTool(name="write_file", description="Write files")],
    )

    merged = deduplicate_discovered_agents([_agent("config", "config", configured), _agent("process", "process", process)])

    assert len(merged) == 1
    assert len(merged[0].mcp_servers) == 1
    server = merged[0].mcp_servers[0]
    assert {tool.name for tool in server.tools} == {"read_file", "write_file"}
    assert server.discovery_sources == ["config:/home/user/.config/claude/mcp.json", "process:pid:4242"]


def test_config_and_kubernetes_server_collapse_by_url_identity() -> None:
    configured = MCPServer(
        name="remote-docs",
        transport=TransportType.SSE,
        url="https://mcp.example.com/sse/",
        config_path="/home/user/.cursor/mcp.json",
    )
    k8s = MCPServer(
        name="prod/docs-mcp",
        transport=TransportType.SSE,
        url="https://mcp.example.com/sse",
        config_path="k8s://prod/docs-mcp",
    )

    merged = deduplicate_discovered_agents([_agent("config", "config", configured), _agent("k8s", "kubernetes", k8s)])

    assert len(merged) == 1
    assert merged[0].mcp_servers[0].discovery_sources == [
        "config:/home/user/.cursor/mcp.json",
        "kubernetes:k8s://prod/docs-mcp",
    ]


def test_distinct_servers_remain_distinct() -> None:
    first = MCPServer(name="fs", command="npx", args=["@modelcontextprotocol/server-filesystem", "/workspace"])
    second = MCPServer(name="github", command="npx", args=["@modelcontextprotocol/server-github"])

    merged = deduplicate_discovered_agents([_agent("a", "config", first), _agent("b", "process", second)])

    assert sum(len(agent.mcp_servers) for agent in merged) == 2
    assert server_identity_key(first) != server_identity_key(second)
