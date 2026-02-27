"""Tests for agent detail and lifecycle API endpoints."""

from unittest.mock import patch

from starlette.testclient import TestClient

from agent_bom.api.server import app
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package


def _mock_agents():
    """Return a list with one test agent for mocking discover_all."""
    srv = MCPServer(
        name="test-server",
        command="npx",
        args=["-y", "test-server"],
        env={"API_KEY": "sk-test", "DEBUG": "1"},
        packages=[
            Package(name="express", version="4.18.2", ecosystem="npm"),
        ],
        tools=[
            MCPTool(name="read_file", description="Read file contents"),
            MCPTool(name="write_file", description="Write file contents"),
        ],
    )
    return [
        Agent(
            name="test-agent",
            agent_type=AgentType.CLAUDE_DESKTOP,
            config_path="/tmp/test-config.json",
            mcp_servers=[srv],
        ),
    ]


@patch("agent_bom.discovery.discover_all", side_effect=_mock_agents)
def test_agent_detail_found(_mock):
    """GET /v1/agents/{name} returns 200 with agent detail."""
    client = TestClient(app)
    resp = client.get("/v1/agents/test-agent")
    assert resp.status_code == 200
    data = resp.json()
    assert data["agent"]["name"] == "test-agent"
    assert data["summary"]["total_servers"] == 1
    assert data["summary"]["total_tools"] == 2
    assert data["summary"]["total_credentials"] >= 1
    assert "blast_radius" in data
    assert "credentials" in data


@patch("agent_bom.discovery.discover_all", return_value=[])
def test_agent_detail_not_found(_mock):
    """GET /v1/agents/{name} returns 404 for unknown agent."""
    client = TestClient(app)
    resp = client.get("/v1/agents/nonexistent-agent")
    assert resp.status_code == 404


@patch("agent_bom.discovery.discover_all", side_effect=_mock_agents)
def test_agent_lifecycle_nodes_edges(_mock):
    """GET /v1/agents/{name}/lifecycle returns React Flow graph structure."""
    client = TestClient(app)
    resp = client.get("/v1/agents/test-agent/lifecycle")
    assert resp.status_code == 200
    data = resp.json()
    assert "nodes" in data
    assert "edges" in data
    assert "stats" in data
    # Should have at least: agent + server + 2 tools + 1 credential + 1 package = 6 nodes
    assert len(data["nodes"]) >= 5
    assert len(data["edges"]) >= 4
    # Check node types
    node_types = {n["data"]["nodeType"] for n in data["nodes"]}
    assert "agent" in node_types
    assert "server" in node_types
    assert "tool" in node_types
    assert "package" in node_types


@patch("agent_bom.discovery.discover_all", return_value=[])
def test_agent_lifecycle_not_found(_mock):
    """GET /v1/agents/{name}/lifecycle returns 404 for unknown agent."""
    client = TestClient(app)
    resp = client.get("/v1/agents/nonexistent-agent/lifecycle")
    assert resp.status_code == 404


@patch("agent_bom.discovery.discover_all", side_effect=_mock_agents)
def test_agent_detail_credential_detection(_mock):
    """Agent detail correctly identifies credential env vars."""
    client = TestClient(app)
    resp = client.get("/v1/agents/test-agent")
    data = resp.json()
    # API_KEY should be detected as credential, DEBUG should not
    assert "API_KEY" in data["credentials"]
    assert "DEBUG" not in data["credentials"]


@patch("agent_bom.discovery.discover_all", side_effect=_mock_agents)
def test_agent_lifecycle_edge_structure(_mock):
    """Lifecycle edges have correct source/target and styling."""
    client = TestClient(app)
    resp = client.get("/v1/agents/test-agent/lifecycle")
    data = resp.json()
    # All edges should have required fields
    for edge in data["edges"]:
        assert "id" in edge
        assert "source" in edge
        assert "target" in edge
        assert "type" in edge
        assert edge["type"] == "smoothstep"
