"""Tests for agent spawn tree visualization."""

from agent_bom.output.agent_mesh import build_spawn_tree


def test_parent_child_edges():
    agents = [
        {"name": "eve", "agent_type": "custom", "parent_agent": None, "mcp_servers": []},
        {"name": "genbot-1", "agent_type": "custom", "parent_agent": "eve", "mcp_servers": []},
        {"name": "genbot-2", "agent_type": "custom", "parent_agent": "eve", "mcp_servers": []},
    ]
    result = build_spawn_tree(agents)
    edges = result["edges"]
    delegation_edges = [e for e in edges if e.get("data", {}).get("edgeType") == "delegation"]
    assert len(delegation_edges) == 2
    sources = {e["source"] for e in delegation_edges}
    assert all("eve" in s for s in sources)


def test_orphan_agents():
    agents = [
        {"name": "standalone", "agent_type": "claude-desktop", "mcp_servers": []},
    ]
    result = build_spawn_tree(agents)
    assert len(result["nodes"]) == 1
    assert len(result["edges"]) == 0


def test_mixed_hierarchy():
    agents = [
        {"name": "root", "agent_type": "custom", "parent_agent": None, "mcp_servers": []},
        {"name": "child", "agent_type": "custom", "parent_agent": "root", "mcp_servers": []},
        {"name": "orphan", "agent_type": "cursor", "mcp_servers": []},
    ]
    result = build_spawn_tree(agents)
    assert len(result["nodes"]) == 3
    delegation_edges = [e for e in result["edges"] if e.get("data", {}).get("edgeType") == "delegation"]
    assert len(delegation_edges) == 1


def test_empty_agents():
    result = build_spawn_tree([])
    assert result["nodes"] == []
    assert result["edges"] == []
