"""Graph agent population matches the report's canonical agent identity."""

from __future__ import annotations

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType, RelationshipType


def _framework_agent(stable_id: str, name: str, *, edges: list[dict] | None = None) -> dict:
    return {
        "stable_id": stable_id,
        "kind": "framework_agent",
        "framework": "langchain",
        "name": name,
        "file_path": "app/agent.py",
        "line_number": 11,
        "confidence": "high",
        "capabilities": [{"name": "lookup", "source": "decorator"}],
        "model_refs": ["gpt-4o"],
        "credential_refs": [],
        "topology_edges": edges or [],
        "dynamic_edges": False,
    }


def _project_report(framework_agents: list[dict]) -> dict:
    return {
        "scan_id": "scan-project-identity",
        "agents": [
            {
                "name": "project:sampleapp",
                "agent_type": "custom",
                "source": "project",
                "config_path": "/work/sampleapp",
                "metadata": {"project_root": "/work/sampleapp", "evidence_sources": ["project", "project-config"]},
                "mcp_servers": [
                    {
                        "name": "github",
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github"],
                        "surface": "mcp-server",
                        "packages": [],
                        "tools": [],
                    },
                    {"name": "app", "command": "project", "args": ["/work/sampleapp/app"], "surface": "other", "packages": []},
                ],
            }
        ],
        "blast_radius": [],
        "ai_inventory": {"framework_agents": framework_agents},
    }


def _agent_ids(graph) -> list[str]:
    return sorted(node.id for node in graph.nodes.values() if node.entity_type == EntityType.AGENT)


def test_code_level_agent_constructs_fold_into_the_project_agent() -> None:
    graph = build_unified_graph_from_report(
        _project_report([_framework_agent("fa-agent", "agent"), _framework_agent("fa-executor", "executor")])
    )

    assert _agent_ids(graph) == ["agent:project:sampleapp"]
    host = graph.nodes["agent:project:sampleapp"]
    assert [item["name"] for item in host.attributes["code_agents"]] == ["agent", "executor"]
    framework_edges = [
        edge for edge in graph.edges if edge.source == "agent:project:sampleapp" and edge.relationship == RelationshipType.USES_FRAMEWORK
    ]
    assert len(framework_edges) == 1
    model_edges = [
        edge for edge in graph.edges if edge.source == "agent:project:sampleapp" and edge.relationship == RelationshipType.SERVES_MODEL
    ]
    assert len(model_edges) == 1


def test_multi_agent_topology_participants_stay_distinct_agents() -> None:
    delegation = {
        "source_id": "fa-crew",
        "source_name": "crew",
        "target_id": "fa-researcher",
        "target_name": "Researcher",
        "relationship": "delegated_to",
        "framework": "crewai",
    }
    graph = build_unified_graph_from_report(
        _project_report(
            [
                _framework_agent("fa-crew", "crew", edges=[delegation]),
                _framework_agent("fa-researcher", "Researcher"),
                _framework_agent("fa-helper", "helper"),
            ]
        )
    )

    assert _agent_ids(graph) == ["agent:project:sampleapp", "fa-crew", "fa-researcher"]
    assert [item["name"] for item in graph.nodes["agent:project:sampleapp"].attributes["code_agents"]] == ["helper"]


def test_framework_agents_without_a_project_host_keep_their_nodes() -> None:
    report = _project_report([_framework_agent("fa-agent", "agent")])
    report["agents"] = []

    graph = build_unified_graph_from_report(report)

    assert _agent_ids(graph) == ["fa-agent"]
