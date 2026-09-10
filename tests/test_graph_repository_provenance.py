"""Manifest inventory must preserve dependencies without inventing MCP topology."""

from copy import deepcopy

import pytest

from agent_bom.graph import EntityType, RelationshipType
from agent_bom.graph.builder import build_unified_graph_from_report


def _report(source="project"):
    return {
        "scan_id": "repo-provenance",
        "agents": [
            {
                "name": "project:repo" if source == "project" else "repo-deps:root",
                "source": source,
                "type": "custom",
                "config_path": "/repo",
                "mcp_servers": [
                    {
                        "name": "repo",
                        "command": "project" if source == "project" else "",
                        "surface": "other" if source == "project" else "filesystem",
                        "packages": [
                            {
                                "name": "flask",
                                "version": "2.0.0",
                                "ecosystem": "pypi",
                                "vulnerabilities": [{"id": "CVE-2025-0001", "severity": "high"}],
                            }
                        ],
                    }
                ],
            }
        ],
    }


@pytest.mark.parametrize("source", ["project", "repo-lockfiles"])
def test_repository_inventory_keeps_package_vulnerability_path_without_runtime_claims(source):
    report = _report(source)
    report["agents"][0]["mcp_servers"][0].update(tools=[{"name": "shell"}], credential_env_vars=["API_TOKEN"])
    graph = build_unified_graph_from_report(report)
    assert not any(
        n.entity_type in {EntityType.AGENT, EntityType.SERVER, EntityType.PROVIDER, EntityType.TOOL, EntityType.CREDENTIAL}
        for n in graph.nodes.values()
    )
    assert any(n.entity_type == EntityType.DIRECTORY for n in graph.nodes.values())
    assert all(n.data_sources == [source] for n in graph.nodes.values())
    package = next(n for n in graph.nodes.values() if n.entity_type == EntityType.PACKAGE)
    assert any(e.target == package.id and graph.nodes[e.source].entity_type == EntityType.DIRECTORY for e in graph.edges)
    assert any(e.source == package.id and e.target == "vuln:CVE-2025-0001" for e in graph.edges)
    assert not any(
        e.relationship in {RelationshipType.USES, RelationshipType.SHARES_SERVER, RelationshipType.EXPLOITABLE_VIA} for e in graph.edges
    )


@pytest.mark.parametrize("reverse", [False, True])
def test_repository_and_real_mcp_with_same_label_stay_distinct(reverse):
    report = _report()
    runtime = deepcopy(report["agents"][0])
    runtime["source"] = "local"
    runtime["mcp_servers"][0].update(surface="mcp-server", command="uvx", tools=[{"name": "read"}])
    report["agents"].append(runtime)
    if reverse:
        report["agents"].reverse()
    graph = build_unified_graph_from_report(report)
    assert sum(n.entity_type == EntityType.AGENT for n in graph.nodes.values()) == 1
    assert sum(n.entity_type == EntityType.SERVER for n in graph.nodes.values()) == 1
    assert any(n.entity_type == EntityType.TOOL for n in graph.nodes.values())
    assert not any(e.relationship == RelationshipType.SHARES_SERVER for e in graph.edges)


def test_project_source_does_not_override_real_mcp_surface():
    report = _report()
    report["agents"][0]["mcp_servers"][0].update(surface="mcp-server", command="uvx")
    graph = build_unified_graph_from_report(report)
    assert any(n.entity_type == EntityType.AGENT for n in graph.nodes.values())
    assert any(n.entity_type == EntityType.SERVER for n in graph.nodes.values())


def test_repository_graph_roundtrip_retains_types_and_tenant(tmp_path):
    from agent_bom.db import graph_store

    graph = build_unified_graph_from_report(_report(), tenant_id="repo-tenant")
    with graph_store.open_graph_db(tmp_path / "graph.db") as conn:
        graph_store.save_graph(conn, graph)
        restored = graph_store.load_graph(conn, scan_id=graph.scan_id, tenant_id="repo-tenant")
        other = graph_store.load_graph(conn, scan_id=graph.scan_id, tenant_id="other")
    assert restored is not None
    assert not any(n.entity_type in {EntityType.AGENT, EntityType.SERVER} for n in restored.nodes.values())
    assert len(restored.nodes) == len(graph.nodes)
    assert len(restored.edges) == len(graph.edges)
    assert other is None or not other.nodes
