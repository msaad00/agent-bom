"""Without a cloud containment tree the roll-up groups by agent.

A local project scan has no org/account containment, so every node used to be a
top-level orphan: the agent card said ``severity: critical`` while its aggregate
said ``worst_severity: none`` because nothing rolled up beneath it. The agent's
MCP servers, their packages, tools, credentials, and the packages'
vulnerabilities are the agent's subtree.
"""

from __future__ import annotations

import pytest

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.rollup import drill_down, rollup_view


def _agent_stack(scan_id: str = "local-scan") -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id="default")
    nodes = [
        UnifiedNode(id="agent:project:sampleapp", entity_type=EntityType.AGENT, label="project:sampleapp", severity="critical"),
        UnifiedNode(id="server:github", entity_type=EntityType.SERVER, label="github"),
        UnifiedNode(id="server:filesystem", entity_type=EntityType.SERVER, label="filesystem"),
        UnifiedNode(id="cred:GITHUB_PERSONAL_ACCESS_TOKEN", entity_type=EntityType.CREDENTIAL, label="GITHUB_PERSONAL_ACCESS_TOKEN"),
        UnifiedNode(id="tool:create_issue", entity_type=EntityType.TOOL, label="create_issue"),
        UnifiedNode(id="pkg:npm:form-data@4.0.0", entity_type=EntityType.PACKAGE, label="form-data@4.0.0"),
        UnifiedNode(id="vuln:CVE-2025-7783", entity_type=EntityType.VULNERABILITY, label="CVE-2025-7783", severity="critical"),
        UnifiedNode(id="provider:local", entity_type=EntityType.PROVIDER, label="local"),
    ]
    for node in nodes:
        graph.add_node(node)
    for source, target, rel in (
        ("agent:project:sampleapp", "server:github", RelationshipType.USES),
        ("agent:project:sampleapp", "server:filesystem", RelationshipType.USES),
        ("server:github", "cred:GITHUB_PERSONAL_ACCESS_TOKEN", RelationshipType.EXPOSES_CRED),
        ("server:github", "tool:create_issue", RelationshipType.PROVIDES_TOOL),
        ("server:github", "pkg:npm:form-data@4.0.0", RelationshipType.DEPENDS_ON),
        ("server:filesystem", "pkg:npm:form-data@4.0.0", RelationshipType.DEPENDS_ON),
        ("pkg:npm:form-data@4.0.0", "vuln:CVE-2025-7783", RelationshipType.VULNERABLE_TO),
        ("provider:local", "agent:project:sampleapp", RelationshipType.HOSTS),
    ):
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=rel))
    return graph


def _entry(payload: dict, node_id: str) -> dict:
    return next(item for item in payload["top_level"] if item["id"] == node_id)


def test_agent_is_a_container_whose_aggregate_matches_its_severity() -> None:
    payload = rollup_view(_agent_stack())

    agent = _entry(payload, "agent:project:sampleapp")
    assert agent["is_container"] is True
    assert agent["direct_child_count"] == 2
    assert agent["aggregate"]["descendant_count"] == 6
    assert agent["aggregate"]["worst_severity"] == "critical"
    assert agent["severity"] == agent["aggregate"]["worst_severity"]
    top_ids = {item["id"] for item in payload["top_level"]}
    assert not top_ids & {"server:github", "pkg:npm:form-data@4.0.0", "vuln:CVE-2025-7783", "cred:GITHUB_PERSONAL_ACCESS_TOKEN"}
    assert payload["summary"]["container_count"] >= 1


def test_no_top_level_entry_claims_a_severity_its_subtree_does_not_hold() -> None:
    payload = rollup_view(_agent_stack())

    for item in payload["top_level"]:
        if item["has_children"] and item["severity"]:
            assert item["aggregate"]["worst_severity"] == item["severity"], item["id"]


def test_drilling_into_the_agent_returns_its_servers() -> None:
    payload = drill_down(_agent_stack(), "agent:project:sampleapp")

    assert sorted(child["id"] for child in payload["children"]) == ["server:filesystem", "server:github"]


def test_rest_drill_down_walks_the_agent_stack(tmp_path, monkeypatch) -> None:
    pytest.importorskip("fastapi", reason="fastapi not installed")
    from fastapi.testclient import TestClient

    from agent_bom.api import stores
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.server import app
    from agent_bom.api.store import InMemoryJobStore

    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_agent_stack())
    monkeypatch.setattr(stores, "_store", InMemoryJobStore())
    monkeypatch.setattr(stores, "_graph_store", store)
    client = TestClient(app)
    top = client.get("/v1/graph/rollup").json()
    drilled = client.get("/v1/graph/rollup", params={"node": "agent:project:sampleapp"}).json()

    assert _entry(top, "agent:project:sampleapp")["aggregate"]["worst_severity"] == "critical"
    assert sorted(child["id"] for child in drilled["children"]) == ["server:filesystem", "server:github"]
    github = next(child for child in drilled["children"] if child["id"] == "server:github")
    assert github["aggregate"]["worst_severity"] == "critical"
