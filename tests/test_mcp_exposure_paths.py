"""Tests for MCP graph ExposurePath tooling."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.mcp_tools.graph import deploy_decision_impl, exposure_paths_impl


class _GraphStore:
    def __init__(self) -> None:
        self.path = AttackPath(
            source="agent:prod-assistant",
            target="vuln:CVE-2026-0001",
            hops=["agent:prod-assistant", "package:requests", "vuln:CVE-2026-0001"],
            composite_risk=88.0,
            summary="Prod assistant reaches vulnerable requests package",
            credential_exposure=["AWS_TOKEN"],
            tool_exposure=["read_file"],
            vuln_ids=["CVE-2026-0001"],
        )
        self.nodes = [
            UnifiedNode(id="agent:prod-assistant", entity_type=EntityType.AGENT, label="prod-assistant", risk_score=72.0),
            UnifiedNode(id="package:requests", entity_type=EntityType.PACKAGE, label="requests", risk_score=70.0),
            UnifiedNode(
                id="vuln:CVE-2026-0001",
                entity_type=EntityType.VULNERABILITY,
                label="CVE-2026-0001",
                severity="high",
                risk_score=88.0,
            ),
        ]
        self.edges = [
            UnifiedEdge(source="agent:prod-assistant", target="package:requests", relationship=RelationshipType.DEPENDS_ON),
            UnifiedEdge(source="package:requests", target="vuln:CVE-2026-0001", relationship=RelationshipType.VULNERABLE_TO),
        ]

    def attack_paths(self, **_kwargs):
        return "scan-1", "2026-05-14T18:00:00Z", [self.path], 1

    def nodes_by_ids(self, *, node_ids: set[str], **_kwargs):
        return [node for node in self.nodes if node.id in node_ids]

    def edges_for_node_ids(self, **_kwargs):
        return self.edges

    def snapshot_stats(self, **_kwargs):
        return {"attack_path_count": 1, "max_attack_path_risk": 88.0}


class _FailingGraphStore:
    def attack_paths(self, **_kwargs):
        raise RuntimeError("failed to read /Users/example/.agent-bom/db/graph.db")


@pytest.mark.asyncio
async def test_exposure_paths_impl_returns_agent_native_contract():
    response = await exposure_paths_impl(_get_graph_store=lambda: _GraphStore(), _truncate_response=lambda value: value)
    payload = json.loads(response)

    assert payload["schema_version"] == "v1"
    assert payload["tool"] == "exposure_paths"
    assert payload["scan_id"] == "scan-1"
    assert payload["count"] == 1
    path = payload["paths"][0]
    assert path["riskScore"] == 88.0
    assert path["severity"] == "high"
    assert path["source"]["role"] == "agent"
    assert path["target"]["role"] == "vulnerability"
    assert path["findings"] == ["CVE-2026-0001"]
    assert path["reachableTools"] == ["read_file"]
    assert path["exposedCredentials"] == ["AWS_TOKEN"]
    assert path["relationships"]


@pytest.mark.asyncio
async def test_exposure_paths_impl_validates_agent_limits():
    response = await exposure_paths_impl(limit=0, _get_graph_store=lambda: _GraphStore())
    payload = json.loads(response)

    assert payload["error"]["code"] == "AGENTBOM_MCP_VALIDATION_INVALID_ARGUMENT"
    assert payload["error"]["details"]["argument"] == "limit"


@pytest.mark.asyncio
async def test_exposure_paths_impl_explains_empty_queue():
    response = await exposure_paths_impl(min_risk=95, _get_graph_store=lambda: _GraphStore(), _truncate_response=lambda value: value)
    payload = json.loads(response)

    assert payload["count"] == 0
    assert payload["total"] == 1
    assert payload["message"] == "0 paths matched min_risk=95; lower min_risk to inspect lower-risk ExposurePaths."


@pytest.mark.asyncio
async def test_exposure_paths_impl_redacts_internal_errors():
    response = await exposure_paths_impl(_get_graph_store=lambda: _FailingGraphStore())
    payload = json.loads(response)

    assert payload["error"]["code"] == "AGENTBOM_MCP_INTERNAL_UNEXPECTED"
    assert payload["error"]["message"] == "An internal error has occurred."
    assert "graph.db" not in payload["error"]["message"]


@pytest.mark.asyncio
async def test_deploy_decision_blocks_high_risk_candidate():
    response = await deploy_decision_impl(
        candidate="requests",
        _get_graph_store=lambda: _GraphStore(),
        _truncate_response=lambda value: value,
    )
    payload = json.loads(response)

    assert payload["schema_version"] == "v1"
    assert payload["tool"] == "should_i_deploy"
    assert payload["decision"] == "block"
    assert payload["maxRisk"] == 88.0
    assert payload["matchedPathCount"] == 1
    assert payload["matchedPaths"][0]["findings"] == ["CVE-2026-0001"]


@pytest.mark.asyncio
async def test_deploy_decision_does_not_approve_without_matching_evidence():
    response = await deploy_decision_impl(candidate="safe-service", _get_graph_store=lambda: _GraphStore())
    payload = json.loads(response)

    assert payload["decision"] == "warn"
    assert payload["maxRisk"] is None
    assert payload["evidenceStatus"] == "not_evaluated"
    assert payload["matchedPathCount"] == 0
    assert "not an approval" in payload["reasons"][0]


@pytest.mark.asyncio
async def test_deploy_decision_validates_candidate():
    response = await deploy_decision_impl(candidate=" ", _get_graph_store=lambda: _GraphStore())
    payload = json.loads(response)

    assert payload["error"]["code"] == "AGENTBOM_MCP_VALIDATION_INVALID_ARGUMENT"
    assert payload["error"]["details"]["argument"] == "candidate"


@pytest.fixture
def topology_store(tmp_path):
    """Persist topology without path rows, as CLI report ingestion can do."""
    from agent_bom.api.graph_store import SQLiteGraphStore

    store = SQLiteGraphStore(tmp_path / "graph.db")
    graph = UnifiedGraph(scan_id="topology", tenant_id="default")
    for node_id, kind in [("agent:a", EntityType.AGENT), ("server:s", EntityType.SERVER), ("pkg:p", EntityType.PACKAGE)]:
        graph.add_node(UnifiedNode(id=node_id, entity_type=kind, label=node_id))
    graph.add_edge(UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES))
    graph.add_edge(UnifiedEdge(source="server:s", target="pkg:p", relationship=RelationshipType.DEPENDS_ON))
    for index in range(3):
        node_id = f"vuln:{index}"
        graph.add_node(UnifiedNode(id=node_id, entity_type=EntityType.VULNERABILITY, label=node_id, severity="critical"))
        graph.add_edge(UnifiedEdge(source="pkg:p", target=node_id, relationship=RelationshipType.VULNERABLE_TO))
    store.save_graph(graph)
    return store


@pytest.mark.asyncio
async def test_exposure_paths_derives_persisted_topology_with_limits(topology_store):
    payload = json.loads(await exposure_paths_impl(scan_id="topology", limit=2, _get_graph_store=lambda: topology_store))
    assert payload["count"] == 2
    assert payload["total"] == 3
    assert payload["completeness"]["complete"] is False
    assert all(path["reachability"] == "unknown" for path in payload["paths"])
    assert all(path["riskScore"] <= 39 for path in payload["paths"])
    assert payload["paths"][0]["nodeIds"][:3] == ["agent:a", "server:s", "pkg:p"]
    filtered = json.loads(await exposure_paths_impl(scan_id="topology", min_risk=40, _get_graph_store=lambda: topology_store))
    assert filtered["count"] == 0
    assert filtered["total"] == 3
    assert "min_risk=40" in filtered["message"]


@pytest.mark.asyncio
async def test_exposure_paths_fallback_preserves_tenant_scope(topology_store, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "other")
    payload = json.loads(await exposure_paths_impl(tenant_id="default", scan_id="topology", _get_graph_store=lambda: topology_store))
    assert payload["count"] == 0
    assert payload["nodes"] == []
    assert payload["edges"] == []


@pytest.mark.asyncio
async def test_deploy_decision_does_not_approve_structural_candidates(topology_store):
    payload = json.loads(await deploy_decision_impl(candidate="pkg:p", _get_graph_store=lambda: topology_store))
    assert payload["matchedPathCount"] == 3
    assert payload["decision"] == "warn"
    assert payload["evidenceStatus"] == "not_evaluated"


@pytest.mark.asyncio
async def test_exposure_paths_discloses_bounded_derivation(topology_store, monkeypatch):
    monkeypatch.setattr("agent_bom.mcp_tools.graph.GRAPH_INVESTIGATION_NODE_BUDGET", 2, raising=False)
    payload = json.loads(await exposure_paths_impl(scan_id="topology", _get_graph_store=lambda: topology_store))
    assert payload["completeness"]["complete"] is False
    assert payload["completeness"]["reason"] == "node_budget"
    assert "No conclusion" in payload["message"]


def test_shared_derivation_imports_without_fastapi():
    result = subprocess.run(
        [sys.executable, "-c", "import sys; sys.modules['fastapi'] = None; import agent_bom.mcp_tools.graph"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
