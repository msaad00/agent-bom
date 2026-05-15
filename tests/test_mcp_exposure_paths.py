"""Tests for MCP graph ExposurePath tooling."""

from __future__ import annotations

import json

import pytest

from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedNode
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
async def test_deploy_decision_allows_without_matching_paths():
    response = await deploy_decision_impl(candidate="safe-service", _get_graph_store=lambda: _GraphStore())
    payload = json.loads(response)

    assert payload["decision"] == "allow"
    assert payload["matchedPathCount"] == 0


@pytest.mark.asyncio
async def test_deploy_decision_validates_candidate():
    response = await deploy_decision_impl(candidate=" ", _get_graph_store=lambda: _GraphStore())
    payload = json.loads(response)

    assert payload["error"]["code"] == "AGENTBOM_MCP_VALIDATION_INVALID_ARGUMENT"
    assert payload["error"]["details"]["argument"] == "candidate"
