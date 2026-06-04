"""Governance overlay: project identity/JIT/policy/drift into the unified graph."""

from __future__ import annotations

import pytest

from agent_bom.api.agent_identity_store import (
    InMemoryAgentIdentityStore,
    create_conditional_policy,
    issue_identity,
    issue_jit_grant,
)
from agent_bom.api.drift_incident_store import DriftIncident
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.governance_overlay import apply_governance_overlay
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


class _FakeDriftStore:
    def __init__(self, incidents):
        self._incidents = incidents

    def list(self, tenant_id, *, include_resolved=False, limit=200):
        return [i for i in self._incidents if i.tenant_id == tenant_id and (include_resolved or not i.resolved)]


def _base_graph() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="s1", tenant_id="default")
    graph.add_node(UnifiedNode(id="agent:agent-a", entity_type=EntityType.AGENT, label="agent-a"))
    graph.add_node(UnifiedNode(id="tool:srv:read_file", entity_type=EntityType.TOOL, label="read_file"))
    graph.add_node(UnifiedNode(id="tool:srv:list_files", entity_type=EntityType.TOOL, label="list_files"))
    return graph


def _rels(graph, rel):
    return [(e.source, e.target) for e in graph.edges if e.relationship == rel]


def test_overlay_projects_identity_scope_and_jit_into_graph():
    store = InMemoryAgentIdentityStore()
    identity, _ = issue_identity(store, agent_id="agent-a", tenant_id="default", allowed_tools=["list_files"])
    issue_jit_grant(
        store,
        identity_id=identity.identity_id,
        agent_id="agent-a",
        tenant_id="default",
        tool_name="read_file",
        ttl_seconds=300,
        approved_by="admin",
    )
    create_conditional_policy(
        store, tenant_id="default", name="prod-only", effect="require", agent_ids=["agent-a"], allowed_environments=["prod"]
    )

    graph = _base_graph()
    stats = apply_governance_overlay(graph, tenant_id="default", identity_store=store, drift_store=_FakeDriftStore([]))
    assert stats["nodes_added"] >= 3

    identity_nodes = [n for n in graph.nodes.values() if n.entity_type == EntityType.MANAGED_IDENTITY]
    assert len(identity_nodes) == 1
    iid = identity_nodes[0].id

    # agent → managed_identity (authenticates_as)
    assert ("agent:agent-a", iid) in _rels(graph, RelationshipType.AUTHENTICATES_AS)
    # managed_identity → list_files (standing scope) and access_grant → read_file (JIT)
    scoped = _rels(graph, RelationshipType.SCOPED_TO)
    assert (iid, "tool:srv:list_files") in scoped
    grant_nodes = [n for n in graph.nodes.values() if n.entity_type == EntityType.ACCESS_GRANT]
    assert len(grant_nodes) == 1
    assert (grant_nodes[0].id, "tool:srv:read_file") in scoped
    # identity → grant (attached)
    assert (iid, grant_nodes[0].id) in _rels(graph, RelationshipType.ATTACHED)
    # access_policy governs the agent
    policy_nodes = [n for n in graph.nodes.values() if n.entity_type == EntityType.ACCESS_POLICY]
    assert len(policy_nodes) == 1
    assert (policy_nodes[0].id, "agent:agent-a") in _rels(graph, RelationshipType.GOVERNS)


def test_overlay_projects_drift_incident_and_links_violated_tool():
    incident = DriftIncident(
        incident_id="inc1",
        tenant_id="default",
        blueprint_id="agent-a",
        status="drift_detected",
        drift_score=0.8,
        violation_count=1,
        warning_count=0,
        top_violations=[{"tool_name": "read_file", "type": "unauthorized_tool"}],
        first_detected_at="2026-06-01T00:00:00Z",
        last_detected_at="2026-06-02T00:00:00Z",
        occurrences=2,
    )
    graph = _base_graph()
    apply_governance_overlay(
        graph,
        tenant_id="default",
        identity_store=InMemoryAgentIdentityStore(),
        drift_store=_FakeDriftStore([incident]),
    )
    drift_nodes = [n for n in graph.nodes.values() if n.entity_type == EntityType.DRIFT_INCIDENT]
    assert len(drift_nodes) == 1
    did = drift_nodes[0].id
    assert drift_nodes[0].risk_score == pytest.approx(8.0)
    # agent ↔ drift (bidirectional) and drift → violated tool
    assert ("agent:agent-a", did) in _rels(graph, RelationshipType.EXHIBITS_DRIFT)
    assert (did, "tool:srv:read_file") in _rels(graph, RelationshipType.SCOPED_TO)


def test_overlay_is_resilient_to_missing_matches_and_empty_stores():
    graph = _base_graph()
    # No identities/drift → no-op, no raise.
    stats = apply_governance_overlay(
        graph, tenant_id="default", identity_store=InMemoryAgentIdentityStore(), drift_store=_FakeDriftStore([])
    )
    assert stats == {"nodes_added": 0, "edges_added": 0}

    # Identity whose agent has no matching node still adds the node (unlinked).
    store = InMemoryAgentIdentityStore()
    issue_identity(store, agent_id="ghost-agent", tenant_id="default")
    stats = apply_governance_overlay(graph, tenant_id="default", identity_store=store, drift_store=_FakeDriftStore([]))
    assert stats["nodes_added"] == 1
    assert not [e for e in graph.edges if e.relationship == RelationshipType.AUTHENTICATES_AS]


def test_governance_endpoint_returns_overlay_subgraph(tmp_path):
    from starlette.testclient import TestClient

    from agent_bom.api import stores as api_stores
    from agent_bom.api.agent_identity_store import set_agent_identity_store
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.server import app
    from agent_bom.api.stores import set_graph_store

    store = SQLiteGraphStore(tmp_path / "graph.db")
    graph = UnifiedGraph(scan_id="gov-scan", tenant_id="default")
    graph.add_node(UnifiedNode(id="agent:agent-a", entity_type=EntityType.AGENT, label="agent-a"))
    graph.add_node(UnifiedNode(id="tool:srv:list_files", entity_type=EntityType.TOOL, label="list_files"))
    store.save_graph(graph)

    identity_store = InMemoryAgentIdentityStore()
    issue_identity(identity_store, agent_id="agent-a", tenant_id="default", allowed_tools=["list_files"])

    original_graph = api_stores._graph_store
    try:
        set_graph_store(store)
        set_agent_identity_store(identity_store)
        client = TestClient(app)
        resp = client.get("/v1/graph/governance?scan_id=gov-scan")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        kinds = {n["entity_type"] for n in body["nodes"]}
        assert "managed_identity" in kinds
        assert body["governance_counts"].get("managed_identity") == 1
        assert body["overlay"]["nodes_added"] >= 1
        # agent → managed_identity edge present
        assert any(e["relationship"] == "authenticates_as" for e in body["edges"])
    finally:
        set_graph_store(original_graph)
        set_agent_identity_store(None)
