"""Governance overlay: project identity/JIT/policy/drift into the unified graph."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from agent_bom.api.agent_identity_store import (
    InMemoryAgentIdentityStore,
    create_conditional_policy,
    issue_identity,
    issue_jit_grant,
)
from agent_bom.api.drift_incident_store import DriftIncident
from agent_bom.api.routes.graph import _governance_graph_payload
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
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


class _EmptyBlueprintStore:
    """An explicitly empty blueprint store.

    Injected rather than relying on the process singleton being empty: the
    singleton is shared, so a test seeding blueprints elsewhere leaked five
    nodes into this "empty stores" case and turned it red.
    """

    def list_blueprints(self, *_args, **_kwargs):
        return SimpleNamespace(blueprints=[])


def test_overlay_is_resilient_to_missing_matches_and_empty_stores():
    graph = _base_graph()
    # No identities/drift/blueprints → no-op, no raise.
    stats = apply_governance_overlay(
        graph,
        tenant_id="default",
        identity_store=InMemoryAgentIdentityStore(),
        drift_store=_FakeDriftStore([]),
        blueprint_store=_EmptyBlueprintStore(),
    )
    assert stats == {"nodes_added": 0, "edges_added": 0}

    # Identity whose agent has no matching node still adds the node (unlinked).
    store = InMemoryAgentIdentityStore()
    issue_identity(store, agent_id="ghost-agent", tenant_id="default")
    # Explicit empty store: omitting it read whatever the process-global
    # blueprint store happened to hold, so an unrelated demo-estate test
    # seeding 5 blueprints earlier in the run turned this into 6 == 1.
    stats = apply_governance_overlay(
        graph,
        tenant_id="default",
        identity_store=store,
        drift_store=_FakeDriftStore([]),
        blueprint_store=_EmptyBlueprintStore(),
    )
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


def test_governance_payload_caps_edges_and_attack_paths_for_large_graphs():
    graph = UnifiedGraph(scan_id="gov-large", tenant_id="default")
    graph.add_node(
        UnifiedNode(
            id="managed_identity:svc",
            entity_type=EntityType.MANAGED_IDENTITY,
            label="svc",
        )
    )
    for index in range(8):
        tool_id = f"tool:srv:tool-{index}"
        graph.add_node(UnifiedNode(id=tool_id, entity_type=EntityType.TOOL, label=f"tool-{index}"))
        graph.add_edge(UnifiedEdge(source="managed_identity:svc", target=tool_id, relationship=RelationshipType.CAN_ACCESS))
        graph.attack_paths.append(
            AttackPath(
                source="managed_identity:svc",
                target=tool_id,
                hops=["managed_identity:svc", tool_id],
                edges=["can_access"],
                composite_risk=7.0,
                summary=f"governance path {index}",
            )
        )

    payload = _governance_graph_payload(
        graph,
        tenant_id="default",
        overlay_stats={"nodes_added": 0},
        node_limit=20,
        edge_limit=3,
        attack_path_limit=2,
    )

    assert len(payload["edges"]) == 3
    assert payload["edge_pagination"] == {"total": 8, "limit": 3, "has_more": True}
    assert len(payload["attack_paths"]) == 2
    assert payload["attack_path_pagination"] == {"total": 8, "limit": 2, "has_more": True}
    assert payload["stats"]["edge_count"] == 3


@pytest.mark.parametrize("state", ["expired", "invalid"])
def test_expired_or_invalid_identity_does_not_link_agent_to_tool(state):
    store = InMemoryAgentIdentityStore()
    identity, _ = issue_identity(store, agent_id="agent-a", tenant_id="default", allowed_tools=["read_file"])
    identity.expires_at = "invalid" if state == "invalid" else (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    store.put(identity)
    graph = _base_graph()
    apply_governance_overlay(
        graph, tenant_id="default", identity_store=store, drift_store=_FakeDriftStore([]), blueprint_store=_EmptyBlueprintStore()
    )
    assert identity.is_live() is False
    assert "tool:srv:read_file" not in graph.reachable_from("agent:agent-a", traversable_only=True)
    assert graph.nodes[f"managed_identity:{identity.identity_id}"].status.value == "inactive"


def test_duplicate_agent_labels_do_not_bind_one_identity_to_both_workloads():
    store = InMemoryAgentIdentityStore()
    issue_identity(store, agent_id="agent-a", tenant_id="default", allowed_tools=["read_file"])
    graph = _base_graph()
    graph.add_node(UnifiedNode(id="agent:other-account", entity_type=EntityType.AGENT, label="agent-a"))
    apply_governance_overlay(
        graph, tenant_id="default", identity_store=store, drift_store=_FakeDriftStore([]), blueprint_store=_EmptyBlueprintStore()
    )
    assert not _rels(graph, RelationshipType.AUTHENTICATES_AS)
    assert "ambiguous_agent_identity" in graph.analysis_status["governance_overlay"].reason_codes


@pytest.mark.parametrize(
    "effect,conditions,expected",
    [
        ("deny", {}, "explicit_deny"),
        ("require", {"allowed_environments": ["prod"]}, "context_required"),
        ("deny", {"allowed_environments": ["prod"]}, "context_required"),
    ],
)
def test_governance_scope_preserves_deny_and_missing_request_context(effect, conditions, expected):
    from agent_bom.api.agent_identity_store import AccessContext, evaluate_conditional_access
    from agent_bom.graph.path_derivation import _derived_governance_attack_paths

    store = InMemoryAgentIdentityStore()
    identity, _ = issue_identity(store, agent_id="agent-a", tenant_id="default", allowed_tools=["run_shell"])
    create_conditional_policy(
        store, tenant_id="default", name="guard", effect=effect, agent_ids=["agent-a"], tools=["run_shell"], **conditions
    )
    if expected == "explicit_deny":
        allowed, _, _ = evaluate_conditional_access(
            store.list_conditional_policies("default"),
            AccessContext(identity_id=identity.identity_id, agent_id="agent-a", tool_name="run_shell"),
        )
        assert allowed is False
    graph = _base_graph()
    graph.add_node(UnifiedNode(id="tool:srv:run_shell", entity_type=EntityType.TOOL, label="run_shell"))
    apply_governance_overlay(
        graph, tenant_id="default", identity_store=store, drift_store=_FakeDriftStore([]), blueprint_store=_EmptyBlueprintStore()
    )
    scope = next(e for e in graph.edges if e.source == f"managed_identity:{identity.identity_id}" and e.target == "tool:srv:run_shell")
    assert scope.traversable is False
    assert scope.evidence["authorization_state"] == expected
    assert "tool:srv:run_shell" not in graph.reachable_from("agent:agent-a", traversable_only=True)
    assert not any(p.target == "tool:srv:run_shell" for p in _derived_governance_attack_paths(graph))
    assert graph.analysis_status["governance_overlay"].status.value == "limited"


@pytest.mark.parametrize("state", ["requested", "expired", "revoked", "future", "active"])
def test_jit_lifecycle_remains_consistent_with_live_grant_filter(state):
    from agent_bom.api.agent_identity_store import request_jit_grant

    store = InMemoryAgentIdentityStore()
    identity, _ = issue_identity(store, agent_id="agent-a", tenant_id="default", allowed_tools=["list_files"])
    grant = request_jit_grant(store, identity_id=identity.identity_id, agent_id="agent-a", tenant_id="default", tool_name="read_file")
    now = datetime.now(timezone.utc)
    if state != "requested":
        grant.status = "revoked" if state == "revoked" else "active"
        grant.starts_at = (now + timedelta(hours=1) if state == "future" else now - timedelta(hours=1)).isoformat()
        grant.expires_at = (now - timedelta(minutes=30) if state == "expired" else now + timedelta(hours=2)).isoformat()
        store.put_jit_grant(grant)
    graph = _base_graph()
    apply_governance_overlay(
        graph, tenant_id="default", identity_store=store, drift_store=_FakeDriftStore([]), blueprint_store=_EmptyBlueprintStore()
    )
    assert ("tool:srv:read_file" in graph.reachable_from("agent:agent-a", traversable_only=True)) is (state == "active")


def test_exact_agent_id_binding_does_not_use_another_workloads_matching_label():
    store = InMemoryAgentIdentityStore()
    identity, _ = issue_identity(store, agent_id="agent:agent-a", tenant_id="default", allowed_tools=["read_file"])
    graph = _base_graph()
    graph.add_node(UnifiedNode(id="agent:other-account", entity_type=EntityType.AGENT, label="agent:agent-a"))
    apply_governance_overlay(
        graph, tenant_id="default", identity_store=store, drift_store=_FakeDriftStore([]), blueprint_store=_EmptyBlueprintStore()
    )
    edges = [e for e in graph.edges if e.relationship is RelationshipType.AUTHENTICATES_AS]
    assert len(edges) == 1
    assert edges[0].source == "agent:agent-a"
    assert edges[0].target == f"managed_identity:{identity.identity_id}"
    assert edges[0].evidence == {"identity_match_basis": "exact_node_id", "runtime_observed_state": "not_observed"}


@pytest.mark.parametrize("failure", ["unavailable", "limit"])
def test_incomplete_policy_collection_cannot_prove_unconditional_scope(monkeypatch, failure):
    store = InMemoryAgentIdentityStore()
    identity, _ = issue_identity(store, agent_id="agent-a", tenant_id="default", allowed_tools=["read_file"])
    if failure == "unavailable":

        def policies(*args, **kwargs):
            raise RuntimeError("unavailable")
    else:
        policy = create_conditional_policy(store, tenant_id="default", name="require", effect="require")

        def policies(*args, **kwargs):
            return [policy] * 500

    monkeypatch.setattr(store, "list_conditional_policies", policies)
    graph = _base_graph()
    apply_governance_overlay(
        graph, tenant_id="default", identity_store=store, drift_store=_FakeDriftStore([]), blueprint_store=_EmptyBlueprintStore()
    )
    scope = next(e for e in graph.edges if e.source == f"managed_identity:{identity.identity_id}" and e.target == "tool:srv:read_file")
    assert scope.traversable is False
    assert scope.evidence["authorization_state"] == "policy_evidence_unavailable"
    assert graph.analysis_status["governance_overlay"].status.value == "limited"


@pytest.mark.parametrize("state", ["expired", "denied", "conditional"])
def test_governance_api_preserves_qualified_authority(tmp_path, state):
    from starlette.testclient import TestClient

    from agent_bom.api import stores as api_stores
    from agent_bom.api.agent_identity_store import get_agent_identity_store, set_agent_identity_store
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.server import app
    from agent_bom.api.stores import set_graph_store

    graph = _base_graph()
    graph.scan_id = "qualified-scan"
    graph_store = SQLiteGraphStore(tmp_path / "graph.db")
    graph_store.save_graph(graph)
    identity_store = InMemoryAgentIdentityStore()
    identity, _ = issue_identity(identity_store, agent_id="agent-a", tenant_id="default", allowed_tools=["read_file"])
    if state == "expired":
        identity.expires_at = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        identity_store.put(identity)
    else:
        create_conditional_policy(
            identity_store,
            tenant_id="default",
            name="guard",
            effect="deny",
            identity_ids=[identity.identity_id],
            tools=["read_file"],
            allowed_environments=["prod"] if state == "conditional" else [],
        )
    original_graph, original_identity = api_stores._graph_store, get_agent_identity_store()
    try:
        set_graph_store(graph_store)
        set_agent_identity_store(identity_store)
        response = TestClient(app).get("/v1/graph/governance?scan_id=qualified-scan")
        assert response.status_code == 200
        body = response.json()
        assert body["stats"]["analysis_status"]["governance_overlay"]["status"] == "limited"
        scopes = [
            e for e in body["edges"] if e["source"] == f"managed_identity:{identity.identity_id}" and e["relationship"] == "scoped_to"
        ]
        if state == "expired":
            assert not scopes
        else:
            assert len(scopes) == 1
            assert scopes[0]["traversable"] is False
            assert scopes[0]["evidence"]["authorization_state"] == ("explicit_deny" if state == "denied" else "context_required")
            if state == "conditional":
                assert scopes[0]["evidence"]["required_context"] == ["allowed_environments"]
    finally:
        set_graph_store(original_graph)
        set_agent_identity_store(original_identity)


def test_governance_payload_retains_unavailable_identity_collection(monkeypatch):
    store = InMemoryAgentIdentityStore()

    def unavailable(*args, **kwargs):
        raise RuntimeError("unavailable")

    monkeypatch.setattr(store, "list", unavailable)
    graph = _base_graph()
    overlay = apply_governance_overlay(
        graph, tenant_id="default", identity_store=store, drift_store=_FakeDriftStore([]), blueprint_store=_EmptyBlueprintStore()
    )
    body = _governance_graph_payload(
        graph,
        tenant_id="default",
        overlay_stats=overlay,
        node_limit=2000,
        edge_limit=2000,
        attack_path_limit=100,
    )
    assert not body["nodes"]
    assert body["stats"]["analysis_status"]["governance_overlay"]["status"] == "limited"
    assert body["stats"]["analysis_status"]["governance_overlay"]["reason_codes"] == ["identities_unavailable"]
