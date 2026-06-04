"""Project the agent-identity governance control plane into the unified graph.

The cost/identity/drift control plane lives in dedicated stores
(``agent_identity_store``, ``drift_incident_store``) that are not part of a scan
snapshot. This overlay reads the live governance state for a tenant and emits it
as first-class graph nodes and edges, linked to the agent and tool nodes already
in the graph, so attack-path traversal can run:

    agent → managed_identity → access_grant → tool → vulnerable package
    agent ↔ drift_incident → tool

Matching to existing agent/tool nodes is by label (agent name / tool name); a
governance node with no match is still added so it is visible, just unlinked.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, NodeStatus, RelationshipType

_OVERLAY_SOURCE = "governance-overlay"


def _label_index(graph: UnifiedGraph, entity_type: EntityType) -> dict[str, list[str]]:
    index: dict[str, list[str]] = defaultdict(list)
    for node in graph.nodes.values():
        if node.entity_type == entity_type:
            index[node.label.strip().lower()].append(node.id)
    return index


def _gnode(node_id: str, entity_type: EntityType, label: str, **kw: Any) -> UnifiedNode:
    attributes = kw.pop("attributes", {})
    # Governance context nodes carry an "info" severity so they survive default
    # graph queries (severity_id 0 / unknown is dropped by some filters) while
    # never outranking real findings. Callers (e.g. drift) override this.
    kw.setdefault("severity", "info")
    return UnifiedNode(
        id=node_id,
        entity_type=entity_type,
        label=label,
        data_sources=[_OVERLAY_SOURCE],
        attributes=attributes,
        **kw,
    )


def _gedge(source: str, target: str, rel: RelationshipType, **kw: Any) -> UnifiedEdge:
    return UnifiedEdge(source=source, target=target, relationship=rel, provenance={"source": _OVERLAY_SOURCE}, **kw)


def apply_governance_overlay(
    graph: UnifiedGraph,
    *,
    tenant_id: str,
    identity_store: Any = None,
    drift_store: Any = None,
) -> dict[str, int]:
    """Add managed-identity / JIT / conditional-policy / drift nodes+edges in place.

    Returns a count of added nodes and edges. Reads from the global stores when
    ``identity_store`` / ``drift_store`` are not supplied. Never raises: a store
    failure degrades to a partial overlay.
    """
    if identity_store is None:
        from agent_bom.api.agent_identity_store import get_agent_identity_store

        identity_store = get_agent_identity_store()
    if drift_store is None:
        from agent_bom.api.drift_incident_store import get_drift_incident_store

        drift_store = get_drift_incident_store()

    agents_by_label = _label_index(graph, EntityType.AGENT)
    tools_by_label = _label_index(graph, EntityType.TOOL)
    added_nodes = 0
    added_edges = 0

    def add_node(node: UnifiedNode) -> None:
        nonlocal added_nodes
        if node.id not in graph.nodes:
            graph.add_node(node)
            added_nodes += 1

    def add_edge(edge: UnifiedEdge) -> None:
        nonlocal added_edges
        graph.add_edge(edge)
        added_edges += 1

    def link_tool(source_id: str, tool_name: str, rel: RelationshipType, **kw: Any) -> None:
        for tool_id in tools_by_label.get(tool_name.strip().lower(), []):
            add_edge(_gedge(source_id, tool_id, rel, **kw))

    # ── Managed identities (+ standing per-tool scope) ──
    identity_node_by_id: dict[str, str] = {}
    try:
        identities = identity_store.list(tenant_id, include_inactive=False, limit=500)
    except Exception:  # noqa: BLE001
        identities = []
    for identity in identities:
        nid = f"managed_identity:{identity.identity_id}"
        identity_node_by_id[identity.identity_id] = nid
        add_node(
            _gnode(
                nid,
                EntityType.MANAGED_IDENTITY,
                identity.agent_id or identity.identity_id,
                status=NodeStatus.ACTIVE if identity.status == "active" else NodeStatus.INACTIVE,
                attributes={
                    "identity_id": identity.identity_id,
                    "agent_id": identity.agent_id,
                    "role": identity.role,
                    "status": identity.status,
                    "expires_at": identity.expires_at,
                    "allowed_tools": list(identity.allowed_tools),
                    "scope_bound": bool(identity.allowed_tools),
                },
            )
        )
        for agent_id in agents_by_label.get((identity.agent_id or "").strip().lower(), []):
            add_edge(_gedge(agent_id, nid, RelationshipType.AUTHENTICATES_AS))
        for tool_name in identity.allowed_tools:
            if tool_name != "*":
                link_tool(nid, tool_name, RelationshipType.SCOPED_TO, weight=3.0)

    # ── JIT grants (time-bound access to a tool) ──
    try:
        grants = identity_store.list_jit_grants(tenant_id, include_inactive=False, limit=500)
    except Exception:  # noqa: BLE001
        grants = []
    for grant in grants:
        if grant.status != "active":
            continue
        gid = f"access_grant:{grant.grant_id}"
        add_node(
            _gnode(
                gid,
                EntityType.ACCESS_GRANT,
                f"JIT {grant.tool_name}",
                status=NodeStatus.ACTIVE,
                attributes={
                    "grant_id": grant.grant_id,
                    "identity_id": grant.identity_id,
                    "tool": grant.tool_name,
                    "approved_by": grant.approved_by,
                    "expires_at": grant.expires_at,
                    "ticket_id": grant.ticket_id,
                },
            )
        )
        identity_node = identity_node_by_id.get(grant.identity_id)
        if identity_node:
            add_edge(_gedge(identity_node, gid, RelationshipType.ATTACHED))
        link_tool(
            gid,
            grant.tool_name,
            RelationshipType.SCOPED_TO,
            weight=4.0,
            valid_from=grant.starts_at,
            valid_to=grant.expires_at,
            evidence={"kind": "jit_grant", "ticket_id": grant.ticket_id},
        )

    # ── Conditional-access policies ──
    try:
        policies = identity_store.list_conditional_policies(tenant_id, include_disabled=False, limit=500)
    except Exception:  # noqa: BLE001
        policies = []
    for policy in policies:
        pid = f"access_policy:{policy.policy_id}"
        add_node(
            _gnode(
                pid,
                EntityType.ACCESS_POLICY,
                policy.name,
                attributes={
                    "policy_id": policy.policy_id,
                    "effect": policy.effect,
                    "priority": policy.priority,
                    "allowed_environments": list(policy.allowed_environments),
                    "allowed_source_cidrs": list(policy.allowed_source_cidrs),
                },
            )
        )
        for agent_name in policy.agent_ids:
            for agent_id in agents_by_label.get(agent_name.strip().lower(), []):
                add_edge(_gedge(pid, agent_id, RelationshipType.GOVERNS))
        for identity_id in policy.identity_ids:
            node = identity_node_by_id.get(identity_id)
            if node:
                add_edge(_gedge(pid, node, RelationshipType.GOVERNS))
        for tool_name in policy.tools:
            if tool_name != "*":
                link_tool(pid, tool_name, RelationshipType.GOVERNS)

    # ── Drift incidents (open) ──
    try:
        incidents = drift_store.list(tenant_id, include_resolved=False, limit=500)
    except Exception:  # noqa: BLE001
        incidents = []
    for incident in incidents:
        did = f"drift_incident:{incident.incident_id}"
        score = float(getattr(incident, "drift_score", 0.0) or 0.0)
        add_node(
            _gnode(
                did,
                EntityType.DRIFT_INCIDENT,
                f"drift: {incident.blueprint_id}",
                status=NodeStatus.VULNERABLE,
                risk_score=round(min(10.0, score * 10.0), 2),
                severity="high" if score >= 0.66 else "medium" if score >= 0.33 else "low",
                attributes={
                    "incident_id": incident.incident_id,
                    "blueprint_id": incident.blueprint_id,
                    "drift_score": score,
                    "violation_count": incident.violation_count,
                    "occurrences": incident.occurrences,
                    "status": incident.status,
                },
            )
        )
        for agent_id in agents_by_label.get((incident.blueprint_id or "").strip().lower(), []):
            add_edge(_gedge(agent_id, did, RelationshipType.EXHIBITS_DRIFT, direction="bidirectional", weight=5.0))
        for violation in getattr(incident, "top_violations", []) or []:
            tool_name = str(violation.get("tool_name", "")) if isinstance(violation, dict) else ""
            if tool_name:
                link_tool(did, tool_name, RelationshipType.SCOPED_TO, weight=4.0, evidence={"kind": "drift_violation"})

    return {"nodes_added": added_nodes, "edges_added": added_edges}
