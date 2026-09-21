"""Project the agent-identity governance control plane into the unified graph.

The cost/identity/drift control plane lives in dedicated stores
(``agent_identity_store``, ``drift_incident_store``) that are not part of a scan
snapshot. This overlay reads the live governance state for a tenant and emits it
as first-class graph nodes and edges, linked to the agent and tool nodes already
in the graph, so attack-path traversal can run:

    agent → managed_identity → access_grant → tool → vulnerable package
    agent ↔ drift_incident → tool

Agent bindings prefer an exact graph node ID, then an unambiguous agent label.
They describe registered identity scope, not an observed authenticated session.
Tool scopes remain context-only when conditional policy evidence is incomplete
or denies access. Unmatched governance nodes remain visible and unlinked.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from agent_bom.api.agent_identity_store import AccessContext, evaluate_conditional_access
from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
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
    blueprint_store: Any = None,
) -> dict[str, int]:
    """Add managed-identity / JIT / conditional-policy / drift nodes+edges in place.

    Returns a count of added nodes and edges. Reads from the global stores when
    ``identity_store`` / ``drift_store`` / ``blueprint_store`` are not supplied.
    Never raises: a store failure degrades to a partial overlay.

    All three stores are injectable for the same reason: a caller that supplies
    empty stores must get an empty overlay. ``blueprint_store`` used to be read
    from the process singleton with no injection point, so a test passing empty
    identity and drift stores still picked up whatever blueprints another test
    had seeded — an "empty stores" case that was not actually empty.
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
    moment = datetime.now(timezone.utc)
    reasons: set[str] = set()
    try:
        policies = identity_store.list_conditional_policies(tenant_id, include_disabled=False, limit=500)
        if len(policies) >= 500:
            reasons.add("conditional_policy_limit")
    except Exception:  # noqa: BLE001
        policies = []
        reasons.add("conditional_policies_unavailable")

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

    def scoped_tool(source_id: str, tool_name: str, identity: Any, **kw: Any) -> None:
        ctx = AccessContext(identity_id=identity.identity_id, agent_id=identity.agent_id, tool_name=tool_name, at=moment)
        applicable = [p for p in policies if p.status == "active" and p.applies_to(ctx)]
        condition_fields = (
            "allowed_environments",
            "allowed_hours_utc",
            "allowed_weekdays",
            "allowed_source_cidrs",
            "allowed_devices",
            "allowed_groups",
            "allowed_clients",
            "require_device_managed",
            "require_device_compliant",
            "require_device_disk_encrypted",
        )
        conditional = [p for p in applicable if any(getattr(p, field, None) for field in condition_fields)]
        unconditional = [p for p in applicable if p not in conditional]
        allowed, _reason, policy_id = evaluate_conditional_access(unconditional, ctx)
        state = "recorded_scope"
        if not allowed:
            state = "explicit_deny"
            reasons.add("explicit_policy_denies")
        elif conditional:
            state = "context_required"
            reasons.add("conditional_access_context_required")
        elif {"conditional_policies_unavailable", "conditional_policy_limit"} & reasons:
            state = "policy_evidence_unavailable"
        evidence = {**kw.pop("evidence", {}), "authorization_state": state}
        if policy_id:
            evidence["policy_ids"] = [policy_id]
        elif conditional:
            evidence["policy_ids"] = sorted(p.policy_id for p in conditional)
            evidence["required_context"] = sorted({field for p in conditional for field in condition_fields if getattr(p, field, None)})
        link_tool(source_id, tool_name, RelationshipType.SCOPED_TO, traversable=state == "recorded_scope", evidence=evidence, **kw)

    # ── Managed identities (+ standing per-tool scope) ──
    identity_node_by_id: dict[str, str] = {}
    live_identities: dict[str, Any] = {}
    try:
        identities = identity_store.list(tenant_id, include_inactive=False, limit=500)
        if len(identities) >= 500:
            reasons.add("identity_limit")
    except Exception:  # noqa: BLE001
        identities = []
        reasons.add("identities_unavailable")
    for identity in identities:
        nid = f"managed_identity:{identity.identity_id}"
        identity_node_by_id[identity.identity_id] = nid
        try:
            live = identity.is_live(at=moment)
        except (TypeError, ValueError):
            live = False
            reasons.add("invalid_identity_validity")
        if live:
            live_identities[identity.identity_id] = identity
        add_node(
            _gnode(
                nid,
                EntityType.MANAGED_IDENTITY,
                identity.agent_id or identity.identity_id,
                status=NodeStatus.ACTIVE if live else NodeStatus.INACTIVE,
                attributes={
                    "identity_id": identity.identity_id,
                    "agent_id": identity.agent_id,
                    "role": identity.role,
                    "status": identity.status,
                    "expires_at": identity.expires_at,
                    "is_live": live,
                    "allowed_tools": list(identity.allowed_tools),
                    "scope_bound": bool(identity.allowed_tools),
                    # Surface the accountability + usage fields the NHI governance
                    # evaluator reads so ownership/dormancy verdicts reflect the
                    # real identity record instead of defaulting every identity to
                    # orphaned + never-observed.
                    "owner": getattr(identity, "owner", "") or "",
                    "owner_type": getattr(identity, "owner_type", "") or "",
                    "last_used_at": getattr(identity, "last_used_at", "") or "",
                },
            )
        )
        if not live:
            reasons.add("inactive_identity")
            continue
        exact_agent = graph.nodes.get(identity.agent_id)
        exact_match = exact_agent is not None and exact_agent.entity_type == EntityType.AGENT
        matches = [identity.agent_id] if exact_match else agents_by_label.get((identity.agent_id or "").strip().lower(), [])
        if len(matches) == 1:
            add_edge(
                _gedge(
                    matches[0],
                    nid,
                    RelationshipType.AUTHENTICATES_AS,
                    valid_from=identity.issued_at,
                    valid_to=identity.expires_at or None,
                    evidence={
                        "identity_match_basis": "exact_node_id" if exact_match else "unique_agent_label",
                        "runtime_observed_state": "not_observed",
                    },
                )
            )
        elif len(matches) > 1:
            reasons.add("ambiguous_agent_identity")
        for tool_name in identity.allowed_tools:
            if tool_name != "*":
                scoped_tool(nid, tool_name, identity, weight=3.0, valid_from=identity.issued_at, valid_to=identity.expires_at or None)

    # ── JIT grants (time-bound access to a tool) ──
    try:
        grants = identity_store.list_jit_grants(tenant_id, include_inactive=False, limit=500)
        if len(grants) >= 500:
            reasons.add("jit_grant_limit")
    except Exception:  # noqa: BLE001
        grants = []
        reasons.add("jit_grants_unavailable")
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
        identity = live_identities.get(grant.identity_id)
        if identity_node and identity:
            add_edge(_gedge(identity_node, gid, RelationshipType.ATTACHED, valid_from=grant.starts_at, valid_to=grant.expires_at))
        else:
            reasons.add("jit_identity_unavailable")
            continue
        scoped_tool(
            gid,
            grant.tool_name,
            identity,
            weight=4.0,
            valid_from=grant.starts_at,
            valid_to=grant.expires_at,
            evidence={"kind": "jit_grant", "ticket_id": grant.ticket_id},
        )

    # ── Conditional-access policies ──
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

    # ── Persisted AI-system blueprints ──
    # Emit the stored, approved blueprints so the snapshot references a durable
    # blueprint entity (by id) rather than a code constant — drift incidents then
    # tie back to the persisted blueprint they derive from. Best-effort: a store
    # failure degrades to no blueprint nodes.
    blueprint_node_by_seed: dict[str, str] = {}
    blueprint_node_by_id: dict[str, str] = {}
    try:
        if blueprint_store is None:
            from agent_bom.api.blueprint_store import get_blueprint_store

            blueprint_store = get_blueprint_store()
        blueprints = blueprint_store.list_blueprints(tenant_id, limit=200).blueprints
    except Exception:  # noqa: BLE001
        blueprints = []
    for blueprint in blueprints:
        bnid = f"blueprint:{blueprint.blueprint_id}"
        blueprint_node_by_id[blueprint.blueprint_id] = bnid
        if blueprint.seeded_from:
            blueprint_node_by_seed[blueprint.seeded_from] = bnid
        add_node(
            _gnode(
                bnid,
                EntityType.BLUEPRINT,
                blueprint.name or blueprint.blueprint_id,
                attributes={
                    "blueprint_id": blueprint.blueprint_id,
                    "owner": blueprint.owner,
                    "approval_status": blueprint.approval_status,
                    "current_version": blueprint.current_version,
                    "latest_version": blueprint.latest_version,
                    "seeded_from": blueprint.seeded_from,
                },
            )
        )
        for owner_name in {blueprint.owner}:
            for agent_id in agents_by_label.get(owner_name.strip().lower(), []):
                add_edge(_gedge(bnid, agent_id, RelationshipType.GOVERNS))

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
        # Tie the incident to the persisted blueprint it drifted from (matched by
        # the archetype the blueprint was seeded from, else a direct id match) so
        # the graph references the stored blueprint, not just the code constant.
        blueprint_node = blueprint_node_by_seed.get(incident.blueprint_id) or blueprint_node_by_id.get(incident.blueprint_id)
        if blueprint_node:
            add_edge(_gedge(blueprint_node, did, RelationshipType.GOVERNS, weight=5.0))
        for violation in getattr(incident, "top_violations", []) or []:
            tool_name = str(violation.get("tool_name", "")) if isinstance(violation, dict) else ""
            if tool_name:
                link_tool(did, tool_name, RelationshipType.SCOPED_TO, weight=4.0, evidence={"kind": "drift_violation"})

    graph.analysis_status["governance_overlay"] = GraphAnalysisStatus(
        status=GraphAnalysisState.LIMITED if reasons else GraphAnalysisState.COMPLETE,
        reason_codes=tuple(sorted(reasons)),
        limits={"max_identities": 500, "max_jit_grants": 500, "max_conditional_policies": 500},
        observed={
            "identities": len(identities),
            "live_identities": len(live_identities),
            "jit_grants": len(grants),
            "conditional_policies": len(policies),
        },
    )
    return {"nodes_added": added_nodes, "edges_added": added_edges}
