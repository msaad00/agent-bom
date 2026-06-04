"""Effective-permission computation and privilege-escalation detection.

The identity graph already records direct access (``CAN_ACCESS``) and
assume/trust relationships (``TRUSTS`` / ``CROSS_ACCOUNT_TRUST`` / ``ASSUMES``)
between principals. This overlay resolves them into *effective* access — what a
principal can reach after assuming the roles it is allowed to assume — and emits
``HAS_PERMISSION`` edges for the transitive closure. A principal that reaches a
resource only by assuming another role is flagged as a privilege-escalation
chain.

Computed over edges already in the graph; no new scanner input. Bounded for
scale: principals and chain depth are capped.
"""

from __future__ import annotations

from collections import defaultdict

from agent_bom.graph.container import InteractionRisk, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.types import EntityType, RelationshipType

_OVERLAY_SOURCE = "effective-permissions"

_PRINCIPAL_TYPES = frozenset(
    {
        EntityType.USER,
        EntityType.GROUP,
        EntityType.ROLE,
        EntityType.SERVICE_ACCOUNT,
        EntityType.SERVICE_PRINCIPAL,
        EntityType.FEDERATED_IDENTITY,
        EntityType.ACCOUNT,
        EntityType.MANAGED_IDENTITY,
    }
)
_RESOURCE_TYPES = frozenset({EntityType.CLOUD_RESOURCE, EntityType.RESOURCE, EntityType.DATA_STORE})
_ASSUME_RELS = frozenset(
    {RelationshipType.TRUSTS, RelationshipType.CROSS_ACCOUNT_TRUST, RelationshipType.ASSUMES, RelationshipType.INHERITS}
)

_MAX_PRINCIPALS = 5000
_MAX_DEPTH = 6
_ADMIN_PRIVILEGE_KEYWORDS = ("administratoraccess", "fullaccess", "poweruseraccess", "iamfullaccess", "*:*", "admin", "owner", "root")


def apply_effective_permissions(graph: UnifiedGraph) -> dict[str, int]:
    """Emit HAS_PERMISSION edges + privilege-escalation signals in place.

    Returns counts of permission edges added and escalation chains found. Never
    raises into the builder.
    """
    principals = [n for n in graph.nodes.values() if n.entity_type in _PRINCIPAL_TYPES]
    if not principals or len(principals) > _MAX_PRINCIPALS:
        return {"has_permission_edges": 0, "privilege_escalations": 0}
    principal_ids = {p.id for p in principals}

    direct_access: dict[str, set[str]] = defaultdict(set)
    assumes: dict[str, set[str]] = defaultdict(set)
    attached_policy_labels: dict[str, list[str]] = defaultdict(list)
    admin_by_policy_actions: set[str] = set()
    for edge in graph.edges:
        rel = edge.relationship
        if rel == RelationshipType.CAN_ACCESS and edge.source in principal_ids:
            target = graph.nodes.get(edge.target)
            if target is not None and target.entity_type in _RESOURCE_TYPES:
                direct_access[edge.source].add(edge.target)
        elif rel in _ASSUME_RELS and edge.source in principal_ids and edge.target in principal_ids:
            assumes[edge.source].add(edge.target)
        elif rel == RelationshipType.ATTACHED and edge.source in principal_ids:
            policy = graph.nodes.get(edge.target)
            if policy is not None and policy.entity_type == EntityType.POLICY:
                attached_policy_labels[edge.source].append(policy.label)
                # Action-derived privilege from the scanner (precise, beats name match).
                if policy.attributes.get("privilege_level") == "admin":
                    admin_by_policy_actions.add(edge.source)

    # A principal is admin-privileged when a scanner-classified policy grants admin
    # actions, or (fallback) its own name or an attached policy name signals broad
    # access (AdministratorAccess / *FullAccess / wildcard).
    admin_principals: set[str] = set(admin_by_policy_actions)
    for p in principals:
        if p.id in admin_principals:
            continue
        haystack = " ".join([p.label, *attached_policy_labels.get(p.id, [])]).lower().replace(" ", "")
        if any(kw in haystack for kw in _ADMIN_PRIVILEGE_KEYWORDS):
            admin_principals.add(p.id)

    def effective(principal_id: str) -> tuple[set[str], set[str], set[str]]:
        """Return (all_resources, via_assume_only, assumed_principal_ids)."""
        direct = set(direct_access.get(principal_id, set()))
        via_assume: set[str] = set()
        assumed: set[str] = set()
        visited = {principal_id}
        frontier = list(assumes.get(principal_id, set()))
        depth = 0
        while frontier and depth < _MAX_DEPTH:
            nxt: list[str] = []
            for pid in frontier:
                if pid in visited:
                    continue
                visited.add(pid)
                assumed.add(pid)
                via_assume |= direct_access.get(pid, set())
                nxt.extend(assumes.get(pid, set()))
            frontier = nxt
            depth += 1
        return direct | via_assume, via_assume - direct, assumed

    edges_added = 0
    escalations = 0
    seen_perm: set[tuple[str, str]] = set()
    for principal in principals:
        all_resources, escalated, assumed = effective(principal.id)
        for resource_id in all_resources:
            key = (principal.id, resource_id)
            if key in seen_perm:
                continue
            seen_perm.add(key)
            via = "assume_chain" if resource_id in escalated else "direct"
            graph.add_edge(
                UnifiedEdge(
                    source=principal.id,
                    target=resource_id,
                    relationship=RelationshipType.HAS_PERMISSION,
                    weight=5.0 if via == "assume_chain" else 2.0,
                    provenance={"source": _OVERLAY_SOURCE},
                    evidence={"access": via},
                )
            )
            edges_added += 1
        if escalated:
            principal.attributes["can_escalate_privilege"] = True
            to_admin = bool(assumed & admin_principals)
            if to_admin:
                principal.attributes["escalates_to_admin"] = True
            exposed = sorted(rid for rid in escalated if graph.nodes.get(rid) and graph.nodes[rid].attributes.get("internet_exposed"))
            risk = 9.5 if exposed else (9.0 if to_admin else 8.5)
            graph.interaction_risks.append(
                InteractionRisk(
                    pattern="privilege_escalation",
                    agents=[principal.label],
                    risk_score=risk,
                    description=(
                        f"{principal.label} reaches {len(escalated)} additional resource(s) by assuming "
                        + ("an admin-privileged role" if to_admin else "another role")
                        + (f", including {len(exposed)} internet-exposed." if exposed else ".")
                    ),
                    owasp_agentic_tag=None,
                )
            )
            escalations += 1

    return {"has_permission_edges": edges_added, "privilege_escalations": escalations}
