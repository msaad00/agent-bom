"""Effective-permission computation and privilege-escalation detection.

The identity graph already records direct access (``CAN_ACCESS``), outbound
assume relationships (``ASSUMES`` — principal → role it may assume), inbound
trust (``TRUSTS`` / ``CROSS_ACCOUNT_TRUST`` — role → principal allowed to assume
it, which this overlay does NOT walk as an assume), and group membership
(``MEMBER_OF`` into a ``GROUP``) between principals. This overlay resolves them
into *effective* access — what a principal can reach after assuming
the roles it is allowed to assume and inheriting the access of the groups it
belongs to — and emits ``HAS_PERMISSION`` edges for the transitive closure. A
principal that reaches a resource only by assuming another role is flagged as a
privilege-escalation chain; group-inherited access is recorded as ``group`` and
is not, by itself, an escalation.

Computed over edges already in the graph; no new scanner input. Bounded for
scale: principals and chain depth are capped.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from agent_bom.graph.container import InteractionRisk, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.types import EntityType, RelationshipType

_logger = logging.getLogger(__name__)

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
# Edges that let a principal gain the access of *another* principal by moving
# outbound. TRUSTS / CROSS_ACCOUNT_TRUST are deliberately excluded: those edges
# are emitted as ``role R -> trusted principal P`` where P is *allowed to assume*
# R (INBOUND trust). Folding them into an assume walk would make an exposed R
# inherit P's access and mint a false HAS_PERMISSION{assume_chain} edge into P's
# account — a fabricated cross-account kill-chain (the same class #3761 removed
# from toxic_findings). ASSUMES (principal -> role) is the genuine outbound
# vector; INHERITS is scoped-policy inheritance, also outbound.
_ASSUME_RELS = frozenset({RelationshipType.ASSUMES, RelationshipType.INHERITS})

_MAX_PRINCIPALS = 5000
_MAX_DEPTH = 6
_ADMIN_PRIVILEGE_KEYWORDS = ("administratoraccess", "fullaccess", "poweruseraccess", "iamfullaccess", "*:*", "admin", "owner", "root")


def apply_effective_permissions(graph: UnifiedGraph) -> dict[str, object]:
    """Emit HAS_PERMISSION edges + privilege-escalation signals in place.

    Returns counts of permission edges added and escalation chains found. Never
    raises into the builder.
    """
    principals = [n for n in graph.nodes.values() if n.entity_type in _PRINCIPAL_TYPES]
    if not principals:
        return {"has_permission_edges": 0, "privilege_escalations": 0}
    if len(principals) > _MAX_PRINCIPALS:
        # Capped, NOT "no escalations". Surface a signal (log + returned reason) so
        # consumers can distinguish "too big to compute" from "genuinely clean".
        _logger.warning(
            "effective-permissions capped: %d principals exceed cap %d; "
            "privilege-escalation NOT computed for this graph (result is 'skipped', not 'none')",
            len(principals),
            _MAX_PRINCIPALS,
        )
        return {
            "has_permission_edges": 0,
            "privilege_escalations": 0,
            "skipped": True,
            "skipped_reason": f"principal_cap_exceeded:{len(principals)}>{_MAX_PRINCIPALS}",
        }
    principal_ids = {p.id for p in principals}

    direct_access: dict[str, set[str]] = defaultdict(set)
    assumes: dict[str, set[str]] = defaultdict(set)
    member_of_groups: dict[str, set[str]] = defaultdict(set)
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
        elif rel == RelationshipType.MEMBER_OF and edge.source in principal_ids:
            # A principal inherits the access of every GROUP it belongs to. Group
            # membership is NOT an assume chain, so it is tracked separately and
            # never flagged as privilege escalation.
            target = graph.nodes.get(edge.target)
            if target is not None and target.entity_type == EntityType.GROUP:
                member_of_groups[edge.source].add(edge.target)
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

    def _group_closure(principal_id: str) -> set[str]:
        """Return the GROUP ids a principal belongs to, transitively (nested groups)."""
        groups: set[str] = set()
        frontier = list(member_of_groups.get(principal_id, set()))
        depth = 0
        while frontier and depth < _MAX_DEPTH:
            nxt: list[str] = []
            for gid in frontier:
                if gid in groups:
                    continue
                groups.add(gid)
                nxt.extend(member_of_groups.get(gid, set()))
            frontier = nxt
            depth += 1
        return groups

    def effective(principal_id: str) -> tuple[set[str], set[str], set[str], set[str]]:
        """Return (all_resources, via_assume_only, via_group_only, assumed_principal_ids)."""
        direct = set(direct_access.get(principal_id, set()))
        # Access inherited from group membership (and the groups a group nests in).
        via_group: set[str] = set()
        for gid in _group_closure(principal_id):
            via_group |= direct_access.get(gid, set())
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
        all_resources = direct | via_assume | via_group
        return all_resources, via_assume - direct, via_group - direct - via_assume, assumed

    edges_added = 0
    escalations = 0
    seen_perm: set[tuple[str, str]] = set()
    for principal in principals:
        all_resources, escalated, via_group_only, assumed = effective(principal.id)
        for resource_id in all_resources:
            key = (principal.id, resource_id)
            if key in seen_perm:
                continue
            seen_perm.add(key)
            if resource_id in escalated:
                via = "assume_chain"
            elif resource_id in via_group_only:
                via = "group"
            else:
                via = "direct"
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
