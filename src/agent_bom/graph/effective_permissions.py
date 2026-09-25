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
import re
from collections import defaultdict
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from agent_bom.cloud.aws_iam_evaluator import IamDecision, evaluate_identity_policies
from agent_bom.cloud.aws_iam_evidence import (
    EvidenceCompleteness,
    NormalizedIamPolicy,
    normalize_iam_policy_document,
)
from agent_bom.cloud.normalization import coerce_truthy
from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.container import InteractionRisk, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
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
_MAX_PERMISSION_WITNESSES = 16

_ANALYZER = "effective_permissions"
# Between plain escalation (8.5) and confirmed admin escalation (9.0): the target
# holds broad admin authority, but only under unverified request conditions.
_CONDITIONAL_ADMIN_ESCALATION_RISK = 8.75
_ESCALATION_ADMIN_ATTRIBUTES = (
    "escalates_to_admin",
    "escalates_to_conditional_admin",
    "admin_escalation_confidence",
    "admin_escalation_targets",
)
_ADMIN_PRIVILEGE_KEYWORDS = ("administratoraccess", "fullaccess", "poweruseraccess", "iamfullaccess", "*:*", "admin", "owner", "root")

# Admin-equivalence probes for real IAM evaluation. A policy that ALLOWs any of
# these unrestricted (Resource "*") actions grants effective admin: either full
# access (``*``) or an IAM self-escalation primitive that lets the identity mint
# arbitrary permissions for itself. Evaluation respects explicit Deny, resource
# scope, and conditions — so a scoped or denied variant is NOT flagged, which a
# name/keyword match cannot distinguish.
_ADMIN_EQUIVALENCE_PROBES: tuple[tuple[str, str], ...] = (
    ("*", "*"),
    ("iam:PutUserPolicy", "*"),
    ("iam:PutRolePolicy", "*"),
    ("iam:PutGroupPolicy", "*"),
    ("iam:AttachUserPolicy", "*"),
    ("iam:AttachRolePolicy", "*"),
    ("iam:AttachGroupPolicy", "*"),
    ("iam:CreatePolicyVersion", "*"),
    ("iam:UpdateAssumeRolePolicy", "*"),
    ("iam:CreateAccessKey", "*"),
)

# Node-attribute keys under which a raw IAM policy document (or list of them) may
# be carried, so the overlay can run real evaluation when the evidence is present.
_POLICY_DOC_KEYS = ("policy_document", "policy_documents", "policy_documents_json")


def _iter_policy_documents(attrs: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Extract raw IAM policy documents from a node's attributes (best-effort)."""
    docs: list[Mapping[str, Any]] = []
    for key in _POLICY_DOC_KEYS:
        value = attrs.get(key)
        if isinstance(value, Mapping):
            docs.append(value)
        elif isinstance(value, (list, tuple)):
            docs.extend(item for item in value if isinstance(item, Mapping))
    return docs


# Every IAM resource in one account (``arn:aws:iam::123456789012:*``) or in any
# account (``arn:aws:iam::*:*``). ``iam:*`` over either lets an identity attach
# AdministratorAccess to itself. Path-scoped forms (``:role/app/*``) are not
# account-wide and stay excluded.
_ACCOUNT_WIDE_IAM_ARN = re.compile(r"arn:(?:aws(?:-[a-z]+)*|\*):iam:\*?:(?:[0-9]{12}|\*):\*")


def _admin_resource_scopes(policies: Sequence[NormalizedIamPolicy]) -> list[str]:
    """Only account-wide IAM ARNs extend the unrestricted probes.

    A specific user/role ARN or a path-scoped wildcard is not account-wide.
    Keep the original scope in evidence rather than substituting Resource '*'.
    Each scope is probed as-is, so a Deny whose resource pattern covers it
    (``*``, the same ARN, or a broader glob) still takes precedence.
    """
    return sorted(
        {
            resource
            for policy in policies
            for statement in policy.statements
            if statement.effect == "Allow"
            for resource in statement.resources
            if _ACCOUNT_WIDE_IAM_ARN.fullmatch(resource)
        }
    )


def _admin_equivalence_decisions(policies: Sequence[NormalizedIamPolicy]) -> set[IamDecision]:
    """Retain deny precedence and uncertainty for global and account-wide probes."""
    probes = [*_ADMIN_EQUIVALENCE_PROBES]
    for resource in _admin_resource_scopes(policies):
        probes.extend((action, resource) for action, _ in _ADMIN_EQUIVALENCE_PROBES if action.startswith("iam:"))
    return {evaluate_identity_policies(policies, action=action, resource=resource).decision for action, resource in probes}


def _potential_conditional_admin(policies: Sequence[NormalizedIamPolicy]) -> bool:
    """Identify broad conditional grants, without claiming their conditions hold.

    Remove Allow conditions only for classification. Deny conditions and
    incomplete-policy markers remain intact, so unresolved restrictions cannot
    produce a confirmed grant or override an explicit deny.
    """
    supported = {
        "Bool",
        "Null",
        "StringEquals",
        "StringNotEquals",
        "StringLike",
        "StringNotLike",
        "ArnEquals",
        "ArnNotEquals",
        "ArnLike",
        "ArnNotLike",
        "IpAddress",
        "NotIpAddress",
        "DateEquals",
        "DateNotEquals",
        "DateLessThan",
        "DateLessThanEquals",
        "DateGreaterThan",
        "DateGreaterThanEquals",
        "NumericEquals",
        "NumericNotEquals",
        "NumericLessThan",
        "NumericLessThanEquals",
        "NumericGreaterThan",
        "NumericGreaterThanEquals",
    }
    for policy in policies:
        for statement in policy.statements:
            for operator, _, _ in statement.conditions:
                parts = operator.split(":")
                if len(parts) > 2 or (len(parts) == 2 and parts[0] not in {"ForAllValues", "ForAnyValue"}):
                    return False
                if parts[-1].removesuffix("IfExists") not in supported:
                    return False
    relaxed = [
        replace(
            policy,
            statements=tuple(
                replace(statement, conditions=()) if statement.effect == "Allow" else statement for statement in policy.statements
            ),
        )
        for policy in policies
    ]
    return IamDecision.ALLOW in _admin_equivalence_decisions(relaxed)


def _normalized_policies_for(principal: UnifiedNode, attached_policies: Sequence[UnifiedNode]) -> list[NormalizedIamPolicy]:
    """Collect normalized IAM policies from a principal's inline + attached documents.

    Documents may be carried on the principal node itself (inline policies) or on
    each attached ``POLICY`` node. Documents that normalize to no statements
    (``UNAVAILABLE``) are dropped so ``[]`` cleanly means "no evidence to evaluate"
    and the caller degrades to the scanner/name signal.
    """
    raw_docs: list[Mapping[str, Any]] = list(_iter_policy_documents(principal.attributes))
    for policy in attached_policies:
        raw_docs.extend(_iter_policy_documents(policy.attributes))
    normalized: list[NormalizedIamPolicy] = []
    for doc in raw_docs:
        parsed = normalize_iam_policy_document(doc)
        if parsed.completeness is not EvidenceCompleteness.UNAVAILABLE:
            normalized.append(parsed)
    return normalized


def _validity_instant(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError, AttributeError):
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None


def apply_effective_permissions(graph: UnifiedGraph, *, at: datetime | None = None) -> dict[str, object]:
    """Emit HAS_PERMISSION edges + privilege-escalation signals in place.

    Source windows are evaluated at ``at`` (UTC now by default). A caller
    rebuilding historical authority must supply that historical evaluation time.
    Derived windows retain the witnessed source intervals; existing historical
    derived edges are not rewritten. Never raises into the builder.
    """
    moment = at or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        graph.analysis_status[_ANALYZER] = GraphAnalysisStatus(
            status=GraphAnalysisState.SKIPPED, reason_codes=("invalid_permission_evaluation_time",)
        )
        return {"has_permission_edges": 0, "privilege_escalations": 0}
    limits = {"max_principals": _MAX_PRINCIPALS, "max_depth": _MAX_DEPTH, "max_permission_witnesses": _MAX_PERMISSION_WITNESSES}
    input_limited = graph.completeness.truncated or graph.completeness.depth_limited
    principals = [n for n in graph.nodes.values() if n.entity_type in _PRINCIPAL_TYPES]
    if not principals:
        graph.analysis_status[_ANALYZER] = GraphAnalysisStatus(
            status=GraphAnalysisState.LIMITED if input_limited else GraphAnalysisState.COMPLETE,
            reason_codes=("incomplete_source_graph",) if input_limited else (),
            limits=limits,
            observed={"principal_count": 0, "privilege_escalations": 0},
        )
        return {"has_permission_edges": 0, "privilege_escalations": 0}
    if len(principals) > _MAX_PRINCIPALS:
        # Capped, NOT "no escalations". Persist the honest SKIPPED status on the
        # graph (the same analysis_status contract fusion uses, surfaced through
        # ``stats()``) AND return a reason so consumers can distinguish "too big
        # to compute" from "genuinely clean".
        _logger.warning(
            "effective-permissions capped: %d principals exceed cap %d; "
            "privilege-escalation NOT computed for this graph (result is 'skipped', not 'none')",
            len(principals),
            _MAX_PRINCIPALS,
        )
        graph.analysis_status[_ANALYZER] = GraphAnalysisStatus(
            status=GraphAnalysisState.SKIPPED,
            reason_codes=("principal_cap_exceeded",),
            limits=limits,
            observed={"principal_count": len(principals), "privilege_escalations": 0},
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
    access_edges: dict[tuple[str, str], UnifiedEdge] = {}
    assume_edges: dict[tuple[str, str], UnifiedEdge] = {}
    membership_edges: dict[tuple[str, str], UnifiedEdge] = {}
    attached_policy_labels: dict[str, list[str]] = defaultdict(list)
    attached_policy_nodes: dict[str, list[UnifiedNode]] = defaultdict(list)
    admin_by_policy_actions: set[str] = set()
    admin_with_unavailable_policy: set[str] = set()
    validity: dict[str, tuple[datetime, datetime | None]] = {}
    invalid_validity = 0
    inactive_edges = 0
    temporal_relations = {*_ASSUME_RELS, RelationshipType.CAN_ACCESS, RelationshipType.MEMBER_OF, RelationshipType.ATTACHED}
    for edge in graph.edges:
        rel = edge.relationship
        if rel in temporal_relations:
            start = _validity_instant(edge.valid_from)
            end = _validity_instant(edge.valid_to) if edge.valid_to is not None else None
            if start is None or (edge.valid_to is not None and end is None) or (end is not None and end <= start):
                invalid_validity += 1
                continue
            if edge.activity_id == 3 or moment < start or (end is not None and moment >= end):
                inactive_edges += 1
                continue
            validity[edge.id] = (start, end)
        # Context-only links cannot acquire authority through a derived overlay.
        # Attached policy documents remain available to the policy evaluator;
        # only access, membership and delegation walks require traversability.
        if not edge.traversable and rel in {*_ASSUME_RELS, RelationshipType.CAN_ACCESS, RelationshipType.MEMBER_OF}:
            continue
        if rel == RelationshipType.CAN_ACCESS and edge.source in principal_ids:
            target = graph.nodes.get(edge.target)
            if target is not None and target.entity_type in _RESOURCE_TYPES:
                direct_access[edge.source].add(edge.target)
                access_edges[(edge.source, edge.target)] = edge
        elif rel in _ASSUME_RELS and edge.source in principal_ids and edge.target in principal_ids:
            assumes[edge.source].add(edge.target)
            key = (edge.source, edge.target)
            if key not in assume_edges or edge.id < assume_edges[key].id:
                assume_edges[key] = edge
        elif rel == RelationshipType.MEMBER_OF and edge.source in principal_ids:
            # A principal inherits the access of every GROUP it belongs to. Group
            # membership is NOT an assume chain, so it is tracked separately and
            # never flagged as privilege escalation.
            target = graph.nodes.get(edge.target)
            if target is not None and target.entity_type == EntityType.GROUP:
                member_of_groups[edge.source].add(edge.target)
                membership_edges[(edge.source, edge.target)] = edge
        elif rel == RelationshipType.ATTACHED and edge.source in principal_ids:
            policy = graph.nodes.get(edge.target)
            if policy is not None and policy.entity_type == EntityType.POLICY:
                attached_policy_labels[edge.source].append(policy.label)
                attached_policy_nodes[edge.source].append(policy)
                # Action-derived privilege from the scanner (precise, beats name match).
                if policy.attributes.get("privilege_level") == "admin":
                    admin_by_policy_actions.add(edge.source)
                    if not _normalized_policies_for(policy, ()):
                        admin_with_unavailable_policy.add(edge.source)

    # Admin-equivalence is derived, in priority order, from:
    #   1. REAL IAM evaluation of attached/inline policy documents (policy
    #      simulation over the actual statements — honors Deny, resource scope,
    #      conditions). This replaces the name/keyword guess for every identity
    #      the evaluator has policy evidence for.
    #   2. The scanner's action-derived ``privilege_level == "admin"`` classification
    #      when collected documents are missing or incomplete. This fallback
    #      ignores Deny, resource scope and conditions, so it cannot override
    #      evaluation of COMPLETE documents.
    #   3. A name/keyword heuristic (AdministratorAccess / *FullAccess / wildcard),
    #      used as a degraded fallback when neither a scanner classification nor
    #      AUTHORITATIVE (COMPLETE) policy evidence is available — the basis is
    #      noted on the node. Evidence that is only PARTIAL/incomplete cannot
    #      authoritatively evaluate the admin probes (the evaluator returns
    #      INDETERMINATE), so it must NOT suppress the heuristic: a role with
    #      AdministratorAccess attached alongside a single malformed statement
    #      still fails toward flagging a possible admin (safe direction).
    admin_principals: set[str] = set()
    # Broad admin grants whose Allow conditions (MFA, source IP, region, ...)
    # have not been verified. They feed escalation analysis as a distinct,
    # lower-confidence target and never set ``admin_equivalent``.
    conditional_admin_principals: set[str] = set()
    admin_via_evaluation = 0
    admin_via_scanner = 0
    admin_via_heuristic = 0
    for p in principals:
        docs = _normalized_policies_for(p, attached_policy_nodes.get(p.id, ()))
        # Evidence is authoritative only when EVERY collected document is COMPLETE.
        # A single PARTIAL document means the evaluator's non-ALLOW verdict is
        # inconclusive, not a real "not admin" — it must not gate out the heuristic.
        evidence_authoritative = bool(docs) and all(d.completeness is EvidenceCompleteness.COMPLETE for d in docs)
        basis: str | None = None
        decisions = _admin_equivalence_decisions(docs) if docs else set()
        pnode = graph.nodes.get(p.id) or p
        # Re-evaluation must not retain a previous unconditional admin label.
        pnode.attributes.pop("admin_equivalent", None)
        pnode.attributes.pop("admin_equivalence_basis", None)
        pnode.attributes["admin_equivalence_status"] = "unknown"
        pnode.attributes["admin_equivalence_resource_scopes"] = _admin_resource_scopes(docs)
        if evidence_authoritative:
            if IamDecision.ALLOW in decisions:
                pnode.attributes["admin_equivalence_status"] = "admin"
            elif IamDecision.INDETERMINATE in decisions:
                if _potential_conditional_admin(docs):
                    pnode.attributes["admin_equivalence_status"] = "conditional_admin"
                    conditional_admin_principals.add(p.id)
            elif p.id not in admin_with_unavailable_policy:
                pnode.attributes["admin_equivalence_status"] = "not_admin"
        if IamDecision.ALLOW in decisions:
            # Real policy evaluation ALLOWs an unrestricted admin/escalation action.
            basis = "policy_evaluation"
            admin_via_evaluation += 1
        elif decisions == {IamDecision.EXPLICIT_DENY} or (evidence_authoritative and p.id not in admin_with_unavailable_policy):
            # COMPLETE documents did not prove unconditional admin-equivalence.
            # Deny, resource scope and unresolved conditions must not be bypassed
            # by an action-only scanner classification or a policy-name guess.
            # Record the evaluation basis without inventing a request context.
            # An unfetched admin policy remains a degraded signal unless every
            # admin probe is explicitly denied by the collected documents.
            # Re-resolve
            # through the graph before writing so the mutation persists on a
            # store-backed container (the held principal may have been evicted from
            # the LRU during the scan above); in-RAM this is the same object.
            (graph.nodes.get(p.id) or p).attributes["admin_equivalence_basis"] = "policy_evaluation"
        elif p.id in admin_by_policy_actions:
            basis = "scanner_actions"
            admin_via_scanner += 1
        else:
            # No documents, OR only PARTIAL/incomplete evidence (non-authoritative):
            # fall back to the name/keyword heuristic and fail toward flagging.
            haystack = " ".join([p.label, *attached_policy_labels.get(p.id, [])]).lower().replace(" ", "")
            if any(kw in haystack for kw in _ADMIN_PRIVILEGE_KEYWORDS):
                basis = "name_heuristic"
                admin_via_heuristic += 1
        if basis is not None:
            admin_principals.add(p.id)
            # Re-resolve before mutating so the write persists store-backed (see above).
            pnode = graph.nodes.get(p.id) or p
            pnode.attributes["admin_equivalent"] = True
            pnode.attributes["admin_equivalence_basis"] = basis

    depth_limited = False
    witness_limited = False

    def _walk(
        principal_id: str, adjacency: Mapping[str, set[str]], source_edges: Mapping[tuple[str, str], UnifiedEdge]
    ) -> dict[str, tuple[str, ...]]:
        """One deterministic shortest witness per reachable principal, not all paths."""
        nonlocal depth_limited
        paths: dict[str, tuple[str, ...]] = {principal_id: ()}
        frontier = [principal_id]
        for _ in range(_MAX_DEPTH):
            next_frontier: list[str] = []
            for source in frontier:
                for target in sorted(adjacency.get(source, set())):
                    if target in paths:
                        continue
                    paths[target] = (*paths[source], source_edges[(source, target)].id)
                    next_frontier.append(target)
            frontier = next_frontier
            if not frontier:
                break
        # Cycles and already visited nodes do not imply unexamined authority.
        if any(target not in paths for source in frontier for target in adjacency.get(source, set())):
            depth_limited = True
        paths.pop(principal_id)
        return paths

    def effective(principal_id: str) -> tuple[set[str], set[str], set[str], set[str], dict[str, dict[str, Any]]]:
        nonlocal witness_limited
        direct = set(direct_access.get(principal_id, set()))
        groups = _walk(principal_id, member_of_groups, membership_edges)
        assumed = _walk(principal_id, assumes, assume_edges)
        via_group: set[str] = set()
        via_assume: set[str] = set()
        proofs: dict[str, dict[str, Any]] = {}
        for access, sources in (("direct", {principal_id: ()}), ("group", groups), ("assume_chain", assumed)):
            for source, chain in sorted(sources.items()):
                for resource in sorted(direct_access.get(source, set())):
                    if access == "group":
                        via_group.add(resource)
                    elif access == "assume_chain":
                        via_assume.add(resource)
                    proof = proofs.setdefault(
                        resource,
                        {
                            "basis": "recorded_graph_connections",
                            "source_scan_id": graph.scan_id,
                            "path_selection": "one_shortest_path_per_grant_and_access",
                            "paths": [],
                            "truncated": False,
                        },
                    )
                    if len(proof["paths"]) >= _MAX_PERMISSION_WITNESSES:
                        proof["truncated"] = True
                        witness_limited = True
                        continue
                    grant = access_edges[(source, resource)]
                    proof["paths"].append(
                        {
                            "access": access,
                            "grant_principal_id": source,
                            "grant_edge_id": grant.id,
                            "source_edge_ids": [*chain, grant.id],
                        }
                    )
        all_resources = direct | via_assume | via_group
        return all_resources, via_assume - direct, via_group - direct - via_assume, set(assumed), proofs

    def witnessed_window(proof: Mapping[str, Any]) -> tuple[str, str | None]:
        intervals = []
        for path in proof["paths"]:
            windows = [validity[edge_id] for edge_id in path["source_edge_ids"]]
            ends = [end for _start, end in windows if end is not None]
            intervals.append((max(start for start, _end in windows), min(ends) if ends else None))
        # Every retained witness contains the evaluation instant. Their union is
        # therefore contiguous; the chosen bounds cannot bridge an unseen gap.
        start = min(start for start, _end in intervals)
        end = None if any(end is None for _start, end in intervals) else max(end for _start, end in intervals if end is not None)
        return start.isoformat(), end.isoformat() if end is not None else None

    edges_added = 0
    escalations = 0
    seen_perm: set[tuple[str, str]] = set()
    for principal in principals:
        all_resources, escalated, via_group_only, assumed, proofs = effective(principal.id)
        for resource_id in sorted(all_resources):
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
            valid_from, valid_to = witnessed_window(proofs[resource_id])
            graph.add_edge(
                UnifiedEdge(
                    source=principal.id,
                    target=resource_id,
                    relationship=RelationshipType.HAS_PERMISSION,
                    valid_from=valid_from,
                    valid_to=valid_to,
                    weight=5.0 if via == "assume_chain" else 2.0,
                    provenance={"source": _OVERLAY_SOURCE},
                    evidence={"access": via, "permission_derivation": proofs[resource_id]},
                )
            )
            edges_added += 1
        for stale in _ESCALATION_ADMIN_ATTRIBUTES:
            principal.attributes.pop(stale, None)
        if escalated:
            principal.attributes["can_escalate_privilege"] = True
            to_admin = bool(assumed & admin_principals)
            to_conditional_admin = not to_admin and bool(assumed & conditional_admin_principals)
            admin_targets = sorted(assumed & (admin_principals | conditional_admin_principals))
            if to_admin:
                principal.attributes["escalates_to_admin"] = True
                principal.attributes["admin_escalation_confidence"] = "confirmed"
            elif to_conditional_admin:
                principal.attributes["escalates_to_conditional_admin"] = True
                principal.attributes["admin_escalation_confidence"] = "conditional"
            if admin_targets:
                principal.attributes["admin_escalation_targets"] = [
                    {
                        "principal_id": target_id,
                        "admin_equivalence_status": "admin" if target_id in admin_principals else "conditional_admin",
                    }
                    for target_id in admin_targets[:_MAX_PERMISSION_WITNESSES]
                ]
            exposed = sorted(
                rid for rid in escalated if graph.nodes.get(rid) and coerce_truthy(graph.nodes[rid].attributes.get("internet_exposed"))
            )
            if exposed:
                risk = 9.5
            elif to_admin:
                risk = 9.0
            elif to_conditional_admin:
                risk = _CONDITIONAL_ADMIN_ESCALATION_RISK
            else:
                risk = 8.5
            if to_admin:
                target_phrase = "an admin-privileged role"
            elif to_conditional_admin:
                target_phrase = "a role with conditional admin permissions (conditions not verified)"
            else:
                target_phrase = "another role"
            graph.interaction_risks.append(
                InteractionRisk(
                    pattern="privilege_escalation",
                    agents=[principal.label],
                    risk_score=risk,
                    description=(
                        f"{principal.label} reaches {len(escalated)} additional resource(s) by assuming "
                        + target_phrase
                        + (f", including {len(exposed)} internet-exposed." if exposed else ".")
                    ),
                    owasp_agentic_tag=None,
                )
            )
            escalations += 1

    reason_codes = tuple(
        code
        for code, limited in (
            ("permission_depth_limit", depth_limited),
            ("permission_witness_limit", witness_limited),
            ("incomplete_source_graph", input_limited),
            ("invalid_permission_validity", invalid_validity > 0),
        )
        if limited
    )
    graph.analysis_status[_ANALYZER] = GraphAnalysisStatus(
        status=GraphAnalysisState.LIMITED if reason_codes else GraphAnalysisState.COMPLETE,
        reason_codes=reason_codes,
        limits=limits,
        observed={
            "principal_count": len(principals),
            "has_permission_edges": edges_added,
            "privilege_escalations": escalations,
            "admin_principals": len(admin_principals),
            "conditional_admin_principals": len(conditional_admin_principals),
            "inactive_source_edges": inactive_edges,
            "invalid_source_validity": invalid_validity,
        },
    )
    return {
        "has_permission_edges": edges_added,
        "privilege_escalations": escalations,
        "admin_principals": len(admin_principals),
        "conditional_admin_principals": len(conditional_admin_principals),
        "admin_via_evaluation": admin_via_evaluation,
        "admin_via_scanner": admin_via_scanner,
        "admin_via_heuristic": admin_via_heuristic,
    }
