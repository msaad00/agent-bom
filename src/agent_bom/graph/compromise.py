"""Read-only foundation for explicit compromise assumptions on one snapshot.

This classifies direct outgoing receipts. It is not an authorization service,
an exploit detector, or a transitive compromise traversal. Callers must first
authorize and pin the snapshot; matching its tenant is an additional invariant.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.correlation_scope import CORRELATION_IDENTITY_VERSION
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.hop_evidence import AuthorizationReceipt, HopAuthorityEvidence, authority_evidence, runtime_evidence_references
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.ocsf import FINDING_ENTITY_TYPES
from agent_bom.graph.types import EntityType, RelationshipType

NodeId = Annotated[str, Field(min_length=1, max_length=1024)]
_PERMISSION_RELATIONSHIPS = {RelationshipType.CAN_ACCESS, RelationshipType.HAS_PERMISSION}
_PRINCIPALS = {
    EntityType.USER,
    EntityType.ROLE,
    EntityType.GROUP,
    EntityType.SERVICE_ACCOUNT,
    EntityType.SERVICE_PRINCIPAL,
    EntityType.FEDERATED_IDENTITY,
    EntityType.MANAGED_IDENTITY,
}


class CompromiseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    root_node_id: NodeId
    assume_control: Literal[True]
    affected_node_id: NodeId | None = None
    assume_exploitation: bool = False
    max_relationships: int = Field(default=128, ge=1, le=512)
    max_evidence_age_seconds: int = Field(default=3600, ge=1, le=86400)

    @field_validator("root_node_id", "affected_node_id")
    @classmethod
    def nonblank(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("node identity must not be blank")
        return value

    @field_validator("assume_control", mode="before")
    @classmethod
    def explicit_assumption(cls, value: object) -> object:
        if value is not True:
            raise ValueError("control must be explicitly assumed")
        return value


class CompromiseAction(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    source_node_id: str
    target_node_id: str
    source_edge_id: str
    source_snapshot_id: str
    relationship: str
    provider: str | None = None
    principal_id: str | None = None
    action: str | None = None
    resource: str | None = None
    observed_at: str | None = None
    binding_ids: list[str] = Field(default_factory=list, max_length=256)
    permission: Literal["supported_at_collection", "denied_at_collection", "unknown"] = "unknown"
    observation: Literal["attempt_recorded", "blocked_attempt", "failed_attempt", "not_recorded"] = "not_recorded"
    runtime_references: list[dict[str, str]] = Field(default_factory=list, max_length=8)
    reason_codes: list[str] = Field(default_factory=list)


class CompromiseAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: Literal["compromise.direct.v1"] = "compromise.direct.v1"
    tenant_id: str
    scan_id: str
    root_node_id: str
    assumed_control_node_id: str
    assessed_at: str
    exploitation: Literal["not_evaluated", "assumed_not_verified"] = "not_evaluated"
    scope: Literal["direct_outgoing_relationships"] = "direct_outgoing_relationships"
    current_access: Literal["not_evaluated"] = "not_evaluated"
    execution: Literal["not_established"] = "not_established"
    collection_coverage: Literal["unknown"] = "unknown"
    collector_independence: Literal["not_assessed"] = "not_assessed"
    relationships_examined: int
    max_relationships: int
    max_evidence_age_seconds: int
    truncated: bool
    reason_codes: list[str]
    actions: list[CompromiseAction] = Field(max_length=8192)


def _instant(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None and parsed.utcoffset() is not None else None
    except (ValueError, TypeError, AttributeError, OverflowError):
        return None


def _controlled_node(graph: UnifiedGraph, request: CompromiseRequest) -> str:
    root = graph.nodes.get(request.root_node_id)
    if root is None:
        raise ValueError("compromise root not found")
    if root.entity_type not in FINDING_ENTITY_TYPES:
        if request.affected_node_id is not None or request.assume_exploitation:
            raise ValueError("affected component assumptions require a finding root")
        return root.id
    affected = graph.nodes.get(request.affected_node_id or "")
    if affected is None or affected.entity_type in FINDING_ENTITY_TYPES or not request.assume_exploitation:
        raise ValueError("finding requires an affected component and explicit exploitation assumption")
    linked = any(
        (edge.source == root.id and edge.target == affected.id and edge.relationship == RelationshipType.AFFECTS)
        or (edge.source == affected.id and edge.target == root.id and edge.relationship == RelationshipType.VULNERABLE_TO)
        for edge in graph.edges
    )
    if not linked:
        raise ValueError("affected component is not linked to this finding")
    return affected.id


def _observation(edge: UnifiedEdge) -> str:
    evidence = edge.evidence
    observed, failed = evidence.get("observation_count"), evidence.get("failure_count")
    runtime = (
        edge.relationship in {RelationshipType.INVOKED, RelationshipType.ACCESSED}
        or evidence.get("runtime_observed") is True
        or evidence.get("runtime_observed_state") in ("observed", "blocked")
        or edge.provenance.get("runtime_observed_state") in ("observed", "blocked")
        or (type(observed) is int and observed > 0)
    )
    if not runtime:
        return "not_recorded"
    if evidence.get("blocked") is True or evidence.get("decision") in ("blocked", "denied", "explicit_deny", "implicit_deny"):
        return "blocked_attempt"
    if evidence.get("runtime_observed_state") == "blocked" or edge.provenance.get("runtime_observed_state") == "blocked":
        return "blocked_attempt"
    if type(observed) is int and type(failed) is int and observed > 0 and failed == observed:
        return "failed_attempt"
    return "attempt_recorded"


def _edge_gaps(edge: UnifiedEdge, at: datetime) -> list[str]:
    gaps: list[str] = []
    if edge.relationship not in _PERMISSION_RELATIONSHIPS:
        gaps.append("relationship_does_not_establish_authority")
    if edge.direction not in {"directed", "bidirectional"} or not edge.traversable:
        gaps.append("relationship_not_traversable")
    correlation = edge.provenance.get("correlation")
    if isinstance(correlation, dict) and correlation.get("identity_version") != CORRELATION_IDENTITY_VERSION:
        gaps.append("correlation_identity_unverified")
    freshness = correlation.get("freshness") if isinstance(correlation, dict) else None
    if (freshness or edge.evidence.get("freshness")) != "fresh":
        gaps.append("evidence_not_fresh")
    start, end = _instant(edge.valid_from), _instant(edge.valid_to)
    if start is None or start > at or (edge.valid_to is not None and (end is None or end <= at)):
        gaps.append("relationship_validity_unverified")
    if edge.evidence.get("required_context"):
        gaps.append("required_context_not_established")
    if edge.evidence.get("blocked") is True:
        gaps.append("recorded_blocker")
    if _observation(edge) in {"blocked_attempt", "failed_attempt"}:
        gaps.append("runtime_attempt_did_not_establish_access")
    return gaps


def _scope_gaps(receipt: AuthorizationReceipt, source: UnifiedNode, target: UnifiedNode | None) -> list[str]:
    if target is None:
        return ["target_not_recorded"]
    # Only native, exact identifiers bind the evaluated request to these nodes.
    # Labels, partial names, wildcards and credentials on neighboring nodes do
    # not prove that the assumed principal can perform this target action.
    principals = (source.id, source.attributes.get("principal_id"))
    resources = (target.id, target.attributes.get("resource_id"))
    if source.entity_type not in _PRINCIPALS or not receipt.principal_id or receipt.principal_id not in principals:
        return ["principal_scope_unverified"]
    if not receipt.resource or receipt.resource not in resources or "*" in receipt.resource or "*" in receipt.action:
        return ["resource_action_scope_unverified"]
    if any(node.attributes.get("cloud_provider") != receipt.provider for node in (source, target)):
        return ["provider_scope_unverified"]
    return []


def _actions(graph: UnifiedGraph, edge: UnifiedEdge, request: CompromiseRequest, at: datetime) -> tuple[list[CompromiseAction], bool, bool]:
    authority_raw = authority_evidence(edge.evidence)
    authority = HopAuthorityEvidence.model_validate(authority_raw) if authority_raw is not None else None
    partial = authority is not None and authority.status == "partial"
    limited = authority is not None and any(
        code.endswith("limit") or code == "permission_witnesses_limited" for code in authority.reason_codes
    )
    gaps = _edge_gaps(edge, at)
    if partial:
        gaps.append("authority_projection_partial")
    observation = _observation(edge)
    base = {
        "source_node_id": edge.source,
        "target_node_id": edge.target,
        "source_edge_id": edge.id,
        "source_snapshot_id": edge.source_scan_id or graph.scan_id,
        "relationship": edge.relationship.value,
        "observation": observation,
        "runtime_references": runtime_evidence_references(edge.evidence) if observation != "not_recorded" else [],
    }
    if authority is None or not authority.decisions:
        return [CompromiseAction.model_validate({**base, "reason_codes": [*gaps, "evaluated_action_not_recorded"]})], limited, partial
    grouped: dict[tuple[str | None, ...], list[AuthorizationReceipt]] = defaultdict(list)
    for item in authority.decisions:
        stamp = _instant(item.observed_at)
        grouped[(item.provider, item.principal_id, item.action, item.resource, stamp.isoformat() if stamp else item.observed_at)].append(
            item
        )
    result: list[CompromiseAction] = []
    for key in sorted(grouped, key=lambda value: tuple(item or "" for item in value)):
        records = grouped[key]
        item = records[0]
        reasons = [*gaps, *_scope_gaps(item, graph.nodes[edge.source], graph.nodes.get(edge.target))]
        stamp = _instant(item.observed_at)
        if stamp is None or not 0 <= (at - stamp).total_seconds() <= request.max_evidence_age_seconds:
            reasons.append("observation_time_unverified")
        decisions = {row.decision for row in records}
        permission = "unknown"
        if not reasons:
            if decisions & {"explicit_deny", "implicit_deny"}:
                permission = "denied_at_collection"
                reasons.append("recorded_denial")
            elif "indeterminate" in decisions:
                reasons.append("authorization_indeterminate")
            elif not all(row.binding_ids for row in records):
                reasons.append("source_bindings_not_recorded")
            else:
                permission = "supported_at_collection"
        result.append(
            CompromiseAction.model_validate(
                {
                    **base,
                    "provider": item.provider,
                    "principal_id": item.principal_id,
                    "action": item.action,
                    "resource": item.resource,
                    "observed_at": key[-1],
                    "binding_ids": sorted({binding for row in records for binding in row.binding_ids}),
                    "permission": permission,
                    "reason_codes": list(dict.fromkeys(reasons)),
                }
            )
        )
    return result, limited, partial


def assess_direct_compromise(graph: UnifiedGraph, request: CompromiseRequest, *, tenant_id: str, at: datetime) -> CompromiseAssessment:
    """Classify at most 512 outgoing relationships from an authorized snapshot.

    The result excludes reverse edges even when generic graph traversal treats
    them as bidirectional. Unknown scope never grants access. No external call,
    graph mutation, permission enforcement or telemetry is performed.
    """
    if not tenant_id or graph.tenant_id != tenant_id:
        raise ValueError("compromise snapshot tenant mismatch")
    if not graph.scan_id:
        raise ValueError("compromise snapshot identity is required")
    if at.tzinfo is None or at.utcoffset() is None:
        raise ValueError("assessment time requires a timezone")
    controlled = _controlled_node(graph, request)
    # adjacency contains synthesized reverse edges for bidirectional traversal;
    # only original stored edge direction is evidence of outbound authority.
    outgoing = sorted((edge for edge in graph.edges if edge.source == controlled), key=lambda edge: edge.id)
    limited = len(outgoing) > request.max_relationships
    reasons = ["relationship_limit"] if limited else []
    actions: list[CompromiseAction] = []
    for edge in outgoing[: request.max_relationships]:
        rows, receipt_limit, partial = _actions(graph, edge, request, at)
        actions.extend(rows)
        limited |= receipt_limit
        if partial:
            reasons.append("authority_projection_partial")
    return CompromiseAssessment(
        tenant_id=tenant_id,
        scan_id=graph.scan_id,
        root_node_id=request.root_node_id,
        assumed_control_node_id=controlled,
        assessed_at=at.astimezone(timezone.utc).isoformat(),
        exploitation="assumed_not_verified" if request.assume_exploitation else "not_evaluated",
        relationships_examined=min(len(outgoing), request.max_relationships),
        truncated=limited,
        max_relationships=request.max_relationships,
        max_evidence_age_seconds=request.max_evidence_age_seconds,
        reason_codes=sorted(set(reasons)),
        actions=actions,
    )
