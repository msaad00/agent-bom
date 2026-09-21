"""Exact-scope recorded-access comparison, without a remediation-success verdict.

This is a producer contract foundation, not a public submission endpoint. Callers
must obtain receipts from a trusted collector and authorize their tenant before
calling it. Digests bind content, not its authenticity. Existing scan/scenario
payloads cannot be upgraded into these receipts by filling missing fields.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Literal, Self, TypedDict

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent_bom.cloud.authorization_evaluator import evaluate_authorization
from agent_bom.cloud.authorization_evidence import (
    AuthorizationDecision,
    AuthorizationEvaluation,
    AuthorizationEvidenceBundle,
    AuthorizationPlane,
    AuthorizationProvider,
    AuthorizationRequest,
    EvidenceSourceState,
)
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.correlation import correlation_graph_digest
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.hop_evidence import authority_evidence
from agent_bom.graph.types import RelationshipType

Identifier = Annotated[str, Field(min_length=1, max_length=2048, pattern=r"^\S(?:.*\S)?$")]
Digest = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]
CoverageComponent = Literal["authorization", "identity_binding", "policy_conditions", "session_context", "alternate_paths"]
_REQUIRED_COVERAGE = frozenset({"authorization", "identity_binding", "policy_conditions", "session_context", "alternate_paths"})
_ACCESS_RELATIONSHIPS = frozenset({RelationshipType.CAN_ACCESS, RelationshipType.HAS_PERMISSION})
_IDENTITY_RELATIONSHIPS = frozenset({RelationshipType.AUTHENTICATES_AS, RelationshipType.ASSUMES, RelationshipType.MEMBER_OF})


class _Receipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class CoverageReceipt(_Receipt):
    component: CoverageComponent
    state: EvidenceSourceState
    evidence_ref: Identifier


class PrincipalReceipt(_Receipt):
    node_id: Identifier
    principal_id: Identifier
    evidence_ref: Identifier


class ResourceReceipt(_Receipt):
    node_id: Identifier
    resource: Identifier
    evidence_ref: Identifier


class IdentityHopReceipt(_Receipt):
    edge_id: Identifier
    evidence_ref: Identifier
    state: EvidenceSourceState = EvidenceSourceState.UNAVAILABLE


class RevocationReceipt(_Receipt):
    """Collector-observed revocation of a grant, never a proposed operation."""

    binding_id: Identifier
    principal_id: Identifier
    action: Identifier
    resource: Identifier
    observed_at: datetime
    evidence_ref: Identifier

    @model_validator(mode="after")
    def aware_time(self) -> Self:
        _require_aware(self.observed_at)
        return self


class AccessCollectionReceipt(_Receipt):
    schema_version: Literal["graph.access-collection.v1"] = "graph.access-collection.v1"
    basis: Literal["observed"]
    tenant_id: Identifier
    source_id: Identifier
    scope: Identifier
    configuration_digest: Digest
    scan_id: Identifier
    graph_digest: Digest
    authorization_digest: Digest
    started_at: datetime
    completed_at: datetime
    collection_mode: Literal["live", "cached", "unknown"]
    coverage: tuple[CoverageReceipt, ...] = Field(max_length=5)
    principals: tuple[PrincipalReceipt, ...] = Field(max_length=10_000)
    resources: tuple[ResourceReceipt, ...] = Field(max_length=10_000)
    identity_hops: tuple[IdentityHopReceipt, ...] = Field(max_length=20_000)
    revocations: tuple[RevocationReceipt, ...] = Field(default=(), max_length=1000)

    @model_validator(mode="after")
    def unambiguous(self) -> Self:
        _require_aware(self.started_at)
        _require_aware(self.completed_at)
        if self.completed_at < self.started_at:
            raise ValueError("collection completion precedes its start")
        for values in (
            [item.component for item in self.coverage],
            [item.node_id for item in self.principals],
            [item.node_id for item in self.resources],
            [item.edge_id for item in self.identity_hops],
            [item.binding_id for item in self.revocations],
        ):
            if len(values) != len(set(values)):
                raise ValueError("receipt keys must be unambiguous")
        return self


class AccessComparisonRequest(_Receipt):
    tenant_id: Identifier
    baseline_scan_id: Identifier
    candidate_scan_id: Identifier
    baseline_graph_digest: Digest
    candidate_graph_digest: Digest
    source_id: Identifier
    scope: Identifier
    configuration_digest: Digest
    provider: AuthorizationProvider
    origin_node_id: Identifier
    identity_node_id: Identifier
    principal_id: Identifier
    target_node_id: Identifier
    resource: Identifier
    action: Identifier
    plane: AuthorizationPlane = AuthorizationPlane.ANY
    baseline_edge_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=32)
    binding_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def distinct_pins(self) -> Self:
        if self.origin_node_id == self.target_node_id or self.identity_node_id == self.target_node_id:
            raise ValueError("access origin and identity must differ from the target resource")
        if self.baseline_scan_id == self.candidate_scan_id:
            raise ValueError("a rescan must have a different snapshot identifier")
        if len(set(self.baseline_edge_ids)) != len(self.baseline_edge_ids) or len(set(self.binding_ids)) != len(self.binding_ids):
            raise ValueError("selected path and binding identifiers must be distinct")
        return self


class AccessComparisonLimits(_Receipt):
    max_nodes: int = Field(default=2000, ge=1, le=10_000)
    max_edges: int = Field(default=10_000, ge=1, le=50_000)
    max_hops: int = Field(default=16, ge=1, le=32)
    max_age_seconds: int = Field(default=3600, ge=1, le=86_400)
    timeout_ms: int = Field(default=1000, ge=1, le=5000)


class ComparisonReason(StrEnum):
    SCOPE_MISMATCH = "collection_scope_mismatch"
    SNAPSHOT_MISMATCH = "snapshot_identity_mismatch"
    GRAPH_DIGEST_MISMATCH = "snapshot_digest_mismatch"
    AUTH_DIGEST_MISMATCH = "authorization_digest_mismatch"
    COVERAGE = "collection_or_context_incomplete"
    NOT_FRESH = "fresh_collection_not_recorded"
    STALE = "candidate_stale"
    TIME_MISMATCH = "collection_time_mismatch"
    NODE_MISSING = "bound_node_unavailable"
    BASELINE = "baseline_access_not_established"
    REVOCATION = "revocation_not_recorded"
    REVOCATION_CONFLICT = "revocation_conflicts_with_current_authorization"
    POLICY = "authorization_indeterminate"
    HOP = "hop_receipt_unavailable"
    BUDGET = "comparison_budget_exhausted"
    INCONSISTENT = "authorization_graph_inconsistent"


class _ComparisonPins(TypedDict):
    baseline_scan_id: str
    candidate_scan_id: str
    baseline_receipt_digest: str
    candidate_receipt_digest: str
    request_digest: str
    compared_at: datetime
    limits: AccessComparisonLimits


class AccessComparisonReceipt(_Receipt):
    schema_version: Literal["graph.access-comparison.v1"] = "graph.access-comparison.v1"
    comparison_method: Literal["azure-gcp-recorded-authority.v1"] = "azure-gcp-recorded-authority.v1"
    limits: AccessComparisonLimits
    outcome: Literal["recorded_authorization_removed", "recorded_access_remains", "unavailable_evidence"]
    claim_scope: Literal["recorded_authorization_only"] = "recorded_authorization_only"
    remediation_verified: Literal[False] = False
    successful_action_proven: Literal[False] = False
    baseline_scan_id: Identifier
    candidate_scan_id: Identifier
    baseline_receipt_digest: Digest
    candidate_receipt_digest: Digest
    request_digest: Digest
    compared_at: datetime
    selected_authorization_removed: bool | None = None
    remaining_path: tuple[Identifier, ...] = Field(default=(), max_length=33)
    remaining_edge_ids: tuple[Identifier, ...] = Field(default=(), max_length=32)
    revocation_evidence_refs: tuple[Identifier, ...] = Field(default=(), max_length=16)
    reason_codes: tuple[ComparisonReason, ...] = Field(default=(), max_length=8)

    @model_validator(mode="after")
    def consistent_outcome(self) -> Self:
        _require_aware(self.compared_at)
        if self.outcome == "unavailable_evidence":
            if (
                not self.reason_codes
                or self.selected_authorization_removed is not None
                or self.remaining_path
                or self.remaining_edge_ids
                or self.revocation_evidence_refs
            ):
                raise ValueError("unavailable evidence cannot assert a comparison outcome")
        else:
            if self.reason_codes or self.selected_authorization_removed is None:
                raise ValueError("recorded outcomes require an established authorization state")
            if bool(self.revocation_evidence_refs) != self.selected_authorization_removed:
                raise ValueError("removed authorization requires revocation evidence")
            if self.outcome == "recorded_access_remains":
                if len(self.remaining_path) < 2 or len(self.remaining_edge_ids) != len(self.remaining_path) - 1:
                    raise ValueError("remaining access requires one complete path witness")
            elif not self.selected_authorization_removed or self.remaining_path or self.remaining_edge_ids:
                raise ValueError("removed authorization cannot include a remaining path")
        return self


@dataclass(frozen=True)
class AccessEvidenceSnapshot:
    receipt: AccessCollectionReceipt
    graph: UnifiedGraph
    authorization: AuthorizationEvidenceBundle


def _require_aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("evidence timestamps must include a timezone")


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def authorization_bundle_digest(bundle: AuthorizationEvidenceBundle) -> str:
    """Bind the complete evaluator input, including source and condition evidence."""
    return _digest(bundle.to_dict())


def _evaluate(snapshot: AccessEvidenceSnapshot, request: AccessComparisonRequest, principal: str) -> AuthorizationEvaluation:
    return evaluate_authorization(
        snapshot.authorization,
        AuthorizationRequest(
            provider=request.provider,
            principal_id=principal,
            action=request.action,
            resource=request.resource,
            plane=request.plane,
        ),
    )


@dataclass
class _ComparisonIndex:
    snapshot: AccessEvidenceSnapshot
    request: AccessComparisonRequest
    principals: dict[str, str]
    identity_hops: dict[str, IdentityHopReceipt]
    evaluations: dict[str, AuthorizationEvaluation]

    @classmethod
    def build(cls, snapshot: AccessEvidenceSnapshot, request: AccessComparisonRequest) -> _ComparisonIndex:
        return cls(
            snapshot,
            request,
            {item.node_id: item.principal_id for item in snapshot.receipt.principals},
            {item.edge_id: item for item in snapshot.receipt.identity_hops},
            {},
        )

    def evaluate(self, principal: str) -> AuthorizationEvaluation:
        if principal not in self.evaluations:
            self.evaluations[principal] = _evaluate(self.snapshot, self.request, principal)
        return self.evaluations[principal]


def _snapshot_gap(snapshot: AccessEvidenceSnapshot, request: AccessComparisonRequest, *, baseline: bool) -> ComparisonReason | None:
    receipt, graph, bundle = snapshot.receipt, snapshot.graph, snapshot.authorization
    if (
        (receipt.tenant_id, receipt.source_id, receipt.scope, receipt.configuration_digest)
        != (
            request.tenant_id,
            request.source_id,
            request.scope,
            request.configuration_digest,
        )
        or bundle.scope != request.scope
        or bundle.provider != request.provider
    ):
        return ComparisonReason.SCOPE_MISMATCH
    scan_id = request.baseline_scan_id if baseline else request.candidate_scan_id
    digest = request.baseline_graph_digest if baseline else request.candidate_graph_digest
    if receipt.scan_id != scan_id or graph.scan_id != scan_id or graph.tenant_id != request.tenant_id:
        return ComparisonReason.SNAPSHOT_MISMATCH
    if receipt.graph_digest != digest or correlation_graph_digest(graph) != digest:
        return ComparisonReason.GRAPH_DIGEST_MISMATCH
    if authorization_bundle_digest(bundle) != receipt.authorization_digest:
        return ComparisonReason.AUTH_DIGEST_MISMATCH
    if receipt.collection_mode != "live":
        return ComparisonReason.NOT_FRESH
    if (
        {item.component for item in receipt.coverage} != _REQUIRED_COVERAGE
        or any(item.state != EvidenceSourceState.COMPLETE for item in receipt.coverage)
        or bundle.incomplete_required_sources()
        or len({item.binding_id for item in bundle.bindings}) != len(bundle.bindings)
        or any(not source.provenance for source in bundle.sources if source.name in bundle.required_sources)
        or graph.completeness.truncated
        or graph.completeness.depth_limited
        or graph.completeness.omitted_nodes
    ):
        return ComparisonReason.COVERAGE
    try:
        graph_time = datetime.fromisoformat(graph.created_at.replace("Z", "+00:00"))
        _require_aware(graph_time)
    except ValueError:
        return ComparisonReason.TIME_MISMATCH
    if not receipt.started_at <= graph_time <= receipt.completed_at:
        return ComparisonReason.TIME_MISMATCH
    observed = bundle.observed_at
    if observed is None or observed.tzinfo is None or not receipt.started_at <= observed <= receipt.completed_at:
        return ComparisonReason.TIME_MISMATCH
    if any(node_id not in graph.nodes for node_id in (request.origin_node_id, request.identity_node_id, request.target_node_id)):
        return ComparisonReason.NODE_MISSING
    principals = {item.node_id: item.principal_id for item in receipt.principals}
    resources = {item.node_id: item.resource for item in receipt.resources}
    if principals.get(request.identity_node_id) != request.principal_id or resources.get(request.target_node_id) != request.resource:
        return ComparisonReason.HOP
    return None


def _hop_allowed(index: _ComparisonIndex, edge: UnifiedEdge) -> tuple[bool, ComparisonReason | None]:
    snapshot, request = index.snapshot, index.request
    # A retained closed edge is historical evidence, even when its collector
    # did not supply valid_to. It cannot witness baseline or residual access.
    if not edge.traversable or edge.activity_id == 3:
        return False, None
    if edge.relationship not in _ACCESS_RELATIONSHIPS | _IDENTITY_RELATIONSHIPS:
        return False, None
    if edge.direction != "directed" or edge.source_scan_id != snapshot.receipt.scan_id:
        return False, ComparisonReason.HOP
    if edge.provenance.get("kind") in {"proposed", "modeled"} or edge.provenance.get("modeled") is True:
        return False, ComparisonReason.HOP
    for value, is_end in ((edge.valid_from, False), (edge.valid_to, True)):
        if value:
            try:
                instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
                _require_aware(instant)
            except ValueError:
                return False, ComparisonReason.HOP
            if (is_end and instant <= snapshot.receipt.completed_at) or (not is_end and instant > snapshot.receipt.completed_at):
                return False, None
    if edge.relationship in _IDENTITY_RELATIONSHIPS:
        # Every reached identity needs a native principal binding so alternate
        # policy evaluation cannot silently skip it. An identity transition is
        # never the terminal action witness, even with a complete hop receipt.
        if edge.target == request.target_node_id or edge.target not in index.principals:
            return False, ComparisonReason.HOP
        receipt = index.identity_hops.get(edge.canonical_id)
        return (True, None) if receipt and receipt.state == EvidenceSourceState.COMPLETE else (False, ComparisonReason.HOP)
    if edge.target != request.target_node_id:
        # Access to a different resource is not authority to assume its identity.
        return False, None
    authority = authority_evidence(edge.evidence)
    if not authority or authority["status"] != "recorded" or not authority["decisions"]:
        return False, ComparisonReason.HOP
    principal = index.principals.get(edge.source)
    observed_at = snapshot.authorization.observed_at
    if observed_at is None:
        return False, ComparisonReason.HOP
    matching = False
    for decision in authority["decisions"]:
        if (
            decision["provider"] != request.provider.value
            or decision.get("principal_id") != principal
            or decision.get("resource") != request.resource
        ):
            return False, ComparisonReason.HOP
        if decision["action"] != request.action:
            continue
        try:
            decision_time = datetime.fromisoformat(str(decision.get("observed_at") or "").replace("Z", "+00:00"))
            _require_aware(decision_time)
        except ValueError:
            return False, ComparisonReason.HOP
        evaluation = index.evaluate(principal or "")
        if (
            decision["decision"] != "allow"
            or evaluation.decision is not AuthorizationDecision.ALLOW
            or not decision["binding_ids"]
            or not set(decision["binding_ids"]) <= set(evaluation.matched_allow_bindings)
            or decision_time != observed_at
        ):
            return False, ComparisonReason.HOP
        matching = True
    return matching, None


def _remaining_path(
    index: _ComparisonIndex,
    limits: AccessComparisonLimits,
    deadline: float,
) -> tuple[tuple[str, ...], tuple[str, ...], ComparisonReason | None]:
    snapshot, request = index.snapshot, index.request
    graph = snapshot.graph
    if len(graph.nodes) > limits.max_nodes or len(graph.edges) > limits.max_edges:
        return (), (), ComparisonReason.BUDGET
    adjacency: dict[str, list[UnifiedEdge]] = {}
    for edge in graph.edges:
        adjacency.setdefault(edge.source, []).append(edge)
    queue: deque[tuple[str, tuple[str, ...], tuple[str, ...]]] = deque([(request.origin_node_id, (request.origin_node_id,), ())])
    visited = {request.origin_node_id}
    found: tuple[tuple[str, ...], tuple[str, ...]] = ((), ())
    materialized_access: set[str] = set()
    while queue:
        current, path, edge_ids = queue.popleft()
        if time.monotonic() >= deadline:
            return (), (), ComparisonReason.BUDGET
        for edge in sorted(adjacency.get(current, []), key=lambda item: item.canonical_id):
            allowed, reason = _hop_allowed(index, edge)
            if reason:
                return (), (), reason
            if not allowed:
                continue
            if edge.target == request.target_node_id:
                materialized_access.add(edge.source)
            if edge.target in visited:
                continue
            if edge.target not in graph.nodes:
                return (), (), ComparisonReason.NODE_MISSING
            if len(edge_ids) >= limits.max_hops:
                return (), (), ComparisonReason.BUDGET
            next_path, next_edges = (*path, edge.target), (*edge_ids, edge.canonical_id)
            visited.add(edge.target)
            if edge.target == request.target_node_id:
                found = (next_path, next_edges)
            else:
                queue.append((edge.target, next_path, next_edges))
    for node_id in visited - {request.target_node_id}:
        principal = index.principals.get(node_id)
        if principal:
            decision = index.evaluate(principal).decision
            if decision is AuthorizationDecision.INDETERMINATE:
                return (), (), ComparisonReason.POLICY
            if decision is AuthorizationDecision.ALLOW and node_id not in materialized_access:
                return (), (), ComparisonReason.INCONSISTENT
        if time.monotonic() >= deadline:
            return (), (), ComparisonReason.BUDGET
    return *found, None


def compare_recorded_access(
    baseline: AccessEvidenceSnapshot,
    candidate: AccessEvidenceSnapshot,
    request: AccessComparisonRequest,
    *,
    now: datetime,
    limits: AccessComparisonLimits | None = None,
) -> AccessComparisonReceipt:
    """Compare trusted, pinned receipts; never mutate grants, snapshots or campaigns.

    A removed result requires a recorded revocation, complete same-scope live
    collection, an evaluator-proven baseline, a current deny, and exhaustive
    traversal of the supported recorded authority relationships within bounds.
    """
    _require_aware(now)
    limits = limits or AccessComparisonLimits()
    deadline = time.monotonic() + limits.timeout_ms / 1000
    common = _ComparisonPins(
        baseline_scan_id=request.baseline_scan_id,
        candidate_scan_id=request.candidate_scan_id,
        baseline_receipt_digest=_digest(baseline.receipt.model_dump(mode="json")),
        candidate_receipt_digest=_digest(candidate.receipt.model_dump(mode="json")),
        request_digest=_digest(request.model_dump(mode="json")),
        compared_at=now,
        limits=limits,
    )

    def unavailable(reason: ComparisonReason) -> AccessComparisonReceipt:
        return AccessComparisonReceipt(**common, outcome="unavailable_evidence", reason_codes=(reason,))

    for snapshot, is_baseline in ((baseline, True), (candidate, False)):
        bundle_size = sum(
            len(items)
            for items in (
                snapshot.authorization.bindings,
                snapshot.authorization.role_definitions,
                snapshot.authorization.memberships,
                snapshot.authorization.resource_ancestry,
            )
        )
        if len(snapshot.graph.nodes) > limits.max_nodes or len(snapshot.graph.edges) > limits.max_edges or bundle_size > limits.max_edges:
            return unavailable(ComparisonReason.BUDGET)
        reason = _snapshot_gap(snapshot, request, baseline=is_baseline)
        if reason:
            return unavailable(reason)
    if candidate.receipt.started_at <= baseline.receipt.completed_at or candidate.receipt.completed_at > now:
        return unavailable(ComparisonReason.TIME_MISMATCH)
    if now - candidate.receipt.completed_at > timedelta(seconds=limits.max_age_seconds):
        return unavailable(ComparisonReason.STALE)
    baseline_index, candidate_index = _ComparisonIndex.build(baseline, request), _ComparisonIndex.build(candidate, request)
    if len(request.baseline_edge_ids) > limits.max_hops or time.monotonic() >= deadline:
        return unavailable(ComparisonReason.BUDGET)
    before = baseline_index.evaluate(request.principal_id)
    if before.decision is not AuthorizationDecision.ALLOW or not set(request.binding_ids) <= set(before.matched_allow_bindings):
        return unavailable(ComparisonReason.BASELINE)
    by_id = {edge.canonical_id: edge for edge in baseline.graph.edges}
    current = request.origin_node_id
    selected_nodes = [current]
    for edge_id in request.baseline_edge_ids:
        edge = by_id.get(edge_id)
        if edge is None or edge.source != current or not _hop_allowed(baseline_index, edge)[0]:
            return unavailable(ComparisonReason.BASELINE)
        current = edge.target
        selected_nodes.append(current)
    if current != request.target_node_id or selected_nodes[-2] != request.identity_node_id:
        return unavailable(ComparisonReason.BASELINE)
    terminal_authority = authority_evidence(by_id[request.baseline_edge_ids[-1]].evidence)
    recorded_binding_ids = {
        binding_id
        for decision in (terminal_authority or {}).get("decisions", [])
        if decision["action"] == request.action
        for binding_id in decision["binding_ids"]
    }
    if not set(request.binding_ids) <= recorded_binding_ids:
        return unavailable(ComparisonReason.BASELINE)
    after = candidate_index.evaluate(request.principal_id)
    if after.decision is AuthorizationDecision.INDETERMINATE:
        return unavailable(ComparisonReason.POLICY)
    remaining, edge_ids, reason = _remaining_path(candidate_index, limits, deadline)
    if reason:
        return unavailable(reason)
    candidate_binding_ids = {item.binding_id for item in candidate.authorization.bindings}
    selected_still_present = bool(set(request.binding_ids) & candidate_binding_ids)
    revocations = [
        item
        for item in candidate.receipt.revocations
        if (
            item.binding_id in request.binding_ids
            and item.principal_id == request.principal_id
            and item.action == request.action
            and item.resource == request.resource
            and candidate.receipt.started_at <= item.observed_at <= candidate.receipt.completed_at
        )
    ]
    if selected_still_present:
        if revocations:
            return unavailable(ComparisonReason.REVOCATION_CONFLICT)
        if after.decision is not AuthorizationDecision.ALLOW or not remaining:
            return unavailable(ComparisonReason.INCONSISTENT)
        return AccessComparisonReceipt(
            **common,
            outcome="recorded_access_remains",
            selected_authorization_removed=False,
            remaining_path=remaining,
            remaining_edge_ids=edge_ids,
        )
    if {item.binding_id for item in revocations} != set(request.binding_ids):
        return unavailable(ComparisonReason.REVOCATION)
    if after.decision is AuthorizationDecision.ALLOW and not remaining:
        return unavailable(ComparisonReason.INCONSISTENT)
    return AccessComparisonReceipt(
        **common,
        outcome="recorded_access_remains" if remaining else "recorded_authorization_removed",
        selected_authorization_removed=True,
        remaining_path=remaining,
        remaining_edge_ids=edge_ids,
        revocation_evidence_refs=tuple(item.evidence_ref for item in revocations),
    )
