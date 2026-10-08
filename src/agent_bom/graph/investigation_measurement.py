"""Measure reviewed graph evidence without promoting it to independent proof.

Inputs remain in the operator's environment. This evaluator never changes an
asset, invokes a provider, or equates graph absence with successful remediation.
"""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Any, Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictBool, model_validator

from agent_bom.graph.integration_contract import GRAPH_ENVELOPE_VERSION

Identifier = Annotated[str, Field(min_length=1, max_length=2048, pattern=r"^\S(?:.*\S)?$")]
Digest = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Edge(_Contract):
    source: Identifier
    target: Identifier
    relationship: Identifier

    def key(self) -> tuple[str, str, str]:
        return self.source, self.target, self.relationship


class RelationshipReview(Edge):
    snapshot: Literal["before", "after"]
    expected: StrictBool
    evidence_ref: Identifier


class OutcomeCheck(_Contract):
    check_id: Identifier
    edge: Edge
    before_present: StrictBool
    after_present: StrictBool
    verification_ref: Identifier


class Timeline(_Contract):
    investigation_started_at: AwareDatetime
    decision_at: AwareDatetime
    change_applied_at: AwareDatetime
    rescan_started_at: AwareDatetime


class InvestigationReview(_Contract):
    schema_version: Literal["investigation-review.v1"]
    evidence_origin: Literal["fixture", "customer_observed"]
    tenant_id: Identifier
    scope_id: Identifier
    reviewer_ref: Identifier
    reviewed_at: AwareDatetime
    before_digest: Digest
    after_digest: Digest
    timeline: Timeline
    change_evidence_ref: Identifier
    relationships: list[RelationshipReview] = Field(max_length=100_000)
    outcomes: list[OutcomeCheck] = Field(max_length=10_000)

    @model_validator(mode="after")
    def unique_reviews(self) -> Self:
        labels = [(row.snapshot, row.key()) for row in self.relationships]
        if len(labels) != len(set(labels)):
            raise ValueError("duplicate or contradictory relationship review")
        ids = [row.check_id for row in self.outcomes]
        edges = [row.edge.key() for row in self.outcomes]
        if len(ids) != len(set(ids)) or len(edges) != len(set(edges)):
            raise ValueError("duplicate outcome check")
        return self


class Snapshot(_Contract):
    scope_id: Identifier
    collected_at: AwareDatetime
    collection_complete: StrictBool
    source_evidence_ref: Identifier
    graph: dict[str, Any]


def evidence_digest(value: dict[str, Any]) -> str:
    """Bind canonical JSON content; this digest does not attest authenticity."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _graph_index(snapshot: Snapshot) -> tuple[set[str], set[tuple[str, str, str]], bool]:
    graph = snapshot.graph
    # Accept the canonical graph-export shape, not a viewport/Cytoscape alias.
    if graph.get("schema_version") not in {None, "1", "1.0", GRAPH_ENVELOPE_VERSION}:
        raise ValueError("unsupported graph export version")
    for key in ("scan_id", "tenant_id"):
        if not isinstance(graph.get(key), str) or not graph[key].strip():
            raise ValueError("graph scope identifiers are required")
    nodes, edges = graph.get("nodes"), graph.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list) or len(nodes) > 100_000 or len(edges) > 500_000:
        raise ValueError("graph arrays missing or exceed evaluation budget")
    node_ids: set[str] = set()
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str) or not node["id"].strip():
            raise ValueError("invalid graph node identity")
        if node["id"] in node_ids:
            raise ValueError("duplicate graph node identity")
        node_ids.add(node["id"])
    edge_keys: set[tuple[str, str, str]] = set()
    for edge in edges:
        if not isinstance(edge, dict):
            raise ValueError("invalid graph relationship")
        item = Edge.model_validate({key: edge.get(key) for key in ("source", "target", "relationship")})
        if item.source not in node_ids or item.target not in node_ids:
            raise ValueError("dangling graph relationship")
        edge_keys.add(item.key())
    completeness = graph.get("completeness") or {}
    pagination = graph.get("pagination") or {}
    if not isinstance(completeness, dict) or not isinstance(pagination, dict):
        raise ValueError("invalid graph completeness")
    complete = (
        snapshot.collection_complete
        and completeness.get("status") == "complete"
        and completeness.get("complete") is True
        and completeness.get("truncated") is False
        and completeness.get("sampled") is False
        and type(completeness.get("returned")) is int
        and type(completeness.get("total")) is int
        and completeness["returned"] == completeness["total"] == len(node_ids)
        and not completeness.get("reason")
        and not completeness.get("source_completeness")
        and not completeness.get("edges_truncated")
        and not completeness.get("depth_limited")
        and not completeness.get("missing_neighbor_endpoints")
        and not pagination.get("has_more")
        and not pagination.get("next_cursor")
    )
    return node_ids, edge_keys, complete


def _presence(edge: Edge, index: tuple[set[str], set[tuple[str, str, str]], bool]) -> bool | None:
    nodes, edges, complete = index
    if edge.key() in edges:
        return True
    # A vanished entity may represent a scope change or failed collection.
    if not complete or edge.source not in nodes or edge.target not in nodes:
        return None
    return False


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def evaluate_investigation(before: dict[str, Any], after: dict[str, Any], review: dict[str, Any]) -> dict[str, Any]:
    """Evaluate the declared review set, preserving unknowns and denominators.

    Review labels, timeline, origin, collector and change references are supplied
    by the operator. Customer-observed is a declaration, never authentication.
    No real-world remediation verdict or source identifiers leave this function.
    """
    spec = InvestigationReview.model_validate(review)
    snapshots = {"before": Snapshot.model_validate(before), "after": Snapshot.model_validate(after)}
    digests = {"before": evidence_digest(before), "after": evidence_digest(after)}
    if (digests["before"], digests["after"]) != (spec.before_digest, spec.after_digest):
        raise ValueError("review does not bind the supplied snapshot content")
    for snapshot in snapshots.values():
        if snapshot.scope_id != spec.scope_id or snapshot.graph.get("tenant_id") != spec.tenant_id:
            raise ValueError("snapshot tenant or collection scope mismatch")
    if snapshots["before"].graph.get("scan_id") == snapshots["after"].graph.get("scan_id"):
        raise ValueError("rescan requires a distinct snapshot identity")
    timeline = spec.timeline
    times = [
        snapshots["before"].collected_at,
        timeline.investigation_started_at,
        timeline.decision_at,
        timeline.change_applied_at,
        timeline.rescan_started_at,
        snapshots["after"].collected_at,
        spec.reviewed_at,
    ]
    if times != sorted(times) or snapshots["before"].collected_at >= snapshots["after"].collected_at:
        raise ValueError("investigation, change and rescan chronology is invalid")
    indexes = {name: _graph_index(snapshot) for name, snapshot in snapshots.items()}
    counts = dict.fromkeys(("true_positive", "false_positive", "true_negative", "false_negative", "unknown"), 0)
    reviewed_observed = 0
    for row in spec.relationships:
        actual = _presence(row, indexes[row.snapshot])
        if actual is None:
            counts["unknown"] += 1
        else:
            reviewed_observed += int(actual)
            key = ("true_" if actual == row.expected else "false_") + ("positive" if actual else "negative")
            counts[key] += 1
    observed = sum(len(index[1]) for index in indexes.values())
    outcomes = dict.fromkeys(("evidence_supported", "failed", "unknown"), 0)
    for check in spec.outcomes:
        states = [_presence(check.edge, indexes[name]) for name in ("before", "after")]
        if None in states:
            outcomes["unknown"] += 1
        elif states == [check.before_present, check.after_present]:
            outcomes["evidence_supported"] += 1
        else:
            outcomes["failed"] += 1
    tp, fp, tn, fn = (counts[key] for key in ("true_positive", "false_positive", "true_negative", "false_negative"))
    return {
        "schema_version": "investigation-measurement.v1",
        "evidence_origin": spec.evidence_origin,
        "independently_verified": False,
        "before_digest": digests["before"],
        "after_digest": digests["after"],
        "review_digest": evidence_digest(review),
        "relationships": {
            **counts,
            "reviewed": len(spec.relationships),
            "observed": observed,
            "unreviewed_observed": observed - reviewed_observed,
            "observed_review_coverage": _ratio(reviewed_observed, observed),
            "precision": _ratio(tp, tp + fp),
            "recall": _ratio(tp, tp + fn),
            "false_positive_rate": _ratio(fp, fp + tn),
            "false_discovery_rate": _ratio(fp, tp + fp),
        },
        "timing": {
            "source": "operator_reported_timestamps",
            "reported_investigation_seconds": (timeline.decision_at - timeline.investigation_started_at).total_seconds(),
            "reported_change_to_rescan_seconds": (snapshots["after"].collected_at - timeline.change_applied_at).total_seconds(),
        },
        "outcomes": {**outcomes, "reviewed": len(spec.outcomes)},
        "collection_complete": {name: index[2] for name, index in indexes.items()},
    }
