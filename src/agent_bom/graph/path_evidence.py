"""Truthful, per-hop evidence receipts for materialized attack paths."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.types import RelationshipType

_RUNTIME_RELATIONSHIPS = frozenset(
    {
        RelationshipType.INVOKED.value,
        RelationshipType.ACCESSED.value,
    }
)


def _relationship(edge: UnifiedEdge) -> str:
    return edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)


def _correlation_provenance(edge: UnifiedEdge) -> dict[str, Any]:
    value = edge.provenance.get("correlation") if isinstance(edge.provenance, dict) else None
    return dict(value) if isinstance(value, dict) else {}


def _source_snapshot_ids(edge: UnifiedEdge, graph: UnifiedGraph) -> list[str]:
    correlation = _correlation_provenance(edge)
    raw = correlation.get("source_scan_ids")
    values = [str(item).strip() for item in raw] if isinstance(raw, list) else []
    if not values:
        fallback = str(edge.source_scan_id or graph.scan_id).strip()
        values = [fallback] if fallback else []
    return sorted(set(item for item in values if item))


def _has_relationship_provenance(edge: UnifiedEdge) -> bool:
    """Require an edge-level receipt; snapshot membership alone is structural."""

    correlation = _correlation_provenance(edge)
    source_ids = correlation.get("source_scan_ids")
    return bool(edge.source_scan_id or (isinstance(source_ids, list) and source_ids) or edge.provenance)


def _freshness(edge: UnifiedEdge) -> str:
    correlation = _correlation_provenance(edge)
    value = correlation.get("freshness") or edge.evidence.get("freshness")
    return str(value or "unknown")


def _runtime_state(edge: UnifiedEdge) -> str:
    explicit = edge.evidence.get("runtime_observed_state") or edge.provenance.get("runtime_observed_state")
    if explicit in {"observed", "blocked", "not_observed"}:
        return str(explicit)
    if edge.evidence.get("blocked") or edge.evidence.get("decision") == "blocked":
        return "blocked"
    if _relationship(edge) in _RUNTIME_RELATIONSHIPS or edge.evidence.get("runtime_observed"):
        return "observed"
    return "not_observed"


def _evidence_tier(edge: UnifiedEdge) -> str:
    if _runtime_state(edge) != "not_observed":
        return "runtime_observed"
    serialized = json.dumps({"evidence": edge.evidence, "provenance": edge.provenance}, sort_keys=True, default=str).lower()
    if any(marker in serialized for marker in ("modeled", "modelled", "iac", "cloud_inventory", "cloud-inventory")):
        return "modeled_infrastructure"
    return "static_evidence"


def _analysis(graph: UnifiedGraph, *, hop_count: int) -> dict[str, Any]:
    status = graph.analysis_status.get("attack_path_fusion")
    if status is None:
        return {"status": "complete", "reason_codes": [], "limits": {}, "observed": {"hop_count": hop_count}}
    result = status.to_dict()
    observed = dict(result.get("observed") or {})
    observed["hop_count"] = hop_count
    result["observed"] = observed
    return result


def _edge_for_hop(graph: UnifiedGraph, source: str, target: str, relationship: str) -> UnifiedEdge | None:
    candidates = [
        edge
        for edge in graph.adjacency.get(source, [])
        if edge.target == target and (not relationship or _relationship(edge) == relationship)
    ]
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda edge: (
            bool(edge.traversable),
            bool(_source_snapshot_ids(edge, graph)),
            float(edge.confidence),
            edge.id,
        ),
    )


def annotate_attack_path_evidence(path: AttackPath, graph: UnifiedGraph) -> AttackPath:
    """Attach deterministic hop receipts and conservatively classify truth."""

    receipts: list[dict[str, Any]] = []
    for index, (source, target) in enumerate(zip(path.hops, path.hops[1:])):
        relationship = path.edges[index] if index < len(path.edges) else ""
        edge = _edge_for_hop(graph, source, target, relationship)
        if edge is None:
            receipts.append(
                {
                    "source_node_id": source,
                    "target_node_id": target,
                    "relationship": relationship,
                    "source_snapshot_ids": [],
                    "evidence_tier": "unknown",
                    "confidence": 0.0,
                    "freshness": "unknown",
                    "runtime_observed_state": "not_observed",
                    "direction": "unknown",
                    "traversable": False,
                    "complete": False,
                    "truncated": False,
                }
            )
            continue
        source_ids = _source_snapshot_ids(edge, graph)
        receipts.append(
            {
                "source_node_id": source,
                "target_node_id": target,
                "relationship": _relationship(edge),
                "source_snapshot_ids": source_ids,
                "evidence_tier": _evidence_tier(edge),
                "confidence": float(edge.confidence),
                "freshness": _freshness(edge),
                "runtime_observed_state": _runtime_state(edge),
                "direction": edge.direction,
                "traversable": bool(edge.traversable),
                "complete": bool(
                    edge.traversable
                    and edge.direction == "directed"
                    and source_ids
                    and _has_relationship_provenance(edge)
                    and edge.source == source
                    and edge.target == target
                ),
                "truncated": False,
            }
        )

    analysis = _analysis(graph, hop_count=max(len(path.hops) - 1, 0))
    truncated = analysis.get("status") in {"limited", "skipped", "failed"}
    if truncated:
        for receipt in receipts:
            receipt["truncated"] = True
    path.hop_evidence = receipts
    path.analysis = analysis

    # A path must contain at least one relationship. Without this guard a
    # single-node structural finding satisfies ``all([])`` and is promoted to
    # confirmed despite having no directed, provenance-backed hop.
    all_complete = (
        bool(receipts)
        and len(receipts) == max(len(path.hops) - 1, 0)
        and all(receipt["complete"] and not receipt["truncated"] for receipt in receipts)
    )
    stale = any(str(receipt["freshness"]).startswith("stale") for receipt in receipts)
    if not all_complete and path.reachability != "unlikely":
        path.reachability = "unknown"
        path.composite_risk = min(path.composite_risk, 39.0)
        if "incomplete_hop_evidence" not in path.reachability_basis:
            path.reachability_basis.append("incomplete_hop_evidence")
    elif stale:
        if path.reachability == "confirmed":
            path.reachability = "likely"
        if "stale_evidence_allowed" not in path.reachability_basis:
            path.reachability_basis.append("stale_evidence_allowed")
    elif all_complete and path.reachability in {"unknown", "likely"}:
        path.reachability = "confirmed"
        if "directed_provenance_backed_hops" not in path.reachability_basis:
            path.reachability_basis.append("directed_provenance_backed_hops")
    return path


def _unavailable_dimension(reason: str, **facts: object) -> dict[str, Any]:
    return {
        "status": "unavailable",
        **facts,
        "basis": [],
        "reasonCodes": [reason],
    }


def _path_completeness(path: AttackPath) -> dict[str, Any]:
    """Project only recorded analyzer and hop coverage; never infer complete."""

    analysis = path.analysis if isinstance(path.analysis, Mapping) else {}
    analysis_status = str(analysis.get("status") or "")
    analysis_reasons = [str(item) for item in analysis.get("reason_codes", []) if str(item)]
    receipts = [item for item in path.hop_evidence if isinstance(item, Mapping)]
    expected_hops = max(len(path.hops) - 1, 0)
    base = {
        "expectedHops": expected_hops,
        "evidencedHops": len(receipts),
        "analysisStatus": analysis_status or None,
    }
    if not analysis_status:
        return {"status": "unavailable", **base, "reasonCodes": ["analysis_not_recorded"]}
    if analysis_status == "failed":
        return {"status": "failed", **base, "reasonCodes": analysis_reasons or ["analysis_failed"]}
    if analysis_status in {"skipped", "not_recorded"}:
        return {"status": "unavailable", **base, "reasonCodes": analysis_reasons or [analysis_status]}
    if analysis_status == "limited":
        return {"status": "partial", **base, "reasonCodes": analysis_reasons or ["analysis_limited"]}
    if analysis_status != "complete":
        return {"status": "unavailable", **base, "reasonCodes": ["analysis_status_unknown"]}
    if expected_hops and not receipts:
        return {"status": "unavailable", **base, "reasonCodes": ["hop_evidence_not_recorded"]}
    if len(receipts) != expected_hops or any(not item.get("complete") or item.get("truncated") for item in receipts):
        return {"status": "partial", **base, "reasonCodes": ["incomplete_hop_evidence"]}
    return {"status": "complete", **base, "reasonCodes": []}


def exposure_evidence_dimensions(path: AttackPath, target_node: Any | None) -> dict[str, Any]:
    """Build independent evidence dimensions shared by graph response surfaces."""

    attributes = getattr(target_node, "attributes", {}) if target_node is not None else {}
    attributes = attributes if isinstance(attributes, Mapping) else {}
    completeness = _path_completeness(path)

    reachability_value = str(path.reachability or "").lower()
    reachability_basis = [str(item) for item in path.reachability_basis if str(item)]
    if (
        reachability_value in {"confirmed", "likely", "unlikely"}
        and reachability_basis
        and completeness["status"] in {"complete", "partial"}
    ):
        reachability = {
            "status": completeness["status"],
            "verdict": reachability_value,
            "basis": reachability_basis,
        }
        if completeness["status"] == "partial":
            reachability["reasonCodes"] = list(completeness["reasonCodes"])
    else:
        reachability = _unavailable_dimension("reachability_not_assessed", verdict=None)

    explicit_exploitability = str(attributes.get("exploitability") or "").lower()
    if explicit_exploitability in {"exploitable", "not_exploitable"}:
        exploitability = {
            "status": "complete",
            "verdict": explicit_exploitability,
            "basis": ["finding_attribute:exploitability"],
        }
    elif attributes.get("network_exploitable") is True:
        exploitability = {
            "status": "complete",
            "verdict": "exploitable",
            "basis": ["finding_attribute:network_exploitable"],
        }
    else:
        exploitability = _unavailable_dimension("exploitability_not_assessed", verdict=None)

    impact_category = str(attributes.get("impact_category") or "").strip()
    impact = (
        {
            "status": "complete",
            "category": impact_category,
            "basis": ["finding_attribute:impact_category"],
        }
        if impact_category
        else _unavailable_dimension("impact_not_assessed", category=None)
    )

    explicit_actionability = attributes.get("actionability")
    if isinstance(explicit_actionability, bool):
        actionability = {
            "status": "complete",
            "actionable": explicit_actionability,
            "basis": ["finding_attribute:actionability"],
        }
    elif attributes.get("actionable") is True:
        actionability = {
            "status": "complete",
            "actionable": True,
            "basis": ["finding_attribute:actionable"],
        }
    elif attributes.get("fixed_version") or attributes.get("remediation"):
        actionability = {
            "status": "complete",
            "actionable": True,
            "basis": ["finding_remediation_evidence"],
        }
    else:
        actionability = _unavailable_dimension("actionability_not_assessed", actionable=None)

    return {
        "reachability": reachability,
        "exploitability": exploitability,
        "impact": impact,
        "actionability": actionability,
        "completeness": completeness,
    }


__all__ = ["annotate_attack_path_evidence", "exposure_evidence_dimensions"]
