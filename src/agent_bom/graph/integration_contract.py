"""Additive graph interchange and evidence provenance contract.

This projection describes recorded evidence. Collector names never establish
successful execution, authorization, or present-day freshness.
"""

from __future__ import annotations

from typing import Any

GRAPH_ENVELOPE_VERSION = "agent-bom.graph/v1"
EVIDENCE_VERSION = "agent-bom.graph-evidence/v1"
_EVIDENCE_TIERS = frozenset({"modeled_infrastructure", "static_evidence", "runtime_observed", "static_scan", "recorded", "derived"})


def validate_graph_version(payload: dict[str, Any]) -> None:
    """Accept legacy unversioned graphs; reject unsupported explicit versions."""
    if "schema_version" in payload and payload["schema_version"] != GRAPH_ENVELOPE_VERSION:
        raise ValueError("Unsupported graph schema version")


def node_evidence_provenance(node: Any) -> dict[str, Any]:
    attrs = node.attributes
    tier = attrs.get("evidence_tier")
    correlation = attrs.get("correlation")
    correlation = correlation if isinstance(correlation, dict) else {}
    snapshots = correlation.get("source_scan_ids", [])
    return {
        "schema_version": EVIDENCE_VERSION,
        "tier": tier if isinstance(tier, str) and tier in _EVIDENCE_TIERS else "unspecified",
        "sources": sorted({value for value in node.data_sources if isinstance(value, str) and value}),
        "source_snapshot_ids": sorted({value for value in snapshots if isinstance(value, str) and value})
        if isinstance(snapshots, list)
        else [],
        "first_seen": node.first_seen or None,
        "last_seen": node.last_seen or None,
        "time_basis": "recorded_observation",
        "execution": "not_established",
    }


GRAPH_COMPATIBILITY = {
    "envelope": GRAPH_ENVELOPE_VERSION,
    "evidence": EVIDENCE_VERSION,
    "legacy_unversioned": "accepted",
    "unknown_optional_fields": "ignored",
    "unsupported_major_version": "rejected",
    "unknown_entity_or_relationship_kind": "rejected",
    "identity": "canonical_id with tenant and snapshot scope",
    "execution": "collector names and topology do not establish successful access",
}
