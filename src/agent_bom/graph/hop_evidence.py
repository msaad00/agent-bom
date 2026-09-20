"""Bounded public projection of stored path receipts, without raw payloads."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agent_bom.graph.container import AttackPath


class HopEvidenceReceipt(BaseModel):
    """Classified receipt fields shared by human and agent path responses.

    Unknown imported fields are intentionally excluded: arbitrary tool output,
    prompts, credentials and provider payloads are not a public hop contract.
    Missing legacy facts stay unknown; they are never recomputed in a client.
    """

    model_config = ConfigDict(extra="ignore", strict=True, allow_inf_nan=False)

    source_node_id: str
    target_node_id: str
    relationship: str
    source_snapshot_ids: list[str] = Field(default_factory=list, max_length=50)
    relationship_provenance: Literal["recorded", "unavailable"] = "unavailable"
    correlation_identity_status: Literal["current", "recomputation_required", "unavailable"] = "unavailable"
    evidence_tier: Literal["static_evidence", "modeled_infrastructure", "runtime_observed", "unknown"] = "unknown"
    confidence: float | None = Field(default=None, ge=0, le=1)
    freshness: Literal["fresh", "stale", "stale_allowed", "unknown"] = "unknown"
    runtime_observed_state: Literal["observed", "blocked", "not_observed", "unknown"] = "unknown"
    runtime_outcome: Literal["blocked", "failed", "unknown"] = "unknown"
    direction: Literal["directed", "bidirectional", "unknown"] = "unknown"
    traversable: bool = False
    complete: bool = False
    truncated: bool = False
    reason_codes: list[str] = Field(default_factory=list, max_length=20)


def exposure_hop_evidence(path: AttackPath) -> list[dict]:
    """Return one classified receipt or explicit gap for every ordered hop."""
    result: list[dict] = []
    for index, (source, target) in enumerate(zip(path.hops, path.hops[1:])):
        relationship = path.edges[index] if index < len(path.edges) else ""
        missing = index >= len(path.hop_evidence)
        raw = path.hop_evidence[index] if not missing else {}
        try:
            receipt = HopEvidenceReceipt.model_validate(raw)
            if (receipt.source_node_id, receipt.target_node_id, receipt.relationship) != (source, target, relationship):
                raise ValueError("hop_identity_mismatch")
        except (ValidationError, ValueError):
            receipt = HopEvidenceReceipt(
                source_node_id=source,
                target_node_id=target,
                relationship=relationship,
                reason_codes=["hop_evidence_not_recorded" if missing else "invalid_hop_receipt"],
            )
        result.append(receipt.model_dump(mode="json"))
    return result
