"""Bounded public projection of stored path receipts, without raw payloads."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agent_bom.graph.container import AttackPath

EvidenceId = Annotated[str, Field(min_length=1, max_length=1024)]


class AuthorizationReceipt(BaseModel):
    """A recorded evaluator request, not a re-evaluation of current access."""

    model_config = ConfigDict(extra="ignore", strict=True)
    source: Literal["authorization-evidence"]
    provider: Literal["azure", "gcp"]
    decision: Literal["allow", "explicit_deny", "implicit_deny", "indeterminate"]
    action: EvidenceId
    principal_id: EvidenceId | None = None
    resource: Annotated[str, Field(min_length=1, max_length=2048)] | None = None
    binding_ids: list[EvidenceId] = Field(default_factory=list, max_length=16)
    observed_at: Annotated[str, Field(max_length=64)] | None = None


class PermissionWitness(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    access: Literal["direct", "group", "assume_chain"]
    grant_principal_id: EvidenceId
    grant_edge_id: EvidenceId
    source_edge_ids: list[EvidenceId] = Field(min_length=1, max_length=7)


class NativeGrantReceipt(BaseModel):
    """An inventoried native grant; no session authorization verdict is implied."""

    model_config = ConfigDict(extra="ignore", strict=True)
    source: Literal["snowflake-objects"]
    privilege: EvidenceId
    account: EvidenceId | None = None
    role: EvidenceId | None = None
    object_fqn: Annotated[str, Field(min_length=1, max_length=2048)] | None = None
    object_type: EvidenceId | None = None


class PermissionDerivationReceipt(BaseModel):
    """Selected structural witnesses; never an exhaustive set of permissions."""

    model_config = ConfigDict(extra="ignore", strict=True)
    basis: Literal["recorded_graph_connections"]
    source_scan_id: EvidenceId
    path_selection: Literal["one_shortest_path_per_grant_and_access"]
    paths: list[PermissionWitness] = Field(max_length=16)
    truncated: bool


class HopAuthorityEvidence(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    status: Literal["recorded", "partial"]
    decisions: list[AuthorizationReceipt] = Field(default_factory=list, max_length=16)
    native_grants: list[NativeGrantReceipt] = Field(default_factory=list, max_length=16)
    derivation: PermissionDerivationReceipt | None = None
    reason_codes: list[str] = Field(default_factory=list, max_length=8)


def authority_evidence(evidence: Mapping[str, Any]) -> dict[str, Any] | None:
    """Project allowlisted, bounded fields without copying arbitrary policy/tool data."""
    raw = evidence.get("authorization_decisions")
    if raw is None and evidence.get("source") == "authorization-evidence" and "action" in evidence:
        raw = [evidence]
    raw_derivation = evidence.get("permission_derivation")
    raw_grants = evidence.get("grant_receipts")
    if raw_grants is None and evidence.get("source") == "snowflake-objects" and "privilege" in evidence:
        raw_grants = [evidence]
    if raw is None and raw_derivation is None and raw_grants is None:
        return None
    reasons: list[str] = []
    decisions: list[AuthorizationReceipt] = []
    grants: list[NativeGrantReceipt] = []
    if raw_grants is not None:
        if not isinstance(raw_grants, list):
            reasons.append("invalid_native_grant")
        else:
            if len(raw_grants) > 16:
                reasons.append("native_grant_limit")
            for item in raw_grants[:16]:
                try:
                    grants.append(NativeGrantReceipt.model_validate(item))
                except ValidationError:
                    reasons.append("invalid_native_grant")
    if raw is not None:
        if not isinstance(raw, list):
            reasons.append("invalid_authorization_receipt")
        else:
            if len(raw) > 16:
                reasons.append("authorization_receipt_limit")
            for item in raw[:16]:
                try:
                    decisions.append(AuthorizationReceipt.model_validate(item))
                except ValidationError:
                    reasons.append("invalid_authorization_receipt")
    derivation = None
    if raw_derivation is not None:
        try:
            derivation = PermissionDerivationReceipt.model_validate(raw_derivation)
            if derivation.truncated:
                reasons.append("permission_witnesses_limited")
        except ValidationError:
            reasons.append("invalid_permission_witnesses")
    if not decisions and not grants and derivation is None:
        reasons.append("authority_receipts_unavailable")
    return HopAuthorityEvidence(
        status="partial" if reasons else "recorded",
        decisions=decisions,
        native_grants=grants,
        derivation=derivation,
        reason_codes=list(dict.fromkeys(reasons)),
    ).model_dump(mode="json")


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
    authority: HopAuthorityEvidence | None = None


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
        payload = receipt.model_dump(mode="json")
        if receipt.authority is None:
            payload.pop("authority")
        result.append(payload)
    return result


def hop_evidence_schema() -> dict[str, Any]:
    """Inline model references for embedding in the existing response schemas."""
    schema = HopEvidenceReceipt.model_json_schema()
    definitions = schema.pop("$defs", {})

    def inline(value: Any) -> Any:
        if isinstance(value, dict):
            if "$ref" in value:
                return inline(definitions[value["$ref"].rsplit("/", 1)[-1]])
            return {key: inline(item) for key, item in value.items()}
        if isinstance(value, list):
            return [inline(item) for item in value]
        return value

    return inline(schema)
