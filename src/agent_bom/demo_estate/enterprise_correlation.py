"""Normalize and correlate the versioned enterprise demo evidence.

The adapter deliberately uses the same relationship and graph-projection
builders as live proxy/runtime events. Provider payloads remain in the raw
fixture; normalized output carries only stable references and provenance.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agent_bom.demo_estate.enterprise import (
    CollectionStatus,
    EnterpriseEstate,
    EstateAsset,
    EstateStage,
    EvidenceSource,
    RawObservation,
    verify_observation_hash,
)
from agent_bom.event_normalization import (
    build_agentic_identity_graph_projection,
    build_event_ref,
    build_event_relationships,
)

NORMALIZATION_VERSION = "enterprise_event.v1"
CORRELATION_VERSION = "enterprise_correlation.v1"


class NormalizedEnterpriseEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    normalization_version: str = NORMALIZATION_VERSION
    event_id: str
    tenant_id: str
    stage: EstateStage
    source: EvidenceSource
    event_type: str
    observed_at: datetime
    trace_id: str
    actor_id: str
    resource_ids: tuple[str, ...]
    evidence_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_run_id: str
    event_relationships: dict[str, Any]
    graph_projection: dict[str, Any]
    # The enforcement verdict this event recorded, normalized out of the
    # provider payload. A scalar, not the payload: normalized output still
    # carries no raw provider body, but a correlation that has to report whether
    # an egress was blocked cannot do it by guessing from the event's source.
    policy_decision: str = ""


class EnterpriseCorrelation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    correlation_version: str = CORRELATION_VERSION
    correlation_id: str
    tenant_id: str
    trace_id: str
    kind: str
    outcome: str
    started_at: datetime
    ended_at: datetime
    event_ids: tuple[str, ...]
    sources: tuple[EvidenceSource, ...]
    asset_ids: tuple[str, ...]
    asset_path: tuple[str, ...]
    data_classifications: tuple[str, ...]
    evidence_hashes: tuple[str, ...]
    evidence_quality: str
    incomplete_sources: tuple[EvidenceSource, ...] = ()


class EnterpriseCollectionHealth(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source: EvidenceSource
    status: CollectionStatus
    records_read: int
    watermark: str
    source_schema: str
    schema_url: str
    failure_code: str = ""


class EnterpriseCorrelationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = CORRELATION_VERSION
    estate_id: str
    tenant_id: str
    estate_content_hash: str
    events: tuple[NormalizedEnterpriseEvent, ...]
    correlations: tuple[EnterpriseCorrelation, ...]
    collection_health: tuple[EnterpriseCollectionHealth, ...]
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @property
    def complete_source_count(self) -> int:
        return sum(1 for row in self.collection_health if row.status is CollectionStatus.COMPLETE)

    @property
    def partial_source_count(self) -> int:
        return sum(1 for row in self.collection_health if row.status is CollectionStatus.PARTIAL)

    def correlation_by_trace(self, trace_id: str) -> EnterpriseCorrelation | None:
        return next((row for row in self.correlations if row.trace_id == trace_id), None)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _actor_type(actor_id: str) -> str:
    lowered = actor_id.casefold()
    if lowered.startswith("agent:"):
        return "agent"
    if "service-principal" in lowered:
        return "service_principal"
    if "serviceaccount" in lowered or "service_account" in lowered:
        return "service_account"
    if lowered.startswith("arn:aws:sts"):
        return "federated_identity"
    if lowered.startswith("snowflake_role:"):
        return "service_account"
    return "user"


_BLOCKED_DECISIONS = frozenset({"block", "blocked", "deny", "denied"})
_ALLOWED_DECISIONS = frozenset({"allow", "allowed", "permit"})


def normalize_policy_decision(observation: RawObservation) -> str:
    """Read the enforcement verdict a provider recorded, in that provider's spelling.

    An MCP gateway writes ``{"decision": "block"}`` at the top level; an OTel
    GenAI span writes ``attributes["agent_bom.decision"]``. Both mean the same
    thing and neither is inferable from the event's source — which is exactly
    what :func:`_correlation_kind` used to do, labelling *every* trace that
    touched an LLM span ``blocked``. That published a verdict the evidence did
    not support on traces where nothing was blocked at all.

    Returns ``""`` when the payload carries no verdict, so "not enforced" and
    "allowed" stay distinguishable.
    """
    payload = observation.raw_payload
    raw = payload.get("decision")
    if raw is None:
        attributes = payload.get("attributes")
        if isinstance(attributes, dict):
            raw = attributes.get("agent_bom.decision")
    if raw is None:
        return ""
    lowered = str(raw).strip().casefold()
    if lowered in _BLOCKED_DECISIONS:
        return "blocked"
    if lowered in _ALLOWED_DECISIONS:
        return "allowed"
    return ""


def _asset_ref_type(asset: EstateAsset) -> str:
    if asset.provider == "mcp" and asset.resource_type == "tool":
        return "tool"
    if asset.provider == "mcp" and asset.resource_type == "server":
        return "server"
    if asset.resource_type == "service_principal":
        return "service_principal"
    if asset.resource_type == "service_account":
        return "service_account"
    if asset.resource_type in {"database", "table"}:
        return "dataset"
    if asset.provider in {"aws", "azure", "gcp", "kubernetes"}:
        return "cloud_resource"
    return "resource"


def _asset_ref(asset: EstateAsset, *, role: str) -> dict[str, Any]:
    ref = build_event_ref(
        ref_type=_asset_ref_type(asset),
        ref_id=asset.asset_id,
        name=asset.display_name,
        role=role,
        source_field="resource_ids",
        attributes={
            "provider": asset.provider,
            "resource_type": asset.resource_type,
            "environment": asset.environment,
            "account_scope": asset.account_scope,
        },
    )
    if ref is None:  # validated assets always carry a non-empty stable id
        raise ValueError(f"could not normalize asset reference: {asset.asset_id}")
    return ref


def _normalize_event(
    observation: RawObservation,
    *,
    tenant_id: str,
    assets_by_id: dict[str, EstateAsset],
) -> NormalizedEnterpriseEvent:
    if not verify_observation_hash(observation):
        raise ValueError(f"evidence hash mismatch for event {observation.event_id}")

    actor = build_event_ref(
        ref_type=_actor_type(observation.actor_id),
        ref_id=observation.actor_id,
        name=observation.actor_id,
        role="actor",
        source_field="actor_id",
    )
    if actor is None:
        raise ValueError(f"could not normalize actor for event {observation.event_id}")

    targets: list[dict[str, Any]] = []
    resources: list[dict[str, Any]] = []
    for resource_id in observation.resource_ids:
        asset = assets_by_id[resource_id]
        ref_type = _asset_ref_type(asset)
        if ref_type == "tool":
            targets.append(_asset_ref(asset, role="invoked_tool"))
        else:
            resources.append(_asset_ref(asset, role="observed_resource"))

    relationships = build_event_relationships(
        source=observation.source.value,
        actor=actor,
        targets=targets,
        resources=resources,
    )
    if relationships is None:
        raise ValueError(f"event {observation.event_id} produced no relationships")
    projection = build_agentic_identity_graph_projection(
        relationships,
        event_id=observation.event_id,
        tenant_id=tenant_id,
    )
    if projection is None:
        raise ValueError(f"event {observation.event_id} produced no graph projection")

    return NormalizedEnterpriseEvent(
        event_id=observation.event_id,
        tenant_id=tenant_id,
        stage=observation.stage,
        source=observation.source,
        event_type=observation.event_type,
        observed_at=observation.observed_at,
        trace_id=observation.trace_id,
        actor_id=observation.actor_id,
        resource_ids=observation.resource_ids,
        evidence_hash=observation.provenance.evidence_hash,
        source_run_id=observation.provenance.run_id,
        event_relationships=relationships,
        graph_projection=projection,
        policy_decision=normalize_policy_decision(observation),
    )


def _unique_in_order(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


@dataclass(frozen=True, slots=True)
class _CorrelationRow:
    """The only fields correlation actually reads from an event.

    Correlation groups by trace, orders by time, and reports which assets and
    sources a trace touched. It never reads the normalized refs, relationships,
    or graph projection — so those must not be a prerequisite for computing it.
    Naming the inputs explicitly is what lets both the full normalizing path and
    the light path below share one correlation implementation rather than
    growing a second one that can disagree.
    """

    event_id: str
    stage: EstateStage
    source: EvidenceSource
    event_type: str
    observed_at: datetime
    trace_id: str
    resource_ids: tuple[str, ...]
    evidence_hash: str
    policy_decision: str = ""

    @classmethod
    def from_normalized(cls, event: NormalizedEnterpriseEvent) -> _CorrelationRow:
        return cls(
            event_id=event.event_id,
            stage=event.stage,
            source=event.source,
            event_type=event.event_type,
            observed_at=event.observed_at,
            trace_id=event.trace_id,
            resource_ids=event.resource_ids,
            evidence_hash=event.evidence_hash,
            policy_decision=event.policy_decision,
        )

    @classmethod
    def from_observation(cls, observation: RawObservation) -> _CorrelationRow:
        return cls(
            event_id=observation.event_id,
            stage=observation.stage,
            source=observation.source,
            event_type=observation.event_type,
            observed_at=observation.observed_at,
            trace_id=observation.trace_id,
            resource_ids=observation.resource_ids,
            evidence_hash=observation.provenance.evidence_hash,
            policy_decision=normalize_policy_decision(observation),
        )


def _correlation_kind(events: tuple[_CorrelationRow, ...]) -> tuple[str, str]:
    """Name what a trace is, and report the outcome its evidence recorded.

    The outcome used to be a constant per kind — any trace touching an LLM span
    was ``blocked``. On the hand-authored incident that was true; on a generated
    estate where most model calls succeed it published a verdict nothing had
    reached. Outcomes now come from the enforcement decision the span or gateway
    actually wrote, and a trace with no decision recorded reports ``observed``
    rather than picking one.
    """
    if any(event.stage is EstateStage.REMEDIATED for event in events):
        return "remediation", "enforced"
    decisions = {event.policy_decision for event in events if event.policy_decision}
    if any(event.source is EvidenceSource.OTEL_LLM for event in events):
        if "blocked" in decisions:
            return "data_egress_attempt", "blocked"
        if "allowed" in decisions:
            return "data_egress_attempt", "allowed"
        return "model_invocation", "observed"
    if any("roleAssignments/write" in event.event_type for event in events):
        return "privilege_change", "observed"
    if any("CreateServiceAccountKey" in event.event_type for event in events):
        return "credential_issuance", "observed"
    if len({event.source for event in events}) >= 2:
        return "cross_vendor_trace", "observed"
    # One principal, one window, one system. A real grouping — and named so
    # nobody reads a causal chain into it.
    return "identity_session", "observed"


# The order a path is walked in, so consecutive hops are drawn as consecutive
# edges: code, then the identity it federates into, then the runtime, then the
# tool, then the AI service, then the data, then the model the data reaches.
# A type missing from this list is not excluded from the estate — it is excluded
# from the *path*, because a path that visits nodes in inventory order is a list.
_PATH_TYPES = (
    "repository",
    "workflow",
    "iam_role",
    "service_principal",
    "service_account",
    "role",
    "container_image",
    "cluster",
    "deployment",
    "server",
    "tool",
    "bedrock_agent",
    "vertex_agent",
    "sagemaker_endpoint",
    "vertex_endpoint",
    "azure_openai_deployment",
    "cognitive_services_account",
    "cortex_function",
    "cortex_search_service",
    "spcs_service",
    "gemini_api",
    "bedrock_knowledge_base",
    "ai_search_index",
    "bucket",
    "storage_account",
    "database",
    "sql_database",
    "table",
    "hosted_model",
    "model_artifact",
    "foundation_model",
    "vertex_model",
    "sagemaker_model",
)

# A path longer than this is a roster, not a route. Sessions can touch dozens of
# assets; drawing all of them as one chain produces an unreadable edge and an
# attack path nobody can act on.
#
# Twelve, not eight: the full pipeline is repository → workflow → identity →
# image → cluster → workload → MCP server → tool → AI service → data store →
# table → model. At eight the cap truncated from the tail, which is where the
# *destination* lives — the incident's own path stopped at the MCP tool and
# dropped the PHI table and the model it was trying to reach, turning the one
# chain the demo exists to show into a chain that goes nowhere.
_MAX_PATH_HOPS = 12

# A trace containing one event is not a correlation — it is an event. Emitting
# one anyway is what let the estate report 6,148 correlations of which 6,145
# were a single row grouped with itself.
_MIN_TRACE_EVENTS = 2


def _asset_path(events: tuple[_CorrelationRow, ...], assets_by_id: dict[str, EstateAsset]) -> tuple[str, ...]:
    ordered_ids = _unique_in_order(resource_id for event in events for resource_id in event.resource_ids)
    selected: list[str] = []
    for resource_type in _PATH_TYPES:
        match = next(
            (resource_id for resource_id in ordered_ids if assets_by_id[resource_id].resource_type == resource_type),
            None,
        )
        if match is not None:
            selected.append(match)
    return tuple((selected or list(ordered_ids))[:_MAX_PATH_HOPS])


def _data_classifications(asset_ids: tuple[str, ...], assets_by_id: dict[str, EstateAsset]) -> tuple[str, ...]:
    classifications = {classification for asset_id in asset_ids for classification in assets_by_id[asset_id].data_classifications}
    regulated = classifications & {"phi", "pii", "pci", "restricted"}
    return tuple(sorted(regulated or classifications))


def _build_correlations(
    events: tuple[_CorrelationRow, ...],
    *,
    tenant_id: str,
    assets_by_id: dict[str, EstateAsset],
    status_by_source: dict[EvidenceSource, CollectionStatus],
) -> tuple[EnterpriseCorrelation, ...]:
    by_trace: dict[str, list[_CorrelationRow]] = {}
    for event in events:
        if event.trace_id:
            by_trace.setdefault(event.trace_id, []).append(event)

    correlations: list[EnterpriseCorrelation] = []
    for trace_id, trace_events in sorted(by_trace.items()):
        if len(trace_events) < _MIN_TRACE_EVENTS:
            continue
        ordered = tuple(sorted(trace_events, key=lambda row: (row.observed_at, row.event_id)))
        kind, outcome = _correlation_kind(ordered)
        sources = tuple(event.source for event in ordered)
        asset_ids = _unique_in_order(resource_id for event in ordered for resource_id in event.resource_ids)
        incomplete_sources = tuple(
            dict.fromkeys(source for source in sources if status_by_source.get(source) is not CollectionStatus.COMPLETE)
        )
        correlation_seed = f"{tenant_id}:{trace_id}:{CORRELATION_VERSION}".encode()
        correlations.append(
            EnterpriseCorrelation(
                correlation_id=f"correlation:{hashlib.sha256(correlation_seed).hexdigest()[:24]}",
                tenant_id=tenant_id,
                trace_id=trace_id,
                kind=kind,
                outcome=outcome,
                started_at=ordered[0].observed_at,
                ended_at=ordered[-1].observed_at,
                event_ids=tuple(event.event_id for event in ordered),
                sources=sources,
                asset_ids=asset_ids,
                asset_path=_asset_path(ordered, assets_by_id),
                data_classifications=_data_classifications(asset_ids, assets_by_id),
                evidence_hashes=tuple(event.evidence_hash for event in ordered),
                evidence_quality="partial" if incomplete_sources else "complete",
                incomplete_sources=incomplete_sources,
            )
        )
    return tuple(correlations)


def _collection_health(estate: EnterpriseEstate) -> tuple[EnterpriseCollectionHealth, ...]:
    return tuple(
        EnterpriseCollectionHealth(
            source=run.source,
            status=run.status,
            records_read=run.records_read,
            watermark=run.watermark,
            source_schema=run.source_schema,
            schema_url=run.schema_url,
            failure_code=run.failure_code,
        )
        for run in estate.collection_runs
    )


def build_estate_correlations(estate: EnterpriseEstate) -> tuple[EnterpriseCorrelation, ...]:
    """Correlate an estate's evidence without normalizing every payload.

    :func:`correlate_enterprise_estate` normalizes each observation into refs,
    relationships and a graph projection before correlating — 5.7 of its 6.3
    seconds on the shipped estate — and correlation reads none of it. A consumer
    that needs the paths and not the payloads (posture findings do) pays that
    cost for output it discards.

    Evidence-hash verification is still performed on every observation. The
    saving comes from skipping projection work, never from trusting unverified
    evidence: a correlation built over tampered evidence is worse than no
    correlation. The correlations returned here are identical to the ones
    :func:`correlate_enterprise_estate` produces, because both call the same
    builder over the same fields.
    """
    assets_by_id = {asset.asset_id: asset for asset in estate.assets}
    rows: list[_CorrelationRow] = []
    for observation in estate.observations:
        if not verify_observation_hash(observation):
            raise ValueError(f"evidence hash mismatch for event {observation.event_id}")
        rows.append(_CorrelationRow.from_observation(observation))
    return _build_correlations(
        tuple(rows),
        tenant_id=estate.tenant_id,
        assets_by_id=assets_by_id,
        status_by_source={row.source: row.status for row in _collection_health(estate)},
    )


def correlate_enterprise_estate(estate: EnterpriseEstate) -> EnterpriseCorrelationResult:
    """Normalize one estate and build deterministic, tenant-scoped correlations."""
    assets_by_id = {asset.asset_id: asset for asset in estate.assets}
    events = tuple(
        _normalize_event(observation, tenant_id=estate.tenant_id, assets_by_id=assets_by_id) for observation in estate.observations
    )
    health = _collection_health(estate)
    status_by_source = {row.source: row.status for row in health}
    correlations = _build_correlations(
        tuple(_CorrelationRow.from_normalized(event) for event in events),
        tenant_id=estate.tenant_id,
        assets_by_id=assets_by_id,
        status_by_source=status_by_source,
    )
    result = EnterpriseCorrelationResult(
        estate_id=estate.estate_id,
        tenant_id=estate.tenant_id,
        estate_content_hash=estate.content_hash,
        events=events,
        correlations=correlations,
        collection_health=health,
        content_hash="0" * 64,
    )
    digest = hashlib.sha256(_canonical_json(result.model_dump(mode="json", exclude={"content_hash"}))).hexdigest()
    return result.model_copy(update={"content_hash": digest})


__all__ = [
    "CORRELATION_VERSION",
    "NORMALIZATION_VERSION",
    "EnterpriseCollectionHealth",
    "EnterpriseCorrelation",
    "EnterpriseCorrelationResult",
    "NormalizedEnterpriseEvent",
    "build_estate_correlations",
    "correlate_enterprise_estate",
]
