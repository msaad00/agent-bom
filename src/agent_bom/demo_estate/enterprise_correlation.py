"""Normalize and correlate the versioned enterprise demo evidence.

The adapter deliberately uses the same relationship and graph-projection
builders as live proxy/runtime events. Provider payloads remain in the raw
fixture; normalized output carries only stable references and provenance.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
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
    )


def _unique_in_order(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


def _correlation_kind(events: tuple[NormalizedEnterpriseEvent, ...]) -> tuple[str, str]:
    if any(event.stage is EstateStage.REMEDIATED for event in events):
        return "remediation", "enforced"
    if any(event.source is EvidenceSource.OTEL_LLM for event in events):
        return "data_egress_attempt", "blocked"
    if any("roleAssignments/write" in event.event_type for event in events):
        return "privilege_change", "observed"
    if any("CreateServiceAccountKey" in event.event_type for event in events):
        return "credential_issuance", "observed"
    return "activity_sequence", "observed"


_PATH_TYPES = ("workflow", "iam_role", "deployment", "tool", "table", "hosted_model")


def _asset_path(
    events: tuple[NormalizedEnterpriseEvent, ...], assets_by_id: dict[str, EstateAsset]
) -> tuple[str, ...]:
    ordered_ids = _unique_in_order(
        resource_id for event in events for resource_id in event.resource_ids
    )
    selected: list[str] = []
    for resource_type in _PATH_TYPES:
        match = next(
            (
                resource_id
                for resource_id in ordered_ids
                if assets_by_id[resource_id].resource_type == resource_type
            ),
            None,
        )
        if match is not None:
            selected.append(match)
    return tuple(selected or ordered_ids)


def _data_classifications(
    asset_ids: tuple[str, ...], assets_by_id: dict[str, EstateAsset]
) -> tuple[str, ...]:
    classifications = {
        classification
        for asset_id in asset_ids
        for classification in assets_by_id[asset_id].data_classifications
    }
    regulated = classifications & {"phi", "pii", "pci", "restricted"}
    return tuple(sorted(regulated or classifications))


def _build_correlations(
    events: tuple[NormalizedEnterpriseEvent, ...],
    *,
    tenant_id: str,
    assets_by_id: dict[str, EstateAsset],
    status_by_source: dict[EvidenceSource, CollectionStatus],
) -> tuple[EnterpriseCorrelation, ...]:
    by_trace: dict[str, list[NormalizedEnterpriseEvent]] = {}
    for event in events:
        if event.trace_id:
            by_trace.setdefault(event.trace_id, []).append(event)

    correlations: list[EnterpriseCorrelation] = []
    for trace_id, trace_events in sorted(by_trace.items()):
        ordered = tuple(sorted(trace_events, key=lambda row: (row.observed_at, row.event_id)))
        kind, outcome = _correlation_kind(ordered)
        sources = tuple(event.source for event in ordered)
        asset_ids = _unique_in_order(
            resource_id for event in ordered for resource_id in event.resource_ids
        )
        incomplete_sources = tuple(
            dict.fromkeys(
                source
                for source in sources
                if status_by_source.get(source) is not CollectionStatus.COMPLETE
            )
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


def correlate_enterprise_estate(estate: EnterpriseEstate) -> EnterpriseCorrelationResult:
    """Normalize one estate and build deterministic, tenant-scoped correlations."""
    assets_by_id = {asset.asset_id: asset for asset in estate.assets}
    events = tuple(
        _normalize_event(observation, tenant_id=estate.tenant_id, assets_by_id=assets_by_id)
        for observation in estate.observations
    )
    health = tuple(
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
    status_by_source = {row.source: row.status for row in health}
    correlations = _build_correlations(
        events,
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
    digest = hashlib.sha256(
        _canonical_json(result.model_dump(mode="json", exclude={"content_hash"}))
    ).hexdigest()
    return result.model_copy(update={"content_hash": digest})


__all__ = [
    "CORRELATION_VERSION",
    "NORMALIZATION_VERSION",
    "EnterpriseCollectionHealth",
    "EnterpriseCorrelation",
    "EnterpriseCorrelationResult",
    "NormalizedEnterpriseEvent",
    "correlate_enterprise_estate",
]
