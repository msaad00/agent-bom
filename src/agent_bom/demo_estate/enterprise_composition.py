"""Put the demo's incident chain inside an enterprise-sized population.

Two halves existed and neither was sufficient alone.
:mod:`agent_bom.demo_estate.enterprise` carries the narrative — one incident
traced across GitHub, AWS, Kubernetes, MCP and Snowflake — but at 20 assets
nothing has to be correlated *out of* anything, so the correlation reads as a
diagram rather than a capability. :mod:`agent_bom.demo_estate.enterprise_scale`
produces thousands of correlated assets but contains no incident, so there is
nothing to find; it also shipped with exactly one consumer, its own test.

Composed, the incident sits inside a population. That is the only arrangement in
which "findings, identities, configuration and logs resolve to one another
across a large multi-vendor estate" is demonstrated instead of asserted.

The narrative half always wins a collision: its ids are referenced by the
correlation layer and by the presentation story, so a generated row shadowing
one would silently rewrite the incident.
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache

from agent_bom.demo_estate.enterprise import (
    ENTERPRISE_SCHEMA_VERSION,
    CollectionRun,
    CollectionStatus,
    EnterpriseEstate,
    EstateSnapshot,
    EstateStage,
    load_enterprise_estate,
)
from agent_bom.demo_estate.enterprise_scale import ScaleProfile, build_scaled_estate


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


@lru_cache(maxsize=2)
def _build_demo_estate_cached(profile: ScaleProfile, tenant_id: str) -> EnterpriseEstate:
    return _build_demo_estate(profile, tenant_id)


def build_demo_estate(profile: ScaleProfile | None = None, *, tenant_id: str = "default") -> EnterpriseEstate:
    """Return the narrative estate embedded in a generated population.

    Memoized because one demo boot builds it three times — once to validate and
    fingerprint the contract, once for the posture findings, once for the graph
    projection — and generation is a pure function of ``(profile, tenant_id)``
    returning a frozen model, so a second build can only ever produce a
    byte-identical estate. At the current size that repetition was a third of
    the boot.

    ``maxsize`` is deliberately small: an estate is thousands of assets and tens
    of thousands of observations, and a cache that holds one per tenant would
    trade a startup second for unbounded resident memory. Two covers the seeding
    path (one tenant, several callers) and evicts anything else.
    """
    return _build_demo_estate_cached(profile or ScaleProfile(), tenant_id)


def _build_demo_estate(profile: ScaleProfile | None, tenant_id: str) -> EnterpriseEstate:
    """Compose the narrative estate into a generated population.

    Both halves are already valid :class:`EnterpriseEstate` values, so this
    composes them rather than re-deriving anything. Construction re-runs every
    contract validator over the union — unique ids, tenant boundary, and events
    referencing known assets — so a composition mistake fails here rather than
    surfacing as a missing node three screens later.
    """
    narrative = load_enterprise_estate(tenant_id=tenant_id)
    population = build_scaled_estate(profile, tenant_id=tenant_id)

    # The narrative wins collisions: the correlation and presentation layers
    # reference its ids by name.
    narrative_asset_ids = {asset.asset_id for asset in narrative.assets}
    narrative_event_ids = {event.event_id for event in narrative.observations}

    assets = narrative.assets + tuple(asset for asset in population.assets if asset.asset_id not in narrative_asset_ids)
    kept_asset_ids = {asset.asset_id for asset in assets}
    observations = narrative.observations + tuple(
        event
        for event in population.observations
        if event.event_id not in narrative_event_ids
        # An event whose asset lost the collision would dangle; the contract
        # rejects that, so drop it here where the reason is visible.
        and all(resource_id in kept_asset_ids for resource_id in event.resource_ids)
    )

    estate = EnterpriseEstate(
        schema_version=ENTERPRISE_SCHEMA_VERSION,
        estate_id=f"{narrative.estate_id}-composed",
        tenant_id=tenant_id,
        display_name=narrative.display_name,
        synthetic=True,
        fictional=True,
        disclosure=narrative.disclosure,
        assets=assets,
        observations=observations,
        collection_runs=_merge_collection_runs(narrative, population),
        snapshots=_merge_snapshots(narrative, assets, observations),
        content_hash="0" * 64,
    )
    digest = hashlib.sha256(_canonical_json(estate.model_dump(mode="json", exclude={"content_hash"}))).hexdigest()
    return estate.model_copy(update={"content_hash": digest})


def _merge_collection_runs(narrative: EnterpriseEstate, population: EnterpriseEstate) -> tuple[CollectionRun, ...]:
    """One run per source, keeping the narrative's and summing records read.

    A source that is partial in either half stays partial in the union: an
    incomplete read must never be promoted to a complete posture just because a
    second collection of the same source happened to succeed.
    """
    runs: dict[str, CollectionRun] = {run.source.value: run for run in narrative.collection_runs}
    for run in population.collection_runs:
        existing = runs.get(run.source.value)
        if existing is None:
            runs[run.source.value] = run
            continue
        if existing.status is CollectionStatus.COMPLETE and run.status is not CollectionStatus.COMPLETE:
            runs[run.source.value] = run.model_copy(update={"records_read": existing.records_read + run.records_read})
        else:
            runs[run.source.value] = existing.model_copy(update={"records_read": existing.records_read + run.records_read})
    return tuple(runs[key] for key in sorted(runs))


def _merge_snapshots(narrative: EnterpriseEstate, assets: tuple, observations: tuple) -> tuple[EstateSnapshot, ...]:
    """Keep the narrative's stage timeline, widened to the composed estate.

    Stage membership stays the narrative's story — baseline predates the
    incident, remediated follows it — while the asset and event sets grow to the
    whole estate so a stage never references something the estate does not hold.
    """
    asset_ids = tuple(asset.asset_id for asset in assets)
    event_ids = tuple(event.event_id for event in observations)
    merged: list[EstateSnapshot] = []
    for snapshot in narrative.snapshots:
        if snapshot.stage is EstateStage.BASELINE:
            # Baseline predates the current collection window, so it carries the
            # population but none of the incident's evidence.
            merged.append(snapshot.model_copy(update={"asset_ids": asset_ids}))
        else:
            merged.append(snapshot.model_copy(update={"asset_ids": asset_ids, "event_ids": event_ids}))
    return tuple(merged)
