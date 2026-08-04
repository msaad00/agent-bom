"""Grow the fictional enterprise estate to a size that shows correlation.

:mod:`agent_bom.demo_estate.enterprise` defines the contract and a hand-authored
narrative spine: one of each thing, one account per cloud. That proves the schema
but understates the product, because the claim being demonstrated — findings,
identities, configuration and logs resolving to one another across vendors — only
becomes visible once there are siblings to disambiguate between.

This module generates a larger estate against that same contract. It does not
fork the schema: every object here is an ``enterprise`` model, so the estate's
own validators (unique ids, tenant boundary, events referencing known assets)
run against generated data exactly as they do against the fixture.

Generation is deterministic. The estate is seeded from its own structure rather
than a random source, so the same :class:`ScaleProfile` always yields the same
``content_hash`` — a demo that shifts between runs cannot be screenshotted,
tested, or trusted.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from agent_bom.demo_estate.enterprise import (
    ENTERPRISE_SCHEMA_VERSION,
    CollectionRun,
    CollectionStatus,
    EnterpriseEstate,
    EstateAsset,
    EstateSnapshot,
    EstateStage,
    EvidenceProvenance,
    EvidenceSource,
    RawObservation,
)
from agent_bom.demo_estate.enterprise import (
    _observation_hash as _canonical_observation_hash,
)

# Clouds that must show real depth: several accounts, every environment. The
# graph audit found `environment` silently null for AWS and GCP and Snowflake
# account drill-down returning one node of six; an estate that repeats either
# shape would demo the defect rather than the product.
CLOUD_PROVIDERS: tuple[str, ...] = ("aws", "azure", "gcp", "snowflake")

ENVIRONMENTS: tuple[str, ...] = ("production", "staging", "development")

_TENANT_DOMAIN = "northstar.example"

# Resource mix per cloud, chosen so each account carries compute, storage, an
# identity and a data surface — the minimum for an attack path to be expressible.
_RESOURCE_MIX: dict[str, tuple[tuple[str, str], ...]] = {
    "aws": (
        ("instance", "ec2"),
        ("bucket", "s3"),
        ("iam_role", "iam"),
        ("database", "rds"),
        ("function", "lambda"),
        ("cluster", "eks"),
    ),
    "azure": (
        ("virtual_machine", "compute"),
        ("storage_account", "storage"),
        ("service_principal", "entra"),
        ("sql_database", "sql"),
        ("function_app", "functions"),
        ("cluster", "aks"),
    ),
    "gcp": (
        ("instance", "compute"),
        ("bucket", "storage"),
        ("service_account", "iam"),
        ("database", "cloudsql"),
        ("function", "cloudfunctions"),
        ("cluster", "gke"),
    ),
    "snowflake": (
        ("warehouse", "compute"),
        ("table", "data"),
        ("role", "rbac"),
        ("database", "data"),
        ("stage", "data"),
        ("share", "data"),
    ),
}

_REGIONS: dict[str, tuple[str, ...]] = {
    "aws": ("us-east-1", "us-west-2", "eu-west-1"),
    "azure": ("eastus", "westeurope", "centralus"),
    "gcp": ("us-central1", "europe-west1", "us-east4"),
    "snowflake": ("us-east-1", "eu-central-1", "us-west-2"),
}

# Which log source speaks for which cloud. Keeping this explicit means a source
# never reports a complete collection while producing no evidence.
_SOURCE_FOR_PROVIDER: dict[str, EvidenceSource] = {
    "aws": EvidenceSource.AWS_CLOUDTRAIL,
    "azure": EvidenceSource.AZURE_ACTIVITY,
    "gcp": EvidenceSource.GCP_AUDIT,
    "snowflake": EvidenceSource.SNOWFLAKE_ACCESS_HISTORY,
}

_EVENT_TYPES: dict[str, tuple[str, ...]] = {
    "aws": ("AssumeRole", "GetObject", "PutBucketPolicy", "CreateAccessKey"),
    "azure": ("Microsoft.Authorization/roleAssignments/write", "Microsoft.Storage/storageAccounts/listKeys"),
    "gcp": ("storage.objects.get", "iam.serviceAccounts.getAccessToken"),
    "snowflake": ("QUERY", "GRANT_ROLE", "COPY_INTO"),
}

_DATA_CLASSES: dict[str, tuple[str, ...]] = {
    "bucket": ("confidential",),
    "storage_account": ("confidential",),
    "database": ("restricted", "phi"),
    "sql_database": ("restricted", "phi"),
    "table": ("restricted", "phi"),
}

# GCP audit collection is deliberately left partial, matching the hand-authored
# estate. An estate where every source succeeds cannot demonstrate that partial
# evidence is reported as partial rather than promoted to a complete posture.
_PARTIAL_SOURCE = EvidenceSource.GCP_AUDIT
_PARTIAL_FAILURE_CODE = "rate_limited"

_EPOCH = datetime(2026, 7, 1, 0, 0, 0, tzinfo=UTC)


@dataclass(frozen=True)
class ScaleProfile:
    """How big the estate should be, and therefore how much story it can carry."""

    accounts_per_cloud: int = 3
    resources_per_account: int = 12
    events_per_asset: int = 2

    def __post_init__(self) -> None:
        if self.accounts_per_cloud < 2:
            raise ValueError("a cloud needs at least two accounts for drill-down to mean anything")
        if self.resources_per_account < len(ENVIRONMENTS):
            raise ValueError("each account needs at least one resource per environment")
        if self.events_per_asset < 1:
            raise ValueError("an asset with no evidence cannot participate in correlation")


def _stable_index(*parts: str) -> int:
    """A deterministic pseudo-index derived from the identity of the thing itself.

    Used instead of a random source so that generation depends only on structure:
    the same profile yields the same estate on every machine and every run.
    """
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big")


def _account_scope(provider: str, index: int) -> str:
    if provider == "aws":
        return f"{100000000000 + index:012d}"
    if provider == "azure":
        return f"sub-{index:04d}-northstar"
    if provider == "gcp":
        return f"northstar-{index:03d}"
    return f"NORTHSTAR_{index:02d}"


def _build_assets(profile: ScaleProfile, tenant_id: str) -> tuple[EstateAsset, ...]:
    assets: list[EstateAsset] = [
        EstateAsset(
            asset_id="organization:northstar-health-ai",
            tenant_id=tenant_id,
            provider="enterprise",
            resource_type="organization",
            native_id="northstar-health-ai",
            display_name="Northstar Health AI",
            environment="production",
            account_scope="northstar-health-ai",
            region="global",
            owner=f"security@{_TENANT_DOMAIN}",
            cost_center="GRC-100",
            data_classifications=("confidential",),
            tags={"synthetic": "true"},
        )
    ]

    for provider in CLOUD_PROVIDERS:
        mix = _RESOURCE_MIX[provider]
        regions = _REGIONS[provider]
        for account_index in range(profile.accounts_per_cloud):
            scope = _account_scope(provider, account_index)
            for slot in range(profile.resources_per_account):
                resource_type, service = mix[slot % len(mix)]
                # Environment cycles per slot so every account carries all three;
                # a provider missing an environment collapses its drill-down.
                environment = ENVIRONMENTS[slot % len(ENVIRONMENTS)]
                name = f"{provider}-{service}-{account_index:02d}-{slot:03d}"
                region = regions[_stable_index(provider, scope, name) % len(regions)]
                assets.append(
                    EstateAsset(
                        asset_id=f"{provider}:{resource_type}:{scope}:{name}",
                        tenant_id=tenant_id,
                        provider=provider,
                        resource_type=resource_type,
                        native_id=f"{provider}://{scope}/{service}/{name}",
                        display_name=name,
                        environment=environment,
                        account_scope=scope,
                        region=region,
                        owner=f"{service}-owners@{_TENANT_DOMAIN}",
                        cost_center=f"{provider.upper()[:3]}-{400 + account_index}",
                        data_classifications=_DATA_CLASSES.get(resource_type, ()),
                        tags={
                            "synthetic": "true",
                            "environment": environment,
                            "owner": f"{service}-owners@{_TENANT_DOMAIN}",
                        },
                    )
                )
    return tuple(assets)


def _sealed(observation: RawObservation) -> RawObservation:
    """Stamp the evidence hash using the estate's own hasher.

    Deliberately not a second implementation: ``verify_observation_hash`` is the
    consumer, so computing the digest any other way would produce evidence that
    fails its own verification — the exact class of defect where one judgement
    gets two implementations.
    """
    digest = _canonical_observation_hash(observation.model_dump(mode="json", exclude={"provenance"}))
    return observation.model_copy(update={"provenance": observation.provenance.model_copy(update={"evidence_hash": digest})})


def _build_observations(assets: tuple[EstateAsset, ...], profile: ScaleProfile, tenant_id: str) -> tuple[RawObservation, ...]:
    observations: list[RawObservation] = []
    for asset in assets:
        source = _SOURCE_FOR_PROVIDER.get(asset.provider)
        if source is None:
            continue
        event_types = _EVENT_TYPES[asset.provider]
        for occurrence in range(profile.events_per_asset):
            seed = _stable_index(asset.asset_id, str(occurrence))
            event_type = event_types[seed % len(event_types)]
            observed_at = _EPOCH + timedelta(minutes=seed % 40320)
            event_id = f"evt-{hashlib.sha256(f'{asset.asset_id}:{occurrence}'.encode()).hexdigest()[:20]}"
            actor = f"{asset.provider}-principal-{seed % 37:02d}@{_TENANT_DOMAIN}"
            row: dict[str, Any] = {
                "event_id": event_id,
                "stage": EstateStage.CURRENT.value,
                "source": source.value,
                "event_type": event_type,
                "observed_at": observed_at.isoformat(),
                "actor_id": actor,
                "resource_ids": [asset.asset_id],
                "trace_id": hashlib.sha256(event_id.encode()).hexdigest()[:32],
                "raw_payload": {
                    "eventName": event_type,
                    "accountScope": asset.account_scope,
                    "region": asset.region,
                    "environment": asset.environment,
                    "readOnly": event_type in {"GetObject", "QUERY", "storage.objects.get"},
                },
            }
            observations.append(
                _sealed(
                    RawObservation(
                        **row,
                        provenance=EvidenceProvenance(
                            source=source,
                            source_event_id=event_id,
                            observed_at=observed_at,
                            run_id=f"demo-run-scaled-{source.value}",
                            tenant_id=tenant_id,
                            evidence_hash="0" * 64,
                            schema_version=ENTERPRISE_SCHEMA_VERSION,
                        ),
                    )
                )
            )
    return tuple(observations)


def _build_collection_runs(observations: tuple[RawObservation, ...], tenant_id: str) -> tuple[CollectionRun, ...]:
    counts: dict[EvidenceSource, int] = {}
    for event in observations:
        counts[event.source] = counts.get(event.source, 0) + 1

    runs: list[CollectionRun] = []
    for source in sorted(counts, key=lambda item: item.value):
        partial = source is _PARTIAL_SOURCE
        started = _EPOCH + timedelta(days=28)
        runs.append(
            CollectionRun(
                run_id=f"demo-run-scaled-{source.value}",
                tenant_id=tenant_id,
                source=source,
                status=CollectionStatus.PARTIAL if partial else CollectionStatus.COMPLETE,
                started_at=started,
                completed_at=started + timedelta(minutes=6),
                records_read=counts[source],
                read_only=True,
                watermark=(started + timedelta(minutes=6)).isoformat(),
                source_schema="generated-demo-collection",
                schema_url="https://github.com/msaad00/agent-bom/blob/main/docs/HOSTED_POC.md",
                next_cursor="cursor-gcp-audit-page-2" if partial else "",
                failure_code=_PARTIAL_FAILURE_CODE if partial else "",
            )
        )
    return tuple(runs)


def _build_snapshots(assets: tuple[EstateAsset, ...], observations: tuple[RawObservation, ...]) -> tuple[EstateSnapshot, ...]:
    asset_ids = tuple(asset.asset_id for asset in assets)
    event_ids = tuple(event.event_id for event in observations)
    # Baseline predates the newest third of the estate, so the diff between
    # stages is a real change rather than a relabelling of the same set.
    baseline_cutoff = max(1, (len(asset_ids) * 2) // 3)
    return (
        EstateSnapshot(
            snapshot_id="scaled-baseline",
            stage=EstateStage.BASELINE,
            observed_at=_EPOCH,
            asset_ids=asset_ids[:baseline_cutoff],
            event_ids=(),
            change_summary="Estate as inventoried before the current collection window.",
        ),
        EstateSnapshot(
            snapshot_id="scaled-current",
            stage=EstateStage.CURRENT,
            observed_at=_EPOCH + timedelta(days=28),
            asset_ids=asset_ids,
            event_ids=event_ids,
            change_summary="Full estate with cross-vendor evidence collected.",
        ),
        EstateSnapshot(
            snapshot_id="scaled-remediated",
            stage=EstateStage.REMEDIATED,
            observed_at=_EPOCH + timedelta(days=35),
            asset_ids=asset_ids,
            event_ids=event_ids,
            change_summary="Estate after remediation of the correlated exposure path.",
        ),
    )


def build_scaled_estate(profile: ScaleProfile | None = None, *, tenant_id: str = "default") -> EnterpriseEstate:
    """Build a deterministic, tenant-scoped, explicitly synthetic estate at scale."""
    profile = profile or ScaleProfile()
    tenant_id = tenant_id.strip()
    if not tenant_id:
        raise ValueError("tenant_id must not be empty")

    assets = _build_assets(profile, tenant_id)
    observations = _build_observations(assets, profile, tenant_id)
    estate = EnterpriseEstate(
        schema_version=ENTERPRISE_SCHEMA_VERSION,
        estate_id="northstar-health-ai-scaled-v1",
        tenant_id=tenant_id,
        display_name="Northstar Health AI",
        synthetic=True,
        fictional=True,
        disclosure=(
            "Synthetic, fictional estate generated for demonstration. No real organization, account, identity, or workload is represented."
        ),
        assets=assets,
        observations=observations,
        collection_runs=_build_collection_runs(observations, tenant_id),
        snapshots=_build_snapshots(assets, observations),
        content_hash="0" * 64,
    )
    digest = hashlib.sha256(
        json.dumps(
            estate.model_dump(mode="json", exclude={"content_hash"}),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()
    return estate.model_copy(update={"content_hash": digest})
