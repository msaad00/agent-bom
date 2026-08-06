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
from agent_bom.demo_estate.enterprise_ai import (
    AI_LANE_TAG,
    build_delivery_assets,
    build_first_party_ai_assets,
    build_third_party_ai_assets,
    index_cloud_accounts,
    mark_cloud_exposure,
)
from agent_bom.demo_estate.enterprise_journeys import (
    actor_for,
    build_journeys,
    session_trace_id,
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

# What the workloads are FOR. Resource names were previously
# ``f"{provider}-{service}-{account:02d}-{slot:03d}"`` -> ``aws-iam-03-020``,
# which is a coordinate, not a name. Nothing in the estate could be reasoned
# about: an over-privileged role called ``aws-iam-03-020`` tells an operator
# nothing about blast radius, and a whole inventory of them reads as generated
# rather than discovered — which is exactly the impression a demo must avoid.
#
# These are the workloads a payer/provider AI platform actually runs, so a role
# named ``prior-auth-reviewer`` failing least-privilege is a sentence a reviewer
# can act on. Kept as one pool per resource CLASS rather than per provider, so
# the same business capability shows up across clouds the way it does in a real
# multi-cloud estate.
_WORKLOAD_NAMES: dict[str, tuple[str, ...]] = {
    "compute": (
        "member-eligibility-api",
        "claims-intake-worker",
        "prior-auth-reviewer",
        "care-gap-scorer",
        "provider-directory-sync",
        "appeals-drafter",
        "clinical-notes-indexer",
        "risk-adjustment-batch",
        "formulary-lookup",
        "benefits-quote-engine",
    ),
    "storage": (
        "member-exports",
        "claims-archive",
        "clinical-attachments",
        "eob-statements",
        "provider-rosters",
        "audit-evidence",
        "model-artifacts",
        "training-corpora",
    ),
    "identity": (
        "member-eligibility-api",
        "claims-etl",
        "prior-auth-reviewer",
        "care-gap-scorer",
        "phi-export-approver",
        "provider-directory-sync",
        "clinical-analytics-reader",
        "appeals-drafter",
        "risk-adjustment-batch",
        "break-glass-admin",
    ),
    "data": (
        "patient-summary",
        "claims-ledger",
        "eligibility-spans",
        "encounters",
        "provider-network",
        "authorizations",
        "pharmacy-fills",
        "care-gaps",
        "quality-measures",
        "risk-scores",
    ),
    "serverless": (
        "eligibility-webhook",
        "claim-status-callback",
        "phi-redactor",
        "fhir-normalizer",
        "eob-renderer",
        "consent-checker",
        "member-match",
        "coverage-notifier",
        "attachment-virus-scan",
        "audit-log-shipper",
    ),
    # No environment token in these: the suffix is appended below, and a pool
    # entry carrying its own would read "member-ai-prod-development".
    "cluster": (
        "member-ai",
        "claims-platform",
        "clinical-intelligence",
        "provider-services",
        "population-health",
        "revenue-cycle",
    ),
}

# Which name pool a resource type draws from. A type with no entry falls back to
# the compute pool rather than silently reverting to a coordinate.
_RESOURCE_NAME_POOL: dict[str, str] = {
    "instance": "compute",
    "virtual_machine": "compute",
    "warehouse": "compute",
    "bucket": "storage",
    "storage_account": "storage",
    "stage": "storage",
    "share": "storage",
    "iam_role": "identity",
    "service_principal": "identity",
    "service_account": "identity",
    "role": "identity",
    "database": "data",
    "sql_database": "data",
    "table": "data",
    "function": "serverless",
    "function_app": "serverless",
    "cluster": "cluster",
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
    "github": EvidenceSource.GITHUB_ACTIONS,
    "kubernetes": EvidenceSource.KUBERNETES_AUDIT,
    "mcp": EvidenceSource.MCP_GATEWAY,
    "agent": EvidenceSource.OTEL_LLM,
    "openai": EvidenceSource.OTEL_LLM,
    "anthropic": EvidenceSource.OTEL_LLM,
    "huggingface": EvidenceSource.OTEL_LLM,
}

# Inventory rows a log never names on their own. A package appears in an SBOM
# and in a vulnerability finding, never in CloudTrail; emitting a control-plane
# event for one would be evidence the estate cannot justify.
_UNOBSERVED_RESOURCE_TYPES: frozenset[str] = frozenset({"package"})

_EVENT_TYPES: dict[str, tuple[str, ...]] = {
    "aws": ("AssumeRole", "GetObject", "PutBucketPolicy", "CreateAccessKey"),
    "azure": ("Microsoft.Authorization/roleAssignments/write", "Microsoft.Storage/storageAccounts/listKeys"),
    "gcp": ("storage.objects.get", "iam.serviceAccounts.getAccessToken"),
    "snowflake": ("QUERY", "GRANT_ROLE", "COPY_INTO"),
    "github": ("workflow_run.completed", "workflow_job.queued"),
    "kubernetes": ("deployments.update", "pods/exec.create", "secrets.get"),
    "mcp": ("tools/call", "tools/list", "initialize"),
    "agent": ("gen_ai.chat", "gen_ai.execute_tool"),
    "openai": ("gen_ai.chat", "gen_ai.embeddings"),
    "anthropic": ("gen_ai.chat", "gen_ai.execute_tool"),
    "huggingface": ("gen_ai.embeddings",),
}

# Control-plane calls a first-party AI service actually produces. Without these
# a Bedrock agent in an AWS account would emit ``GetObject`` — plausible-looking
# evidence that names the wrong API, which is worse than none.
_AI_SERVICE_EVENT_TYPES: dict[str, tuple[str, ...]] = {
    "aws": ("bedrock:InvokeModelWithResponseStream", "bedrock:Retrieve", "sagemaker:InvokeEndpoint"),
    "azure": (
        "Microsoft.CognitiveServices/accounts/deployments/action",
        "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/score/action",
    ),
    "gcp": ("aiplatform.endpoints.predict", "aiplatform.models.get"),
    "snowflake": ("CORTEX_COMPLETE", "CORTEX_SEARCH_QUERY"),
}


def _event_types_for(asset: EstateAsset) -> tuple[str, ...]:
    """Which API calls this asset's own control plane emits."""
    if asset.tags.get(AI_LANE_TAG) == "first_party":
        ai_types = _AI_SERVICE_EVENT_TYPES.get(asset.provider)
        if ai_types:
            return ai_types
    return _EVENT_TYPES[asset.provider]


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


# The floor below which the estate stops reading as an enterprise. Pinned by
# tests so the default cannot be quietly shrunk back to a diagram: a reviewer
# trimming these for speed has to change the assertion and say why.
MIN_ENTERPRISE_ASSETS = 2000
MIN_ENTERPRISE_EVENTS = 6000
MIN_ACCOUNTS_PER_CLOUD = 5
MIN_RESOURCES_PER_ACCOUNT = 20

# Floors for the properties that make the estate *demonstrate* rather than
# assert. Each replaces a number that looked healthy while the thing it stood
# for was absent: 6,148 correlations of which 3 spanned a second vendor, and 439
# findings every one of which was the same CIS scanner.
MIN_CROSS_SOURCE_CORRELATIONS = 300
MIN_ESTATE_FINDINGS = 2000


@dataclass(frozen=True)
class ScaleProfile:
    """How big the estate should be, and therefore how much story it can carry.

    The defaults are the shipped demo size. They are deliberately in the low
    thousands rather than the millions: the read-path wall sits far above this,
    but the demo runs on modest hosted resources, and an estate that takes
    seconds to paint a graph tells a worse story than one that responds
    instantly. Scale proof belongs in a benchmark, not in the thing a prospect
    clicks.
    """

    accounts_per_cloud: int = 8
    resources_per_account: int = 64
    events_per_asset: int = 3

    # The AI estate. ``ai_services_per_account`` are FIRST-PARTY services inside
    # the cloud accounts above — Bedrock, Azure OpenAI, Vertex, Cortex — sharing
    # those accounts' identities and data. The third-party counts below are
    # deliberately smaller in total: external providers are the minority of an
    # enterprise's AI surface, and modelling them as the whole of it is what made
    # nine standalone assets read as the entire AI story.
    ai_services_per_account: int = 14
    mcp_servers: int = 24
    agents: int = 48
    external_models: int = 24

    # Delivery and runtime — the spine a cross-vendor trace walks. One
    # repository, one workflow and one deployment (what the estate had) means
    # every journey converges on the same three nodes.
    repositories: int = 56
    clusters: int = 16
    workloads_per_cluster: int = 8
    packages_per_image: int = 6

    # Multi-source traces. Each is one actor walking CI -> cloud identity ->
    # Kubernetes -> MCP -> warehouse -> model, so this is very nearly the
    # cross-source correlation count.
    journeys: int = 420

    def __post_init__(self) -> None:
        if self.accounts_per_cloud < 2:
            raise ValueError("a cloud needs at least two accounts for drill-down to mean anything")
        if self.resources_per_account < len(ENVIRONMENTS):
            raise ValueError("each account needs at least one resource per environment")
        if self.events_per_asset < 1:
            raise ValueError("an asset with no evidence cannot participate in correlation")
        if self.journeys < 0:
            raise ValueError("journey count cannot be negative")
        if self.mcp_servers < 1 or self.agents < 1:
            raise ValueError("the AI lane needs at least one server and one agent to correlate")


def _stable_index(*parts: str) -> int:
    """A deterministic pseudo-index derived from the identity of the thing itself.

    Used instead of a random source so that generation depends only on structure:
    the same profile yields the same estate on every machine and every run.
    """
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big")


def _workload_name(provider: str, scope: str, resource_type: str, environment: str, slot: int) -> str:
    """Name a resource after the workload it serves, not its coordinates.

    Deterministic: the same (provider, account, type, slot) always yields the
    same name, so snapshots, the drift lens and every pinned test stay stable.

    The environment suffix carries real information — ``claims-etl-prod`` and
    ``claims-etl-staging`` are genuinely different blast radii — and the numeric
    tail only appears when a pool wraps within one account, so the common case
    reads as a name rather than a serial number.
    """
    pool_key = _RESOURCE_NAME_POOL.get(resource_type, "compute")
    pool = _WORKLOAD_NAMES[pool_key]
    offset = _stable_index(provider, scope, resource_type) % len(pool)
    index = (offset + slot) % len(pool)
    wrap = (offset + slot) // len(pool)
    base = f"{pool[index]}-{environment}"
    return base if wrap == 0 else f"{base}-{wrap + 1}"


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
                name = _workload_name(provider, scope, resource_type, environment, slot)
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


def _build_estate_assets(profile: ScaleProfile, tenant_id: str) -> tuple[EstateAsset, ...]:
    """Cloud population, then everything that runs on it, in one inventory.

    Order matters: the AI and delivery lanes are generated *from* the cloud
    accounts, reading back the identities and data stores actually inventoried
    rather than re-deriving them. A second derivation would be free to name a
    principal the estate never created, and the contract would only catch it if
    the principal happened to be referenced by an event.
    """
    cloud = mark_cloud_exposure(_build_assets(profile, tenant_id))
    accounts = index_cloud_accounts(cloud)
    first_party = build_first_party_ai_assets(accounts, tenant_id=tenant_id, per_account=profile.ai_services_per_account)
    third_party = build_third_party_ai_assets(
        accounts,
        tenant_id=tenant_id,
        mcp_servers=profile.mcp_servers,
        agents=profile.agents,
        external_models=profile.external_models,
    )
    delivery = build_delivery_assets(
        accounts,
        tenant_id=tenant_id,
        repositories=profile.repositories,
        clusters=profile.clusters,
        workloads_per_cluster=profile.workloads_per_cluster,
        packages_per_image=profile.packages_per_image,
    )
    return (*cloud, *first_party, *third_party, *delivery)


_PLACEHOLDER_HASH = "0" * 64
_READ_ONLY_EVENTS = frozenset({"GetObject", "QUERY", "storage.objects.get"})


def _seal(observation: RawObservation) -> RawObservation:
    """Stamp the evidence hash using the estate's own hasher.

    Deliberately not a second implementation. ``verify_observation_hash`` is the
    consumer, so computing the digest any other way produces evidence that fails
    its own verification — the exact class of defect where one judgement gets two
    implementations. The first draft of this module did precisely that, and every
    observation failed to verify.

    That constraint is also why this goes through ``model_dump(mode="json")``
    rather than hashing the source dict directly, even though the round-trip is
    the dominant cost of the build. Pydantic serializes ``observed_at`` as
    ``...Z`` where ``datetime.isoformat`` gives ``...+00:00``; matching it by hand
    would mean re-implementing pydantic's serialization and re-opening the same
    defect. The cost is the price of one hasher, and it is worth paying.
    """
    digest = _canonical_observation_hash(observation.model_dump(mode="json", exclude={"provenance"}))
    return observation.model_copy(update={"provenance": observation.provenance.model_copy(update={"evidence_hash": digest})})


def _build_observations(assets: tuple[EstateAsset, ...], profile: ScaleProfile, tenant_id: str) -> tuple[RawObservation, ...]:
    """Per-asset activity, grouped into per-principal daily sessions.

    Two changes from the shape this replaces, and both exist to stop the
    correlation layer from reporting work it never did.

    **The actor comes from one shared pool**, not from ``f"{provider}-principal-…"``.
    A principal that only ever appears in one cloud can never produce a
    cross-vendor grouping, so the old estate could not have correlated across
    vendors even in principle.

    **The trace id is a session, not the event.** Minting a trace per event made
    every group a group of one, which is how 6,148 "correlations" contained 3
    that joined anything. A session — one identity, one day, whatever it touched
    — is a grouping the evidence actually supports.
    """
    observations: list[RawObservation] = []
    occurrences = range(profile.events_per_asset)
    for asset in assets:
        source = _SOURCE_FOR_PROVIDER.get(asset.provider)
        if source is None or asset.resource_type in _UNOBSERVED_RESOURCE_TYPES:
            continue
        # Hoisted: these are constant for every event on this asset, and at
        # scale the per-event recomputation dominated the loop body.
        run_id = f"demo-run-scaled-{source.value}"
        event_types = _event_types_for(asset)
        type_count = len(event_types)
        asset_id = asset.asset_id
        for occurrence in occurrences:
            seed = _stable_index(asset_id, str(occurrence))
            event_type = event_types[seed % type_count]
            observed_at = _EPOCH + timedelta(minutes=seed % 40320)
            actor_id = actor_for(asset, occurrence)
            event_id = f"evt-{hashlib.sha256(f'{asset_id}:{occurrence}'.encode()).hexdigest()[:20]}"
            observations.append(
                _seal(
                    RawObservation(
                        event_id=event_id,
                        stage=EstateStage.CURRENT,
                        source=source,
                        event_type=event_type,
                        observed_at=observed_at,
                        actor_id=actor_id,
                        resource_ids=(asset_id,),
                        trace_id=session_trace_id(actor_id, observed_at, tenant_id),
                        raw_payload={
                            "eventName": event_type,
                            "accountScope": asset.account_scope,
                            "region": asset.region,
                            "environment": asset.environment,
                            "readOnly": event_type in _READ_ONLY_EVENTS,
                        },
                        provenance=EvidenceProvenance(
                            source=source,
                            source_event_id=event_id,
                            observed_at=observed_at,
                            run_id=run_id,
                            tenant_id=tenant_id,
                            evidence_hash=_PLACEHOLDER_HASH,
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

    assets = _build_estate_assets(profile, tenant_id)
    observations = (
        *_build_observations(assets, profile, tenant_id),
        *build_journeys(assets, tenant_id=tenant_id, count=profile.journeys, epoch=_EPOCH),
    )
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
