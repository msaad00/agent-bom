"""Versioned contract for the fictional cross-cloud enterprise demo estate.

The raw observations in :mod:`agent_bom.demo_estate.data` intentionally retain
provider-native field names.  Later pipeline stages normalize them; this module
only validates provenance, stable identity, tenancy, and replay semantics.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from importlib.resources import files
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ENTERPRISE_SCHEMA_VERSION = "1.0.0"
_FIXTURE_NAME = "enterprise_observations.jsonl"

# The hand-authored incident's trace, named rather than discovered.
#
# The presentation layer used to surface "the first correlation of kind
# ``data_egress_attempt``", which was unambiguous only while the incident was the
# estate's sole egress attempt. Once the generated population produces hundreds
# of them, correlations sort by trace id and an arbitrary generated journey
# becomes the headline. ``tests/test_enterprise_demo_contract.py`` asserts this
# id still exists in the fixture, so a renumbered incident fails loudly instead
# of silently promoting a different story.
NARRATIVE_INCIDENT_TRACE_ID = "7f3a9b12c4d5e6f7890abcde12345678"


class EstateStage(StrEnum):
    BASELINE = "baseline"
    CURRENT = "current"
    REMEDIATED = "remediated"


class CollectionStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


class EvidenceSource(StrEnum):
    AWS_CLOUDTRAIL = "aws_cloudtrail"
    AZURE_ACTIVITY = "azure_activity"
    ENTRA_SIGNIN = "entra_signin"
    GCP_AUDIT = "gcp_audit"
    GITHUB_ACTIONS = "github_actions"
    KUBERNETES_AUDIT = "kubernetes_audit"
    MCP_GATEWAY = "mcp_gateway"
    OTEL_LLM = "otel_llm"
    SNOWFLAKE_ACCESS_HISTORY = "snowflake_access_history"


class EstateAsset(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    asset_id: str = Field(min_length=3)
    tenant_id: str = Field(min_length=1)
    provider: str = Field(min_length=2)
    resource_type: str = Field(min_length=2)
    native_id: str = Field(min_length=3)
    display_name: str = Field(min_length=1)
    environment: str
    account_scope: str = Field(min_length=1)
    region: str = "global"
    owner: str = Field(min_length=3)
    cost_center: str = Field(min_length=2)
    data_classifications: tuple[str, ...] = ()
    tags: dict[str, str] = Field(default_factory=dict)

    @property
    def scoped_asset_id(self) -> str:
        return f"{self.tenant_id}:{self.asset_id}"


class EvidenceProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    source: EvidenceSource
    source_event_id: str = Field(min_length=3)
    observed_at: datetime
    run_id: str = Field(min_length=3)
    tenant_id: str = Field(min_length=1)
    evidence_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    schema_version: str = ENTERPRISE_SCHEMA_VERSION

    @field_validator("observed_at")
    @classmethod
    def observed_at_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value


class RawObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    event_id: str = Field(min_length=3)
    stage: EstateStage
    source: EvidenceSource
    event_type: str = Field(min_length=3)
    observed_at: datetime
    actor_id: str = Field(min_length=3)
    resource_ids: tuple[str, ...] = Field(min_length=1)
    trace_id: str = Field(default="", pattern=r"^(?:|[0-9a-f]{32})$")
    raw_payload: dict[str, Any]
    provenance: EvidenceProvenance

    @field_validator("observed_at")
    @classmethod
    def observed_at_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value


class CollectionRun(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    run_id: str
    tenant_id: str
    source: EvidenceSource
    status: CollectionStatus
    started_at: datetime
    completed_at: datetime
    records_read: int = Field(ge=0)
    read_only: bool = True
    watermark: str
    source_schema: str
    schema_url: str
    next_cursor: str = ""
    failure_code: str = ""

    @model_validator(mode="after")
    def validate_failure_state(self) -> CollectionRun:
        if self.status is CollectionStatus.COMPLETE and (self.failure_code or self.next_cursor):
            raise ValueError("complete collections cannot carry failure state")
        if self.status is not CollectionStatus.COMPLETE and not self.failure_code:
            raise ValueError("partial or unavailable collections require a failure_code")
        if self.completed_at < self.started_at:
            raise ValueError("collection completed_at precedes started_at")
        return self


_SOURCE_SCHEMAS: dict[EvidenceSource, tuple[str, str]] = {
    EvidenceSource.AWS_CLOUDTRAIL: (
        "cloudtrail-event-1.11",
        "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html",
    ),
    EvidenceSource.AZURE_ACTIVITY: (
        "azure-activity-log",
        "https://learn.microsoft.com/azure/azure-monitor/platform/activity-log-schema",
    ),
    EvidenceSource.ENTRA_SIGNIN: (
        "entra-signin-log",
        "https://learn.microsoft.com/entra/identity/monitoring-health/concept-activity-log-schemas",
    ),
    EvidenceSource.GCP_AUDIT: (
        "google-cloud-audit-log",
        "https://cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog",
    ),
    EvidenceSource.GITHUB_ACTIONS: (
        "github-workflow-run-webhook",
        "https://docs.github.com/webhooks/webhook-events-and-payloads#workflow_run",
    ),
    EvidenceSource.KUBERNETES_AUDIT: (
        "audit.k8s.io/v1",
        "https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/",
    ),
    EvidenceSource.MCP_GATEWAY: (
        "mcp-2025-11-25",
        "https://modelcontextprotocol.io/specification/2025-11-25/schema#tools-call",
    ),
    EvidenceSource.OTEL_LLM: (
        "otel-genai-semconv-1.43.0",
        "https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/",
    ),
    EvidenceSource.SNOWFLAKE_ACCESS_HISTORY: (
        "snowflake-account-usage-access-history",
        "https://docs.snowflake.com/sql-reference/account-usage/access_history",
    ),
}


class EstateSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    snapshot_id: str
    stage: EstateStage
    observed_at: datetime
    asset_ids: tuple[str, ...]
    event_ids: tuple[str, ...]
    change_summary: str


class EnterpriseEstate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: str
    estate_id: str
    tenant_id: str
    display_name: str
    synthetic: bool
    fictional: bool
    disclosure: str
    assets: tuple[EstateAsset, ...]
    observations: tuple[RawObservation, ...]
    collection_runs: tuple[CollectionRun, ...]
    snapshots: tuple[EstateSnapshot, ...]
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_integrity(self) -> EnterpriseEstate:
        if not self.synthetic or not self.fictional:
            raise ValueError("demo estate must remain explicitly synthetic and fictional")
        asset_ids = [asset.asset_id for asset in self.assets]
        if len(asset_ids) != len(set(asset_ids)):
            raise ValueError("asset_id values must be unique")
        event_ids = [event.event_id for event in self.observations]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("event_id values must be unique")
        known_assets = set(asset_ids)
        for event in self.observations:
            unknown = set(event.resource_ids) - known_assets
            if unknown:
                raise ValueError(f"event {event.event_id} references unknown assets: {sorted(unknown)}")
            if event.provenance.tenant_id != self.tenant_id:
                raise ValueError("observation provenance crosses the estate tenant boundary")
        return self


_ASSET_SPECS: tuple[dict[str, Any], ...] = (
    {
        "asset_id": "organization:northstar-health-ai",
        "provider": "enterprise",
        "resource_type": "organization",
        "native_id": "northstar-health-ai",
        "display_name": "Northstar Health AI",
        "environment": "production",
        "account_scope": "northstar-health-ai",
        "owner": "security@northstar.example",
        "cost_center": "GRC-100",
        "data_classifications": ["confidential"],
    },
    {
        "asset_id": "github:repository:northstar-health/member-copilot",
        "provider": "github",
        "resource_type": "repository",
        "native_id": "github://northstar-health/member-copilot",
        "display_name": "member-copilot",
        "environment": "development",
        "account_scope": "northstar-health",
        "owner": "ai-platform@northstar.example",
        "cost_center": "AI-410",
        "data_classifications": ["confidential"],
    },
    {
        "asset_id": "github:workflow:member-copilot/deploy-prod",
        "provider": "github",
        "resource_type": "workflow",
        "native_id": "github://northstar-health/member-copilot/actions/deploy-prod",
        "display_name": "Deploy member copilot",
        "environment": "production",
        "account_scope": "northstar-health",
        "tags": {"repository": "github:repository:northstar-health/member-copilot"},
        "owner": "ai-platform@northstar.example",
        "cost_center": "AI-410",
        "data_classifications": ["confidential"],
    },
    {
        "asset_id": ("cloud_resource:aws:ecr:image:member-copilot@sha256:4f2c8d66a10b490c6f5e7a2f91f7eb04cf9b1001df06d422ad2c42c5bc82f20a"),
        "provider": "aws",
        "resource_type": "container_image",
        "native_id": (
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/member-copilot@sha256:"
            "4f2c8d66a10b490c6f5e7a2f91f7eb04cf9b1001df06d422ad2c42c5bc82f20a"
        ),
        "display_name": "member-copilot:2026.08.03",
        "environment": "production",
        "account_scope": "123456789012",
        "region": "us-east-1",
        "owner": "ai-platform@northstar.example",
        "cost_center": "AI-410",
        "data_classifications": ["confidential"],
    },
    {
        "asset_id": "cloud_resource:aws:iam:role:member-copilot-prod",
        "provider": "aws",
        "resource_type": "iam_role",
        "native_id": "arn:aws:iam::123456789012:role/member-copilot-prod",
        "display_name": "member-copilot-prod",
        "environment": "production",
        "account_scope": "123456789012",
        "region": "global",
        "owner": "cloud-platform@northstar.example",
        "cost_center": "PLAT-210",
        "data_classifications": ["confidential"],
    },
    {
        "asset_id": "cloud_resource:aws:s3:bucket:member-exports-prod",
        "provider": "aws",
        "resource_type": "bucket",
        "native_id": "arn:aws:s3:::member-exports-prod",
        "display_name": "member-exports-prod",
        "environment": "production",
        "account_scope": "123456789012",
        "region": "us-east-1",
        "owner": "data-platform@northstar.example",
        "cost_center": "DATA-320",
        "data_classifications": ["phi", "pii"],
    },
    {
        "asset_id": "kubernetes:cluster:eks/member-ai-prod",
        "provider": "kubernetes",
        "resource_type": "cluster",
        "native_id": "k8s://eks/member-ai-prod",
        "display_name": "member-ai-prod",
        "environment": "production",
        "account_scope": "123456789012",
        "region": "us-east-1",
        "owner": "cloud-platform@northstar.example",
        "cost_center": "PLAT-210",
        "data_classifications": ["confidential"],
    },
    {
        "asset_id": "kubernetes:workload:member-ai-prod/ai-prod/member-copilot",
        "provider": "kubernetes",
        "resource_type": "deployment",
        "native_id": "k8s://member-ai-prod/ai-prod/deployment/member-copilot",
        "display_name": "member-copilot",
        "environment": "production",
        "account_scope": "member-ai-prod",
        "tags": {
            "cluster": "kubernetes:cluster:eks/member-ai-prod",
            "container_image": (
                "cloud_resource:aws:ecr:image:member-copilot@sha256:"
                "4f2c8d66a10b490c6f5e7a2f91f7eb04cf9b1001df06d422ad2c42c5bc82f20a"
            ),
            "uses_identity": "cloud_resource:aws:iam:role:member-copilot-prod",
            "reads_data": "snowflake:table:nh_prod/analytics/phi/patient_summary",
        },
        "region": "us-east-1",
        "owner": "ai-platform@northstar.example",
        "cost_center": "AI-410",
        "data_classifications": ["phi", "pii"],
    },
    {
        "asset_id": "mcp:server:clinical-analytics",
        "provider": "mcp",
        "resource_type": "server",
        "native_id": "mcp://clinical-analytics",
        "display_name": "Clinical Analytics MCP",
        "environment": "production",
        "account_scope": "member-ai-prod",
        "owner": "data-platform@northstar.example",
        "cost_center": "DATA-320",
        "data_classifications": ["phi", "pii"],
    },
    {
        "asset_id": "mcp:tool:clinical-analytics/execute_sql",
        "provider": "mcp",
        "resource_type": "tool",
        "native_id": "mcp://clinical-analytics/tools/execute_sql",
        "display_name": "execute_sql",
        "environment": "production",
        "account_scope": "member-ai-prod",
        "tags": {
            "mcp_server": "mcp:server:clinical-analytics",
            "write_capable": "false",
            "reads_data": "snowflake:table:nh_prod/analytics/phi/patient_summary",
        },
        "owner": "data-platform@northstar.example",
        "cost_center": "DATA-320",
        "data_classifications": ["phi", "pii"],
    },
    {
        "asset_id": "snowflake:database:nh_prod/analytics",
        "provider": "snowflake",
        "resource_type": "database",
        "native_id": "snowflake://NORTHSTAR/US_EAST_1/ANALYTICS",
        "display_name": "ANALYTICS",
        "environment": "production",
        "account_scope": "NORTHSTAR.US_EAST_1",
        "region": "aws_us_east_1",
        "owner": "data-platform@northstar.example",
        "cost_center": "DATA-320",
        "data_classifications": ["phi", "pii"],
    },
    {
        "asset_id": "snowflake:table:nh_prod/analytics/phi/patient_summary",
        "provider": "snowflake",
        "resource_type": "table",
        "native_id": "snowflake://NORTHSTAR/US_EAST_1/ANALYTICS/PHI/PATIENT_SUMMARY",
        "display_name": "ANALYTICS.PHI.PATIENT_SUMMARY",
        "environment": "production",
        "account_scope": "NORTHSTAR.US_EAST_1",
        "region": "aws_us_east_1",
        "owner": "data-platform@northstar.example",
        "cost_center": "DATA-320",
        "data_classifications": ["phi", "pii"],
    },
    {
        "asset_id": "model:openai:gpt-4.1",
        "provider": "openai",
        "resource_type": "hosted_model",
        "native_id": "openai://models/gpt-4.1",
        "display_name": "GPT-4.1",
        "environment": "production",
        "account_scope": "northstar-health-ai",
        "owner": "ai-platform@northstar.example",
        "cost_center": "AI-410",
        "data_classifications": ["confidential"],
    },
    {
        "asset_id": "model:anthropic:claude-sonnet-4-5",
        "provider": "anthropic",
        "resource_type": "hosted_model",
        "native_id": "anthropic://models/claude-sonnet-4-5",
        "display_name": "Claude Sonnet 4.5",
        "environment": "staging",
        "account_scope": "northstar-health-ai",
        "owner": "ai-platform@northstar.example",
        "cost_center": "AI-410",
        "data_classifications": ["confidential"],
    },
    {
        "asset_id": "model:huggingface:sentence-transformers/all-minilm-l6-v2",
        "provider": "huggingface",
        "resource_type": "model_artifact",
        "native_id": "hf://sentence-transformers/all-MiniLM-L6-v2@c9745ed",
        "display_name": "all-MiniLM-L6-v2",
        "environment": "development",
        "account_scope": "northstar-health-ai",
        "owner": "ai-platform@northstar.example",
        "cost_center": "AI-410",
        "data_classifications": ["public"],
    },
    {
        "asset_id": "cloud_resource:azure:keyvault:vault:nh-prod-member-secrets",
        "provider": "azure",
        "resource_type": "key_vault",
        "native_id": (
            "/subscriptions/11111111-2222-3333-4444-555555555555/"
            "resourceGroups/rg-member-prod/providers/Microsoft.KeyVault/"
            "vaults/nh-prod-member-secrets"
        ),
        "display_name": "nh-prod-member-secrets",
        "environment": "production",
        "account_scope": "11111111-2222-3333-4444-555555555555",
        "region": "eastus2",
        "owner": "cloud-platform@northstar.example",
        "cost_center": "PLAT-210",
        "data_classifications": ["confidential"],
    },
    {
        "asset_id": "identity:azure:service-principal:claims-enrichment",
        "provider": "azure",
        "resource_type": "service_principal",
        "native_id": "entra://northstar-health-ai/servicePrincipals/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "display_name": "claims-enrichment",
        "environment": "production",
        "account_scope": "northstar-health-ai.onmicrosoft.com",
        "owner": "ai-platform@northstar.example",
        "cost_center": "AI-410",
        "data_classifications": ["confidential"],
    },
    {
        "asset_id": "cloud_resource:gcp:storage:bucket:nh-ml-features-prod",
        "provider": "gcp",
        "resource_type": "bucket",
        "native_id": "//storage.googleapis.com/nh-ml-features-prod",
        "display_name": "nh-ml-features-prod",
        "environment": "production",
        "account_scope": "nh-ml-prod-7f3a",
        "region": "us-central1",
        "owner": "ml-platform@northstar.example",
        "cost_center": "ML-430",
        "data_classifications": ["phi", "pii"],
    },
    {
        "asset_id": "identity:gcp:service-account:feature-reader",
        "provider": "gcp",
        "resource_type": "service_account",
        "native_id": "feature-reader@nh-ml-prod-7f3a.iam.gserviceaccount.com",
        "display_name": "feature-reader",
        "environment": "production",
        "account_scope": "nh-ml-prod-7f3a",
        "region": "global",
        "owner": "ml-platform@northstar.example",
        "cost_center": "ML-430",
        "data_classifications": ["confidential"],
    },
    {
        "asset_id": "kubernetes:cluster:aks/claims-staging",
        "provider": "kubernetes",
        "resource_type": "cluster",
        "native_id": "k8s://aks/claims-staging",
        "display_name": "claims-staging",
        "environment": "staging",
        "account_scope": "11111111-2222-3333-4444-555555555555",
        "region": "eastus2",
        "owner": "cloud-platform@northstar.example",
        "cost_center": "PLAT-210",
        "data_classifications": ["confidential"],
    },
)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _observation_hash(row: dict[str, Any]) -> str:
    evidence = {
        key: row[key]
        for key in (
            "event_id",
            "stage",
            "source",
            "event_type",
            "observed_at",
            "actor_id",
            "resource_ids",
            "trace_id",
            "raw_payload",
        )
    }
    return hashlib.sha256(_canonical_json(evidence)).hexdigest()


def verify_observation_hash(observation: RawObservation) -> bool:
    row = observation.model_dump(mode="json", exclude={"provenance"})
    return _observation_hash(row) == observation.provenance.evidence_hash


def _load_observations(tenant_id: str) -> tuple[RawObservation, ...]:
    fixture = files("agent_bom.demo_estate").joinpath("data", _FIXTURE_NAME)
    rows: list[RawObservation] = []
    for line_number, line in enumerate(fixture.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        raw = json.loads(line)
        evidence_hash = _observation_hash(raw)
        raw["provenance"] = {
            "source": raw["source"],
            "source_event_id": raw["event_id"],
            "observed_at": raw["observed_at"],
            "run_id": f"demo-run-{raw['stage']}-{raw['source']}",
            "tenant_id": tenant_id,
            "evidence_hash": evidence_hash,
            "schema_version": ENTERPRISE_SCHEMA_VERSION,
        }
        try:
            rows.append(RawObservation.model_validate(raw))
        except ValueError as exc:
            raise ValueError(f"invalid enterprise fixture line {line_number}") from exc
    return tuple(rows)


def _collection_runs(observations: tuple[RawObservation, ...], tenant_id: str) -> tuple[CollectionRun, ...]:
    counts = {source: 0 for source in EvidenceSource}
    for observation in observations:
        counts[observation.source] += 1
    started_at = datetime.fromisoformat("2026-08-03T18:00:00+00:00")
    completed_at = datetime.fromisoformat("2026-08-03T18:04:00+00:00")
    runs: list[CollectionRun] = []
    for source in EvidenceSource:
        partial = source is EvidenceSource.GCP_AUDIT
        source_schema, schema_url = _SOURCE_SCHEMAS[source]
        runs.append(
            CollectionRun(
                run_id=f"demo-collection-current-{source.value}",
                tenant_id=tenant_id,
                source=source,
                status=CollectionStatus.PARTIAL if partial else CollectionStatus.COMPLETE,
                started_at=started_at,
                completed_at=completed_at,
                records_read=counts[source],
                watermark="2026-08-03T18:04:00Z",
                source_schema=source_schema,
                schema_url=schema_url,
                next_cursor="gcp-page-token-redacted" if partial else "",
                failure_code="rate_limited_after_page_2" if partial else "",
            )
        )
    return tuple(runs)


def _snapshots(assets: tuple[EstateAsset, ...], observations: tuple[RawObservation, ...]) -> tuple[EstateSnapshot, ...]:
    timestamps = {
        EstateStage.BASELINE: datetime.fromisoformat("2026-07-27T18:00:00+00:00"),
        EstateStage.CURRENT: datetime.fromisoformat("2026-08-03T18:05:00+00:00"),
        EstateStage.REMEDIATED: datetime.fromisoformat("2026-08-03T20:30:00+00:00"),
    }
    summaries = {
        EstateStage.BASELINE: "Known-good read-only baseline before the risky deployment.",
        EstateStage.CURRENT: "Correlated CI, identity, workload, MCP, data-access, and LLM exfiltration attempt.",
        EstateStage.REMEDIATED: "Public access removed, standing access revoked, and runtime policy enforced.",
    }
    asset_ids = tuple(sorted(asset.asset_id for asset in assets))
    return tuple(
        EstateSnapshot(
            snapshot_id=f"northstar-{stage.value}-2026-08-03",
            stage=stage,
            observed_at=timestamps[stage],
            asset_ids=asset_ids,
            event_ids=tuple(sorted(row.event_id for row in observations if row.stage is stage)),
            change_summary=summaries[stage],
        )
        for stage in (EstateStage.BASELINE, EstateStage.CURRENT, EstateStage.REMEDIATED)
    )


def load_enterprise_estate(*, tenant_id: str = "default") -> EnterpriseEstate:
    """Load a deterministic, tenant-scoped, explicitly synthetic estate."""
    tenant_id = tenant_id.strip()
    if not tenant_id:
        raise ValueError("tenant_id must not be empty")
    assets = tuple(EstateAsset(tenant_id=tenant_id, **spec) for spec in _ASSET_SPECS)
    observations = _load_observations(tenant_id)
    estate = EnterpriseEstate(
        schema_version=ENTERPRISE_SCHEMA_VERSION,
        estate_id="northstar-health-ai-v1",
        tenant_id=tenant_id,
        display_name="Northstar Health AI",
        synthetic=True,
        fictional=True,
        disclosure=("Synthetic fictional enterprise evidence for product demonstration; it is not customer telemetry or an audit verdict."),
        assets=assets,
        observations=observations,
        collection_runs=_collection_runs(observations, tenant_id),
        snapshots=_snapshots(assets, observations),
        content_hash="0" * 64,
    )
    digest = hashlib.sha256(_canonical_json(estate.model_dump(mode="json", exclude={"content_hash"}))).hexdigest()
    return estate.model_copy(update={"content_hash": digest})
