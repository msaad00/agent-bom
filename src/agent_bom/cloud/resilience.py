"""Provider API resilience evidence for cloud and AI inventory scans.

The scanner already keeps provider implementations separate because each
API paginates and fails differently.  This module gives operators and CI a
single contract to inspect without requiring live cloud credentials.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

ResilienceStatus = Literal["verified", "partial", "not_applicable"]


@dataclass(frozen=True)
class ProviderResilienceProfile:
    provider: str
    surface: str
    pagination: str
    retry_backoff: str
    partial_failure: str
    max_page_safety: str
    synthetic_scale_target: int | None
    status: ResilienceStatus
    evidence: tuple[str, ...]

    def to_dict(self) -> dict:
        data = asdict(self)
        data["evidence"] = list(self.evidence)
        return data


_PROFILES: tuple[ProviderResilienceProfile, ...] = (
    ProviderResilienceProfile(
        provider="aws",
        surface="Bedrock Agents, Lambda, ECS, EKS, SageMaker, Step Functions, EC2",
        pagination="boto3 paginators for list/describe APIs",
        retry_backoff="delegated to botocore retry configuration plus per-call warning capture",
        partial_failure="non-fatal service exceptions are returned as warnings while other providers continue",
        max_page_safety="SDK paginator exhaustion; synthetic tests cover 10k resources without live credentials",
        synthetic_scale_target=10_000,
        status="verified",
        evidence=("src/agent_bom/cloud/aws.py", "tests/test_cloud_resilience.py"),
    ),
    ProviderResilienceProfile(
        provider="azure",
        surface="Azure AI Foundry, Container Apps, AKS, Functions, VMs, CIS resources",
        pagination="Azure SDK ItemPaged iterators/list_all calls",
        retry_backoff="delegated to Azure SDK retry policy; scanner records non-fatal warnings",
        partial_failure="missing SDKs or failed services degrade to warnings instead of empty success",
        max_page_safety="SDK iterator exhaustion; resilience contract is CI-verified",
        synthetic_scale_target=10_000,
        status="partial",
        evidence=("src/agent_bom/cloud/azure.py", "src/agent_bom/cloud/azure_cis_benchmark.py"),
    ),
    ProviderResilienceProfile(
        provider="gcp",
        surface="Vertex AI, Cloud Run, Cloud Functions, GKE, CIS resources",
        pagination="Google Cloud paged iterators from list_* client calls",
        retry_backoff="delegated to google-cloud client retry behavior; scanner reports provider warnings",
        partial_failure="project/API failures are surfaced as warnings while the scan can continue",
        max_page_safety="SDK iterator exhaustion; resilience contract is CI-verified",
        synthetic_scale_target=10_000,
        status="partial",
        evidence=("src/agent_bom/cloud/gcp.py", "src/agent_bom/cloud/gcp_cis_benchmark.py"),
    ),
    ProviderResilienceProfile(
        provider="snowflake",
        surface="Cortex Agents, Snowflake governance, CIS and observability",
        pagination="bounded SQL result sets and warehouse-side filtering",
        retry_backoff="connector-level retry where configured; scanner surfaces query failures",
        partial_failure="governance/observability failures are warning-bearing partial coverage",
        max_page_safety="bounded queries; no unbounded in-memory provider pagination contract",
        synthetic_scale_target=10_000,
        status="partial",
        evidence=("src/agent_bom/cloud/snowflake.py", "src/agent_bom/cloud/snowflake_observability.py"),
    ),
    ProviderResilienceProfile(
        provider="databricks",
        surface="Clusters, jobs, libraries, model-serving and security posture",
        pagination="SDK/list API iteration where supported",
        retry_backoff="provider SDK/client behavior; scanner keeps failures as warnings",
        partial_failure="workspace/API failures do not hide missing inventory",
        max_page_safety="bounded provider calls; contract marks live scale evidence as partial",
        synthetic_scale_target=10_000,
        status="partial",
        evidence=("src/agent_bom/cloud/databricks.py", "src/agent_bom/cloud/databricks_security.py"),
    ),
    ProviderResilienceProfile(
        provider="huggingface",
        surface="Hugging Face model registry, hash and provenance metadata",
        pagination="Hub API/list iterators where repository enumeration is used",
        retry_backoff="shared HTTP retry client for Hub metadata where direct HTTP is used",
        partial_failure="unreachable Hub metadata becomes explicit warning/error evidence",
        max_page_safety="metadata fetches are bounded by discovered model set",
        synthetic_scale_target=10_000,
        status="verified",
        evidence=("src/agent_bom/cloud/huggingface.py", "src/agent_bom/model_hash.py"),
    ),
    ProviderResilienceProfile(
        provider="openai",
        surface="OpenAI assistants, vector stores, model and file inventory",
        pagination="cursor-based pagination via has_more/after loops",
        retry_backoff="OpenAI SDK/client retry behavior plus scanner warnings",
        partial_failure="per-surface failures are warning-bearing partial coverage",
        max_page_safety="cursor exhaustion with page-loop tests",
        synthetic_scale_target=10_000,
        status="verified",
        evidence=("src/agent_bom/cloud/openai_provider.py", "tests/test_cloud_resilience.py"),
    ),
    ProviderResilienceProfile(
        provider="wandb",
        surface="Weights & Biases projects, runs, artifacts and model lineage",
        pagination="W&B SDK iterable collections",
        retry_backoff="W&B SDK/client behavior; scanner surfaces API failures",
        partial_failure="project/run/artifact failures are warnings, not silent success",
        max_page_safety="SDK iterator exhaustion; live scale evidence remains provider-dependent",
        synthetic_scale_target=10_000,
        status="partial",
        evidence=("src/agent_bom/cloud/wandb_provider.py", "tests/test_cloud_providers_cov.py"),
    ),
    ProviderResilienceProfile(
        provider="mlflow",
        surface="MLflow experiments, runs and model registry artifacts",
        pagination="page_token loops for experiments and registered models",
        retry_backoff="MLflow client behavior; scanner returns warning-bearing partial coverage",
        partial_failure="failed experiments/runs keep discovered inventory and add warnings",
        max_page_safety="page-token exhaustion with contract coverage",
        synthetic_scale_target=10_000,
        status="verified",
        evidence=("src/agent_bom/cloud/mlflow_provider.py", "tests/test_cloud_resilience.py"),
    ),
    ProviderResilienceProfile(
        provider="nebius",
        surface="Nebius GPU/AI cloud resources",
        pagination="nextPageToken/pageToken cursor pagination",
        retry_backoff="shared HTTP retry client for API calls",
        partial_failure="API failures surface as warnings/errors rather than empty success",
        max_page_safety="cursor exhaustion with explicit token handling",
        synthetic_scale_target=10_000,
        status="verified",
        evidence=("src/agent_bom/cloud/nebius.py", "tests/test_cloud_resilience.py"),
    ),
    ProviderResilienceProfile(
        provider="coreweave",
        surface="CoreWeave GPU cloud inventory",
        pagination="bounded API/list calls for discovered resources",
        retry_backoff="shared HTTP retry client where HTTP discovery is used",
        partial_failure="provider failures are surfaced as warnings",
        max_page_safety="bounded provider calls; live scale evidence remains provider-dependent",
        synthetic_scale_target=10_000,
        status="partial",
        evidence=("src/agent_bom/cloud/coreweave.py", "src/agent_bom/cloud/gpu_infra.py"),
    ),
    ProviderResilienceProfile(
        provider="ollama",
        surface="Local Ollama model registry",
        pagination="not applicable: local endpoint returns bounded model lists",
        retry_backoff="sync HTTP fallback uses the shared retry-capable client",
        partial_failure="local endpoint failures become explicit warnings",
        max_page_safety="local bounded inventory; no remote page traversal",
        synthetic_scale_target=None,
        status="not_applicable",
        evidence=("src/agent_bom/cloud/ollama.py",),
    ),
    ProviderResilienceProfile(
        provider="lambda",
        surface="Lambda Labs GPU instances via REST API",
        pagination="single-page list (Lambda Cloud API returns all instances)",
        retry_backoff="requests HTTPError surfaced as warnings on API failure",
        partial_failure="API failures surface as warnings, returning partial or empty inventory",
        max_page_safety="bounded single list response; no cursor pagination needed",
        synthetic_scale_target=10_000,
        status="partial",
        evidence=("src/agent_bom/cloud/lambda_labs.py",),
    ),
    ProviderResilienceProfile(
        provider="runpod",
        surface="RunPod GPU pods and serverless endpoints via GraphQL",
        pagination="GraphQL single-query list (pods + endpoints in one request)",
        retry_backoff="requests HTTPError and GraphQL error dict surfaced as warnings",
        partial_failure="pod and serverless failures handled in separate try/except blocks",
        max_page_safety="GraphQL returns bounded result sets; no cursor pagination",
        synthetic_scale_target=10_000,
        status="partial",
        evidence=("src/agent_bom/cloud/runpod.py",),
    ),
    ProviderResilienceProfile(
        provider="vastai",
        surface="Vast.ai rented GPU instances via REST API",
        pagination="single-page list filtered to owner=me",
        retry_backoff="requests HTTPError surfaced as warnings on API failure",
        partial_failure="API failures surface as warnings, returning partial or empty inventory",
        max_page_safety="bounded single list response; no cursor pagination needed",
        synthetic_scale_target=10_000,
        status="partial",
        evidence=("src/agent_bom/cloud/vastai.py",),
    ),
    ProviderResilienceProfile(
        provider="crusoe",
        surface="Crusoe Energy GPU VMs via REST API",
        pagination="single-page VM list (optionally project-scoped)",
        retry_backoff="requests HTTPError surfaced as warnings on API failure",
        partial_failure="API failures surface as warnings, returning partial or empty inventory",
        max_page_safety="bounded single list response; no cursor pagination needed",
        synthetic_scale_target=10_000,
        status="partial",
        evidence=("src/agent_bom/cloud/crusoe.py",),
    ),
)


def provider_resilience_profiles() -> tuple[ProviderResilienceProfile, ...]:
    """Return the immutable provider resilience evidence matrix."""

    return _PROFILES


def provider_resilience_summary() -> dict:
    """Return JSON-serialisable provider resilience posture."""

    profiles = [profile.to_dict() for profile in _PROFILES]
    status_counts: dict[str, int] = {"verified": 0, "partial": 0, "not_applicable": 0}
    for profile in _PROFILES:
        status_counts[profile.status] += 1
    return {
        "schema_version": 1,
        "target_resource_count": 10_000,
        "default_ci_mode": "synthetic_no_credentials",
        "status_counts": status_counts,
        "providers": profiles,
    }


def provider_resilience_gaps() -> list[dict]:
    """Return providers that still need live scale evidence."""

    return [
        {
            "provider": profile.provider,
            "status": profile.status,
            "reason": "live provider-scale evidence remains outstanding",
        }
        for profile in _PROFILES
        if profile.status == "partial"
    ]
