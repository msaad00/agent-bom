"""Correlate locally-discovered agents with cloud-discovered runtimes.

This is the framework piece that backs issue #1892 — proving that a local
agent (Cursor, Claude Desktop, framework code on a developer machine) is
talking to a specific cloud runtime (AWS Bedrock, Azure OpenAI, GCP Vertex)
under a specific identity.

Bar for the strong edge
-----------------------
A `CORRELATES_WITH` edge is reserved for HIGH-confidence matches: the local
agent and the cloud agent must agree on **all three** of the strong identity
signals for the provider — for AWS Bedrock those are the cloud account ID,
the region, and the model ID. SDK presence or a single-signal model-name
substring match is not enough — it would silently merge unrelated agents
across accounts or environments.

Partial matches are still useful, so they emit `POSSIBLY_CORRELATES_WITH`
with a `matched_signals` evidence list. Operators see the candidate without
the platform pretending it is the same agent.

Phase 1 ships AWS Bedrock. Phase 2 will add Azure OpenAI / Functions and
Phase 3 will add GCP Vertex / Cloud Run. The provider-specific extractor +
matcher pair is the only thing each phase adds; the dispatch and edge
emission stay shared.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping, TypeAlias, TypeVar, Union

from agent_bom.models import Agent

# An agent record can flow into the matcher either as the rich `Agent`
# dataclass (used by Python callers and tests) or as the serialized-dict
# shape that already lives inside the scan report (used by the graph
# builder). The strong-signal extractors only need a handful of fields, so
# we normalize both shapes through `_AgentView` instead of forcing one
# canonical type on every caller.
AgentLike: TypeAlias = Union[Agent, Mapping[str, Any]]
_CloudT = TypeVar("_CloudT")

# ---------------------------------------------------------------------------
# Strict-bar requirement: at least this many of the strong signals (account,
# region, model_id) must match for a HIGH-confidence edge. Three out of three
# is the strict bar; we keep it as a constant so the threshold is one place.
# ---------------------------------------------------------------------------
_HIGH_CONFIDENCE_REQUIRED_SIGNALS = 3


class CorrelationConfidence(str, Enum):
    """Confidence level of a cross-environment correlation match."""

    HIGH = "high"
    LOW = "low"


@dataclass(frozen=True)
class CorrelationMatch:
    """One correlation between a local agent and a cloud runtime.

    `matched_signals` lists the strong identity signals that agreed (subset of
    {"account_id", "region", "model_id"} for AWS Bedrock; analogous tuples for
    Azure / GCP in later phases). It is part of the edge evidence so an
    operator can see why we drew this particular line.
    """

    local_agent_name: str
    local_agent_type: str
    cloud_agent_name: str
    cloud_provider: str
    cloud_service: str
    cloud_account_id: str | None
    cloud_region: str | None
    cloud_model_id: str | None
    confidence: CorrelationConfidence
    matched_signals: tuple[str, ...]
    rationale: str


@dataclass(frozen=True)
class _LocalAwsEvidence:
    """Strong AWS identity signals pulled from a locally-discovered agent."""

    agent_name: str
    agent_type: str
    account_ids: frozenset[str]
    regions: frozenset[str]
    model_ids: frozenset[str]


@dataclass(frozen=True)
class _CloudBedrockAgent:
    """Strong identity signals for a cloud-discovered Bedrock agent."""

    agent_name: str
    arn: str
    account_id: str | None
    region: str | None
    model_id: str | None


# ---------------------------------------------------------------------------
# Bedrock identity extractors
# ---------------------------------------------------------------------------

# Authoritative: regional Bedrock ARN. The account segment can be empty for
# legacy ARNs that omit it; we treat that as "account unknown" rather than
# guessing.
_BEDROCK_ARN_RE = re.compile(r"^arn:aws:bedrock:([a-z0-9-]+):([0-9]{0,12}):")

# Local env-var keys that surface AWS account, region, and Bedrock model id
# without requiring source-code analysis. Operators set these explicitly when
# wiring an agent to Bedrock; if any of them is present we treat it as an
# explicit declaration of intent.
_AWS_ACCOUNT_ENV_KEYS = ("AWS_ACCOUNT_ID", "AWS_DEFAULT_ACCOUNT", "BEDROCK_ACCOUNT_ID")
_AWS_REGION_ENV_KEYS = ("AWS_REGION", "AWS_DEFAULT_REGION", "BEDROCK_REGION")
_BEDROCK_MODEL_ENV_KEYS = (
    "BEDROCK_MODEL_ID",
    "BEDROCK_FOUNDATION_MODEL",
    "AWS_BEDROCK_MODEL_ID",
)
# Endpoint URLs surface region (and sometimes a custom account); we parse
# both so an explicit endpoint counts the same as AWS_REGION.
_AWS_ENDPOINT_ENV_KEYS = (
    "AWS_ENDPOINT_URL_BEDROCK",
    "AWS_ENDPOINT_URL_BEDROCK_RUNTIME",
    "BEDROCK_ENDPOINT_URL",
)
_BEDROCK_ENDPOINT_RE = re.compile(
    r"https?://bedrock(?:-runtime)?\.([a-z0-9-]+)\.amazonaws\.com",
)


def _parse_account_and_region_from_arn(arn: str) -> tuple[str | None, str | None]:
    match = _BEDROCK_ARN_RE.search(arn)
    if not match:
        return None, None
    region = match.group(1) or None
    account = match.group(2) or None
    return account, region


def _looks_like_bedrock_model_id(value: str) -> bool:
    # Bedrock foundation/inference IDs are dotted vendor-prefixed identifiers
    # such as `anthropic.claude-3-5-sonnet-20241022-v2:0`,
    # `amazon.titan-text-express-v1`, `meta.llama3-70b-instruct-v1:0`. The
    # leading vendor segment + dot is the cheap, accurate gate; substring
    # matching against vendor names alone is what burned PR #1994 (it counts
    # any string containing "claude" as a Bedrock match).
    if "." not in value:
        return False
    vendor = value.split(".", 1)[0].lower()
    return vendor in {
        "anthropic",
        "amazon",
        "meta",
        "mistral",
        "ai21",
        "cohere",
        "stability",
    }


@dataclass(frozen=True)
class _AgentView:
    """Read-only normalized view over either an Agent or a serialized dict."""

    name: str
    agent_type: str
    config_path: str
    version: str
    metadata: Mapping[str, Any]
    mcp_server_envs: tuple[Mapping[str, Any], ...]


def _normalize(agent: AgentLike) -> _AgentView:
    if isinstance(agent, Agent):
        return _AgentView(
            name=agent.name,
            agent_type=agent.agent_type.value,
            config_path=str(agent.config_path or ""),
            version=str(agent.version or ""),
            metadata=agent.metadata or {},
            mcp_server_envs=tuple((server.env or {}) for server in agent.mcp_servers),
        )

    metadata = agent.get("metadata") or {}
    mcp_servers = agent.get("mcp_servers") or []
    envs: list[Mapping[str, Any]] = []
    for server in mcp_servers:
        if not isinstance(server, Mapping):
            continue
        env = server.get("env")
        if isinstance(env, Mapping):
            envs.append(env)
    return _AgentView(
        name=str(agent.get("name", "")),
        agent_type=str(agent.get("agent_type", "")),
        config_path=str(agent.get("config_path", "") or ""),
        version=str(agent.get("version", "") or ""),
        metadata=metadata if isinstance(metadata, Mapping) else {},
        mcp_server_envs=tuple(envs),
    )


def _extract_local_aws_evidence(view: _AgentView) -> _LocalAwsEvidence | None:
    if _is_cloud_discovered(view):
        return None

    accounts: set[str] = set()
    regions: set[str] = set()
    models: set[str] = set()

    for env in view.mcp_server_envs:
        for key, value in env.items():
            if not isinstance(value, str) or not value:
                continue
            if key in _AWS_ACCOUNT_ENV_KEYS and value.isdigit() and len(value) == 12:
                accounts.add(value)
            elif key in _AWS_REGION_ENV_KEYS:
                regions.add(value.strip().lower())
            elif key in _BEDROCK_MODEL_ENV_KEYS and _looks_like_bedrock_model_id(value):
                models.add(value.strip())
            elif key in _AWS_ENDPOINT_ENV_KEYS:
                endpoint_match = _BEDROCK_ENDPOINT_RE.search(value)
                if endpoint_match:
                    regions.add(endpoint_match.group(1).lower())

    raw_explicit = view.metadata.get("aws")
    explicit_aws: Mapping[str, Any] = raw_explicit if isinstance(raw_explicit, Mapping) else {}
    explicit_account = str(explicit_aws.get("account_id", "")).strip()
    if explicit_account.isdigit() and len(explicit_account) == 12:
        accounts.add(explicit_account)
    explicit_region = str(explicit_aws.get("region", "")).strip().lower()
    if explicit_region:
        regions.add(explicit_region)
    explicit_model = str(explicit_aws.get("bedrock_model_id", "")).strip()
    if _looks_like_bedrock_model_id(explicit_model):
        models.add(explicit_model)

    if not (accounts or regions or models):
        return None

    return _LocalAwsEvidence(
        agent_name=view.name,
        agent_type=view.agent_type,
        account_ids=frozenset(accounts),
        regions=frozenset(regions),
        model_ids=frozenset(models),
    )


def _extract_cloud_bedrock_agent(view: _AgentView) -> _CloudBedrockAgent | None:
    cloud_origin = view.metadata.get("cloud_origin") if isinstance(view.metadata.get("cloud_origin"), Mapping) else None
    if not cloud_origin or cloud_origin.get("provider") != "aws" or cloud_origin.get("service") != "bedrock":
        return None

    arn = str(cloud_origin.get("resource_id") or view.config_path or "")
    arn_account, arn_region = _parse_account_and_region_from_arn(arn)

    scope = cloud_origin.get("scope") or {}
    scope_account = str(scope.get("account_id") or "").strip() if isinstance(scope, Mapping) else ""
    account_id = scope_account or arn_account

    location = str(cloud_origin.get("location") or "").strip().lower()
    region = location or arn_region

    foundation_model = view.version.strip()
    model_id = foundation_model if _looks_like_bedrock_model_id(foundation_model) else None

    return _CloudBedrockAgent(
        agent_name=view.name,
        arn=arn,
        account_id=account_id,
        region=region,
        model_id=model_id,
    )


# ---------------------------------------------------------------------------
# Bedrock matcher
# ---------------------------------------------------------------------------


def _match_bedrock(
    local: _LocalAwsEvidence,
    cloud: _CloudBedrockAgent,
) -> CorrelationMatch | None:
    matched: list[str] = []

    if cloud.account_id and cloud.account_id in local.account_ids:
        matched.append("account_id")
    if cloud.region and cloud.region in local.regions:
        matched.append("region")
    if cloud.model_id and cloud.model_id in local.model_ids:
        matched.append("model_id")

    if not matched:
        return None

    confidence = CorrelationConfidence.HIGH if len(matched) >= _HIGH_CONFIDENCE_REQUIRED_SIGNALS else CorrelationConfidence.LOW

    rationale_parts = []
    if "account_id" in matched:
        rationale_parts.append(f"account {cloud.account_id}")
    if "region" in matched:
        rationale_parts.append(f"region {cloud.region}")
    if "model_id" in matched:
        rationale_parts.append(f"model {cloud.model_id}")

    rationale = (
        "Strong triplet (account + region + model) matched."
        if confidence is CorrelationConfidence.HIGH
        else "Partial match — kept as low-confidence candidate. Matched: " + ", ".join(rationale_parts) + "."
    )

    return CorrelationMatch(
        local_agent_name=local.agent_name,
        local_agent_type=local.agent_type,
        cloud_agent_name=cloud.agent_name,
        cloud_provider="aws",
        cloud_service="bedrock",
        cloud_account_id=cloud.account_id,
        cloud_region=cloud.region,
        cloud_model_id=cloud.model_id,
        confidence=confidence,
        matched_signals=tuple(matched),
        rationale=rationale,
    )


def _add_candidate(index: dict[str, list[_CloudT]], key: str | None, cloud: _CloudT) -> None:
    """Add a cloud asset to a signal index when the signal is usable."""
    if key:
        index.setdefault(key, []).append(cloud)


def _iter_indexed_candidates(index: dict[str, list[_CloudT]], keys: Iterable[str]) -> list[_CloudT]:
    """Return unique cloud assets that share at least one strong signal.

    The matchers still apply their strict scoring after this prefilter. This
    only removes pairs that cannot possibly match because none of their
    provider identity signals intersect.
    """
    candidates: list[_CloudT] = []
    seen: set[int] = set()
    for key in keys:
        for cloud in index.get(key, []):
            marker = id(cloud)
            if marker in seen:
                continue
            seen.add(marker)
            candidates.append(cloud)
    return candidates


def correlate_bedrock(agents: Iterable[AgentLike]) -> list[CorrelationMatch]:
    """Match local agents to cloud-discovered Bedrock agents."""
    local_evidence: list[_LocalAwsEvidence] = []
    cloud_index: dict[str, list[_CloudBedrockAgent]] = {}

    for agent in agents:
        view = _normalize(agent)
        cloud = _extract_cloud_bedrock_agent(view)
        if cloud is not None:
            _add_candidate(cloud_index, cloud.account_id, cloud)
            _add_candidate(cloud_index, cloud.region, cloud)
            _add_candidate(cloud_index, cloud.model_id, cloud)
            continue
        local = _extract_local_aws_evidence(view)
        if local is not None:
            local_evidence.append(local)

    matches: list[CorrelationMatch] = []
    for local in local_evidence:
        candidate_keys = (*local.account_ids, *local.regions, *local.model_ids)
        for cloud in _iter_indexed_candidates(cloud_index, candidate_keys):
            match = _match_bedrock(local, cloud)
            if match is not None:
                matches.append(match)
    return matches


# ---------------------------------------------------------------------------
# Azure OpenAI identity extractors + matcher (#1892 Phase 2)
# ---------------------------------------------------------------------------

# Authoritative Azure resource ID for an OpenAI deployment:
#   /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.CognitiveServices/accounts/{account}/deployments/{deployment}
_AZURE_RESOURCE_RE = re.compile(
    r"^/subscriptions/(?P<sub>[0-9a-f-]{36})/resourceGroups/(?P<rg>[^/]+)/providers/Microsoft\.CognitiveServices/accounts/(?P<account>[^/]+)/deployments/(?P<deployment>[^/]+)",
    re.IGNORECASE,
)
# Local Azure OpenAI endpoint hostname: `https://{account-name}.openai.azure.com/...`.
_AZURE_OPENAI_ENDPOINT_RE = re.compile(r"https?://([a-z0-9-]+)\.openai\.azure\.com", re.IGNORECASE)

_AZURE_SUBSCRIPTION_ENV_KEYS = ("AZURE_SUBSCRIPTION_ID", "ARM_SUBSCRIPTION_ID")
_AZURE_OPENAI_ENDPOINT_ENV_KEYS = ("AZURE_OPENAI_ENDPOINT", "OPENAI_API_BASE", "OPENAI_BASE_URL")
_AZURE_OPENAI_DEPLOYMENT_ENV_KEYS = (
    "AZURE_OPENAI_DEPLOYMENT",
    "AZURE_OPENAI_DEPLOYMENT_NAME",
    "OPENAI_DEPLOYMENT_ID",
)
# `OPENAI_API_TYPE=azure` is the marker that distinguishes Azure-flavored
# OpenAI usage from public api.openai.com — we don't act on it alone, but
# a non-azure value disqualifies the agent from Azure correlation.
_AZURE_OPENAI_API_TYPE_KEYS = ("OPENAI_API_TYPE",)


@dataclass(frozen=True)
class _LocalAzureOpenAIEvidence:
    agent_name: str
    agent_type: str
    subscription_ids: frozenset[str]
    account_names: frozenset[str]
    deployment_names: frozenset[str]


@dataclass(frozen=True)
class _CloudAzureOpenAIDeployment:
    agent_name: str
    resource_id: str
    subscription_id: str | None
    account_name: str | None
    deployment_name: str | None
    location: str | None


def _parse_azure_resource_id(resource_id: str) -> tuple[str | None, str | None, str | None]:
    match = _AZURE_RESOURCE_RE.search(resource_id)
    if not match:
        return None, None, None
    return (
        match.group("sub").lower(),
        match.group("account").lower(),
        match.group("deployment").lower(),
    )


def _is_azure_uuid(value: str) -> bool:
    if len(value) != 36 or value.count("-") != 4:
        return False
    return all(ch in "0123456789abcdef-" for ch in value.lower())


def _extract_local_azure_openai_evidence(view: _AgentView) -> _LocalAzureOpenAIEvidence | None:
    if _is_cloud_discovered(view):
        return None

    api_type_disqualifies = False
    subscriptions: set[str] = set()
    accounts: set[str] = set()
    deployments: set[str] = set()

    for env in view.mcp_server_envs:
        for key, value in env.items():
            if not isinstance(value, str) or not value:
                continue
            stripped = value.strip()
            if key in _AZURE_OPENAI_API_TYPE_KEYS:
                if stripped.lower() != "azure":
                    api_type_disqualifies = True
            elif key in _AZURE_SUBSCRIPTION_ENV_KEYS and _is_azure_uuid(stripped):
                subscriptions.add(stripped.lower())
            elif key in _AZURE_OPENAI_ENDPOINT_ENV_KEYS:
                endpoint_match = _AZURE_OPENAI_ENDPOINT_RE.search(stripped)
                if endpoint_match:
                    accounts.add(endpoint_match.group(1).lower())
            elif key in _AZURE_OPENAI_DEPLOYMENT_ENV_KEYS:
                deployments.add(stripped.lower())

    raw_explicit = view.metadata.get("azure")
    explicit_azure: Mapping[str, Any] = raw_explicit if isinstance(raw_explicit, Mapping) else {}
    explicit_sub = str(explicit_azure.get("subscription_id", "")).strip()
    if _is_azure_uuid(explicit_sub):
        subscriptions.add(explicit_sub.lower())
    explicit_account = str(explicit_azure.get("openai_account_name", "")).strip()
    if explicit_account:
        accounts.add(explicit_account.lower())
    explicit_deployment = str(explicit_azure.get("openai_deployment_name", "")).strip()
    if explicit_deployment:
        deployments.add(explicit_deployment.lower())

    # Explicit `OPENAI_API_TYPE` set to anything other than `azure` is a
    # firm signal the agent talks to public OpenAI, not Azure — drop the
    # whole agent rather than emit cross-tenant noise.
    if api_type_disqualifies:
        return None
    if not (subscriptions or accounts or deployments):
        return None

    return _LocalAzureOpenAIEvidence(
        agent_name=view.name,
        agent_type=view.agent_type,
        subscription_ids=frozenset(subscriptions),
        account_names=frozenset(accounts),
        deployment_names=frozenset(deployments),
    )


def _extract_cloud_azure_openai_deployment(view: _AgentView) -> _CloudAzureOpenAIDeployment | None:
    cloud_origin_raw = view.metadata.get("cloud_origin")
    cloud_origin: Mapping[str, Any] = cloud_origin_raw if isinstance(cloud_origin_raw, Mapping) else {}
    if not cloud_origin or cloud_origin.get("provider") != "azure" or cloud_origin.get("service") != "openai":
        return None

    resource_id = str(cloud_origin.get("resource_id") or view.config_path or "")
    arn_sub, arn_account, arn_deployment = _parse_azure_resource_id(resource_id)

    scope_raw = cloud_origin.get("scope")
    scope: Mapping[str, Any] = scope_raw if isinstance(scope_raw, Mapping) else {}
    scope_sub = str(scope.get("subscription_id") or "").strip().lower()
    subscription_id = scope_sub or arn_sub

    raw_identity_raw = cloud_origin.get("raw_identity")
    raw_identity: Mapping[str, Any] = raw_identity_raw if isinstance(raw_identity_raw, Mapping) else {}
    account_name = str(raw_identity.get("account_name") or arn_account or "").strip().lower() or None
    deployment_name = (
        str(raw_identity.get("deployment_name") or arn_deployment or cloud_origin.get("resource_name") or "").strip().lower() or None
    )
    location = str(cloud_origin.get("location") or "").strip().lower() or None

    return _CloudAzureOpenAIDeployment(
        agent_name=view.name,
        resource_id=resource_id,
        subscription_id=subscription_id,
        account_name=account_name,
        deployment_name=deployment_name,
        location=location,
    )


def _match_azure_openai(
    local: _LocalAzureOpenAIEvidence,
    cloud: _CloudAzureOpenAIDeployment,
) -> CorrelationMatch | None:
    matched: list[str] = []

    if cloud.subscription_id and cloud.subscription_id in local.subscription_ids:
        matched.append("subscription_id")
    if cloud.account_name and cloud.account_name in local.account_names:
        matched.append("account_name")
    if cloud.deployment_name and cloud.deployment_name in local.deployment_names:
        matched.append("deployment_name")

    if not matched:
        return None

    confidence = CorrelationConfidence.HIGH if len(matched) >= _HIGH_CONFIDENCE_REQUIRED_SIGNALS else CorrelationConfidence.LOW

    rationale_parts: list[str] = []
    if "subscription_id" in matched:
        rationale_parts.append(f"subscription {cloud.subscription_id}")
    if "account_name" in matched:
        rationale_parts.append(f"account {cloud.account_name}")
    if "deployment_name" in matched:
        rationale_parts.append(f"deployment {cloud.deployment_name}")

    rationale = (
        "Strong triplet (subscription + account + deployment) matched."
        if confidence is CorrelationConfidence.HIGH
        else "Partial match — kept as low-confidence candidate. Matched: " + ", ".join(rationale_parts) + "."
    )

    return CorrelationMatch(
        local_agent_name=local.agent_name,
        local_agent_type=local.agent_type,
        cloud_agent_name=cloud.agent_name,
        cloud_provider="azure",
        cloud_service="openai",
        cloud_account_id=cloud.subscription_id,
        cloud_region=cloud.location,
        cloud_model_id=cloud.deployment_name,
        confidence=confidence,
        matched_signals=tuple(matched),
        rationale=rationale,
    )


def correlate_azure_openai(agents: Iterable[AgentLike]) -> list[CorrelationMatch]:
    """Match local agents to cloud-discovered Azure OpenAI deployments."""
    local_evidence: list[_LocalAzureOpenAIEvidence] = []
    cloud_index: dict[str, list[_CloudAzureOpenAIDeployment]] = {}

    for agent in agents:
        view = _normalize(agent)
        cloud = _extract_cloud_azure_openai_deployment(view)
        if cloud is not None:
            _add_candidate(cloud_index, cloud.subscription_id, cloud)
            _add_candidate(cloud_index, cloud.account_name, cloud)
            _add_candidate(cloud_index, cloud.deployment_name, cloud)
            continue
        local = _extract_local_azure_openai_evidence(view)
        if local is not None:
            local_evidence.append(local)

    matches: list[CorrelationMatch] = []
    for local in local_evidence:
        candidate_keys = (*local.subscription_ids, *local.account_names, *local.deployment_names)
        for cloud in _iter_indexed_candidates(cloud_index, candidate_keys):
            match = _match_azure_openai(local, cloud)
            if match is not None:
                matches.append(match)
    return matches


# ---------------------------------------------------------------------------
# GCP Vertex AI identity extractors + matcher (#1892 Phase 3)
# ---------------------------------------------------------------------------

# Authoritative Vertex endpoint resource path:
#   projects/{project_id}/locations/{region}/endpoints/{endpoint_id}
_VERTEX_RESOURCE_RE = re.compile(
    r"^projects/(?P<project>[a-z0-9-]+)/locations/(?P<location>[a-z0-9-]+)/endpoints/(?P<endpoint>[a-z0-9_-]+)",
    re.IGNORECASE,
)
# Vertex regional API hostname: `{region}-aiplatform.googleapis.com` —
# present in regional client URLs but not parseable into a project/endpoint
# on its own. We parse it for region only.
_VERTEX_HOSTNAME_RE = re.compile(r"https?://([a-z0-9-]+)-aiplatform\.googleapis\.com", re.IGNORECASE)

_GCP_PROJECT_ENV_KEYS = (
    "GOOGLE_CLOUD_PROJECT",
    "GCP_PROJECT",
    "GCP_PROJECT_ID",
    "GOOGLE_PROJECT_ID",
)
_GCP_LOCATION_ENV_KEYS = (
    "GOOGLE_CLOUD_REGION",
    "GOOGLE_CLOUD_LOCATION",
    "VERTEX_AI_LOCATION",
    "VERTEX_LOCATION",
)
_VERTEX_ENDPOINT_ENV_KEYS = (
    "VERTEX_AI_ENDPOINT_ID",
    "VERTEX_ENDPOINT_ID",
    "VERTEX_AI_ENDPOINT",
)
# `aiplatform.init(project=..., location=...)` is invoked from code, but
# operators commonly set these env knobs ahead of the SDK call so the
# extractor uses env as the cheap, accurate signal.


@dataclass(frozen=True)
class _LocalGcpVertexEvidence:
    agent_name: str
    agent_type: str
    project_ids: frozenset[str]
    locations: frozenset[str]
    endpoint_ids: frozenset[str]


@dataclass(frozen=True)
class _CloudGcpVertexEndpoint:
    agent_name: str
    resource_name: str
    project_id: str | None
    location: str | None
    endpoint_id: str | None


def _parse_vertex_resource(resource_name: str) -> tuple[str | None, str | None, str | None]:
    match = _VERTEX_RESOURCE_RE.search(resource_name)
    if not match:
        return None, None, None
    return (
        match.group("project").lower(),
        match.group("location").lower(),
        match.group("endpoint").lower(),
    )


def _looks_like_gcp_project_id(value: str) -> bool:
    # GCP project IDs are lowercase, 6–30 chars, alphanumeric + hyphens,
    # must start with a letter, may not end with a hyphen. The cheap gate
    # is enough — we just need to refuse arbitrary strings like "test" or
    # email addresses being treated as a project match.
    if not (6 <= len(value) <= 30):
        return False
    if not value[0].isalpha():
        return False
    if value.endswith("-"):
        return False
    return all(ch.isalnum() or ch == "-" for ch in value)


def _extract_local_gcp_vertex_evidence(view: _AgentView) -> _LocalGcpVertexEvidence | None:
    if _is_cloud_discovered(view):
        return None

    projects: set[str] = set()
    locations: set[str] = set()
    endpoints: set[str] = set()

    for env in view.mcp_server_envs:
        for key, value in env.items():
            if not isinstance(value, str) or not value:
                continue
            stripped = value.strip()
            if key in _GCP_PROJECT_ENV_KEYS and _looks_like_gcp_project_id(stripped.lower()):
                projects.add(stripped.lower())
            elif key in _GCP_LOCATION_ENV_KEYS:
                locations.add(stripped.lower())
            elif key in _VERTEX_ENDPOINT_ENV_KEYS:
                # Accept either a bare numeric/named endpoint id OR a full
                # resource path; if it's a path, parse all three at once.
                project_from_path, location_from_path, endpoint_from_path = _parse_vertex_resource(stripped)
                if endpoint_from_path:
                    endpoints.add(endpoint_from_path)
                    if project_from_path:
                        projects.add(project_from_path)
                    if location_from_path:
                        locations.add(location_from_path)
                else:
                    endpoints.add(stripped.lower())

    raw_explicit = view.metadata.get("gcp")
    explicit_gcp: Mapping[str, Any] = raw_explicit if isinstance(raw_explicit, Mapping) else {}
    explicit_project = str(explicit_gcp.get("project_id", "")).strip().lower()
    if _looks_like_gcp_project_id(explicit_project):
        projects.add(explicit_project)
    explicit_location = str(explicit_gcp.get("location", "")).strip().lower()
    if explicit_location:
        locations.add(explicit_location)
    explicit_endpoint = str(explicit_gcp.get("vertex_endpoint_id", "")).strip().lower()
    if explicit_endpoint:
        endpoints.add(explicit_endpoint)

    if not (projects or locations or endpoints):
        return None

    return _LocalGcpVertexEvidence(
        agent_name=view.name,
        agent_type=view.agent_type,
        project_ids=frozenset(projects),
        locations=frozenset(locations),
        endpoint_ids=frozenset(endpoints),
    )


def _extract_cloud_gcp_vertex_endpoint(view: _AgentView) -> _CloudGcpVertexEndpoint | None:
    cloud_origin_raw = view.metadata.get("cloud_origin")
    cloud_origin: Mapping[str, Any] = cloud_origin_raw if isinstance(cloud_origin_raw, Mapping) else {}
    if not cloud_origin or cloud_origin.get("provider") != "gcp" or cloud_origin.get("service") != "vertex-ai":
        return None

    resource_name = str(cloud_origin.get("resource_id") or view.config_path or "")
    arn_project, arn_location, arn_endpoint = _parse_vertex_resource(resource_name)

    scope_raw = cloud_origin.get("scope")
    scope: Mapping[str, Any] = scope_raw if isinstance(scope_raw, Mapping) else {}
    scope_project = str(scope.get("project_id") or "").strip().lower()
    project_id = scope_project or arn_project

    location = str(cloud_origin.get("location") or "").strip().lower() or arn_location
    endpoint_id = arn_endpoint

    return _CloudGcpVertexEndpoint(
        agent_name=view.name,
        resource_name=resource_name,
        project_id=project_id or None,
        location=location or None,
        endpoint_id=endpoint_id or None,
    )


def _match_gcp_vertex(
    local: _LocalGcpVertexEvidence,
    cloud: _CloudGcpVertexEndpoint,
) -> CorrelationMatch | None:
    matched: list[str] = []

    if cloud.project_id and cloud.project_id in local.project_ids:
        matched.append("project_id")
    if cloud.location and cloud.location in local.locations:
        matched.append("location")
    if cloud.endpoint_id and cloud.endpoint_id in local.endpoint_ids:
        matched.append("endpoint_id")

    if not matched:
        return None

    confidence = CorrelationConfidence.HIGH if len(matched) >= _HIGH_CONFIDENCE_REQUIRED_SIGNALS else CorrelationConfidence.LOW

    rationale_parts: list[str] = []
    if "project_id" in matched:
        rationale_parts.append(f"project {cloud.project_id}")
    if "location" in matched:
        rationale_parts.append(f"location {cloud.location}")
    if "endpoint_id" in matched:
        rationale_parts.append(f"endpoint {cloud.endpoint_id}")

    rationale = (
        "Strong triplet (project + location + endpoint) matched."
        if confidence is CorrelationConfidence.HIGH
        else "Partial match — kept as low-confidence candidate. Matched: " + ", ".join(rationale_parts) + "."
    )

    return CorrelationMatch(
        local_agent_name=local.agent_name,
        local_agent_type=local.agent_type,
        cloud_agent_name=cloud.agent_name,
        cloud_provider="gcp",
        cloud_service="vertex-ai",
        cloud_account_id=cloud.project_id,
        cloud_region=cloud.location,
        cloud_model_id=cloud.endpoint_id,
        confidence=confidence,
        matched_signals=tuple(matched),
        rationale=rationale,
    )


def correlate_gcp_vertex(agents: Iterable[AgentLike]) -> list[CorrelationMatch]:
    """Match local agents to cloud-discovered GCP Vertex AI endpoints."""
    local_evidence: list[_LocalGcpVertexEvidence] = []
    cloud_index: dict[str, list[_CloudGcpVertexEndpoint]] = {}

    for agent in agents:
        view = _normalize(agent)
        cloud = _extract_cloud_gcp_vertex_endpoint(view)
        if cloud is not None:
            _add_candidate(cloud_index, cloud.project_id, cloud)
            _add_candidate(cloud_index, cloud.location, cloud)
            _add_candidate(cloud_index, cloud.endpoint_id, cloud)
            continue
        local = _extract_local_gcp_vertex_evidence(view)
        if local is not None:
            local_evidence.append(local)

    matches: list[CorrelationMatch] = []
    for local in local_evidence:
        candidate_keys = (*local.project_ids, *local.locations, *local.endpoint_ids)
        for cloud in _iter_indexed_candidates(cloud_index, candidate_keys):
            match = _match_gcp_vertex(local, cloud)
            if match is not None:
                matches.append(match)
    return matches


# ---------------------------------------------------------------------------
# Top-level orchestrator. Phase 2 (Azure) and Phase 3 (GCP) plug in here.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CrossEnvironmentResult:
    """All cross-environment matches produced for one scan."""

    matches: tuple[CorrelationMatch, ...] = field(default_factory=tuple)

    def by_confidence(self, confidence: CorrelationConfidence) -> tuple[CorrelationMatch, ...]:
        return tuple(match for match in self.matches if match.confidence is confidence)


def correlate_cross_environment(agents: Iterable[AgentLike]) -> CrossEnvironmentResult:
    """Run every provider-specific matcher over the agent set."""
    materialized = list(agents)
    matches: list[CorrelationMatch] = []
    matches.extend(correlate_bedrock(materialized))
    matches.extend(correlate_azure_openai(materialized))
    matches.extend(correlate_gcp_vertex(materialized))
    return CrossEnvironmentResult(matches=tuple(matches))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_cloud_discovered(view: _AgentView) -> bool:
    """Cloud-discovered agents carry a `cloud_origin` envelope."""
    cloud_origin = view.metadata.get("cloud_origin")
    return isinstance(cloud_origin, Mapping) and bool(cloud_origin.get("provider"))
