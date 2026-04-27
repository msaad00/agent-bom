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
from typing import Any, Iterable, Mapping, TypeAlias, Union

from agent_bom.models import Agent

# An agent record can flow into the matcher either as the rich `Agent`
# dataclass (used by Python callers and tests) or as the serialized-dict
# shape that already lives inside the scan report (used by the graph
# builder). The strong-signal extractors only need a handful of fields, so
# we normalize both shapes through `_AgentView` instead of forcing one
# canonical type on every caller.
AgentLike: TypeAlias = Union[Agent, Mapping[str, Any]]

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


def correlate_bedrock(agents: Iterable[AgentLike]) -> list[CorrelationMatch]:
    """Match local agents to cloud-discovered Bedrock agents."""
    local_evidence: list[_LocalAwsEvidence] = []
    cloud_bedrock: list[_CloudBedrockAgent] = []

    for agent in agents:
        view = _normalize(agent)
        cloud = _extract_cloud_bedrock_agent(view)
        if cloud is not None:
            cloud_bedrock.append(cloud)
            continue
        local = _extract_local_aws_evidence(view)
        if local is not None:
            local_evidence.append(local)

    matches: list[CorrelationMatch] = []
    for local in local_evidence:
        for cloud in cloud_bedrock:
            match = _match_bedrock(local, cloud)
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
    return CrossEnvironmentResult(matches=tuple(matches))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_cloud_discovered(view: _AgentView) -> bool:
    """Cloud-discovered agents carry a `cloud_origin` envelope."""
    cloud_origin = view.metadata.get("cloud_origin")
    return isinstance(cloud_origin, Mapping) and bool(cloud_origin.get("provider"))
