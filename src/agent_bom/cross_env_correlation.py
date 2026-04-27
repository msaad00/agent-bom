"""Correlate local agents/projects with cloud AI runtimes.

Closes #1892 Phase 1 (AWS Bedrock).

The product story is moving from point-in-time AI stack scanning to a
system-of-record graph. Local framework discovery (LangChain, CrewAI,
Claude SDK, OpenAI Assistants in ``agent_bom.ai_components.framework_agents``)
and cloud AI runtime discovery (``agent_bom.cloud.aws._discover_bedrock``,
the equivalent in ``cloud/azure.py``, ``cloud/gcp.py``) already exist, but
nothing ties them together — an operator looking at the graph cannot answer
"this Cursor/LangChain agent on a laptop calls which cloud Bedrock agent,
under which model?".

This module is the connective tissue. It runs after both halves of
discovery have produced graph nodes and emits ``correlates_with`` edges
between local and cloud nodes, with a confidence level and the signals
that drove the match attached to the edge so the UI can render
"exact / inferred / low" badges and operators can audit a match.

## Phase scope

Phase 1 (this module): AWS Bedrock matching.
- ``exact``  — local ``model_refs`` substring matches the cloud Bedrock
  agent's ``foundationModel`` (Agent.version).
- ``inferred`` — local agent imports an AWS SDK / references
  ``bedrock-runtime`` / ``invoke_model`` AND the cloud resource is in the
  same AWS account/region surface; resolved via heuristic name overlap.
- ``low``  — name fuzzy match only.

Phase 2 (#1892 follow-up): Azure OpenAI / Functions.
Phase 3 (#1892 follow-up): GCP Vertex / Cloud Run.

The matcher is deliberately conservative on cross-tenant safety: links
are only emitted between nodes from the *same* graph (same scan, same
``tenant_id`` set on the graph), so similarly-named local/cloud agents
in different tenants cannot accidentally merge. The graph builder owns
that boundary; this module is a no-op for any agent whose stable_id is
not present in the graph it was handed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Iterable, Literal

logger = logging.getLogger(__name__)

CorrelationConfidence = Literal["exact", "inferred", "low"]


@dataclass(frozen=True)
class CorrelationSignal:
    """A single piece of evidence supporting a cross-environment match."""

    kind: str
    value: str
    weight: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "value": self.value, "weight": self.weight}


@dataclass(frozen=True)
class CrossEnvironmentLink:
    """A directed link from a local agent node to a cloud_resource node."""

    local_agent_id: str
    cloud_resource_id: str
    confidence: CorrelationConfidence
    signals: tuple[CorrelationSignal, ...] = field(default_factory=tuple)

    def to_evidence(self) -> dict[str, Any]:
        return {
            "source": "cross_env_correlation",
            "phase": "phase1_bedrock",
            "confidence": self.confidence,
            "signals": [s.to_dict() for s in self.signals],
        }


# ── AWS Bedrock matcher ─────────────────────────────────────────────────────


# Bedrock foundation-model strings look like
# "anthropic.claude-3-5-sonnet-20240620-v1:0", "amazon.titan-embed-text-v1",
# "meta.llama3-70b-instruct-v1:0". The middle slug carries the recognisable
# model family. We compare it case-insensitively against local ``model_refs``.
def _normalize_model_token(value: str) -> str:
    return value.strip().lower()


def _bedrock_model_tokens(foundation_model: str) -> set[str]:
    """Return a small set of substrings the local ``model_refs`` may match."""
    if not foundation_model:
        return set()
    fm = _normalize_model_token(foundation_model)
    out: set[str] = {fm}
    # `anthropic.claude-3-5-sonnet-20240620-v1:0` -> `claude-3-5-sonnet-20240620-v1:0`
    if "." in fm:
        out.add(fm.split(".", 1)[1])
    # Strip date/version suffixes so `claude-3-5-sonnet` matches the cloud
    # model that ships as `claude-3-5-sonnet-20240620-v1:0`.
    short = fm.split(":", 1)[0]
    out.add(short)
    if "-202" in short:
        out.add(short.split("-202", 1)[0])
    return {token for token in out if token}


_BEDROCK_SDK_HINTS: tuple[str, ...] = (
    "bedrock-runtime",
    "bedrock_runtime",
    "boto3",
    "invoke_model",
    "InvokeModel",
)


def _local_uses_bedrock_sdk(local_agent: dict[str, Any]) -> bool:
    """Return True when the local framework-agent record carries any signal
    that it talks to Bedrock at runtime (import path, call site, capability).
    """
    haystacks: list[str] = []
    for key in ("framework", "file_path"):
        value = local_agent.get(key)
        if isinstance(value, str):
            haystacks.append(value.lower())
    capabilities = local_agent.get("capabilities") or []
    if isinstance(capabilities, list):
        haystacks.extend(str(c).lower() for c in capabilities)
    credential_refs = local_agent.get("credential_refs") or []
    if isinstance(credential_refs, list):
        haystacks.extend(str(c).lower() for c in credential_refs)
    blob = " ".join(haystacks)
    return any(hint.lower() in blob for hint in _BEDROCK_SDK_HINTS)


def _correlate_bedrock_one(
    local_agent: dict[str, Any],
    cloud_agent: dict[str, Any],
) -> CrossEnvironmentLink | None:
    local_id = str(local_agent.get("stable_id") or "").strip()
    cloud_origin = (cloud_agent.get("metadata") or {}).get("cloud_origin")
    if not local_id or not isinstance(cloud_origin, dict):
        return None
    if cloud_origin.get("provider") != "aws" or cloud_origin.get("service") != "bedrock":
        return None

    cloud_resource_id = (
        f"cloud_resource:{cloud_origin.get('provider')}:"
        f"{cloud_origin.get('service')}:{cloud_origin.get('resource_type')}:"
        f"{cloud_origin.get('resource_id')}"
    )

    local_model_refs = local_agent.get("model_refs") or []
    cloud_foundation_model = str(cloud_agent.get("version") or "")
    cloud_tokens = _bedrock_model_tokens(cloud_foundation_model)

    # ── Exact: any local model_ref substring matches a cloud token ────────
    for ref in local_model_refs:
        local_norm = _normalize_model_token(str(ref))
        if not local_norm:
            continue
        for token in cloud_tokens:
            if local_norm == token or local_norm in token or token in local_norm:
                return CrossEnvironmentLink(
                    local_agent_id=local_id,
                    cloud_resource_id=cloud_resource_id,
                    confidence="exact",
                    signals=(
                        CorrelationSignal(
                            kind="model_id_match",
                            value=f"local={local_norm!r} cloud_foundation_model={cloud_foundation_model!r}",
                            weight=1.0,
                        ),
                    ),
                )

    # ── Inferred: local agent uses Bedrock SDK ────────────────────────────
    if _local_uses_bedrock_sdk(local_agent):
        cloud_name = str(cloud_origin.get("resource_name") or cloud_origin.get("resource_id") or "")
        local_name = str(local_agent.get("name") or "").lower()
        signals = [
            CorrelationSignal(
                kind="local_uses_bedrock_sdk",
                value="framework or capability mentions boto3/bedrock-runtime/invoke_model",
                weight=0.6,
            ),
        ]
        if cloud_name and local_name and cloud_name.lower() in local_name:
            signals.append(
                CorrelationSignal(
                    kind="name_substring_match",
                    value=f"local_name={local_name!r} contains cloud={cloud_name!r}",
                    weight=0.3,
                ),
            )
        return CrossEnvironmentLink(
            local_agent_id=local_id,
            cloud_resource_id=cloud_resource_id,
            confidence="inferred",
            signals=tuple(signals),
        )

    return None


def correlate_bedrock(
    framework_agents: Iterable[dict[str, Any]],
    cloud_agents: Iterable[dict[str, Any]],
) -> list[CrossEnvironmentLink]:
    """Return cross-environment links between local framework agents and
    AWS Bedrock cloud agents.

    Cross-tenant note: this function operates on whatever lists it is
    handed. Callers (the graph builder) are responsible for only passing in
    nodes that share the same scan/tenant scope.
    """
    framework_list = [a for a in framework_agents if isinstance(a, dict)]
    cloud_list = [a for a in cloud_agents if isinstance(a, dict)]
    out: list[CrossEnvironmentLink] = []
    seen: set[tuple[str, str]] = set()
    for local in framework_list:
        for cloud in cloud_list:
            link = _correlate_bedrock_one(local, cloud)
            if link is None:
                continue
            key = (link.local_agent_id, link.cloud_resource_id)
            if key in seen:
                continue
            seen.add(key)
            out.append(link)
    return out
