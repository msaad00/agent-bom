"""Canonical operator-facing view of the enterprise demo evidence."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from agent_bom.demo_estate.enterprise import load_enterprise_estate
from agent_bom.demo_estate.enterprise_correlation import (
    EnterpriseCollectionHealth,
    EnterpriseCorrelation,
    NormalizedEnterpriseEvent,
    correlate_enterprise_estate,
)

ENTERPRISE_STORY_SCHEMA_VERSION = "enterprise_demo_story.v1"
ENTERPRISE_STORY_SCENARIO = (
    "A GitHub deployment assumes an AWS workload identity, reaches a Kubernetes "
    "copilot and clinical analytics MCP tool, reads Snowflake PHI, and is blocked "
    "before model egress; Azure, GCP, and remediation evidence remain correlated."
)


class EnterpriseDemoSummary(BaseModel):
    """Stable counts shown by CLI, API, and dashboard consumers."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    assets: int = Field(ge=0)
    observations: int = Field(ge=0)
    evidence_sources: int = Field(ge=0)
    complete_sources: int = Field(ge=0)
    partial_sources: int = Field(ge=0)
    correlations: int = Field(ge=0)
    snapshots: int = Field(ge=0)


class EnterpriseDemoStory(BaseModel):
    """One read model for every operator-facing synthetic-demo surface."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = ENTERPRISE_STORY_SCHEMA_VERSION
    synthetic: Literal[True] = True
    fictional: Literal[True] = True
    disclosure: str
    estate_id: str
    estate_name: str
    tenant_id: str
    scenario: str = ENTERPRISE_STORY_SCENARIO
    estate_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    story_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    summary: EnterpriseDemoSummary
    primary_correlation: EnterpriseCorrelation
    events: tuple[NormalizedEnterpriseEvent, ...]
    correlations: tuple[EnterpriseCorrelation, ...]
    collection_health: tuple[EnterpriseCollectionHealth, ...]


def build_enterprise_demo_story(*, tenant_id: str = "demo-tenant") -> EnterpriseDemoStory:
    """Load, verify, normalize, and present the bundled fictional estate."""

    estate = load_enterprise_estate(tenant_id=tenant_id)
    result = correlate_enterprise_estate(estate)
    primary = next(
        (row for row in result.correlations if row.kind == "data_egress_attempt"),
        None,
    )
    if primary is None:
        raise ValueError("enterprise demo is missing its primary data-egress correlation")

    return EnterpriseDemoStory(
        disclosure=estate.disclosure,
        estate_id=estate.estate_id,
        estate_name=estate.display_name,
        tenant_id=estate.tenant_id,
        estate_content_hash=estate.content_hash,
        story_content_hash=result.content_hash,
        summary=EnterpriseDemoSummary(
            assets=len(estate.assets),
            observations=len(estate.observations),
            evidence_sources=len(result.collection_health),
            complete_sources=result.complete_source_count,
            partial_sources=result.partial_source_count,
            correlations=len(result.correlations),
            snapshots=len(estate.snapshots),
        ),
        primary_correlation=primary,
        events=result.events,
        correlations=result.correlations,
        collection_health=result.collection_health,
    )


__all__ = [
    "ENTERPRISE_STORY_SCENARIO",
    "ENTERPRISE_STORY_SCHEMA_VERSION",
    "EnterpriseDemoStory",
    "EnterpriseDemoSummary",
    "build_enterprise_demo_story",
]
