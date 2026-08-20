"""Canonical operator-facing view of the enterprise demo evidence."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from agent_bom.demo_estate.enterprise import NARRATIVE_INCIDENT_TRACE_ID
from agent_bom.demo_estate.enterprise_composition import build_demo_estate
from agent_bom.demo_estate.enterprise_correlation import (
    EnterpriseCollectionHealth,
    EnterpriseCorrelation,
    NormalizedEnterpriseEvent,
    correlate_enterprise_estate,
)
from agent_bom.demo_estate.enterprise_findings import (
    EstateFindingSummary,
    EstateFindingView,
    build_estate_findings,
    summarize_estate_findings,
    to_finding_view,
)
from agent_bom.demo_estate.showcase_graph import SHOWCASE_SCAN_ID
from agent_bom.graph.severity import severity_worst_first_rank

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
    # Correlation rows that actually span more than one evidence source.
    #
    # ``correlations`` counts trace groups, and the generated population gives
    # almost every observation its own trace — so at estate scale that number
    # runs into the thousands while the rows that join evidence *across vendors*
    # stay in single digits. Publishing only the first invites every surface to
    # read a labelled event as a cross-vendor correlation. This is the figure the
    # graph already agrees with: ``project_estate_into_graph`` draws a chain only
    # for a correlation with more than one inventoried asset.
    cross_source_correlations: int = Field(default=0, ge=0)
    snapshots: int = Field(ge=0)
    findings: int = Field(default=0, ge=0)


class EnterpriseDemoListBound(BaseModel):
    """What one truncated list holds, and what it was truncated out of."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    returned: int = Field(ge=0)
    total: int = Field(ge=0)
    limit: int = Field(ge=0)
    truncated: bool


class EnterpriseDemoBounds(BaseModel):
    """The bound on every list the story returns.

    ``events``, ``correlations`` and ``findings`` are ranked slices of an estate
    an order of magnitude larger — the artifact holds single-digit percentages
    of the first two. A consumer holding only the payload has no other way to
    learn that, so the bound travels with it: a page size that does not name
    what it is a page of is the same defect as a page size reported as a total.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    events: EnterpriseDemoListBound
    correlations: EnterpriseDemoListBound
    findings: EnterpriseDemoListBound


class EnterpriseDemoCountMetadata(BaseModel):
    """Definition and completeness carried beside an ambiguous demo count."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    definition: str
    source: str
    scope: str
    window: str
    filters: tuple[str, ...] = ()
    returned: int = Field(ge=0)
    total: int = Field(ge=0)
    completeness: Literal["complete", "partial", "unknown"]


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
    graph_snapshot_id: str = SHOWCASE_SCAN_ID
    summary: EnterpriseDemoSummary
    bounds: EnterpriseDemoBounds
    count_metadata: dict[str, EnterpriseDemoCountMetadata]
    primary_correlation: EnterpriseCorrelation
    events: tuple[NormalizedEnterpriseEvent, ...]
    correlations: tuple[EnterpriseCorrelation, ...]
    collection_health: tuple[EnterpriseCollectionHealth, ...]
    finding_summary: EstateFindingSummary
    findings: tuple[EstateFindingView, ...] = ()


# Bounded so the story stays legible at estate scale. The summary reports the
# unbounded totals and ``bounds`` names each limit, so the view is smaller than
# the estate and says so rather than passing for the whole of it.
_STORY_CORRELATION_LIMIT = 50
_STORY_EVENT_LIMIT = 200
_STORY_FINDING_LIMIT = 100


def build_enterprise_demo_story(*, tenant_id: str = "demo-tenant") -> EnterpriseDemoStory:
    """Load, verify, normalize, and present the bundled fictional estate."""

    estate = build_demo_estate(tenant_id=tenant_id)
    result = correlate_enterprise_estate(estate)
    # Named, not discovered. "The first data-egress correlation" identified the
    # incident only while it was the only one; the population now produces
    # hundreds, and correlations sort by trace id, so the headline would have
    # become whichever generated journey happened to hash lowest.
    primary = result.correlation_by_trace(NARRATIVE_INCIDENT_TRACE_ID)
    if primary is None or primary.kind != "data_egress_attempt":
        raise ValueError("enterprise demo is missing its primary data-egress correlation")

    # `summary` carries the true totals; these fields carry what a reader can
    # actually use. Composing the incident into a population takes the estate to
    # thousands of events, and returning every correlated row would hand the UI
    # ~6k `activity_sequence` entries — a data dump in which the incident is
    # invisible. Lead with the incident, then a bounded remainder, newest first.
    ranked = (primary, *(row for row in result.correlations if row is not primary))
    correlations = ranked[:_STORY_CORRELATION_LIMIT]
    events = result.events[:_STORY_EVENT_LIMIT]

    # Findings follow the same rule as correlations and events: the summary
    # below carries the whole estate's totals, this list carries what a reader
    # can act on. Ranked worst-first and with the incident's own findings ahead
    # of the population, so the bounded page is the top of the estate rather
    # than an arbitrary slice of it.
    estate_findings = build_estate_findings(estate, correlation_result=result)
    finding_summary = summarize_estate_findings(estate, estate_findings)
    ranked_findings = sorted(
        estate_findings,
        key=lambda finding: (
            0 if finding.evidence.get("correlation_id") else 1,
            severity_worst_first_rank(finding.severity),
            finding.id,
        ),
    )
    findings = tuple(to_finding_view(finding) for finding in ranked_findings[:_STORY_FINDING_LIMIT])

    def _bound(returned: int, total: int, limit: int) -> EnterpriseDemoListBound:
        return EnterpriseDemoListBound(returned=returned, total=total, limit=limit, truncated=returned < total)

    def _count(
        *,
        definition: str,
        source: str,
        returned: int,
        total: int,
        filters: tuple[str, ...] = (),
    ) -> EnterpriseDemoCountMetadata:
        return EnterpriseDemoCountMetadata(
            definition=definition,
            source=source,
            scope="whole bundled fictional estate",
            window="bundled synthetic snapshot",
            filters=filters,
            returned=returned,
            total=total,
            completeness="partial" if returned < total else "complete",
        )

    cross_source_total = sum(1 for row in result.correlations if len(set(row.sources)) >= 2)
    evidence_link_total = finding_summary.attack_paths_evidenced

    return EnterpriseDemoStory(
        disclosure=estate.disclosure,
        estate_id=estate.estate_id,
        estate_name=estate.display_name,
        tenant_id=estate.tenant_id,
        estate_content_hash=estate.content_hash,
        story_content_hash=result.content_hash,
        graph_snapshot_id=SHOWCASE_SCAN_ID,
        summary=EnterpriseDemoSummary(
            assets=len(estate.assets),
            observations=len(estate.observations),
            evidence_sources=len(result.collection_health),
            complete_sources=result.complete_source_count,
            partial_sources=result.partial_source_count,
            correlations=len(result.correlations),
            cross_source_correlations=cross_source_total,
            snapshots=len(estate.snapshots),
            findings=finding_summary.total,
        ),
        bounds=EnterpriseDemoBounds(
            events=_bound(len(events), len(estate.observations), _STORY_EVENT_LIMIT),
            correlations=_bound(len(correlations), len(result.correlations), _STORY_CORRELATION_LIMIT),
            findings=_bound(len(findings), finding_summary.total, _STORY_FINDING_LIMIT),
        ),
        count_metadata={
            "findings": _count(
                definition="Synthetic findings across the fictional estate; not current persisted control-plane findings.",
                source="synthetic_estate_findings",
                returned=len(findings),
                total=finding_summary.total,
                filters=("ranked worst-first", "primary incident first"),
            ),
            "correlations": _count(
                definition="Synthetic trace-group correlations; a row may contain evidence from only one source.",
                source="synthetic_estate_correlations",
                returned=len(correlations),
                total=len(result.correlations),
                filters=("primary incident first", "newest remainder first"),
            ),
            "cross_source_correlations": _count(
                definition="Synthetic correlation rows joining evidence from at least two distinct sources.",
                source="synthetic_estate_correlations",
                returned=cross_source_total,
                total=cross_source_total,
                filters=("distinct source count >= 2",),
            ),
            "attack_paths_evidenced": _count(
                definition="Unique correlation identifiers referenced by synthetic finding evidence; not persisted or derived graph paths.",
                source="synthetic_finding_evidence",
                returned=evidence_link_total,
                total=evidence_link_total,
                filters=("finding evidence has correlation_id",),
            ),
        },
        primary_correlation=primary,
        events=events,
        correlations=correlations,
        collection_health=result.collection_health,
        finding_summary=finding_summary,
        findings=findings,
    )


__all__ = [
    "ENTERPRISE_STORY_SCENARIO",
    "ENTERPRISE_STORY_SCHEMA_VERSION",
    "EnterpriseDemoBounds",
    "EnterpriseDemoListBound",
    "EnterpriseDemoStory",
    "EnterpriseDemoSummary",
    "build_enterprise_demo_story",
]
