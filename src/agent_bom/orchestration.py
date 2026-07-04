"""Orchestrator read model (façade).

Exposes the registered pipeline stage order as data — ``scan → enrich →
correlate → graph → findings`` — with the registered component drivers for each
stage pulled from the scanner, enricher, and matcher registries.

This is a READ MODEL only. It does NOT execute anything and does NOT replace the
existing execution path (`ScanPipeline` / `_run_scan_sync` in
``agent_bom.api.pipeline``), which remains the de-facto orchestrator. Scanner
driver execution for registry-backed ``run_attr`` dispatch lives in
``agent_bom.scanners.executor`` and honors each driver's ``failure_mode``.

The ``graph`` and ``findings`` stages exist in the real pipeline but have no
component registry yet, so they are surfaced as ordered, non-registry-backed
stages with an empty driver list.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from agent_bom.components.enricher_registry import list_registered_enrichers
from agent_bom.components.matcher_registry import list_registered_matchers
from agent_bom.scanners.registry import list_registered_scanners


class PipelineStage(str, Enum):
    """High-level orchestration stage, in execution order."""

    SCAN = "scan"
    ENRICH = "enrich"
    CORRELATE = "correlate"
    GRAPH = "graph"
    FINDINGS = "findings"


STAGE_ORDER: tuple[PipelineStage, ...] = (
    PipelineStage.SCAN,
    PipelineStage.ENRICH,
    PipelineStage.CORRELATE,
    PipelineStage.GRAPH,
    PipelineStage.FINDINGS,
)

_STAGE_SUMMARIES: dict[PipelineStage, str] = {
    PipelineStage.SCAN: "Discover targets and produce raw findings via scanner drivers.",
    PipelineStage.ENRICH: "Augment findings with CVSS/EPSS/KEV/GHSA, registry, AI, and estate context.",
    PipelineStage.CORRELATE: "Deduplicate and correlate evidence across sources and environments.",
    PipelineStage.GRAPH: "Fuse findings into the ContextGraph and score blast radius (not registry-backed yet).",
    PipelineStage.FINDINGS: "Normalize, dedupe, and emit the unified Finding set (not registry-backed yet).",
}


@dataclass(frozen=True)
class StageView:
    """Read-only view of one orchestration stage and its registered drivers."""

    stage: PipelineStage
    drivers: tuple[str, ...]
    registry_backed: bool
    summary: str

    def to_dict(self) -> dict[str, object]:
        return {
            "stage": self.stage.value,
            "drivers": list(self.drivers),
            "registry_backed": self.registry_backed,
            "summary": self.summary,
        }


def _stage_drivers(stage: PipelineStage, *, include_planned: bool) -> tuple[bool, tuple[str, ...]]:
    if stage is PipelineStage.SCAN:
        return True, tuple(r.name for r in list_registered_scanners(include_planned=include_planned))
    if stage is PipelineStage.ENRICH:
        return True, tuple(r.name for r in list_registered_enrichers(include_planned=include_planned))
    if stage is PipelineStage.CORRELATE:
        return True, tuple(r.name for r in list_registered_matchers(include_planned=include_planned))
    # graph and findings stages run in the pipeline but have no component registry yet.
    return False, ()


def ordered_stages(*, include_planned: bool = True) -> list[StageView]:
    """Return the registered stages in execution order with their drivers."""

    views: list[StageView] = []
    for stage in STAGE_ORDER:
        registry_backed, drivers = _stage_drivers(stage, include_planned=include_planned)
        views.append(
            StageView(
                stage=stage,
                drivers=drivers,
                registry_backed=registry_backed,
                summary=_STAGE_SUMMARIES[stage],
            )
        )
    return views


def stage_names() -> list[str]:
    """Return the stage names in execution order."""

    return [stage.value for stage in STAGE_ORDER]


def orchestration_summary(*, include_planned: bool = True) -> dict[str, object]:
    """Return a compact orchestration summary for API/UI surfaces."""

    stages = ordered_stages(include_planned=include_planned)
    return {
        "stage_order": stage_names(),
        "stages": [view.to_dict() for view in stages],
        "registry_backed_stages": [view.stage.value for view in stages if view.registry_backed],
    }


__all__ = [
    "STAGE_ORDER",
    "PipelineStage",
    "StageView",
    "orchestration_summary",
    "ordered_stages",
    "stage_names",
]
