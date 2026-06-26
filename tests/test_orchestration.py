"""Tests for the orchestrator read model."""

from __future__ import annotations

import pytest

from agent_bom.orchestration import (
    STAGE_ORDER,
    PipelineStage,
    orchestration_summary,
    ordered_stages,
    stage_names,
)


@pytest.fixture(autouse=True)
def reset_registries(monkeypatch):
    import agent_bom.components.enricher_registry as enricher_registry
    import agent_bom.components.matcher_registry as matcher_registry
    import agent_bom.scanners.registry as scanner_registry
    from agent_bom.extensions import ENTRYPOINTS_ENABLED_ENV

    monkeypatch.delenv(ENTRYPOINTS_ENABLED_ENV, raising=False)
    scanner_registry._reset_scanner_registry_for_tests()
    enricher_registry._reset_enricher_registry_for_tests()
    matcher_registry._reset_matcher_registry_for_tests()
    yield
    scanner_registry._reset_scanner_registry_for_tests()
    enricher_registry._reset_enricher_registry_for_tests()
    matcher_registry._reset_matcher_registry_for_tests()
    scanner_registry.list_registered_scanners()


def test_stage_order_is_scan_enrich_correlate_graph_findings() -> None:
    assert stage_names() == ["scan", "enrich", "correlate", "graph", "findings"]
    assert STAGE_ORDER == (
        PipelineStage.SCAN,
        PipelineStage.ENRICH,
        PipelineStage.CORRELATE,
        PipelineStage.GRAPH,
        PipelineStage.FINDINGS,
    )


def test_ordered_stages_carry_registered_drivers_per_phase() -> None:
    from agent_bom.components.enricher_registry import list_registered_enrichers
    from agent_bom.components.matcher_registry import list_registered_matchers
    from agent_bom.scanners.registry import list_registered_scanners

    stages = {view.stage: view for view in ordered_stages()}

    assert [view.stage for view in ordered_stages()] == list(STAGE_ORDER)
    assert set(stages[PipelineStage.SCAN].drivers) == {r.name for r in list_registered_scanners()}
    assert set(stages[PipelineStage.ENRICH].drivers) == {r.name for r in list_registered_enrichers()}
    assert set(stages[PipelineStage.CORRELATE].drivers) == {r.name for r in list_registered_matchers()}


def test_graph_and_findings_stages_are_present_but_not_registry_backed() -> None:
    stages = {view.stage: view for view in ordered_stages()}

    assert stages[PipelineStage.GRAPH].registry_backed is False
    assert stages[PipelineStage.GRAPH].drivers == ()
    assert stages[PipelineStage.FINDINGS].registry_backed is False
    assert stages[PipelineStage.FINDINGS].drivers == ()

    assert stages[PipelineStage.SCAN].registry_backed is True
    assert stages[PipelineStage.ENRICH].registry_backed is True
    assert stages[PipelineStage.CORRELATE].registry_backed is True


def test_orchestration_summary_shape() -> None:
    summary = orchestration_summary()
    assert summary["stage_order"] == ["scan", "enrich", "correlate", "graph", "findings"]
    assert summary["registry_backed_stages"] == ["scan", "enrich", "correlate"]
    assert len(summary["stages"]) == 5
