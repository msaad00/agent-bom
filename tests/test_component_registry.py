"""Tests for the enricher and matcher component registries."""

from __future__ import annotations

import sys
import types
from collections.abc import Callable
from typing import Any

import pytest

from agent_bom.components.base import EnricherRegistration, MatcherRegistration
from agent_bom.extensions import ENTRYPOINTS_ENABLED_ENV, ExtensionCapabilities
from agent_bom.scanners.base import ScannerExecutionState, ScannerPhase


class FakeEntryPoint:
    def __init__(self, name: str, loader: Callable[[], Any]) -> None:
        self.name = name
        self._loader = loader

    def load(self) -> Any:
        return self._loader()


class FakeEntryPoints(list):
    def select(self, *, group: str) -> list[FakeEntryPoint]:
        return [entry_point for entry_point in self if getattr(entry_point, "group", group) == group]


def _patch_entry_points(monkeypatch, entries_by_group: dict[str, list[FakeEntryPoint]]) -> None:
    entries = FakeEntryPoints()
    for group, group_entries in entries_by_group.items():
        for entry_point in group_entries:
            entry_point.group = group
            entries.append(entry_point)
    monkeypatch.setattr("agent_bom.extensions.metadata.entry_points", lambda: entries)


@pytest.fixture(autouse=True)
def reset_component_registries(monkeypatch):
    import agent_bom.components.enricher_registry as enricher_registry
    import agent_bom.components.matcher_registry as matcher_registry

    monkeypatch.delenv(ENTRYPOINTS_ENABLED_ENV, raising=False)
    enricher_registry._reset_enricher_registry_for_tests()
    matcher_registry._reset_matcher_registry_for_tests()
    yield
    enricher_registry._reset_enricher_registry_for_tests()
    matcher_registry._reset_matcher_registry_for_tests()


def test_enricher_registry_loads_builtins() -> None:
    from agent_bom.components.enricher_registry import enricher_registry_summary, list_registered_enrichers

    enrichers = {registration.name: registration for registration in list_registered_enrichers()}

    expected = {"vulnerability-intel", "enrichment-posture", "registry-reputation", "estate-discovery", "ai-enrichment"}
    assert expected <= set(enrichers)
    assert enrichers["vulnerability-intel"].capabilities.network_access is True
    assert enrichers["vulnerability-intel"].phase is ScannerPhase.ENRICHMENT
    assert enrichers["enrichment-posture"].execution_state is ScannerExecutionState.PASSIVE
    assert enrichers["ai-enrichment"].enabled_by_default is False

    summary = enricher_registry_summary()
    assert summary["total"] == len(enrichers)
    assert summary["passive"] == 1


def test_matcher_registry_loads_builtins() -> None:
    from agent_bom.components.matcher_registry import list_registered_matchers, matcher_registry_summary

    matchers = {registration.name: registration for registration in list_registered_matchers()}

    expected = {"agent-dedup", "cross-environment", "runtime-correlation"}
    assert expected <= set(matchers)
    assert matchers["agent-dedup"].run_attr == "correlate_agents"
    assert matchers["cross-environment"].phase is ScannerPhase.ANALYSIS
    assert matchers["runtime-correlation"].capabilities.network_access is False

    summary = matcher_registry_summary()
    assert summary["total"] == len(matchers)


def test_duplicate_enricher_registration_is_rejected() -> None:
    from agent_bom.components.enricher_registry import register_enricher

    registration = EnricherRegistration(name="dup-enricher", module="agent_bom.tests.fake")
    register_enricher(registration)
    with pytest.raises(ValueError, match="duplicate enricher registration"):
        register_enricher(registration)


def test_duplicate_matcher_registration_is_rejected() -> None:
    from agent_bom.components.matcher_registry import register_matcher

    registration = MatcherRegistration(name="dup-matcher", module="agent_bom.tests.fake")
    register_matcher(registration)
    with pytest.raises(ValueError, match="duplicate matcher registration"):
        register_matcher(registration)


def test_enricher_to_dict_is_api_safe() -> None:
    from agent_bom.components.enricher_registry import get_enricher_registration

    payload = get_enricher_registration("vulnerability-intel").to_dict()
    assert payload["role"] == "enricher"
    assert payload["capabilities"]["network_access"] is True
    assert "cvss" in payload["enriches"]


def test_entry_point_enricher_registration_loads_only_when_enabled(monkeypatch) -> None:
    import agent_bom.components.enricher_registry as enricher_registry

    module_name = "agent_bom.tests.fake_enricher_driver"
    fake_module = types.ModuleType(module_name)
    fake_module.run = lambda **_: {"ok": True}
    monkeypatch.setitem(sys.modules, module_name, fake_module)

    registration = EnricherRegistration(
        name="acme-enricher",
        module=module_name,
        source="entry_point",
        phase=ScannerPhase.ENRICHMENT,
        run_attr="run",
        input_types=("vulnerabilities",),
        output_types=("enriched_vulnerabilities",),
        capabilities=ExtensionCapabilities(scan_modes=("analysis",)),
    )
    _patch_entry_points(
        monkeypatch,
        {"agent_bom.enricher_drivers": [FakeEntryPoint("acme-enricher", lambda: registration)]},
    )

    enricher_registry._reset_enricher_registry_for_tests()
    assert "acme-enricher" not in {item.name for item in enricher_registry.list_registered_enrichers()}

    monkeypatch.setenv(ENTRYPOINTS_ENABLED_ENV, "true")
    enricher_registry._reset_enricher_registry_for_tests()
    enrichers = {item.name: item for item in enricher_registry.list_registered_enrichers()}
    assert enrichers["acme-enricher"].source == "entry_point"
    assert enrichers["acme-enricher"].input_types == ("vulnerabilities",)
