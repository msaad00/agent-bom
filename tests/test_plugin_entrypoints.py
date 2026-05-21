"""Regression tests for bounded plugin entry-point discovery."""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest

from agent_bom.extensions import ENTRYPOINTS_ENABLED_ENV, ExtensionCapabilities
from agent_bom.plugin_entrypoints import (
    ADVISORY_SOURCES_ENTRY_POINT_GROUP,
    MAX_PLUGIN_ENTRY_POINTS_PER_GROUP,
    MCP_TOOLS_ENTRY_POINT_GROUP,
    RUNTIME_EMITTERS_ENTRY_POINT_GROUP,
)


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
def reset_plugin_entrypoint_registry(monkeypatch):
    import agent_bom.plugin_entrypoints as plugin_entrypoints

    monkeypatch.delenv(ENTRYPOINTS_ENABLED_ENV, raising=False)
    plugin_entrypoints._reset_plugin_entrypoint_registry_for_tests()
    yield
    monkeypatch.delenv(ENTRYPOINTS_ENABLED_ENV, raising=False)
    plugin_entrypoints._reset_plugin_entrypoint_registry_for_tests()


def test_plugin_entrypoints_are_disabled_by_default(monkeypatch) -> None:
    import agent_bom.plugin_entrypoints as plugin_entrypoints

    _patch_entry_points(
        monkeypatch,
        {
            MCP_TOOLS_ENTRY_POINT_GROUP: [
                FakeEntryPoint(
                    "custom-tool",
                    lambda: SimpleNamespace(name="custom-tool", module="acme_agent_bom.tools"),
                )
            ]
        },
    )

    assert plugin_entrypoints.list_mcp_tool_plugins() == []
    assert plugin_entrypoints.list_advisory_source_plugins() == []
    assert plugin_entrypoints.list_runtime_emitter_plugins() == []
    assert plugin_entrypoints.plugin_entrypoint_warnings() == []


def test_enabled_plugin_entrypoints_discover_three_groups(monkeypatch) -> None:
    import agent_bom.plugin_entrypoints as plugin_entrypoints

    monkeypatch.setenv(ENTRYPOINTS_ENABLED_ENV, "true")
    _patch_entry_points(
        monkeypatch,
        {
            MCP_TOOLS_ENTRY_POINT_GROUP: [
                FakeEntryPoint(
                    "posture-tool",
                    lambda: SimpleNamespace(
                        name="posture-tool",
                        module="acme_agent_bom.mcp",
                        register_attr="install_tools",
                        capabilities=ExtensionCapabilities(
                            scan_modes=("mcp_tool",),
                            required_scopes=("operator_enabled_mcp_tool",),
                            data_boundary="metadata_only",
                        ),
                    ),
                )
            ],
            ADVISORY_SOURCES_ENTRY_POINT_GROUP: [
                FakeEntryPoint(
                    "private-feed",
                    lambda: SimpleNamespace(
                        name="private-feed",
                        module="acme_agent_bom.advisories",
                        lookup_attr="lookup_advisory",
                        sync_attr="sync_feed",
                    ),
                )
            ],
            RUNTIME_EMITTERS_ENTRY_POINT_GROUP: [
                FakeEntryPoint(
                    "kinesis",
                    lambda: SimpleNamespace(
                        name="kinesis",
                        module="acme_agent_bom.emitters",
                        emit_attr="put_event",
                        flush_attr="flush_batch",
                    ),
                )
            ],
        },
    )

    mcp_plugins = {plugin.name: plugin for plugin in plugin_entrypoints.list_mcp_tool_plugins()}
    advisory_plugins = {plugin.name: plugin for plugin in plugin_entrypoints.list_advisory_source_plugins()}
    emitter_plugins = {plugin.name: plugin for plugin in plugin_entrypoints.list_runtime_emitter_plugins()}

    assert mcp_plugins["posture-tool"].module == "acme_agent_bom.mcp"
    assert mcp_plugins["posture-tool"].register_attr == "install_tools"
    assert mcp_plugins["posture-tool"].capabilities.data_boundary == "metadata_only"
    assert advisory_plugins["private-feed"].lookup_attr == "lookup_advisory"
    assert advisory_plugins["private-feed"].sync_attr == "sync_feed"
    assert emitter_plugins["kinesis"].emit_attr == "put_event"
    assert emitter_plugins["kinesis"].flush_attr == "flush_batch"


def test_plugin_entrypoint_failures_are_sanitized_and_non_fatal(monkeypatch) -> None:
    import agent_bom.plugin_entrypoints as plugin_entrypoints

    monkeypatch.setenv(ENTRYPOINTS_ENABLED_ENV, "1")

    def fail_load() -> Any:
        raise RuntimeError("failed https://user:tok123@example.com/feed?key=secret from /Users/alice/.agent-bom/plugin.py")

    _patch_entry_points(
        monkeypatch,
        {
            ADVISORY_SOURCES_ENTRY_POINT_GROUP: [
                FakeEntryPoint("bad-feed", fail_load),
                FakeEntryPoint(
                    "good-feed",
                    lambda: SimpleNamespace(name="good-feed", module="acme_agent_bom.good_feed"),
                ),
            ]
        },
    )

    advisory_plugins = {plugin.name: plugin for plugin in plugin_entrypoints.list_advisory_source_plugins()}
    warnings = " ".join(plugin_entrypoints.plugin_entrypoint_warnings())

    assert advisory_plugins["good-feed"].module == "acme_agent_bom.good_feed"
    assert "bad-feed" in warnings
    assert "tok123" not in warnings
    assert "key=secret" not in warnings
    assert "/Users/alice" not in warnings


def test_plugin_entrypoint_loading_is_bounded_per_group(monkeypatch) -> None:
    import agent_bom.plugin_entrypoints as plugin_entrypoints

    monkeypatch.setenv(ENTRYPOINTS_ENABLED_ENV, "yes")
    _patch_entry_points(
        monkeypatch,
        {
            RUNTIME_EMITTERS_ENTRY_POINT_GROUP: [
                FakeEntryPoint(
                    f"emitter-{index:02d}",
                    lambda index=index: SimpleNamespace(name=f"emitter-{index:02d}", module=f"acme_agent_bom.emitters_{index}"),
                )
                for index in range(MAX_PLUGIN_ENTRY_POINTS_PER_GROUP + 3)
            ]
        },
    )

    emitter_plugins = plugin_entrypoints.list_runtime_emitter_plugins()
    warnings = " ".join(plugin_entrypoints.plugin_entrypoint_warnings())

    assert len(emitter_plugins) == MAX_PLUGIN_ENTRY_POINTS_PER_GROUP
    assert emitter_plugins[0].name == "emitter-00"
    assert emitter_plugins[-1].name == f"emitter-{MAX_PLUGIN_ENTRY_POINTS_PER_GROUP - 1:02d}"
    assert "loading first" in warnings
    assert RUNTIME_EMITTERS_ENTRY_POINT_GROUP in warnings
