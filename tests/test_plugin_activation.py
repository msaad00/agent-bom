"""Regression tests for opt-in runtime activation of plugin entry points."""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest

from agent_bom.extensions import ENTRYPOINTS_ENABLED_ENV
from agent_bom.plugin_activation import (
    ACTIVATE_ADVISORY_SOURCE_PLUGINS_ENV,
    ACTIVATE_MCP_TOOL_PLUGINS_ENV,
    ACTIVATE_RUNTIME_EMITTER_PLUGINS_ENV,
)

_FAKE_MODULE = "acme_agent_bom_fake_plugin"


class _FakeMcp:
    def __init__(self) -> None:
        self.registered: list[str] = []


@pytest.fixture()
def fake_plugin_module():
    """Install a fake operator plugin module exposing all plugin callables."""

    module = types.ModuleType(_FAKE_MODULE)
    buffer: list[dict[str, Any]] = []

    def register_tools(mcp: _FakeMcp) -> None:
        mcp.registered.append("acme-tool")

    def lookup(advisory_id: str) -> dict[str, Any]:
        return {"id": advisory_id, "summary": "acme advisory", "source_url": "https://feeds.internal/acme"}

    def sync(*, since: str | None = None) -> dict[str, Any]:
        return {"items": 0, "since": since}

    def emit(event: dict[str, Any]) -> dict[str, Any]:
        buffer.append(event)
        return {"queued": True}

    def flush() -> dict[str, Any]:
        count = len(buffer)
        buffer.clear()
        return {"flushed": count}

    module.register_tools = register_tools  # type: ignore[attr-defined]
    module.lookup = lookup  # type: ignore[attr-defined]
    module.sync = sync  # type: ignore[attr-defined]
    module.emit = emit  # type: ignore[attr-defined]
    module.flush = flush  # type: ignore[attr-defined]
    module.buffer = buffer  # type: ignore[attr-defined]
    sys.modules[_FAKE_MODULE] = module
    try:
        yield module
    finally:
        sys.modules.pop(_FAKE_MODULE, None)


@pytest.fixture(autouse=True)
def seeded_registry(monkeypatch):
    """Seed discovery with fake registrations and reset activation state."""

    import agent_bom.plugin_activation as plugin_activation
    import agent_bom.plugin_entrypoints as plugin_entrypoints

    for env in (
        ENTRYPOINTS_ENABLED_ENV,
        ACTIVATE_MCP_TOOL_PLUGINS_ENV,
        ACTIVATE_ADVISORY_SOURCE_PLUGINS_ENV,
        ACTIVATE_RUNTIME_EMITTER_PLUGINS_ENV,
    ):
        monkeypatch.delenv(env, raising=False)

    plugin_entrypoints._reset_plugin_entrypoint_registry_for_tests()
    plugin_activation._reset_plugin_activation_for_tests()

    plugin_entrypoints._MCP_TOOL_PLUGINS["acme-mcp"] = plugin_entrypoints.McpToolPluginRegistration(name="acme-mcp", module=_FAKE_MODULE)
    plugin_entrypoints._ADVISORY_SOURCE_PLUGINS["acme-adv"] = plugin_entrypoints.AdvisorySourcePluginRegistration(
        name="acme-adv", module=_FAKE_MODULE
    )
    plugin_entrypoints._RUNTIME_EMITTER_PLUGINS["acme-emit"] = plugin_entrypoints.RuntimeEmitterPluginRegistration(
        name="acme-emit", module=_FAKE_MODULE
    )
    plugin_entrypoints._PLUGIN_ENTRYPOINTS_LOADED = True

    yield

    plugin_entrypoints._reset_plugin_entrypoint_registry_for_tests()
    plugin_activation._reset_plugin_activation_for_tests()


def _enable_all(monkeypatch) -> None:
    monkeypatch.setenv(ENTRYPOINTS_ENABLED_ENV, "true")
    monkeypatch.setenv(ACTIVATE_MCP_TOOL_PLUGINS_ENV, "true")
    monkeypatch.setenv(ACTIVATE_ADVISORY_SOURCE_PLUGINS_ENV, "true")
    monkeypatch.setenv(ACTIVATE_RUNTIME_EMITTER_PLUGINS_ENV, "true")


def test_activation_is_off_by_default(monkeypatch, fake_plugin_module) -> None:
    import agent_bom.plugin_activation as plugin_activation

    # Even with discovery on, activation stays off without the group flag.
    monkeypatch.setenv(ENTRYPOINTS_ENABLED_ENV, "true")

    assert plugin_activation.mcp_tool_activation_enabled() is False
    assert plugin_activation.advisory_source_activation_enabled() is False
    assert plugin_activation.runtime_emitter_activation_enabled() is False

    mcp = _FakeMcp()
    assert plugin_activation.activate_mcp_tool_plugins(mcp) == []
    assert mcp.registered == []
    assert plugin_activation.advisory_source_lookup("CVE-2026-0001") == []
    assert plugin_activation.fan_out_runtime_event({"tenant_id": "t1"}) == 0


def test_activation_requires_discovery_flag_too(monkeypatch, fake_plugin_module) -> None:
    import agent_bom.plugin_activation as plugin_activation

    # Group flag on but discovery off => still inert (double gate).
    monkeypatch.setenv(ACTIVATE_MCP_TOOL_PLUGINS_ENV, "true")

    assert plugin_activation.mcp_tool_activation_enabled() is False
    assert plugin_activation.activate_mcp_tool_plugins(_FakeMcp()) == []


def test_mcp_tool_plugin_registers_on_live_server(monkeypatch, fake_plugin_module) -> None:
    import agent_bom.plugin_activation as plugin_activation

    _enable_all(monkeypatch)
    mcp = _FakeMcp()
    registered = plugin_activation.activate_mcp_tool_plugins(mcp)

    assert registered == ["acme-mcp"]
    assert mcp.registered == ["acme-tool"]


def test_advisory_source_lookup_is_provenance_tagged(monkeypatch, fake_plugin_module) -> None:
    import agent_bom.plugin_activation as plugin_activation

    _enable_all(monkeypatch)
    results = plugin_activation.advisory_source_lookup("CVE-2026-0002")

    assert len(results) == 1
    assert results[0]["source"] == "acme-adv"
    assert results[0]["provenance"] == "operator_advisory_plugin"
    assert results[0]["result"]["id"] == "CVE-2026-0002"


def test_runtime_emitter_fan_out_forwards_redacted_envelope(monkeypatch, fake_plugin_module) -> None:
    import agent_bom.plugin_activation as plugin_activation

    _enable_all(monkeypatch)
    observation = {
        "tenant_id": "t1",
        "observation_id": "obs-1",
        "tool_name": "shell",
        "verdict": "blocked",
        # A raw payload field that must NOT be forwarded to the emitter.
        "raw_prompt": "super secret prompt body",
    }
    delivered = plugin_activation.fan_out_runtime_event(observation)

    assert delivered == 1
    assert len(fake_plugin_module.buffer) == 1
    envelope = fake_plugin_module.buffer[0]
    assert envelope["schema_version"] == "runtime.emitter_envelope.v1"
    assert envelope["redaction_status"] == "metadata_only"
    assert envelope["tenant_id"] == "t1"
    assert envelope["tool"] == "shell"
    assert "raw_prompt" not in envelope
    assert "super secret prompt body" not in str(envelope)

    flushed = plugin_activation.flush_runtime_emitters()
    assert flushed == {"flushed": ["acme-emit"], "failed": []}
    assert fake_plugin_module.buffer == []


def test_failing_plugin_is_isolated_and_sanitized(monkeypatch, fake_plugin_module) -> None:
    import agent_bom.plugin_activation as plugin_activation

    _enable_all(monkeypatch)

    def boom(_advisory_id: str) -> dict[str, Any]:
        raise RuntimeError("boom https://user:tok999@example.com/feed?key=secret")

    monkeypatch.setattr(fake_plugin_module, "lookup", boom)

    results = plugin_activation.advisory_source_lookup("CVE-2026-0003")
    assert results[0]["source"] == "acme-adv"
    assert "error" in results[0]
    assert "result" not in results[0]

    warnings = " ".join(plugin_activation.plugin_activation_warnings())
    assert "acme-adv" in warnings
    assert "tok999" not in warnings
    assert "key=secret" not in warnings


def test_missing_callable_is_reported_not_raised(monkeypatch, fake_plugin_module) -> None:
    import agent_bom.plugin_activation as plugin_activation

    _enable_all(monkeypatch)
    # Remove the register callable so binding must fail gracefully.
    monkeypatch.delattr(fake_plugin_module, "register_tools")

    mcp = _FakeMcp()
    assert plugin_activation.activate_mcp_tool_plugins(mcp) == []
    assert mcp.registered == []
    warnings = " ".join(plugin_activation.plugin_activation_warnings())
    assert "acme-mcp" in warnings


def test_activation_status_reports_bound_plugins(monkeypatch, fake_plugin_module) -> None:
    import agent_bom.plugin_activation as plugin_activation

    _enable_all(monkeypatch)
    status = plugin_activation.plugin_activation_status()

    assert status["schema_version"] == plugin_activation.PLUGIN_ACTIVATION_STATUS_SCHEMA_VERSION
    assert status["discovery_enabled"] is True
    assert status["totals"]["activated_plugins"] == 3
    by_group = {group["group"]: group for group in status["groups"]}
    assert by_group["agent_bom.mcp_tools"]["activated_plugins"] == ["acme-mcp"]
    assert by_group["agent_bom.advisory_sources"]["enabled"] is True
    assert by_group["agent_bom.runtime_emitters"]["activated_count"] == 1


def test_activation_flags_helper_is_pure_env_read(monkeypatch, fake_plugin_module) -> None:
    import agent_bom.plugin_activation as plugin_activation

    assert plugin_activation.activation_flags() == {
        "agent_bom.mcp_tools": False,
        "agent_bom.advisory_sources": False,
        "agent_bom.runtime_emitters": False,
    }
    _enable_all(monkeypatch)
    assert plugin_activation.activation_flags() == {
        "agent_bom.mcp_tools": True,
        "agent_bom.advisory_sources": True,
        "agent_bom.runtime_emitters": True,
    }
