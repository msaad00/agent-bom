"""Opt-in runtime activation for discovered plugin entry points.

Discovery (``plugin_entrypoints``) is metadata-only: it enumerates installed
third-party MCP tools, advisory sources, and runtime emitters without executing
them. This module is the *activation* seam. It imports the operator-owned
implementation module a registration advertises, binds its declared callables,
and exposes bounded fan-out helpers that the live MCP server, threat-intel
lookup, and runtime ingest paths call.

Activation is doubly gated and off by default:

1. ``AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS`` must enable discovery, and
2. the per-group activation flag must be set:
   - ``AGENT_BOM_ACTIVATE_MCP_TOOL_PLUGINS``
   - ``AGENT_BOM_ACTIVATE_ADVISORY_SOURCE_PLUGINS``
   - ``AGENT_BOM_ACTIVATE_RUNTIME_EMITTER_PLUGINS``

When a group is not activated the helpers are no-ops, so default behavior is
unchanged. Import, binding, and invocation failures are non-fatal: they are
sanitized into warnings and the deterministic core keeps running.
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agent_bom.extensions import entrypoint_extensions_enabled, sanitize_registry_warning
from agent_bom.plugin_entrypoints import (
    ADVISORY_SOURCES_ENTRY_POINT_GROUP,
    MAX_PLUGIN_ENTRY_POINTS_PER_GROUP,
    MCP_TOOLS_ENTRY_POINT_GROUP,
    RUNTIME_EMITTERS_ENTRY_POINT_GROUP,
    AdvisorySourcePluginRegistration,
    McpToolPluginRegistration,
    RuntimeEmitterPluginRegistration,
    list_advisory_source_plugins,
    list_mcp_tool_plugins,
    list_runtime_emitter_plugins,
)
from agent_bom.security import sanitize_text

ACTIVATE_MCP_TOOL_PLUGINS_ENV = "AGENT_BOM_ACTIVATE_MCP_TOOL_PLUGINS"
ACTIVATE_ADVISORY_SOURCE_PLUGINS_ENV = "AGENT_BOM_ACTIVATE_ADVISORY_SOURCE_PLUGINS"
ACTIVATE_RUNTIME_EMITTER_PLUGINS_ENV = "AGENT_BOM_ACTIVATE_RUNTIME_EMITTER_PLUGINS"

PLUGIN_ACTIVATION_STATUS_SCHEMA_VERSION = "agent-bom.plugin_activation_status.v1"

# Bound results returned to a plugin call are metadata envelopes; cap how much
# a third-party plugin can push back into a control-plane response.
_MAX_PLUGIN_RESULT_ITEMS = 32


@dataclass(frozen=True)
class ActivatedMcpToolPlugin:
    """A discovered MCP tool plugin bound to its ``register`` callable."""

    name: str
    register: Callable[[Any], Any]


@dataclass(frozen=True)
class ActivatedAdvisorySource:
    """A discovered advisory source bound to its ``lookup``/``sync`` callables."""

    name: str
    lookup: Callable[..., Any]
    sync: Callable[..., Any] | None


@dataclass(frozen=True)
class ActivatedRuntimeEmitter:
    """A discovered runtime emitter bound to its ``emit``/``flush`` callables."""

    name: str
    emit: Callable[..., Any]
    flush: Callable[..., Any] | None


_ACTIVATION_WARNINGS: list[str] = []


def _truthy(env_var: str) -> bool:
    return os.getenv(env_var, "").strip().lower() in {"1", "true", "yes", "on"}


def mcp_tool_activation_enabled() -> bool:
    """Return True when MCP tool plugins may register on the live server."""

    return entrypoint_extensions_enabled() and _truthy(ACTIVATE_MCP_TOOL_PLUGINS_ENV)


def advisory_source_activation_enabled() -> bool:
    """Return True when advisory source plugins may be queried."""

    return entrypoint_extensions_enabled() and _truthy(ACTIVATE_ADVISORY_SOURCE_PLUGINS_ENV)


def runtime_emitter_activation_enabled() -> bool:
    """Return True when runtime emitter plugins may receive events."""

    return entrypoint_extensions_enabled() and _truthy(ACTIVATE_RUNTIME_EMITTER_PLUGINS_ENV)


def _warn(message: str) -> None:
    _ACTIVATION_WARNINGS.append(sanitize_registry_warning(message))


def _resolve_attr(module_name: str, attr: str, *, plugin: str) -> Callable[..., Any] | None:
    """Import *module_name* and return its *attr* callable, or None on failure."""

    try:
        module = importlib.import_module(module_name)
    except Exception as exc:  # noqa: BLE001 - third-party import must not crash us
        _warn(f"Could not import module for plugin {plugin}: {exc}")
        return None
    candidate = getattr(module, attr, None)
    if not callable(candidate):
        _warn(f"Plugin {plugin} does not expose a callable '{attr}' attribute")
        return None
    return candidate


def _capped(registrations: list[Any]) -> list[Any]:
    return registrations[:MAX_PLUGIN_ENTRY_POINTS_PER_GROUP]


def activated_mcp_tool_plugins() -> list[ActivatedMcpToolPlugin]:
    """Bind discovered MCP tool plugins to their register callables."""

    if not mcp_tool_activation_enabled():
        return []
    bound: list[ActivatedMcpToolPlugin] = []
    plugins: list[McpToolPluginRegistration] = _capped(list_mcp_tool_plugins())
    for plugin in plugins:
        register = _resolve_attr(plugin.module, plugin.register_attr, plugin=plugin.name)
        if register is not None:
            bound.append(ActivatedMcpToolPlugin(name=plugin.name, register=register))
    return bound


def activated_advisory_sources() -> list[ActivatedAdvisorySource]:
    """Bind discovered advisory sources to their lookup/sync callables."""

    if not advisory_source_activation_enabled():
        return []
    bound: list[ActivatedAdvisorySource] = []
    plugins: list[AdvisorySourcePluginRegistration] = _capped(list_advisory_source_plugins())
    for plugin in plugins:
        lookup = _resolve_attr(plugin.module, plugin.lookup_attr, plugin=plugin.name)
        if lookup is None:
            continue
        sync = getattr(importlib.import_module(plugin.module), plugin.sync_attr, None)
        bound.append(
            ActivatedAdvisorySource(
                name=plugin.name,
                lookup=lookup,
                sync=sync if callable(sync) else None,
            )
        )
    return bound


def activated_runtime_emitters() -> list[ActivatedRuntimeEmitter]:
    """Bind discovered runtime emitters to their emit/flush callables."""

    if not runtime_emitter_activation_enabled():
        return []
    bound: list[ActivatedRuntimeEmitter] = []
    plugins: list[RuntimeEmitterPluginRegistration] = _capped(list_runtime_emitter_plugins())
    for plugin in plugins:
        emit = _resolve_attr(plugin.module, plugin.emit_attr, plugin=plugin.name)
        if emit is None:
            continue
        flush = getattr(importlib.import_module(plugin.module), plugin.flush_attr, None)
        bound.append(
            ActivatedRuntimeEmitter(
                name=plugin.name,
                emit=emit,
                flush=flush if callable(flush) else None,
            )
        )
    return bound


def activate_mcp_tool_plugins(mcp: Any) -> list[str]:
    """Register activated MCP tool plugins on a live FastMCP-compatible server.

    Returns the names of plugins that registered successfully. A plugin whose
    ``register`` callable raises is skipped with a sanitized warning; the rest
    of the server stays intact.
    """

    registered: list[str] = []
    for plugin in activated_mcp_tool_plugins():
        try:
            plugin.register(mcp)
        except Exception as exc:  # noqa: BLE001 - one bad plugin must not break the server
            _warn(f"MCP tool plugin {plugin.name} failed to register: {exc}")
            continue
        registered.append(plugin.name)
    return registered


def _bounded_result(value: Any) -> Any:
    """Bound and shallow-sanitize a value returned by a third-party plugin."""

    if isinstance(value, dict):
        bounded: dict[str, Any] = {}
        for key in list(value)[:_MAX_PLUGIN_RESULT_ITEMS]:
            bounded[sanitize_text(str(key), max_len=120)] = _bounded_result(value[key])
        return bounded
    if isinstance(value, list):
        return [_bounded_result(item) for item in value[:_MAX_PLUGIN_RESULT_ITEMS]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return sanitize_text(str(value), max_len=500)


def advisory_source_lookup(advisory_id: str) -> list[dict[str, Any]]:
    """Fan an advisory lookup out to activated operator advisory sources.

    Returns one provenance-tagged record per source. Empty (a no-op) unless
    advisory source activation is enabled. Never raises: a failing source is
    reported inline with an ``error`` marker instead of aborting the lookup.
    """

    advisory = (advisory_id or "").strip()
    if not advisory:
        return []
    results: list[dict[str, Any]] = []
    for source in activated_advisory_sources():
        record: dict[str, Any] = {"source": source.name, "provenance": "operator_advisory_plugin"}
        try:
            record["result"] = _bounded_result(source.lookup(advisory))
        except Exception as exc:  # noqa: BLE001 - isolate third-party failures
            message = sanitize_text(str(exc), max_len=200)
            _warn(f"Advisory source {source.name} lookup failed: {exc}")
            record["error"] = message
        results.append(record)
    return results


def _runtime_event_envelope(observation: Any) -> dict[str, Any]:
    """Build a redacted routing envelope for a runtime observation.

    Only metadata routing fields are forwarded: never raw prompts, tool
    arguments, or credential values. Mirrors the ``redacted_payloads`` guarantee
    declared by runtime emitter plugins.
    """

    getter = observation.get if isinstance(observation, dict) else lambda key, default=None: getattr(observation, key, default)
    return {
        "schema_version": "runtime.emitter_envelope.v1",
        "tenant_id": sanitize_text(str(getter("tenant_id", "") or "default"), max_len=120),
        "observation_id": sanitize_text(str(getter("observation_id", "") or ""), max_len=200),
        "session_id": sanitize_text(str(getter("session_id", "") or ""), max_len=200),
        "observed_at": sanitize_text(str(getter("observed_at", "") or ""), max_len=80),
        "source": sanitize_text(str(getter("source", "") or ""), max_len=120),
        "surface": sanitize_text(str(getter("surface", "") or "runtime"), max_len=80),
        "event_type": sanitize_text(str(getter("event_type", "") or "runtime_event"), max_len=120),
        "severity": sanitize_text(str(getter("severity", "") or "unknown"), max_len=40),
        "verdict": sanitize_text(str(getter("verdict", "") or "observed"), max_len=80),
        "tool": sanitize_text(str(getter("tool_name", "") or ""), max_len=200),
        "agent": sanitize_text(str(getter("agent_name", "") or ""), max_len=200),
        "redaction_status": "metadata_only",
    }


def fan_out_runtime_event(observation: Any) -> int:
    """Forward a redacted runtime event envelope to activated emitters.

    ``observation`` may be a ``RuntimeObservationRecord`` or a plain dict.
    Returns the number of emitters that accepted the envelope. Never raises:
    default deployments (no activation) return 0 with zero overhead.
    """

    emitters = activated_runtime_emitters()
    if not emitters:
        return 0
    envelope = _runtime_event_envelope(observation)
    delivered = 0
    for emitter in emitters:
        try:
            emitter.emit(envelope)
        except Exception as exc:  # noqa: BLE001 - isolate third-party failures
            _warn(f"Runtime emitter {emitter.name} failed to emit: {exc}")
            continue
        delivered += 1
    return delivered


def flush_runtime_emitters() -> dict[str, Any]:
    """Flush all activated runtime emitters, isolating per-emitter failures."""

    flushed: list[str] = []
    failed: list[str] = []
    for emitter in activated_runtime_emitters():
        if emitter.flush is None:
            continue
        try:
            emitter.flush()
        except Exception as exc:  # noqa: BLE001 - isolate third-party failures
            _warn(f"Runtime emitter {emitter.name} failed to flush: {exc}")
            failed.append(emitter.name)
            continue
        flushed.append(emitter.name)
    return {"flushed": sorted(flushed), "failed": sorted(failed)}


def plugin_activation_warnings() -> list[str]:
    """Return sanitized non-fatal activation warnings collected this process."""

    return list(_ACTIVATION_WARNINGS)


def activation_flags() -> dict[str, bool]:
    """Return the per-group activation flag state (pure env read, no imports)."""

    return {
        MCP_TOOLS_ENTRY_POINT_GROUP: mcp_tool_activation_enabled(),
        ADVISORY_SOURCES_ENTRY_POINT_GROUP: advisory_source_activation_enabled(),
        RUNTIME_EMITTERS_ENTRY_POINT_GROUP: runtime_emitter_activation_enabled(),
    }


def plugin_activation_status() -> dict[str, Any]:
    """Return activation status, binding activated plugins to report live counts.

    Unlike ``plugin_registry_status`` (strictly metadata-only), this binds the
    callables for activated groups so operators can confirm what is wired. Groups
    that are not activated report zero activated plugins without importing any
    third-party module.
    """

    group_bindings: list[tuple[str, str, bool, list[str]]] = [
        (
            MCP_TOOLS_ENTRY_POINT_GROUP,
            ACTIVATE_MCP_TOOL_PLUGINS_ENV,
            mcp_tool_activation_enabled(),
            [plugin.name for plugin in activated_mcp_tool_plugins()],
        ),
        (
            ADVISORY_SOURCES_ENTRY_POINT_GROUP,
            ACTIVATE_ADVISORY_SOURCE_PLUGINS_ENV,
            advisory_source_activation_enabled(),
            [source.name for source in activated_advisory_sources()],
        ),
        (
            RUNTIME_EMITTERS_ENTRY_POINT_GROUP,
            ACTIVATE_RUNTIME_EMITTER_PLUGINS_ENV,
            runtime_emitter_activation_enabled(),
            [emitter.name for emitter in activated_runtime_emitters()],
        ),
    ]
    groups: list[dict[str, Any]] = [
        {
            "group": group,
            "activation_env": activation_env,
            "enabled": enabled,
            "activated_plugins": names,
            "activated_count": len(names),
        }
        for group, activation_env, enabled, names in group_bindings
    ]
    return {
        "schema_version": PLUGIN_ACTIVATION_STATUS_SCHEMA_VERSION,
        "discovery_enabled": entrypoint_extensions_enabled(),
        "totals": {"activated_plugins": sum(len(names) for *_, names in group_bindings)},
        "groups": groups,
        "warnings": plugin_activation_warnings(),
    }


def _reset_plugin_activation_for_tests() -> None:
    _ACTIVATION_WARNINGS.clear()


__all__ = [
    "ACTIVATE_ADVISORY_SOURCE_PLUGINS_ENV",
    "ACTIVATE_MCP_TOOL_PLUGINS_ENV",
    "ACTIVATE_RUNTIME_EMITTER_PLUGINS_ENV",
    "PLUGIN_ACTIVATION_STATUS_SCHEMA_VERSION",
    "ActivatedAdvisorySource",
    "ActivatedMcpToolPlugin",
    "ActivatedRuntimeEmitter",
    "activate_mcp_tool_plugins",
    "activated_advisory_sources",
    "activated_mcp_tool_plugins",
    "activated_runtime_emitters",
    "activation_flags",
    "advisory_source_activation_enabled",
    "advisory_source_lookup",
    "fan_out_runtime_event",
    "flush_runtime_emitters",
    "mcp_tool_activation_enabled",
    "plugin_activation_status",
    "plugin_activation_warnings",
    "runtime_emitter_activation_enabled",
]
