"""Metadata-only plugin entry-point discovery.

This module intentionally does not wire discovered plugins into runtime
execution paths. It gives v0.88 plugin authors a bounded, opt-in discovery
contract for MCP tools, advisory sources, and runtime emitters while keeping
default behavior unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_bom.extensions import (
    ExtensionCapabilities,
    RegistryEntry,
    _entry_points_for_group,
    entrypoint_extensions_enabled,
    iter_entry_point_registrations,
    sanitize_registry_warning,
)
from agent_bom.security import sanitize_text

MCP_TOOLS_ENTRY_POINT_GROUP = "agent_bom.mcp_tools"
ADVISORY_SOURCES_ENTRY_POINT_GROUP = "agent_bom.advisory_sources"
RUNTIME_EMITTERS_ENTRY_POINT_GROUP = "agent_bom.runtime_emitters"

PLUGIN_ENTRY_POINT_GROUPS: tuple[str, ...] = (
    MCP_TOOLS_ENTRY_POINT_GROUP,
    ADVISORY_SOURCES_ENTRY_POINT_GROUP,
    RUNTIME_EMITTERS_ENTRY_POINT_GROUP,
)

PLUGIN_REGISTRY_STATUS_SCHEMA_VERSION = "agent-bom.plugin_registry_status.v1"

PLUGIN_REGISTRY_GROUPS: tuple[dict[str, str], ...] = (
    {
        "group": "agent_bom.cloud_providers",
        "label": "Cloud providers",
        "description": "Agentless cloud and AI-platform inventory discovery providers.",
    },
    {
        "group": "agent_bom.connectors",
        "label": "Connectors",
        "description": "SaaS and workflow connectors used for inventory and evidence exchange.",
    },
    {
        "group": "agent_bom.inventory_parsers",
        "label": "Inventory parsers",
        "description": "Local manifest and package inventory parser plugins.",
    },
    {
        "group": MCP_TOOLS_ENTRY_POINT_GROUP,
        "label": "MCP tools",
        "description": "Third-party MCP tool registration plugins.",
    },
    {
        "group": ADVISORY_SOURCES_ENTRY_POINT_GROUP,
        "label": "Advisory sources",
        "description": "Threat-intel and advisory lookup source plugins.",
    },
    {
        "group": RUNTIME_EMITTERS_ENTRY_POINT_GROUP,
        "label": "Runtime emitters",
        "description": "Runtime event emitter plugins for operator-enabled sinks.",
    },
)

MAX_PLUGIN_ENTRY_POINTS_PER_GROUP = 32


@dataclass(frozen=True)
class McpToolPluginRegistration(RegistryEntry):
    """Metadata for a third-party MCP tool registration function."""

    register_attr: str = "register_tools"


@dataclass(frozen=True)
class AdvisorySourcePluginRegistration(RegistryEntry):
    """Metadata for a third-party advisory source integration."""

    lookup_attr: str = "lookup"
    sync_attr: str = "sync"


@dataclass(frozen=True)
class RuntimeEmitterPluginRegistration(RegistryEntry):
    """Metadata for a third-party runtime event emitter."""

    emit_attr: str = "emit"
    flush_attr: str = "flush"


PluginRegistration = McpToolPluginRegistration | AdvisorySourcePluginRegistration | RuntimeEmitterPluginRegistration

_MCP_TOOL_PLUGINS: dict[str, McpToolPluginRegistration] = {}
_ADVISORY_SOURCE_PLUGINS: dict[str, AdvisorySourcePluginRegistration] = {}
_RUNTIME_EMITTER_PLUGINS: dict[str, RuntimeEmitterPluginRegistration] = {}
_PLUGIN_ENTRYPOINT_WARNINGS: list[str] = []
_PLUGIN_ENTRYPOINTS_LOADED = False


def _plugin_capabilities(
    *,
    scan_modes: tuple[str, ...],
    data_boundary: str,
    required_scopes: tuple[str, ...] = (),
    outbound_destinations: tuple[str, ...] = (),
    network_access: bool = False,
    writes: bool = False,
    guarantees: tuple[str, ...] = ("read_only",),
) -> ExtensionCapabilities:
    return ExtensionCapabilities(
        scan_modes=scan_modes,
        required_scopes=required_scopes,
        outbound_destinations=outbound_destinations,
        data_boundary=data_boundary,
        writes=writes,
        network_access=network_access,
        guarantees=guarantees,
    )


def _coerce_capabilities(value: Any, fallback: ExtensionCapabilities) -> ExtensionCapabilities:
    capabilities = getattr(value, "capabilities", fallback)
    return capabilities if isinstance(capabilities, ExtensionCapabilities) else fallback


def _name_and_module(value: Any, entry_point_name: str, registration_type: str) -> tuple[str, str]:
    name = str(getattr(value, "name", entry_point_name)).strip()
    module = str(getattr(value, "module", "")).strip()
    if not name or not module:
        raise ValueError(f"{registration_type} plugin registration must declare name and module")
    return name, module


def _coerce_mcp_tool_plugin(value: Any, entry_point_name: str) -> McpToolPluginRegistration:
    if isinstance(value, McpToolPluginRegistration):
        return value
    fallback = _plugin_capabilities(
        scan_modes=("mcp_tool",),
        data_boundary="mcp_tool_metadata_only",
        required_scopes=("operator_enabled_mcp_tool",),
    )
    name, module = _name_and_module(value, entry_point_name, "MCP tool")
    return McpToolPluginRegistration(
        name=name,
        module=module,
        capabilities=_coerce_capabilities(value, fallback),
        source=str(getattr(value, "source", "entry_point")),
        discover_attr=str(getattr(value, "discover_attr", "discover")),
        register_attr=str(getattr(value, "register_attr", "register_tools")),
    )


def _coerce_advisory_source_plugin(value: Any, entry_point_name: str) -> AdvisorySourcePluginRegistration:
    if isinstance(value, AdvisorySourcePluginRegistration):
        return value
    fallback = _plugin_capabilities(
        scan_modes=("advisory_lookup",),
        data_boundary="advisory_metadata_lookup",
        required_scopes=("advisory_source_read",),
        outbound_destinations=(),
        network_access=False,
    )
    name, module = _name_and_module(value, entry_point_name, "advisory source")
    return AdvisorySourcePluginRegistration(
        name=name,
        module=module,
        capabilities=_coerce_capabilities(value, fallback),
        source=str(getattr(value, "source", "entry_point")),
        discover_attr=str(getattr(value, "discover_attr", "discover")),
        lookup_attr=str(getattr(value, "lookup_attr", "lookup")),
        sync_attr=str(getattr(value, "sync_attr", "sync")),
    )


def _coerce_runtime_emitter_plugin(value: Any, entry_point_name: str) -> RuntimeEmitterPluginRegistration:
    if isinstance(value, RuntimeEmitterPluginRegistration):
        return value
    fallback = _plugin_capabilities(
        scan_modes=("runtime_event_emit",),
        data_boundary="runtime_event_metadata_redacted",
        required_scopes=("runtime_event_write",),
        writes=True,
        guarantees=("operator_enabled", "redacted_payloads"),
    )
    name, module = _name_and_module(value, entry_point_name, "runtime emitter")
    return RuntimeEmitterPluginRegistration(
        name=name,
        module=module,
        capabilities=_coerce_capabilities(value, fallback),
        source=str(getattr(value, "source", "entry_point")),
        discover_attr=str(getattr(value, "discover_attr", "discover")),
        emit_attr=str(getattr(value, "emit_attr", "emit")),
        flush_attr=str(getattr(value, "flush_attr", "flush")),
    )


def _register_plugin(registry: dict[str, Any], registration: Any) -> None:
    registry[registration.name] = registration


def _load_group(*, group: str, coerce) -> list[Any]:
    return iter_entry_point_registrations(
        group=group,
        coerce=coerce,
        warnings=_PLUGIN_ENTRYPOINT_WARNINGS,
        max_entry_points=MAX_PLUGIN_ENTRY_POINTS_PER_GROUP,
    )


def _ensure_plugin_entrypoints_loaded() -> None:
    global _PLUGIN_ENTRYPOINTS_LOADED
    if _PLUGIN_ENTRYPOINTS_LOADED:
        return

    for registration in _load_group(group=MCP_TOOLS_ENTRY_POINT_GROUP, coerce=_coerce_mcp_tool_plugin):
        _register_plugin(_MCP_TOOL_PLUGINS, registration)
    for registration in _load_group(group=ADVISORY_SOURCES_ENTRY_POINT_GROUP, coerce=_coerce_advisory_source_plugin):
        _register_plugin(_ADVISORY_SOURCE_PLUGINS, registration)
    for registration in _load_group(group=RUNTIME_EMITTERS_ENTRY_POINT_GROUP, coerce=_coerce_runtime_emitter_plugin):
        _register_plugin(_RUNTIME_EMITTER_PLUGINS, registration)

    _PLUGIN_ENTRYPOINTS_LOADED = True


def list_mcp_tool_plugins() -> list[McpToolPluginRegistration]:
    """Return discovered third-party MCP tool plugin metadata."""

    _ensure_plugin_entrypoints_loaded()
    return [_MCP_TOOL_PLUGINS[name] for name in sorted(_MCP_TOOL_PLUGINS)]


def list_advisory_source_plugins() -> list[AdvisorySourcePluginRegistration]:
    """Return discovered third-party advisory source plugin metadata."""

    _ensure_plugin_entrypoints_loaded()
    return [_ADVISORY_SOURCE_PLUGINS[name] for name in sorted(_ADVISORY_SOURCE_PLUGINS)]


def list_runtime_emitter_plugins() -> list[RuntimeEmitterPluginRegistration]:
    """Return discovered third-party runtime emitter plugin metadata."""

    _ensure_plugin_entrypoints_loaded()
    return [_RUNTIME_EMITTER_PLUGINS[name] for name in sorted(_RUNTIME_EMITTER_PLUGINS)]


def plugin_entrypoint_warnings() -> list[str]:
    """Return sanitized non-fatal plugin entry-point loading warnings."""

    _ensure_plugin_entrypoints_loaded()
    return list(_PLUGIN_ENTRYPOINT_WARNINGS)


def _safe_entrypoint_metadata(group: str, warnings: list[str]) -> list[dict[str, str]]:
    try:
        entry_points = list(_entry_points_for_group(group))
    except Exception:  # noqa: BLE001
        warnings.append(sanitize_registry_warning(f"Could not enumerate entry points for {group}"))
        return []

    entries: list[dict[str, str]] = []
    for entry_point in entry_points:
        distribution = ""
        dist = getattr(entry_point, "dist", None)
        if dist is not None:
            metadata = getattr(dist, "metadata", {}) or {}
            distribution = str(metadata.get("Name", "") or getattr(dist, "name", "") or "")
        entries.append(
            {
                "name": sanitize_text(str(getattr(entry_point, "name", "unknown")), max_len=120),
                "value": sanitize_text(str(getattr(entry_point, "value", "")), max_len=300),
                "distribution": sanitize_text(distribution, max_len=120),
            }
        )
    return sorted(entries, key=lambda item: (item["name"], item["value"]))


def _builtin_registry_counts() -> dict[str, int]:
    from agent_bom.cloud import builtin_provider_registrations
    from agent_bom.connectors import builtin_connector_registrations
    from agent_bom.parsers import builtin_inventory_parser_registrations

    return {
        "agent_bom.cloud_providers": len(builtin_provider_registrations()),
        "agent_bom.connectors": len(builtin_connector_registrations()),
        "agent_bom.inventory_parsers": len(builtin_inventory_parser_registrations()),
        MCP_TOOLS_ENTRY_POINT_GROUP: 0,
        ADVISORY_SOURCES_ENTRY_POINT_GROUP: 0,
        RUNTIME_EMITTERS_ENTRY_POINT_GROUP: 0,
    }


def plugin_registry_status() -> dict[str, Any]:
    """Return metadata-only plugin registry status for CLI and API callers.

    This intentionally enumerates installed entry-point declarations without
    calling ``EntryPoint.load()``. Runtime activation remains opt-in via
    ``AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS``.
    """

    warnings: list[str] = []
    builtin_counts = _builtin_registry_counts()
    groups: list[dict[str, Any]] = []
    total_builtin = 0
    total_declared = 0
    for group_info in PLUGIN_REGISTRY_GROUPS:
        group_name = group_info["group"]
        entry_points = _safe_entrypoint_metadata(group_name, warnings)
        builtin_count = builtin_counts.get(group_name, 0)
        total_builtin += builtin_count
        total_declared += len(entry_points)
        groups.append(
            {
                **group_info,
                "builtin_count": builtin_count,
                "declared_entrypoint_count": len(entry_points),
                "declared_entrypoints": entry_points,
            }
        )
    return {
        "schema_version": PLUGIN_REGISTRY_STATUS_SCHEMA_VERSION,
        "entrypoints_enabled": entrypoint_extensions_enabled(),
        "metadata_only": True,
        "activation_env": "AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS",
        "totals": {
            "groups": len(groups),
            "builtin_registrations": total_builtin,
            "declared_entrypoints": total_declared,
        },
        "groups": groups,
        "warnings": warnings,
    }


def _reset_plugin_entrypoint_registry_for_tests() -> None:
    _MCP_TOOL_PLUGINS.clear()
    _ADVISORY_SOURCE_PLUGINS.clear()
    _RUNTIME_EMITTER_PLUGINS.clear()
    _PLUGIN_ENTRYPOINT_WARNINGS.clear()
    global _PLUGIN_ENTRYPOINTS_LOADED
    _PLUGIN_ENTRYPOINTS_LOADED = False


__all__ = [
    "ADVISORY_SOURCES_ENTRY_POINT_GROUP",
    "MCP_TOOLS_ENTRY_POINT_GROUP",
    "MAX_PLUGIN_ENTRY_POINTS_PER_GROUP",
    "PLUGIN_ENTRY_POINT_GROUPS",
    "RUNTIME_EMITTERS_ENTRY_POINT_GROUP",
    "AdvisorySourcePluginRegistration",
    "McpToolPluginRegistration",
    "RuntimeEmitterPluginRegistration",
    "list_advisory_source_plugins",
    "list_mcp_tool_plugins",
    "list_runtime_emitter_plugins",
    "plugin_entrypoint_warnings",
    "plugin_registry_status",
]
