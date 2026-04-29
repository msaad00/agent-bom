"""SaaS connector auto-discovery for AI agents and integrations.

Discovers AI agents, bots, and automations from SaaS platforms:
Jira, ServiceNow, Slack.

Each connector uses pure httpx (no SDKs) via the shared http_client module.
"""

from __future__ import annotations

import importlib
from typing import Any

from agent_bom.cloud.normalization import sanitize_discovery_warnings
from agent_bom.extensions import ExtensionCapabilities, iter_entry_point_registrations
from agent_bom.models import Agent

from .base import ConnectorError, ConnectorRegistration, ConnectorStatus

_ENTRY_POINT_GROUP = "agent_bom.connectors"

# Backward-compatible module lookup surface.
_CONNECTORS: dict[str, str] = {
    "jira": "agent_bom.connectors.jira_connector",
    "servicenow": "agent_bom.connectors.servicenow_connector",
    "slack": "agent_bom.connectors.slack_connector",
}

_BUILTIN_CONNECTORS: dict[str, str] = dict(_CONNECTORS)
_CONNECTOR_REGISTRY: dict[str, ConnectorRegistration] = {}
_CONNECTOR_REGISTRY_WARNINGS: list[str] = []
_CONNECTOR_REGISTRY_LOADED = False


def _connector_capabilities(name: str) -> ExtensionCapabilities:
    return ExtensionCapabilities(
        scan_modes=("inventory",),
        required_scopes=(f"{name}:read",),
        outbound_destinations=(name,),
        data_boundary="agentless_read_only",
        network_access=True,
    )


def _registration_for_connector(name: str, module: str, *, source: str = "builtin") -> ConnectorRegistration:
    return ConnectorRegistration(
        name=name,
        module=module,
        capabilities=_connector_capabilities(name),
        source=source,
    )


def builtin_connector_registrations() -> list[ConnectorRegistration]:
    """Return built-in SaaS connector registrations."""

    return [_registration_for_connector(name, module) for name, module in _BUILTIN_CONNECTORS.items()]


def _coerce_connector_registration(value: Any, entry_point_name: str) -> ConnectorRegistration:
    if isinstance(value, ConnectorRegistration):
        return value
    name = str(getattr(value, "name", entry_point_name)).strip()
    module = str(getattr(value, "module", "")).strip()
    if not name or not module:
        raise ValueError("connector registration must declare name and module")
    capabilities = getattr(value, "capabilities", ExtensionCapabilities())
    if not isinstance(capabilities, ExtensionCapabilities):
        capabilities = ExtensionCapabilities()
    return ConnectorRegistration(
        name=name,
        module=module,
        capabilities=capabilities,
        source=str(getattr(value, "source", "entry_point")),
        discover_attr=str(getattr(value, "discover_attr", "discover")),
        health_attr=str(getattr(value, "health_attr", "health_check")),
    )


def register_connector(registration: ConnectorRegistration) -> None:
    """Register a SaaS connector for discovery lookup."""

    _CONNECTOR_REGISTRY[registration.name] = registration
    _CONNECTORS[registration.name] = registration.module


def _ensure_connector_registry_loaded() -> None:
    global _CONNECTOR_REGISTRY_LOADED
    if _CONNECTOR_REGISTRY_LOADED:
        return
    for registration in builtin_connector_registrations():
        register_connector(registration)
    for registration in iter_entry_point_registrations(
        group=_ENTRY_POINT_GROUP,
        coerce=_coerce_connector_registration,
        warnings=_CONNECTOR_REGISTRY_WARNINGS,
    ):
        register_connector(registration)
    _CONNECTOR_REGISTRY_LOADED = True


def list_registered_connectors() -> list[ConnectorRegistration]:
    """Return registered connectors with capability declarations."""

    _ensure_connector_registry_loaded()
    registrations = dict(_CONNECTOR_REGISTRY)
    for name, module in _CONNECTORS.items():
        registrations.setdefault(name, _registration_for_connector(name, module, source="legacy"))
    return [registrations[name] for name in sorted(registrations)]


def connector_registry_warnings() -> list[str]:
    """Return sanitized non-fatal registry loading warnings."""

    _ensure_connector_registry_loaded()
    return list(_CONNECTOR_REGISTRY_WARNINGS)


def _reset_connector_registry_for_tests() -> None:
    _CONNECTOR_REGISTRY.clear()
    _CONNECTOR_REGISTRY_WARNINGS.clear()
    _CONNECTORS.clear()
    global _CONNECTOR_REGISTRY_LOADED
    _CONNECTOR_REGISTRY_LOADED = False


def discover_from_connector(
    connector: str,
    **kwargs: Any,
) -> tuple[list[Agent], list[str]]:
    """Lazily import and call the named connector's ``discover()`` function.

    Returns:
        (agents, warnings) — discovered agents and non-fatal warning messages.

    Raises:
        ValueError: if *connector* is not a known connector name.
        ConnectorError: if the connector API call fails.
    """
    _ensure_connector_registry_loaded()
    if connector not in _CONNECTORS:
        raise ValueError(f"Unknown connector '{connector}'. Available: {', '.join(sorted(_CONNECTORS))}")
    registration = _CONNECTOR_REGISTRY.get(connector)
    mod = importlib.import_module(_CONNECTORS[connector])
    discover_attr = registration.discover_attr if registration else "discover"
    agents, warnings = getattr(mod, discover_attr)(**kwargs)
    return agents, sanitize_discovery_warnings(warnings)


def check_connector_health(
    connector: str,
    **kwargs: Any,
) -> ConnectorStatus:
    """Check if a connector can authenticate and reach its API."""
    _ensure_connector_registry_loaded()
    if connector not in _CONNECTORS:
        raise ValueError(f"Unknown connector '{connector}'.")
    registration = _CONNECTOR_REGISTRY.get(connector)
    mod = importlib.import_module(_CONNECTORS[connector])
    health_attr = registration.health_attr if registration else "health_check"
    return getattr(mod, health_attr)(**kwargs)


def list_connectors() -> list[str]:
    """Return sorted list of available connector names."""
    _ensure_connector_registry_loaded()
    return sorted(_CONNECTORS.keys())


__all__ = [
    "ConnectorError",
    "ConnectorRegistration",
    "ConnectorStatus",
    "check_connector_health",
    "discover_from_connector",
    "list_connectors",
    "list_registered_connectors",
    "connector_registry_warnings",
    "register_connector",
    "builtin_connector_registrations",
]
