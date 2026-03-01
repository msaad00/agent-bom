"""SaaS connector auto-discovery for AI agents and integrations.

Discovers AI agents, bots, and automations from SaaS platforms:
Jira, ServiceNow, Slack.

Each connector uses pure httpx (no SDKs) via the shared http_client module.
"""

from __future__ import annotations

import importlib
from typing import Any

from agent_bom.models import Agent

from .base import ConnectorError, ConnectorStatus

_CONNECTORS: dict[str, str] = {
    "jira": "agent_bom.connectors.jira_connector",
    "servicenow": "agent_bom.connectors.servicenow_connector",
    "slack": "agent_bom.connectors.slack_connector",
}


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
    if connector not in _CONNECTORS:
        raise ValueError(f"Unknown connector '{connector}'. Available: {', '.join(sorted(_CONNECTORS))}")
    mod = importlib.import_module(_CONNECTORS[connector])
    return mod.discover(**kwargs)


def check_connector_health(
    connector: str,
    **kwargs: Any,
) -> ConnectorStatus:
    """Check if a connector can authenticate and reach its API."""
    if connector not in _CONNECTORS:
        raise ValueError(f"Unknown connector '{connector}'.")
    mod = importlib.import_module(_CONNECTORS[connector])
    return mod.health_check(**kwargs)


def list_connectors() -> list[str]:
    """Return sorted list of available connector names."""
    return sorted(_CONNECTORS.keys())
