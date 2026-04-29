"""Shared base types for SaaS connector discovery modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from agent_bom.extensions import ExtensionCapabilities, RegistryEntry
from agent_bom.models import Agent


class ConnectorError(Exception):
    """Raised when a connector fails to authenticate or discover."""


class ConnectorHealthState(str, Enum):
    """Health state of a SaaS connector."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNREACHABLE = "unreachable"
    AUTH_FAILED = "auth_failed"


# Shared timeout for health-check probes (intentionally shorter than discovery).
CONNECTOR_HEALTH_TIMEOUT: float = 10.0


@dataclass
class ConnectorStatus:
    """Health check result for a connector."""

    connector: str
    state: ConnectorHealthState
    message: str = ""
    api_version: str = ""
    details: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ConnectorRegistration(RegistryEntry):
    """Registry metadata for a SaaS connector implementation."""

    health_attr: str = "health_check"


class Connector(Protocol):
    """Protocol implemented by SaaS connector discovery extensions."""

    name: str
    capabilities: ExtensionCapabilities

    def discover(self, **kwargs: Any) -> tuple[list[Agent], list[str]]:
        """Discover connector inventory and return user-safe warnings."""

    def health_check(self, **kwargs: Any) -> ConnectorStatus:
        """Check connector health."""
