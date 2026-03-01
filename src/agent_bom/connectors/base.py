"""Shared base types for SaaS connector discovery modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ConnectorError(Exception):
    """Raised when a connector fails to authenticate or discover."""


class ConnectorHealthState(str, Enum):
    """Health state of a SaaS connector."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNREACHABLE = "unreachable"
    AUTH_FAILED = "auth_failed"


@dataclass
class ConnectorStatus:
    """Health check result for a connector."""

    connector: str
    state: ConnectorHealthState
    message: str = ""
    api_version: str = ""
    details: dict = field(default_factory=dict)
