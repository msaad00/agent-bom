"""Transport-independent gateway callback and audit failure contracts."""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from agent_bom.gateway_upstreams import UpstreamConfig

AuditSink = Callable[[dict[str, Any]], Awaitable[None]]


GatewayAuditSender = Callable[[dict[str, Any], dict[str, str]], Awaitable[dict[str, Any]]]


UpstreamCaller = Callable[[UpstreamConfig, dict[str, Any], dict[str, str]], Awaitable[dict[str, Any]]]


class GatewayAuditDeliveryUnavailableError(RuntimeError):
    """The gateway could not durably retain a runtime audit event."""
