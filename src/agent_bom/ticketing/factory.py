"""Build the right transport for a stored connection + its decrypted secret.

The action layer never chooses a transport or handles a credential — it hands the
stored connection (and the just-decrypted secret) here and gets back a ready
:class:`~agent_bom.ticketing.transport.TicketingTransport`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from agent_bom.ticketing.jira_rest import JiraRestTransport
from agent_bom.ticketing.mcp_transport import McpTicketingTransport
from agent_bom.ticketing.models import (
    PROVIDER_JIRA,
    TRANSPORT_MCP,
    TRANSPORT_REST,
    TicketingConnectionRecord,
)
from agent_bom.ticketing.transport import TicketingTransport, TicketingTransportError

_McpCaller = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]


def build_transport(
    record: TicketingConnectionRecord,
    secret: str,
    *,
    mcp_caller: _McpCaller | None = None,
    rest_client_factory: Callable[..., Any] | None = None,
) -> TicketingTransport:
    """Return a transport for the connection. ``secret`` is already decrypted."""
    transport = (record.transport or "").strip().lower()
    if transport == TRANSPORT_MCP:
        return McpTicketingTransport(record, secret, caller=mcp_caller)
    if transport == TRANSPORT_REST:
        provider = (record.provider or "").strip().lower()
        if provider == PROVIDER_JIRA:
            if rest_client_factory is not None:
                return JiraRestTransport(record, secret, client_factory=rest_client_factory)
            return JiraRestTransport(record, secret)
        raise TicketingTransportError(
            f"Direct-REST ticketing for provider '{record.provider}' is not implemented yet; connect it via an ITSM MCP server instead."
        )
    raise TicketingTransportError(f"Unsupported ticketing transport '{record.transport}'.")
