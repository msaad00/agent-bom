"""Scoped ITSM / ticketing connector (#4004).

Files a ticket for a finding/issue and syncs its status back, through a
**stored, scoped, encrypted, revocable connection** configured once in the
Connections hub — never a per-action credential (see the platform invariant in
`/develop` §11 and `AGENTS.md`). The action call (MCP tool, REST, UI) takes a
finding/issue reference + a target project only; auth and the base URL are always
resolved from the stored connection.

The connector is transport-pluggable behind one interface
(:class:`~agent_bom.ticketing.transport.TicketingTransport`):

* **MCP-client transport (primary)** — agent-bom acts as an MCP *client* of a
  configured ITSM MCP server (e.g. an Atlassian/Jira MCP server) and routes
  ``create_ticket`` / ``sync_status`` to that server's tools. Interoperable by
  design; no hardcoded per-vendor REST for MCP-capable ITSMs.
* **Direct-REST transport (fallback)** — a verified per-vendor REST adapter
  (Jira Cloud REST v3 today) for ITSMs without an MCP server. Jira supports
  OAuth 2.0 (3LO) Bearer *and*, as a secondary fallback, an API token — both
  entered once at connect time, sealed at rest, and never re-entered.

Our own ``create_ticket`` / ``sync_ticket_status`` MCP tools + REST endpoints
dispatch to whichever transport the stored connection selected.
"""

from __future__ import annotations

from agent_bom.ticketing.models import (
    AUTH_API_TOKEN,
    AUTH_MCP,
    AUTH_OAUTH,
    PROVIDER_GENERIC,
    PROVIDER_JIRA,
    PROVIDER_SERVICENOW,
    SUPPORTED_TICKETING_PROVIDERS,
    TRANSPORT_MCP,
    TRANSPORT_REST,
    TicketDraft,
    TicketingConnectionRecord,
    TicketRef,
    TicketStatus,
)

__all__ = [
    "AUTH_API_TOKEN",
    "AUTH_MCP",
    "AUTH_OAUTH",
    "PROVIDER_GENERIC",
    "PROVIDER_JIRA",
    "PROVIDER_SERVICENOW",
    "SUPPORTED_TICKETING_PROVIDERS",
    "TRANSPORT_MCP",
    "TRANSPORT_REST",
    "TicketDraft",
    "TicketRef",
    "TicketStatus",
    "TicketingConnectionRecord",
]
