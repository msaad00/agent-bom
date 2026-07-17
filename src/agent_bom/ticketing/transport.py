"""Pluggable ticketing transport interface + status mapping.

A transport is the only thing that knows *how* to reach an ITSM. Everything
above it (service, MCP tools, REST route) speaks the neutral model in
:mod:`agent_bom.ticketing.models`. Two transports implement this interface:

* :class:`~agent_bom.ticketing.mcp_transport.McpTicketingTransport` (primary)
* :class:`~agent_bom.ticketing.jira_rest.JiraRestTransport` (fallback)

A transport is always constructed from a stored connection + its *already
decrypted* secret bundle — it never accepts a credential from the action caller.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from agent_bom.ticketing.models import TicketDraft, TicketRef, TicketStatus


class TicketingTransportError(RuntimeError):
    """Raised when an ITSM transport call fails.

    The message is sanitized/curated by the caller before it reaches an API
    client; it never carries the connection secret or a raw provider token.
    """


class TicketingTransport(ABC):
    """Create a ticket and read its status through a stored connection."""

    @abstractmethod
    async def create_ticket(self, draft: TicketDraft) -> TicketRef:
        """File a ticket for ``draft`` and return its provider reference."""

    @abstractmethod
    async def get_status(self, ref: TicketRef) -> TicketStatus:
        """Return the canonical status of a previously created ticket."""


# ── Vendor → canonical status mapping ─────────────────────────────────────────
# Jira Cloud groups every status into a statusCategory whose ``key`` is one of
# ``new`` / ``indeterminate`` / ``done`` (``undefined`` for un-categorized). We
# map on the key primarily and fall back to the human category name, since the
# per-status names are customer-configurable but the category is not.
_JIRA_CATEGORY_KEY = {
    "new": TicketStatus.OPEN,
    "undefined": TicketStatus.OPEN,
    "indeterminate": TicketStatus.IN_PROGRESS,
    "done": TicketStatus.DONE,
    # Some payloads surface color-derived keys; map them defensively too.
    "in-flight": TicketStatus.IN_PROGRESS,
    "completed": TicketStatus.DONE,
}
_JIRA_CATEGORY_NAME = {
    "to do": TicketStatus.OPEN,
    "new": TicketStatus.OPEN,
    "in progress": TicketStatus.IN_PROGRESS,
    "done": TicketStatus.DONE,
}


def map_jira_status(category_key: str, category_name: str = "") -> TicketStatus:
    """Map a Jira ``statusCategory`` (key, then name) to the canonical status."""
    mapped = _JIRA_CATEGORY_KEY.get((category_key or "").strip().lower())
    if mapped is not None:
        return mapped
    mapped = _JIRA_CATEGORY_NAME.get((category_name or "").strip().lower())
    return mapped if mapped is not None else TicketStatus.UNKNOWN


def map_servicenow_status(display_label: str) -> TicketStatus:
    """Map a ServiceNow incident ``state`` display label to canonical status.

    Numeric ``state`` values are instance-customizable, so we map on the display
    label (fetched with ``sysparm_display_value=true``) which is stable and
    human-meaningful across instances.
    """
    label = (display_label or "").strip().lower()
    if not label:
        return TicketStatus.UNKNOWN
    if any(term in label for term in ("resolved", "closed", "complete", "cancel", "done")):
        return TicketStatus.DONE
    if any(term in label for term in ("progress", "work", "hold", "pending", "assigned")):
        return TicketStatus.IN_PROGRESS
    if any(term in label for term in ("new", "open")):
        return TicketStatus.OPEN
    return TicketStatus.UNKNOWN


def map_status_token(token: str) -> TicketStatus:
    """Map a free-form status token (from a generic MCP ITSM tool) to canonical.

    Tries the canonical enum first, then the same heuristics as the vendor maps.
    """
    raw = (token or "").strip().lower().replace(" ", "_")
    for status in TicketStatus:
        if raw == status.value:
            return status
    generic = map_servicenow_status(token)
    return generic
