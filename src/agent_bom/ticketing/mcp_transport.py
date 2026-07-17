"""MCP-client ticketing transport (primary).

agent-bom acts as an MCP *client* of a configured ITSM MCP server (e.g. an
Atlassian/Jira MCP server, official-remote or self-hosted) and routes
``create_ticket`` / ``sync_status`` to that server's tools. This reuses the same
MCP-client machinery agent-bom already uses to introspect servers
(:mod:`agent_bom.mcp_introspect`) — a ``streamablehttp_client`` + ``ClientSession``
handshake — with the server's own bearer auth resolved once from the stored
connection.

The tool names are non-secret connection params (``auth_params.create_tool`` /
``auth_params.status_tool``); the server's bearer token is the sealed secret. No
credential is ever taken from the action caller. The actual tool invocation is
injected behind :class:`_ToolCaller` so tests drive a mock/generic ITSM MCP
server without a live network.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

from agent_bom.ticketing.models import (
    TicketDraft,
    TicketingConnectionRecord,
    TicketRef,
    TicketStatus,
)
from agent_bom.ticketing.transport import TicketingTransport, TicketingTransportError, map_status_token

# A caller invokes one tool on the connected ITSM MCP server and returns the
# tool result already reduced to a JSON dict (structuredContent, or parsed text).
_ToolCaller = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]

# Default MCP tool names if the connection did not specify its own.
_DEFAULT_CREATE_TOOL = "create_issue"
_DEFAULT_STATUS_TOOL = "get_issue"


class McpTicketingTransport(TicketingTransport):
    """Drive a configured ITSM MCP server's create/status tools as a client."""

    def __init__(
        self,
        record: TicketingConnectionRecord,
        secret: str,
        *,
        caller: _ToolCaller | None = None,
    ) -> None:
        self._record = record
        self._secret = secret
        self._create_tool = str(record.auth_params.get("create_tool") or _DEFAULT_CREATE_TOOL)
        self._status_tool = str(record.auth_params.get("status_tool") or _DEFAULT_STATUS_TOOL)
        self._caller = caller or _default_caller(record, secret)

    async def create_ticket(self, draft: TicketDraft) -> TicketRef:
        result = await self._caller(self._create_tool, draft.to_arguments())
        external_id = _first_str(result, "external_id", "id", "key", "sys_id", "issue_id")
        key = _first_str(result, "key", "number", "external_id", "id")
        url = _first_str(result, "url", "link", "self")
        if not external_id and not key:
            raise TicketingTransportError("The ITSM MCP server did not return a ticket id.")
        status_token = _first_str(result, "status", "state")
        return TicketRef(
            provider=self._record.provider,
            external_id=external_id or key,
            key=key,
            url=url,
            status=map_status_token(status_token) if status_token else TicketStatus.OPEN,
        )

    async def get_status(self, ref: TicketRef) -> TicketStatus:
        handle = (ref.external_id or ref.key).strip()
        if not handle:
            raise TicketingTransportError("A ticket id is required to read status.")
        result = await self._caller(self._status_tool, {"ticket_id": handle, "key": ref.key, "external_id": ref.external_id})
        token = _first_str(result, "status", "state")
        return map_status_token(token) if token else TicketStatus.UNKNOWN


def _first_str(data: dict[str, Any], *keys: str) -> str:
    """First non-empty string value across ``keys`` (case-insensitive keys)."""
    lowered = {str(k).lower(): v for k, v in data.items()} if isinstance(data, dict) else {}
    for key in keys:
        value = lowered.get(key.lower())
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _default_caller(record: TicketingConnectionRecord, secret: str) -> _ToolCaller:
    """Build the real MCP-client caller for the connection's server endpoint.

    Uses ``streamablehttp_client`` + ``ClientSession`` (the transport agent-bom
    already speaks). The server's bearer token (the sealed secret) is sent as an
    ``Authorization`` header; nothing is taken from the action caller.
    """

    endpoint = (record.endpoint or "").strip()

    async def _call(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if not endpoint:
            raise TicketingTransportError("The ITSM MCP connection has no server endpoint.")
        try:
            from mcp import ClientSession
            from mcp.client.streamable_http import streamablehttp_client
        except ImportError as exc:  # pragma: no cover - mcp is a core extra
            raise TicketingTransportError("The MCP client SDK is not installed for the MCP ticketing transport.") from exc

        headers = {"Authorization": f"Bearer {secret}"} if secret else None
        try:
            async with streamablehttp_client(endpoint, headers=headers) as (read, write, _get_session_id):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool(tool_name, arguments)
        except TicketingTransportError:
            raise
        except Exception as exc:  # noqa: BLE001 - any client/transport failure
            raise TicketingTransportError(f"ITSM MCP server call '{tool_name}' failed.") from exc
        if getattr(result, "isError", False):
            raise TicketingTransportError(f"ITSM MCP server reported an error for '{tool_name}'.")
        return _reduce_tool_result(result)

    return _call


def _reduce_tool_result(result: Any) -> dict[str, Any]:
    """Reduce an MCP ``CallToolResult`` to a JSON dict.

    Prefers ``structuredContent``; otherwise parses the first JSON text block.
    """
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if not text:
            continue
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return {}
