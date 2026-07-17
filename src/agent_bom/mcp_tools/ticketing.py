"""MCP ticketing tools — file a ticket / sync its status through a stored
connect-once ITSM connection.

Exposes the same connect-once actions to headless MCP clients that the REST plane
offers. Neither tool accepts a credential, token, or base URL: auth and endpoint
are resolved only from the stored, encrypted, tenant-scoped connection. The
tools are ``destructiveHint`` writes, gated at the dispatch layer by an
authenticated admin operator + ``ticketing:write`` scope, and every action is
audit-logged by the service.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)


def _parse_finding(finding_json: str) -> dict[str, Any]:
    if not finding_json.strip():
        return {}
    try:
        parsed = json.loads(finding_json)
    except (ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


async def create_ticket_impl(
    *,
    finding: str = "",
    project: str = "",
    connection_id: str = "",
    finding_id: str = "",
    issue_type: str = "",
    source_url: str = "",
    operator_role: str = "viewer",
    operator_scopes: str = "",
    reason: str = "",
    tenant_id: str = "default",
    _truncate_response,
    _authenticated_actor: str = "",
) -> str:
    """File a ticket for a finding through the stored ITSM connection."""
    from agent_bom.ticketing.service import TicketingError, create_ticket_for_finding

    finding_dict = _parse_finding(finding)
    if not finding_dict:
        return json.dumps({"error": "A 'finding' JSON object is required to file a ticket.", "status": "rejected"})
    resolved_tenant = resolve_mcp_tool_tenant_id(tenant_id)
    actor = (_authenticated_actor or "mcp-operator").strip()
    try:
        result = await create_ticket_for_finding(
            tenant_id=resolved_tenant,
            connection_id=connection_id.strip(),
            finding=finding_dict,
            project=project.strip(),
            finding_id=finding_id.strip(),
            issue_type=issue_type.strip(),
            source_url=source_url.strip(),
            actor=actor,
        )
    except TicketingError as exc:
        return json.dumps({"error": str(exc), "code": exc.code, "status": "rejected"})
    except Exception as exc:  # noqa: BLE001
        logger.warning("MCP create_ticket failed")
        return json.dumps({"error": sanitize_error(exc), "status": "error"})
    return _truncate_response(json.dumps(result, indent=2, default=str))


async def sync_ticket_status_impl(
    *,
    ticket_id: str = "",
    operator_role: str = "viewer",
    operator_scopes: str = "",
    reason: str = "",
    tenant_id: str = "default",
    _truncate_response,
    _authenticated_actor: str = "",
) -> str:
    """Refresh a filed ticket's status from its ITSM, through the connection."""
    from agent_bom.ticketing.service import TicketingError, sync_ticket_status

    if not ticket_id.strip():
        return json.dumps({"error": "A ticket_id is required.", "status": "rejected"})
    resolved_tenant = resolve_mcp_tool_tenant_id(tenant_id)
    actor = (_authenticated_actor or "mcp-operator").strip()
    try:
        result = await sync_ticket_status(tenant_id=resolved_tenant, ticket_id=ticket_id.strip(), actor=actor)
    except TicketingError as exc:
        return json.dumps({"error": str(exc), "code": exc.code, "status": "rejected"})
    except Exception as exc:  # noqa: BLE001
        logger.warning("MCP sync_ticket_status failed")
        return json.dumps({"error": sanitize_error(exc), "status": "error"})
    return _truncate_response(json.dumps(result, indent=2, default=str))
