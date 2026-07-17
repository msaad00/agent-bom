"""Ticketing MCP tool registration surface.

Keeps the FastMCP tool decorators for the connect-once ITSM ticketing actions
out of ``mcp_server.py`` (mirroring ``mcp_server_operator_tools`` /
``mcp_server_specialized``) while the implementation logic lives in
:mod:`agent_bom.mcp_tools.ticketing`. Both tools are ``destructiveHint`` writes,
gated at the dispatch layer by an authenticated admin operator +
``ticketing:write`` scope. Neither accepts a credential, token, or base URL —
auth and endpoint are resolved only from the stored, encrypted connection.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from agent_bom.mcp_tools.ticketing import create_ticket_impl, sync_ticket_status_impl


def register_ticketing_tools(mcp, *, write_action, execute_tool_async, truncate_response) -> None:
    """Register the ticketing write tools on the FastMCP server."""

    @mcp.tool(annotations=write_action, title="Create ITSM Ticket")
    async def create_ticket(
        finding: Annotated[str, Field(description="Finding/issue as a JSON object (the vulnerability details to file).")] = "",
        project: Annotated[str, Field(description="Target ITSM project/queue key. Uses the connection default if omitted.")] = "",
        connection_id: Annotated[
            str, Field(description="Stored ticketing connection id. Uses the tenant's only connection if omitted.")
        ] = "",
        finding_id: Annotated[str, Field(description="Stable finding id for idempotency. Derived from the finding if omitted.")] = "",
        issue_type: Annotated[str, Field(description="ITSM issue type (e.g. Bug). Provider default if omitted.")] = "",
        source_url: Annotated[str, Field(description="Optional deep link back into agent-bom for provenance.")] = "",
        operator_role: Annotated[str, Field(description="Operator role for this write action (audit).")] = "viewer",
        operator_scopes: Annotated[str, Field(description="Comma-separated operator scopes (audit).")] = "",
        reason: Annotated[str, Field(description="Human audit reason for filing the ticket.")] = "",
        tenant_id: Annotated[str, Field(description="Tenant scope for the connection and audit logging.")] = "default",
    ) -> str:
        """File an ITSM ticket for a finding through a stored connection.

        Connect-once: auth and the ITSM base URL come only from the stored,
        encrypted connection — no credential or link is passed here. Requires an
        admin operator + ``ticketing:write`` scope. Idempotent per finding.
        """
        return await execute_tool_async(
            "create_ticket",
            create_ticket_impl,
            destructive=True,
            required_scope="ticketing:write",
            finding=finding,
            project=project,
            connection_id=connection_id,
            finding_id=finding_id,
            issue_type=issue_type,
            source_url=source_url,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=write_action, title="Sync ITSM Ticket Status")
    async def sync_ticket_status(
        ticket_id: Annotated[str, Field(description="agent-bom ticket link id returned by create_ticket.")] = "",
        operator_role: Annotated[str, Field(description="Operator role for this write action (audit).")] = "viewer",
        operator_scopes: Annotated[str, Field(description="Comma-separated operator scopes (audit).")] = "",
        reason: Annotated[str, Field(description="Human audit reason for syncing status.")] = "",
        tenant_id: Annotated[str, Field(description="Tenant scope for the connection and audit logging.")] = "default",
    ) -> str:
        """Refresh a filed ticket's status from its ITSM through the connection.

        Requires an admin operator + ``ticketing:write`` scope. Resolves auth and
        endpoint from the stored connection only.
        """
        return await execute_tool_async(
            "sync_ticket_status",
            sync_ticket_status_impl,
            destructive=True,
            required_scope="ticketing:write",
            ticket_id=ticket_id,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=truncate_response,
        )
