"""Identity MCP registrations with per-server dispatch bindings."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from .bindings import OperatorToolBindings


def register_shield_status(bindings: OperatorToolBindings) -> None:
    from agent_bom.mcp_tools.runtime import shield_status_impl

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="Shield Status")
    async def shield_status(
        session_id: Annotated[
            str,
            Field(description="Shield session id to inspect."),
        ] = "default",
    ) -> str:
        """Return current Shield assessment for a session without changing enforcement state."""
        return await bindings.execute_tool_async(
            "shield_status",
            shield_status_impl,
            session_id=session_id,
            _truncate_response=bindings.truncate_response,
        )


def register_shield_start(bindings: OperatorToolBindings) -> None:
    from agent_bom.mcp_tools.runtime import shield_start_impl

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.write_action, title="Shield Start")
    async def shield_start(
        session_id: Annotated[
            str,
            Field(description="Shield session id to start."),
        ] = "default",
        correlation_window: Annotated[
            float,
            Field(ge=1.0, le=3600.0, description="Alert correlation window in seconds."),
        ] = 30.0,
        operator_role: Annotated[
            str,
            Field(description="Operator role for this write action. Must be admin."),
        ] = "viewer",
        operator_scopes: Annotated[
            str,
            Field(description="Comma-separated operator scopes. Must include shield:write."),
        ] = "",
        reason: Annotated[
            str,
            Field(description="Human audit reason for starting Shield enforcement."),
        ] = "",
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope for audit logging."),
        ] = "default",
    ) -> str:
        """Start Shield enforcement for a session. Requires admin role, shield:write scope, and audit reason."""
        return await bindings.execute_tool_async(
            "shield_start",
            shield_start_impl,
            destructive=True,
            required_scope="shield:write",
            session_id=session_id,
            correlation_window=correlation_window,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


def register_shield_unblock(bindings: OperatorToolBindings) -> None:
    from agent_bom.mcp_tools.runtime import shield_unblock_impl

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.write_action, title="Shield Unblock")
    async def shield_unblock(
        session_id: Annotated[
            str,
            Field(description="Shield session id to unblock."),
        ] = "default",
        operator_role: Annotated[
            str,
            Field(description="Operator role for this write action. Must be admin."),
        ] = "viewer",
        operator_scopes: Annotated[
            str,
            Field(description="Comma-separated operator scopes. Must include shield:write."),
        ] = "",
        reason: Annotated[
            str,
            Field(description="Human audit reason for unblocking Shield enforcement."),
        ] = "",
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope for audit logging."),
        ] = "default",
    ) -> str:
        """Unblock Shield enforcement for a session. Requires admin role, shield:write scope, and audit reason."""
        return await bindings.execute_tool_async(
            "shield_unblock",
            shield_unblock_impl,
            destructive=True,
            required_scope="shield:write",
            session_id=session_id,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


def register_shield_break_glass(bindings: OperatorToolBindings) -> None:
    from agent_bom.mcp_tools.runtime import shield_break_glass_impl

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.write_action, title="Shield Break Glass")
    async def shield_break_glass(
        session_id: Annotated[
            str,
            Field(description="Shield session id to override."),
        ] = "default",
        operator_role: Annotated[
            str,
            Field(description="Operator role for this write action. Must be admin."),
        ] = "viewer",
        operator_scopes: Annotated[
            str,
            Field(description="Comma-separated operator scopes. Must include shield:write."),
        ] = "",
        reason: Annotated[
            str,
            Field(description="Human audit reason for emergency Shield override."),
        ] = "",
        tenant_id: Annotated[
            str,
            Field(description="Tenant scope for audit logging."),
        ] = "default",
    ) -> str:
        """Run Shield break-glass override. Requires admin role, shield:write scope, and audit reason."""
        return await bindings.execute_tool_async(
            "shield_break_glass",
            shield_break_glass_impl,
            destructive=True,
            required_scope="shield:write",
            session_id=session_id,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


def register_identity_issue(bindings: OperatorToolBindings) -> None:
    from agent_bom.mcp_tools.identity import identity_issue_impl

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.write_action, title="Identity Issue")
    async def identity_issue(
        agent_id: Annotated[str, Field(description="Agent identifier the issued identity represents.")],
        role: Annotated[str, Field(description="Identity role label, for example agent or service.")] = "agent",
        blueprint_id: Annotated[str, Field(description="Optional runtime blueprint id bound to the identity.")] = "",
        ttl_seconds: Annotated[int, Field(ge=60, le=31536000, description="Identity lifetime in seconds.")] = 7776000,
        allowed_tools: Annotated[str, Field(description="Comma-separated per-tool scope allowlist. Empty means any tool.")] = "",
        operator_role: Annotated[str, Field(description="Operator role for this write action. Must be admin.")] = "viewer",
        operator_scopes: Annotated[str, Field(description="Comma-separated operator scopes. Must include identity:write.")] = "",
        reason: Annotated[str, Field(description="Human audit reason for issuing the identity.")] = "",
        tenant_id: Annotated[str, Field(description="Tenant scope for the identity and audit logging.")] = "default",
    ) -> str:
        """Issue a managed agent identity. Requires admin role, identity:write scope, and an audit reason. Returns the raw token once."""
        return await bindings.execute_tool_async(
            "identity_issue",
            identity_issue_impl,
            destructive=True,
            required_scope="identity:write",
            agent_id=agent_id,
            role=role,
            blueprint_id=blueprint_id,
            ttl_seconds=ttl_seconds,
            allowed_tools=allowed_tools,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


def register_identity_rotate(bindings: OperatorToolBindings) -> None:
    from agent_bom.mcp_tools.identity import identity_rotate_impl

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.write_action, title="Identity Rotate")
    async def identity_rotate(
        identity_id: Annotated[str, Field(description="Identity id to rotate.")],
        overlap_seconds: Annotated[int, Field(ge=0, le=86400, description="Seconds the old token stays live during rotation.")] = 3600,
        ttl_seconds: Annotated[int, Field(ge=60, le=31536000, description="Lifetime of the replacement identity in seconds.")] = 7776000,
        operator_role: Annotated[str, Field(description="Operator role for this write action. Must be admin.")] = "viewer",
        operator_scopes: Annotated[str, Field(description="Comma-separated operator scopes. Must include identity:write.")] = "",
        reason: Annotated[str, Field(description="Human audit reason for rotating the identity.")] = "",
        tenant_id: Annotated[str, Field(description="Tenant scope for audit logging.")] = "default",
    ) -> str:
        """Rotate a managed identity, keeping the old token live during the overlap window.

        Requires admin role, identity:write scope, and an audit reason.
        """
        return await bindings.execute_tool_async(
            "identity_rotate",
            identity_rotate_impl,
            destructive=True,
            required_scope="identity:write",
            identity_id=identity_id,
            overlap_seconds=overlap_seconds,
            ttl_seconds=ttl_seconds,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


def register_identity_revoke(bindings: OperatorToolBindings) -> None:
    from agent_bom.mcp_tools.identity import identity_revoke_impl

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.write_action, title="Identity Revoke")
    async def identity_revoke(
        identity_id: Annotated[str, Field(description="Identity id to revoke.")],
        operator_role: Annotated[str, Field(description="Operator role for this write action. Must be admin.")] = "viewer",
        operator_scopes: Annotated[str, Field(description="Comma-separated operator scopes. Must include identity:write.")] = "",
        reason: Annotated[str, Field(description="Human audit reason for revoking the identity.")] = "",
        tenant_id: Annotated[str, Field(description="Tenant scope for audit logging.")] = "default",
    ) -> str:
        """Revoke a managed identity immediately. Requires admin role, identity:write scope, and an audit reason."""
        return await bindings.execute_tool_async(
            "identity_revoke",
            identity_revoke_impl,
            destructive=True,
            required_scope="identity:write",
            identity_id=identity_id,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


def register_identity_grant_jit(bindings: OperatorToolBindings) -> None:
    from agent_bom.mcp_tools.identity import identity_grant_jit_impl

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.write_action, title="Identity Grant JIT")
    async def identity_grant_jit(
        identity_id: Annotated[str, Field(description="Identity id to grant time-bound access to.")],
        tool_name: Annotated[str, Field(description="Tool the grant authorizes, beyond the identity's standing scope.")],
        ttl_seconds: Annotated[int, Field(ge=60, le=86400, description="Grant lifetime in seconds.")] = 3600,
        ticket_id: Annotated[str, Field(description="Optional change/incident ticket id for the grant.")] = "",
        operator_role: Annotated[str, Field(description="Operator role for this write action. Must be admin.")] = "viewer",
        operator_scopes: Annotated[str, Field(description="Comma-separated operator scopes. Must include identity:write.")] = "",
        reason: Annotated[str, Field(description="Human audit reason for granting access.")] = "",
        tenant_id: Annotated[str, Field(description="Tenant scope for audit logging.")] = "default",
    ) -> str:
        """Grant an identity time-bound JIT access to one tool. Requires admin role, identity:write scope, and an audit reason."""
        return await bindings.execute_tool_async(
            "identity_grant_jit",
            identity_grant_jit_impl,
            destructive=True,
            required_scope="identity:write",
            identity_id=identity_id,
            tool_name=tool_name,
            ttl_seconds=ttl_seconds,
            ticket_id=ticket_id,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


def register_identity_revoke_jit(bindings: OperatorToolBindings) -> None:
    from agent_bom.mcp_tools.identity import identity_revoke_jit_impl

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.write_action, title="Identity Revoke JIT")
    async def identity_revoke_jit(
        grant_id: Annotated[str, Field(description="JIT grant id to revoke.")],
        operator_role: Annotated[str, Field(description="Operator role for this write action. Must be admin.")] = "viewer",
        operator_scopes: Annotated[str, Field(description="Comma-separated operator scopes. Must include identity:write.")] = "",
        reason: Annotated[str, Field(description="Human audit reason for revoking the grant.")] = "",
        tenant_id: Annotated[str, Field(description="Tenant scope for audit logging.")] = "default",
    ) -> str:
        """Revoke an active JIT grant immediately. Requires admin role, identity:write scope, and an audit reason."""
        return await bindings.execute_tool_async(
            "identity_revoke_jit",
            identity_revoke_jit_impl,
            destructive=True,
            required_scope="identity:write",
            grant_id=grant_id,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
            _truncate_response=bindings.truncate_response,
        )


REGISTRATIONS = (
    register_shield_status,
    register_shield_start,
    register_shield_unblock,
    register_shield_break_glass,
    register_identity_issue,
    register_identity_rotate,
    register_identity_revoke,
    register_identity_grant_jit,
    register_identity_revoke_jit,
)
