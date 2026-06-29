"""MCP identity-lifecycle write tools.

Agent-identity provisioning (issue / rotate / revoke) and JIT access grants were
reachable only over REST. These tools expose the same lifecycle to headless MCP
clients, gated by an operator-supplied admin role + ``identity:write`` scope +
audit reason — the same write-authorization contract the Shield write tools use.
The underlying REST handlers still write the HMAC-chained lifecycle audit events,
so MCP-driven lifecycle changes are provenance-tracked identically to API calls.
"""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace
from typing import Any, cast

from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)


def _request(tenant_id: str, actor: str) -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(tenant_id=resolve_mcp_tool_tenant_id(tenant_id), actor=actor or "mcp-operator"))


def _csv_set(value: str) -> set[str]:
    return {part.strip() for part in value.split(",") if part.strip()}


def _csv_list(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _has_identity_write_scope(operator_scopes: str) -> bool:
    return bool(_csv_set(operator_scopes) & {"*", "identity:*", "identity:write"})


def _authorize_identity_write(
    *,
    action: str,
    operator_role: str,
    operator_scopes: str,
    reason: str,
    tenant_id: str,
    resource: str,
    authenticated_actor: str = "",
) -> tuple[bool, dict[str, Any]]:
    """Gate an identity write the same way Shield write tools gate enforcement."""
    normalized_role = (operator_role or "").strip().lower()
    clean_reason = (reason or "").strip()
    if normalized_role != "admin":
        return (
            False,
            {
                "error": "identity write action requires admin role",
                "action": action,
                "required_role": "admin",
                "provided_role": normalized_role or "unset",
                "status": "blocked",
            },
        )
    if not _has_identity_write_scope(operator_scopes):
        return (
            False,
            {
                "error": "identity write action requires identity:write scope",
                "action": action,
                "required_role": "admin",
                "required_scope": "identity:write",
                "status": "blocked",
            },
        )
    if len(clean_reason) < 8:
        return (
            False,
            {
                "error": "identity write action requires an audit reason of at least 8 characters",
                "action": action,
                "required_role": "admin",
                "status": "blocked",
            },
        )
    return (
        True,
        {
            "action": action,
            "actor": (authenticated_actor or "").strip() or "mcp-operator",
            "actor_role": normalized_role,
            "tenant_id": resolve_mcp_tool_tenant_id(tenant_id),
            "resource": resource,
            "reason": clean_reason,
        },
    )


def _write_policy(context: dict[str, Any]) -> dict[str, Any]:
    return {
        "required_role": "admin",
        "required_scope": "identity:write",
        "actor": context["actor"],
        "actor_role": context["actor_role"],
        "audit_logged": True,
        "tenant_id": context["tenant_id"],
    }


async def _run_write(
    *,
    action: str,
    operator_role: str,
    operator_scopes: str,
    reason: str,
    tenant_id: str,
    resource: str,
    handler,
    _truncate_response,
    _authenticated_actor: str = "",
) -> str:
    """Authorize, invoke the REST handler, and decorate the response."""
    authorized, context = _authorize_identity_write(
        action=action,
        operator_role=operator_role,
        operator_scopes=operator_scopes,
        reason=reason,
        tenant_id=tenant_id,
        resource=resource,
        authenticated_actor=_authenticated_actor,
    )
    if not authorized:
        return json.dumps(context)
    try:
        from fastapi import HTTPException

        request = _request(tenant_id, context["actor"])
        try:
            payload = await handler(request)
        except HTTPException as exc:
            return json.dumps({"error": sanitize_error(exc.detail), "action": action, "status": "rejected"})
        if isinstance(payload, dict):
            payload["mcp_write_policy"] = _write_policy(context)
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:  # noqa: BLE001
        logger.exception("MCP identity write error: %s", action)
        return json.dumps({"error": sanitize_error(exc)})


async def identity_issue_impl(
    *,
    agent_id: str,
    role: str = "agent",
    blueprint_id: str = "",
    ttl_seconds: int = 90 * 86400,
    allowed_tools: str = "",
    operator_role: str = "viewer",
    operator_scopes: str = "",
    reason: str = "",
    tenant_id: str = "default",
    _truncate_response,
    _authenticated_actor: str = "",
) -> str:
    """Issue a managed agent identity. Returns the raw token exactly once."""
    from agent_bom.api.routes.identities import issue_agent_identity

    body = {
        "agent_id": agent_id,
        "role": role,
        "blueprint_id": blueprint_id,
        "ttl_seconds": ttl_seconds,
        "allowed_tools": _csv_list(allowed_tools),
    }
    return await _run_write(
        action="agent_identity.issued",
        operator_role=operator_role,
        operator_scopes=operator_scopes,
        reason=reason,
        tenant_id=tenant_id,
        resource=f"identity/{agent_id}",
        handler=lambda req: issue_agent_identity(cast(Any, req), body),
        _truncate_response=_truncate_response,
        _authenticated_actor=_authenticated_actor,
    )


async def identity_rotate_impl(
    *,
    identity_id: str,
    overlap_seconds: int = 3600,
    ttl_seconds: int = 90 * 86400,
    operator_role: str = "viewer",
    operator_scopes: str = "",
    reason: str = "",
    tenant_id: str = "default",
    _truncate_response,
    _authenticated_actor: str = "",
) -> str:
    """Rotate a managed identity, keeping the old token live during the overlap."""
    from agent_bom.api.routes.identities import rotate_agent_identity

    body = {"overlap_seconds": overlap_seconds, "ttl_seconds": ttl_seconds}
    return await _run_write(
        action="agent_identity.rotated",
        operator_role=operator_role,
        operator_scopes=operator_scopes,
        reason=reason,
        tenant_id=tenant_id,
        resource=f"identity/{identity_id}",
        handler=lambda req: rotate_agent_identity(cast(Any, req), identity_id, body),
        _truncate_response=_truncate_response,
        _authenticated_actor=_authenticated_actor,
    )


async def identity_revoke_impl(
    *,
    identity_id: str,
    operator_role: str = "viewer",
    operator_scopes: str = "",
    reason: str = "",
    tenant_id: str = "default",
    _truncate_response,
    _authenticated_actor: str = "",
) -> str:
    """Revoke a managed identity immediately; its token can no longer authenticate."""
    from agent_bom.api.routes.identities import revoke_agent_identity

    body = {"reason": (reason or "").strip()}
    return await _run_write(
        action="agent_identity.revoked",
        operator_role=operator_role,
        operator_scopes=operator_scopes,
        reason=reason,
        tenant_id=tenant_id,
        resource=f"identity/{identity_id}",
        handler=lambda req: revoke_agent_identity(cast(Any, req), identity_id, body),
        _truncate_response=_truncate_response,
        _authenticated_actor=_authenticated_actor,
    )


async def identity_grant_jit_impl(
    *,
    identity_id: str,
    tool_name: str,
    ttl_seconds: int = 3600,
    ticket_id: str = "",
    operator_role: str = "viewer",
    operator_scopes: str = "",
    reason: str = "",
    tenant_id: str = "default",
    _truncate_response,
    _authenticated_actor: str = "",
) -> str:
    """Grant one identity time-bound JIT access to one tool."""
    from agent_bom.api.routes.identities import grant_agent_identity_jit

    body = {"tool_name": tool_name, "ttl_seconds": ttl_seconds, "reason": (reason or "").strip(), "ticket_id": ticket_id}
    return await _run_write(
        action="agent_identity.jit_granted",
        operator_role=operator_role,
        operator_scopes=operator_scopes,
        reason=reason,
        tenant_id=tenant_id,
        resource=f"identity/{identity_id}",
        handler=lambda req: grant_agent_identity_jit(cast(Any, req), identity_id, body),
        _truncate_response=_truncate_response,
        _authenticated_actor=_authenticated_actor,
    )


async def identity_revoke_jit_impl(
    *,
    grant_id: str,
    operator_role: str = "viewer",
    operator_scopes: str = "",
    reason: str = "",
    tenant_id: str = "default",
    _truncate_response,
    _authenticated_actor: str = "",
) -> str:
    """Revoke an active JIT grant immediately."""
    from agent_bom.api.routes.identities import revoke_agent_identity_jit

    body = {"reason": (reason or "").strip()}
    return await _run_write(
        action="agent_identity.jit_revoked",
        operator_role=operator_role,
        operator_scopes=operator_scopes,
        reason=reason,
        tenant_id=tenant_id,
        resource=f"identity-jit/{grant_id}",
        handler=lambda req: revoke_agent_identity_jit(cast(Any, req), grant_id, body),
        _truncate_response=_truncate_response,
        _authenticated_actor=_authenticated_actor,
    )
