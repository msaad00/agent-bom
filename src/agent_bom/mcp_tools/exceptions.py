"""MCP exception workflow over the canonical tenant-scoped exception store."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id


async def list_exceptions_impl(
    *,
    status: str = "",
    limit: int = 100,
    tenant_id: str = "default",
    _truncate_response,
) -> str:
    """List one bounded page of exception evidence for the bound tenant."""
    from agent_bom.api.stores import _get_exception_store

    resolved_tenant = resolve_mcp_tool_tenant_id(tenant_id)
    rows = _get_exception_store().list_all(status=status.strip() or None, tenant_id=resolved_tenant)
    bounded = rows[: max(1, min(limit, 500))]
    return _truncate_response(
        json.dumps(
            {
                "schema_version": "v1",
                "tenant_id": resolved_tenant,
                "exceptions": [row.to_dict() for row in bounded],
                "total": len(rows),
                "limit": max(1, min(limit, 500)),
                "truncated": len(rows) > len(bounded),
            },
            indent=2,
        )
    )


async def request_exception_impl(
    *,
    vulnerability_id: str = "",
    package_name: str = "*",
    server_name: str = "",
    exception_reason: str = "",
    expires_at: str = "",
    tenant_id: str = "default",
    _truncate_response,
    _authenticated_actor: str = "",
    **_audit: str,
) -> str:
    """Create a pending exception through the same store as REST and UI."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import VulnException
    from agent_bom.api.stores import _get_exception_store

    vuln_id = vulnerability_id.strip()
    clean_reason = exception_reason.strip()
    if not vuln_id:
        return json.dumps({"status": "rejected", "error": "vulnerability_id is required"})
    if len(clean_reason) < 8:
        return json.dumps({"status": "rejected", "error": "exception_reason must be at least 8 characters"})
    if expires_at.strip():
        try:
            parsed = datetime.fromisoformat(expires_at.strip().replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("timezone required")
        except ValueError:
            return json.dumps({"status": "rejected", "error": "expires_at must be a timezone-aware ISO-8601 timestamp"})

    resolved_tenant = resolve_mcp_tool_tenant_id(tenant_id)
    actor = (_authenticated_actor or "mcp-operator").strip()
    exception = VulnException(
        vuln_id=vuln_id,
        package_name=package_name.strip() or "*",
        server_name=server_name.strip(),
        reason=clean_reason,
        requested_by=actor,
        expires_at=expires_at.strip(),
        tenant_id=resolved_tenant,
    )
    _get_exception_store().put(exception)
    log_action(
        "exception_create",
        actor=actor,
        resource=f"exception/{exception.exception_id}",
        tenant_id=resolved_tenant,
        vuln_id=vuln_id,
        package=exception.package_name,
    )
    return _truncate_response(json.dumps(exception.to_dict(), indent=2))


async def approve_exception_impl(
    *,
    exception_id: str = "",
    tenant_id: str = "default",
    _truncate_response,
    _authenticated_actor: str = "",
    **_audit: str,
) -> str:
    """Activate one pending exception through the canonical lifecycle store."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import ExceptionStatus
    from agent_bom.api.stores import _get_exception_store

    clean_id = exception_id.strip()
    if not clean_id:
        return json.dumps({"status": "rejected", "error": "exception_id is required"})
    resolved_tenant = resolve_mcp_tool_tenant_id(tenant_id)
    store = _get_exception_store()
    exception = store.get(clean_id, tenant_id=resolved_tenant)
    if exception is None:
        return json.dumps({"status": "not_found", "error": "exception not found"})
    if exception.status != ExceptionStatus.PENDING:
        return json.dumps(
            {
                "status": "conflict",
                "error": f"cannot approve exception in {exception.status.value} state",
                "exception": exception.to_dict(),
            }
        )

    actor = (_authenticated_actor or "mcp-operator").strip()
    exception.status = ExceptionStatus.ACTIVE
    exception.approved_by = actor
    exception.approved_at = datetime.now(timezone.utc).isoformat()
    store.put(exception)
    log_action(
        "exception_approve",
        actor=actor,
        resource=f"exception/{clean_id}",
        tenant_id=resolved_tenant,
    )
    return _truncate_response(json.dumps(exception.to_dict(), indent=2))
