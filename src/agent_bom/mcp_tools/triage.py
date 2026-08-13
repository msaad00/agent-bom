"""MCP findings-triage tool — record a triage decision to the exception store.

Exposes the same write the REST ``POST /v1/findings/triage`` endpoint and the
CLI ``findings triage`` command perform: it persists a tenant-scoped triage
decision (queue state, VEX-eligible decision + justification, assignee) to the
one exception store via the shared ``record_finding_triage`` helper. No new
business logic lives here — this is the headless MCP surface over the existing
store write.

The tool is a ``destructiveHint`` write, gated at the dispatch layer by an
authenticated admin operator + ``findings:write`` scope, and audit-logged by the
shared helper.
"""

from __future__ import annotations

import json
import logging

from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)


async def findings_triage_impl(
    *,
    vulnerability_id: str = "",
    package: str = "*",
    server_name: str = "",
    assignee: str = "",
    queue_state: str = "open",
    decision: str = "under_investigation",
    justification: str = "",
    decision_reason: str = "",
    expires_at: str = "",
    operator_role: str = "viewer",
    operator_scopes: str = "",
    reason: str = "",
    tenant_id: str = "default",
    _truncate_response,
    _authenticated_actor: str = "",
) -> str:
    """Record a tenant-scoped finding triage decision through the shared store."""
    from fastapi import HTTPException
    from pydantic import ValidationError

    from agent_bom.api.models import FindingTriageRequest
    from agent_bom.api.routes.enterprise import record_finding_triage

    if not vulnerability_id.strip():
        return json.dumps({"error": "A 'vulnerability_id' is required to record a triage decision.", "status": "rejected"})

    resolved_tenant = resolve_mcp_tool_tenant_id(tenant_id)
    actor = (_authenticated_actor or "mcp-operator").strip()
    try:
        req = FindingTriageRequest(
            vulnerability_id=vulnerability_id.strip(),
            package=(package.strip() or "*"),
            server_name=server_name.strip(),
            assignee=assignee.strip(),
            queue_state=queue_state.strip() or "open",  # type: ignore[arg-type]
            decision=decision.strip() or "under_investigation",  # type: ignore[arg-type]
            justification=(justification.strip() or None),  # type: ignore[arg-type]
            decision_reason=decision_reason.strip(),
            expires_at=expires_at.strip(),
        )
    except ValidationError as exc:
        return json.dumps({"error": exc.errors(include_url=False), "status": "rejected"})

    try:
        result = record_finding_triage(tenant_id=resolved_tenant, actor=actor, req=req)
    except HTTPException as exc:
        return json.dumps({"error": str(exc.detail), "status": "rejected"})
    except Exception as exc:  # noqa: BLE001
        logger.warning("MCP findings_triage failed")
        return json.dumps({"error": sanitize_error(exc), "status": "error"})
    return _truncate_response(json.dumps(result, indent=2, default=str))
