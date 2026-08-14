"""MCP parity surface for the canonical risk-campaign workflow."""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace
from typing import Any

from pydantic import ValidationError

from agent_bom.api.idempotency_store import IdempotencyConflictError
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)


def _request_for_tenant(tenant_id: str, actor: str) -> Any:
    return SimpleNamespace(
        state=SimpleNamespace(tenant_id=tenant_id, api_key_name=actor, auth_method="mcp"),
        headers={},
    )


def _load_source(tenant_id: str) -> dict[str, Any]:
    from agent_bom.api.routes.campaigns import _load_findings, _source_payload

    return _source_payload(_load_findings(_request_for_tenant(tenant_id, "mcp-operator")))


async def risk_campaign_workflow_impl(
    *,
    action: str = "list",
    campaign_id: str = "",
    version: int = 0,
    owner: str = "",
    sla_due_at: str = "",
    state: str = "",
    connection_id: str = "",
    project: str = "",
    issue_type: str = "",
    cursor: str = "",
    limit: int = 25,
    idempotency_key: str = "",
    tenant_id: str = "default",
    _truncate_response,
    _authenticated_actor: str = "",
) -> str:
    """List, assign, ticket, and verify tenant-scoped remediation campaigns."""
    # Imported lazily: the campaign workflow runs against the FastAPI route layer,
    # so fastapi is only needed when this write tool is invoked — never at MCP
    # import/boot. Keeps the stdio MCP server importable in the clean (no-api-extra)
    # wheel, which the packaging smoke exercises.
    from fastapi import HTTPException, Response

    from agent_bom.api.routes.campaigns import (
        CampaignTicketAction,
        CampaignUpdate,
        _campaigns,
        _source_incomplete,
        campaign_verification_queue,
        create_campaign_tickets,
        sync_campaign_tickets,
        update_campaign_workflow,
        verify_campaign_workflow,
    )

    resolved_tenant = resolve_mcp_tool_tenant_id(tenant_id)
    actor = (_authenticated_actor or "mcp-operator").strip()
    normalized_action = action.strip().lower()
    request = _request_for_tenant(resolved_tenant, actor)
    try:
        source = _load_source(resolved_tenant)
        if normalized_action == "list":
            campaigns = _campaigns(request, source)
            result: dict[str, Any] = {
                "schema_version": "risk-campaigns.v1",
                "tenant_id": resolved_tenant,
                "campaigns": campaigns,
                "count": len(campaigns),
                "membership_complete": not _source_incomplete(source),
            }
        elif normalized_action == "update":
            if not campaign_id.strip() or version < 1:
                return json.dumps({"status": "rejected", "error": "campaign_id and version are required for update."})
            update_values: dict[str, Any] = {"version": version}
            if owner:
                update_values["owner"] = owner
            if sla_due_at:
                update_values["sla_due_at"] = sla_due_at
            if state:
                update_values["state"] = state
            result = update_campaign_workflow(
                request=request,
                campaign_id=campaign_id.strip(),
                body=CampaignUpdate.model_validate(update_values),
                source=source,
            )
        elif normalized_action == "verify":
            if not campaign_id.strip() or version < 1:
                return json.dumps({"status": "rejected", "error": "campaign_id and version are required for verify."})
            result = verify_campaign_workflow(
                tenant_id=resolved_tenant,
                campaign_id=campaign_id.strip(),
                version=version,
                source=source,
                actor=actor,
                idempotency_key=idempotency_key.strip(),
            )
        elif normalized_action == "verification_queue":
            result = await campaign_verification_queue(
                request,
                cursor=cursor.strip() or None,
                limit=limit,
                _role=None,
            )
        elif normalized_action == "ticket_create":
            if not campaign_id.strip() or not connection_id.strip():
                return json.dumps({"status": "rejected", "error": "campaign_id and connection_id are required."})
            result = await create_campaign_tickets(
                request,
                campaign_id.strip(),
                CampaignTicketAction(
                    connection_id=connection_id,
                    project=project,
                    issue_type=issue_type,
                    cursor=cursor.strip() or None,
                    limit=limit,
                ),
                Response(),
                _role=None,
            )
        elif normalized_action == "ticket_sync":
            if not campaign_id.strip():
                return json.dumps({"status": "rejected", "error": "campaign_id is required."})
            result = await sync_campaign_tickets(
                request,
                campaign_id.strip(),
                Response(),
                cursor=cursor.strip() or None,
                limit=limit,
                _role=None,
            )
        else:
            return json.dumps(
                {
                    "status": "rejected",
                    "error": "Unsupported action. Use list, update, verify, verification_queue, ticket_create, or ticket_sync.",
                }
            )
    except ValidationError as exc:
        return json.dumps({"status": "rejected", "error": exc.errors(include_url=False)})
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {"reason": str(exc.detail)}
        return json.dumps({"status": "rejected", "http_status": exc.status_code, **detail})
    except IdempotencyConflictError:
        return json.dumps(
            {
                "status": "rejected",
                "http_status": 409,
                "reason": "Idempotency key was reused with a different verification request.",
            }
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("MCP risk campaign workflow failed")
        return json.dumps({"status": "error", "error": sanitize_error(exc)})
    return _truncate_response(json.dumps(result, indent=2, default=str))


__all__ = ["risk_campaign_workflow_impl"]
