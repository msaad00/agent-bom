"""Authenticated, tenant-scoped remediation campaign API."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Literal

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_bom.api.audit_log import log_action
from agent_bom.api.campaign_store import get_campaign_store
from agent_bom.api.risk_campaigns import derive_campaigns
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.rbac import require_authenticated_permission
from agent_bom.security import sanitize_error
from agent_bom.ticketing.service import TicketingError, create_ticket_for_finding, sync_ticket_status

router = APIRouter(tags=["campaigns"])
_logger = logging.getLogger(__name__)
_READ = require_authenticated_permission("read")
_WRITE = require_authenticated_permission("scan")


class CampaignUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    owner: str | None = Field(default=None, max_length=200)
    sla_due_at: str | None = Field(default=None, max_length=64)
    state: Literal["open", "in_progress", "blocked", "done"] | None = None
    verification_status: Literal["unverified", "pending", "verified", "failed"] | None = None

    @field_validator("sla_due_at")
    @classmethod
    def _valid_sla_due_at(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("sla_due_at must include a timezone")
        return parsed.isoformat()


class CampaignTicketAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    connection_id: str = Field(min_length=1, max_length=200)
    project: str = Field(default="", max_length=200)
    issue_type: str = Field(default="", max_length=100)


def _tenant(request: Request) -> str:
    return require_request_tenant_id(request)


def _actor(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "system"


def _load_findings(request: Request) -> list[dict[str, Any]]:
    from agent_bom.api.routes.scan import _list_findings_impl

    payload = _list_findings_impl(request, None, None, "effective_reach", 1000, 0, None, False, None, None, None, None, 90)
    rows = payload.get("findings") or []
    return [row for row in rows if isinstance(row, dict)]


def _campaigns(tenant_id: str, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    workflows = {row.campaign_id: row for row in get_campaign_store().list(tenant_id)}
    return derive_campaigns(
        findings,
        tenant_id=tenant_id,
        workflow_by_id=workflows,
        window_days=90,
        finding_limit=1000,
        truncated=len(findings) >= 1000,
    )


def _find_campaign(campaigns: list[dict[str, Any]], campaign_id: str) -> dict[str, Any]:
    campaign = next((item for item in campaigns if item["id"] == campaign_id), None)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found in the current findings window.")
    return campaign


def _audit(action: str, request: Request, campaign_id: str, **details: Any) -> None:
    try:
        log_action(
            action,
            actor=_actor(request),
            resource=f"risk-campaign/{campaign_id}",
            tenant_id=_tenant(request),
            **details,
        )
    except Exception:  # noqa: BLE001 - audit failure must not corrupt workflow state
        _logger.warning("risk campaign audit append failed")


@router.get("/campaigns")
async def list_campaigns(request: Request, _role: Any = _READ) -> dict[str, Any]:
    tenant_id = _tenant(request)
    findings = await anyio.to_thread.run_sync(_load_findings, request)
    campaigns = _campaigns(tenant_id, findings)
    return {
        "schema_version": "risk-campaigns.v1",
        "tenant_id": tenant_id,
        "campaigns": campaigns,
        "count": len(campaigns),
        "finding_window_days": 90,
        "finding_limit": 1000,
        "truncated": len(findings) >= 1000,
    }


@router.patch("/campaigns/{campaign_id}")
async def update_campaign(request: Request, campaign_id: str, body: CampaignUpdate, _role: Any = _WRITE) -> dict[str, Any]:
    tenant_id = _tenant(request)
    findings = await anyio.to_thread.run_sync(_load_findings, request)
    campaign = _find_campaign(_campaigns(tenant_id, findings), campaign_id)
    existing = get_campaign_store().get(tenant_id, campaign_id)
    fields = body.model_fields_set
    owner = (body.owner.strip() if body.owner else None) if "owner" in fields else (existing.owner if existing else campaign["owner"])
    sla_due_at = body.sla_due_at if "sla_due_at" in fields else (existing.sla_due_at if existing else campaign["sla_due_at"])
    state = (body.state if "state" in fields else (existing.state if existing else campaign["state"])) or "open"
    verification_status = (
        body.verification_status
        if "verification_status" in fields
        else (existing.verification_status if existing else campaign["verification_status"])
    ) or "unverified"
    workflow = get_campaign_store().upsert(
        tenant_id,
        campaign_id,
        owner=owner,
        sla_due_at=sla_due_at,
        state=state,
        verification_status=verification_status,
    )
    campaign.update(workflow.to_dict())
    _audit("risk_campaign.update", request, campaign_id, state=state, verification_status=verification_status)
    return campaign


@router.post("/campaigns/{campaign_id}/tickets")
async def create_campaign_tickets(
    request: Request,
    campaign_id: str,
    body: CampaignTicketAction,
    response: Response,
    _role: Any = _WRITE,
) -> dict[str, Any]:
    tenant_id = _tenant(request)
    findings = await anyio.to_thread.run_sync(_load_findings, request)
    campaign = _find_campaign(_campaigns(tenant_id, findings), campaign_id)
    rows = {
        str(row.get("id") or row.get("canonical_id") or row.get("finding_id") or row.get("vulnerability_id") or ""): row for row in findings
    }
    tickets: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for finding_id in campaign["finding_ids"]:
        try:
            tickets.append(
                await create_ticket_for_finding(
                    tenant_id=tenant_id,
                    connection_id=body.connection_id.strip(),
                    finding=rows[finding_id],
                    project=body.project.strip(),
                    finding_id=finding_id,
                    issue_type=body.issue_type.strip(),
                    actor=_actor(request),
                )
            )
        except TicketingError as exc:
            errors.append({"finding_id": finding_id, "code": exc.code, "detail": sanitize_error(exc, generic=True)})
        except Exception as exc:  # noqa: BLE001 - one transport failure must not hide successful tickets
            errors.append({"finding_id": finding_id, "code": "transport_error", "detail": sanitize_error(exc, generic=True)})
    if errors:
        response.status_code = 207
    _audit("risk_campaign.ticket_bulk_create", request, campaign_id, created=len(tickets), failed=len(errors))
    return {
        "schema_version": "risk-campaign-tickets.v1",
        "campaign_id": campaign_id,
        "created": len(tickets),
        "failed": len(errors),
        "tickets": tickets,
        "errors": errors,
        "per_action_credential": False,
    }


@router.post("/campaigns/{campaign_id}/tickets/sync")
async def sync_campaign_tickets(request: Request, campaign_id: str, response: Response, _role: Any = _WRITE) -> dict[str, Any]:
    from agent_bom.ticketing.connection_store import get_ticketing_store

    tenant_id = _tenant(request)
    findings = await anyio.to_thread.run_sync(_load_findings, request)
    campaign = _find_campaign(_campaigns(tenant_id, findings), campaign_id)
    finding_ids = set(campaign["finding_ids"])
    links = [link for link in get_ticketing_store().list_ticket_links(tenant_id) if link.dedupe_key in finding_ids]
    synced: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for link in links:
        try:
            synced.append(await sync_ticket_status(tenant_id=tenant_id, ticket_id=link.id, actor=_actor(request)))
        except TicketingError as exc:
            errors.append({"ticket_id": link.id, "code": exc.code, "detail": sanitize_error(exc, generic=True)})
        except Exception as exc:  # noqa: BLE001 - preserve the rest of the bulk sync
            errors.append({"ticket_id": link.id, "code": "transport_error", "detail": sanitize_error(exc, generic=True)})
    if errors:
        response.status_code = 207
    _audit("risk_campaign.ticket_bulk_sync", request, campaign_id, synced=len(synced), failed=len(errors))
    return {
        "schema_version": "risk-campaign-ticket-sync.v1",
        "campaign_id": campaign_id,
        "synced": len(synced),
        "failed": len(errors),
        "tickets": synced,
        "errors": errors,
    }
