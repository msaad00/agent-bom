"""Authenticated, tenant-scoped remediation campaign API."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from datetime import datetime
from typing import Any, Literal

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Query, Request, Response
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
    version: int = Field(ge=1)

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
    cursor: str | None = Field(default=None, max_length=512)
    limit: int = Field(default=25, ge=1, le=25)


class CampaignResponse(BaseModel):
    id: str
    tenant_id: str
    title: str
    finding_ids: list[str]
    finding_count: int
    severity: str
    priority_score: float
    priority_score_method: str
    priority_score_components: dict[str, float]
    score_factors: dict[str, Any]
    expected_risk_reduction: dict[str, Any]
    owner: str | None
    sla_due_at: str | None
    state: str
    verification_status: str
    updated_at: str | None
    source: str
    membership_fingerprint: str
    generation: int
    active: bool
    version: int
    membership_complete: bool
    membership_provisional: bool


class CampaignListResponse(BaseModel):
    schema_version: str
    tenant_id: str
    campaigns: list[CampaignResponse]
    count: int
    finding_window_days: int
    finding_limit: int
    truncated: bool
    total_findings: int | None
    total_approximate: bool
    membership_complete: bool


class CampaignActionResponse(BaseModel):
    schema_version: str
    campaign_id: str
    failed: int
    tickets: list[CampaignTicketResult]
    per_action_credential: bool
    total: int
    processed: int
    next_cursor: str | None
    has_more: bool
    action_limit: int


class CampaignTicketCreateResponse(CampaignActionResponse):
    created: int
    errors: list[CampaignTicketCreateError]


class CampaignTicketSyncResponse(CampaignActionResponse):
    synced: int
    errors: list[CampaignTicketSyncError]


class CampaignTicketRecord(BaseModel):
    id: str
    tenant_id: str = ""
    connection_id: str = ""
    dedupe_key: str = ""
    provider: str = ""
    status: str = ""
    external_id: str = ""
    key: str = ""
    url: str = ""
    created_at: str = ""
    updated_at: str = ""


class CampaignTicketAuditMetadata(BaseModel):
    connect_once: bool = True
    per_action_credential: bool = False
    note: str = ""


class CampaignTicketResult(BaseModel):
    schema_version: str = "ticketing.ticket.v1"
    ticket: CampaignTicketRecord
    connection_id: str = ""
    provider: str = ""
    transport: str = ""
    deduplicated: bool = False
    audit_metadata: CampaignTicketAuditMetadata = Field(default_factory=CampaignTicketAuditMetadata)


class CampaignTicketCreateError(BaseModel):
    finding_id: str
    code: str
    detail: str


class CampaignTicketSyncError(BaseModel):
    ticket_id: str
    code: str
    detail: str


class CampaignVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int = Field(ge=1)


class CampaignVerificationEvidence(BaseModel):
    source: Literal["canonical_findings_spine"]
    finding_window_days: int
    finding_limit: int
    membership_complete: Literal[True]


class CampaignVerificationResponse(BaseModel):
    schema_version: Literal["risk-campaign-verification.v1"]
    campaign_id: str
    verification_status: Literal["verified", "failed"]
    state: str
    remaining_finding_ids: list[str]
    remaining_count: int
    original_member_count: int
    evidence_scope: CampaignVerificationEvidence
    version: int
    verified_at: str


def _tenant(request: Request) -> str:
    return require_request_tenant_id(request)


def _actor(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "system"


def _load_findings(request: Request) -> dict[str, Any]:
    from agent_bom.api.routes.scan import _list_findings_impl

    payload = _list_findings_impl(request, None, None, "effective_reach", 1000, 0, None, False, None, None, None, None, 90)
    payload["findings"] = [row for row in payload.get("findings") or [] if isinstance(row, dict)]
    return payload


def _source_payload(value: Any) -> dict[str, Any]:
    if isinstance(value, list):
        return {"findings": value, "total": len(value), "total_approximate": False, "has_more": False}
    return value


def _source_incomplete(source: dict[str, Any]) -> bool:
    findings = source["findings"]
    total = source.get("total")
    return bool(
        total is None or source.get("has_more") or source.get("total_approximate") or (isinstance(total, int) and total > len(findings))
    )


def _canonical_finding_id(row: dict[str, Any]) -> str:
    return str(row.get("id") or row.get("canonical_id") or row.get("finding_id") or row.get("vulnerability_id") or "").strip()


def _campaigns(request: Request, source: dict[str, Any]) -> list[dict[str, Any]]:
    tenant_id = _tenant(request)
    findings = source["findings"]
    incomplete = _source_incomplete(source)
    initial = derive_campaigns(findings, tenant_id=tenant_id, workflow_by_id={}, window_days=90, finding_limit=1000, truncated=incomplete)
    memberships: dict[str, str | tuple[str, tuple[str, ...]]] = {
        str(item["id"]): (str(item["membership_fingerprint"]), tuple(sorted(str(value) for value in item["finding_ids"])))
        for item in initial
    }
    before = {row.campaign_id: row for row in get_campaign_store().list(tenant_id)}
    if incomplete:
        workflows = {
            campaign_id: row
            for campaign_id, row in before.items()
            if row.active and row.membership_fingerprint == (memberships.get(campaign_id) or (None, ()))[0]
        }
        campaigns = derive_campaigns(
            findings,
            tenant_id=tenant_id,
            workflow_by_id=workflows,
            window_days=90,
            finding_limit=1000,
            truncated=True,
        )
        for campaign in campaigns:
            campaign["membership_complete"] = False
            campaign["membership_provisional"] = True
        return campaigns
    reconciled = get_campaign_store().reconcile_memberships(tenant_id, memberships, complete=True)
    for row in reconciled:
        old = before.get(row.campaign_id)
        if old is None:
            _audit("risk_campaign.membership_observed", request, row.campaign_id, generation=row.generation)
        elif row.generation != old.generation:
            _audit("risk_campaign.membership_reset", request, row.campaign_id, generation=row.generation)
    for campaign_id, old in before.items():
        if old.active and campaign_id not in memberships:
            _audit("risk_campaign.membership_retired", request, campaign_id, generation=old.generation)
    workflows = {row.campaign_id: row for row in reconciled}
    campaigns = derive_campaigns(
        findings,
        tenant_id=tenant_id,
        workflow_by_id=workflows,
        window_days=90,
        finding_limit=1000,
        truncated=False,
    )
    for campaign in campaigns:
        campaign["membership_complete"] = True
        campaign["membership_provisional"] = False
    return campaigns


def _item_fingerprint(items: list[str]) -> str:
    return hashlib.sha256("\x1f".join(sorted(items)).encode()).hexdigest()


def _cursor(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str | None) -> dict[str, Any] | None:
    if not cursor:
        return None
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        value = json.loads(raw)
        required_strings = ("action", "campaign", "membership", "items")
        if not isinstance(value, dict) or any(not isinstance(value.get(key), str) for key in required_strings):
            raise ValueError("invalid cursor shape")
        if not isinstance(value.get("generation"), int) or not isinstance(value.get("offset"), int) or value["offset"] < 0:
            raise ValueError("invalid cursor position")
        return value
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid campaign action cursor.") from exc


def _offset(cursor: dict[str, Any] | None, expected: dict[str, Any], total: int) -> int:
    if cursor is None:
        return 0
    if any(cursor.get(key) != value for key, value in expected.items()) or cursor["offset"] >= total:
        raise HTTPException(status_code=409, detail="Campaign action cursor is stale or does not match this action.")
    return int(cursor["offset"])


def _find_campaign(campaigns: list[dict[str, Any]], campaign_id: str) -> dict[str, Any]:
    campaign = next((item for item in campaigns if item["id"] == campaign_id), None)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found in the current findings window.")
    return campaign


def _require_complete_membership(campaign: dict[str, Any]) -> None:
    if not campaign.get("membership_complete") or campaign.get("membership_provisional"):
        raise HTTPException(
            status_code=409,
            detail="Campaign membership is provisional; refresh after the complete findings snapshot is available.",
        )


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


@router.get("/campaigns", response_model=CampaignListResponse)
async def list_campaigns(request: Request, _role: Any = _READ) -> dict[str, Any]:
    tenant_id = _tenant(request)
    source = _source_payload(await anyio.to_thread.run_sync(_load_findings, request))
    campaigns = _campaigns(request, source)
    total = source.get("total")
    truncated = _source_incomplete(source)
    return {
        "schema_version": "risk-campaigns.v1",
        "tenant_id": tenant_id,
        "campaigns": campaigns,
        "count": len(campaigns),
        "finding_window_days": 90,
        "finding_limit": 1000,
        "truncated": truncated,
        "total_findings": total,
        "total_approximate": bool(source.get("total_approximate")),
        "membership_complete": not truncated,
    }


@router.patch("/campaigns/{campaign_id}", response_model=CampaignResponse)
async def update_campaign(request: Request, campaign_id: str, body: CampaignUpdate, _role: Any = _WRITE) -> dict[str, Any]:
    tenant_id = _tenant(request)
    source = _source_payload(await anyio.to_thread.run_sync(_load_findings, request))
    campaign = _find_campaign(_campaigns(request, source), campaign_id)
    _require_complete_membership(campaign)
    fields = body.model_dump(exclude_unset=True, exclude={"version"})
    if "owner" in fields:
        fields["owner"] = body.owner.strip() if body.owner else None
    workflow = get_campaign_store().patch(tenant_id, campaign_id, expected_version=body.version, fields=fields)
    if workflow is None:
        raise HTTPException(status_code=409, detail="Campaign changed; refresh and retry with the current version.")
    campaign.update(workflow.to_dict())
    _audit("risk_campaign.update", request, campaign_id, state=workflow.state, verification_status=workflow.verification_status)
    return campaign


@router.post("/campaigns/{campaign_id}/verify", response_model=CampaignVerificationResponse)
async def verify_campaign(request: Request, campaign_id: str, body: CampaignVerificationRequest, _role: Any = _WRITE) -> dict[str, Any]:
    tenant_id = _tenant(request)
    source = _source_payload(await anyio.to_thread.run_sync(_load_findings, request))
    if _source_incomplete(source):
        raise HTTPException(status_code=409, detail="Campaign verification requires a complete findings snapshot.")
    store = get_campaign_store()
    stored = store.get(tenant_id, campaign_id)
    if stored is None or not stored.member_ids:
        raise HTTPException(status_code=404, detail="Campaign membership evidence was not found for this tenant.")
    current_ids = {_canonical_finding_id(row) for row in source["findings"]}
    current_ids.discard("")
    remaining = tuple(sorted(set(stored.member_ids) & current_ids))
    verified = store.verify(tenant_id, campaign_id, expected_version=body.version, remaining_ids=remaining)
    if verified is None:
        raise HTTPException(status_code=409, detail="Campaign changed; refresh and retry with the current version.")
    _audit(
        "risk_campaign.verify",
        request,
        campaign_id,
        verification_status=verified.verification_status,
        remaining_count=len(remaining),
    )
    return {
        "schema_version": "risk-campaign-verification.v1",
        "campaign_id": campaign_id,
        "verification_status": verified.verification_status,
        "state": verified.state,
        "remaining_finding_ids": list(remaining),
        "remaining_count": len(remaining),
        "original_member_count": len(stored.member_ids),
        "evidence_scope": {
            "source": "canonical_findings_spine",
            "finding_window_days": 90,
            "finding_limit": 1000,
            "membership_complete": True,
        },
        "version": verified.version,
        "verified_at": verified.updated_at,
    }


@router.post(
    "/campaigns/{campaign_id}/tickets",
    response_model=CampaignTicketCreateResponse,
    responses={207: {"model": CampaignTicketCreateResponse}},
)
async def create_campaign_tickets(
    request: Request,
    campaign_id: str,
    body: CampaignTicketAction,
    response: Response,
    _role: Any = _WRITE,
) -> dict[str, Any]:
    tenant_id = _tenant(request)
    source = _source_payload(await anyio.to_thread.run_sync(_load_findings, request))
    decoded_cursor = _decode_cursor(body.cursor)
    findings = source["findings"]
    campaign = _find_campaign(_campaigns(request, source), campaign_id)
    _require_complete_membership(campaign)
    rows: dict[str, dict[str, Any]] = {}
    for row in findings:
        identity = _canonical_finding_id(row)
        if identity and identity not in rows:
            rows[identity] = row
    tickets: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    all_ids = sorted(campaign["finding_ids"])
    cursor_context = {
        "action": "create",
        "campaign": campaign_id,
        "membership": campaign["membership_fingerprint"],
        "generation": campaign["generation"],
        "items": _item_fingerprint(all_ids),
        "connection": body.connection_id.strip(),
        "project": body.project.strip(),
        "issue_type": body.issue_type.strip(),
    }
    offset = _offset(decoded_cursor, cursor_context, len(all_ids))
    selected = all_ids[offset : offset + body.limit]
    for finding_id in selected:
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
    next_offset = offset + len(selected)
    return {
        "schema_version": "risk-campaign-tickets.v1",
        "campaign_id": campaign_id,
        "created": len(tickets),
        "failed": len(errors),
        "tickets": tickets,
        "errors": errors,
        "per_action_credential": False,
        "total": len(all_ids),
        "processed": len(selected),
        "next_cursor": _cursor({**cursor_context, "offset": next_offset}) if next_offset < len(all_ids) else None,
        "has_more": next_offset < len(all_ids),
        "action_limit": 25,
    }


@router.post(
    "/campaigns/{campaign_id}/tickets/sync",
    response_model=CampaignTicketSyncResponse,
    responses={207: {"model": CampaignTicketSyncResponse}},
)
async def sync_campaign_tickets(
    request: Request,
    campaign_id: str,
    response: Response,
    cursor: str | None = None,
    limit: int = Query(25, ge=1, le=25),
    _role: Any = _WRITE,
) -> dict[str, Any]:
    from agent_bom.ticketing.connection_store import get_ticketing_store

    tenant_id = _tenant(request)
    source = _source_payload(await anyio.to_thread.run_sync(_load_findings, request))
    decoded_cursor = _decode_cursor(cursor)
    campaign = _find_campaign(_campaigns(request, source), campaign_id)
    _require_complete_membership(campaign)
    finding_ids = set(campaign["finding_ids"])
    links = get_ticketing_store().list_ticket_links_for_findings(tenant_id, finding_ids, limit=1001)
    if len(links) > 1000:
        raise HTTPException(status_code=409, detail="Campaign has too many linked tickets for one bounded sync snapshot.")
    links.sort(key=lambda link: link.id)
    link_ids = [f"{link.id}:{link.dedupe_key}:{link.connection_id}" for link in links]
    cursor_context = {
        "action": "sync",
        "campaign": campaign_id,
        "membership": campaign["membership_fingerprint"],
        "generation": campaign["generation"],
        "items": _item_fingerprint(link_ids),
    }
    offset = _offset(decoded_cursor, cursor_context, len(links))
    selected = links[offset : offset + limit]
    synced: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for link in selected:
        try:
            synced.append(await sync_ticket_status(tenant_id=tenant_id, ticket_id=link.id, actor=_actor(request)))
        except TicketingError as exc:
            errors.append({"ticket_id": link.id, "code": exc.code, "detail": sanitize_error(exc, generic=True)})
        except Exception as exc:  # noqa: BLE001 - preserve the rest of the bulk sync
            errors.append({"ticket_id": link.id, "code": "transport_error", "detail": sanitize_error(exc, generic=True)})
    if errors:
        response.status_code = 207
    _audit("risk_campaign.ticket_bulk_sync", request, campaign_id, synced=len(synced), failed=len(errors))
    next_offset = offset + len(selected)
    return {
        "schema_version": "risk-campaign-ticket-sync.v1",
        "campaign_id": campaign_id,
        "synced": len(synced),
        "failed": len(errors),
        "tickets": synced,
        "errors": errors,
        "per_action_credential": False,
        "total": len(links),
        "processed": len(selected),
        "next_cursor": _cursor({**cursor_context, "offset": next_offset}) if next_offset < len(links) else None,
        "has_more": next_offset < len(links),
        "action_limit": 25,
    }
