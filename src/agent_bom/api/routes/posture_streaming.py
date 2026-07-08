"""Posture webhook outbox observability routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.audit_log import log_action
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.posture_streaming import WebhookOutbox, default_webhook_outbox_path

router = APIRouter()

_OUTBOX: WebhookOutbox | None = None
_OUTBOX_OVERRIDE = False


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _actor(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "api"


def get_posture_webhook_outbox() -> WebhookOutbox:
    global _OUTBOX
    path = default_webhook_outbox_path()
    if _OUTBOX_OVERRIDE and _OUTBOX is not None:
        return _OUTBOX
    if _OUTBOX is None or _OUTBOX.path != path:
        _OUTBOX = WebhookOutbox(path)
    return _OUTBOX


def set_posture_webhook_outbox(outbox: WebhookOutbox | None) -> None:
    global _OUTBOX, _OUTBOX_OVERRIDE
    _OUTBOX = outbox
    _OUTBOX_OVERRIDE = outbox is not None


@router.get("/posture/webhooks/outbox", tags=["posture"])
async def list_posture_webhook_outbox(
    request: Request,
    status: str | None = Query(default=None, pattern="^(pending|delivered|dead_letter)$"),
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict:
    """List webhook outbox rows for the current tenant.

    This is an observability surface for the shipped outbox core. It does not
    deliver events and does not configure webhook destinations.
    """
    tenant_id = _tenant_id(request)
    outbox = get_posture_webhook_outbox()
    rows = [record.to_dict() for record in outbox.records(tenant_id=tenant_id, status=status, limit=limit)]
    return {
        "schema_version": "v1",
        "tenant_id": tenant_id,
        "status": status,
        "count": len(rows),
        "records": rows,
        "stats": outbox.stats(tenant_id=tenant_id),
    }


@router.get("/posture/webhooks/outbox/stats", tags=["posture"])
async def get_posture_webhook_outbox_stats(request: Request) -> dict:
    """Return webhook outbox status counts for the current tenant."""
    return {"schema_version": "v1", "stats": get_posture_webhook_outbox().stats(tenant_id=_tenant_id(request))}


@router.post("/posture/webhooks/outbox/{row_id}/retry", tags=["posture"], status_code=202)
async def retry_posture_webhook_outbox_record(request: Request, row_id: int) -> dict:
    """Requeue one dead-lettered webhook row for the current tenant."""
    tenant_id = _tenant_id(request)
    outbox = get_posture_webhook_outbox()
    if not outbox.requeue_dead_letter(tenant_id=tenant_id, row_id=row_id):
        raise HTTPException(status_code=404, detail="Dead-letter webhook row not found")
    log_action(
        "posture.webhook_outbox_requeued",
        actor=_actor(request),
        resource=f"posture-webhook-outbox/{row_id}",
        tenant_id=tenant_id,
    )
    return {"schema_version": "v1", "row_id": row_id, "status": "pending"}
