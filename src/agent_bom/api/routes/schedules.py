"""Scheduled scanning API routes.

Endpoints:
    POST   /v1/schedules                     create scan schedule
    GET    /v1/schedules                     list all schedules
    GET    /v1/schedules/{schedule_id}       get schedule
    DELETE /v1/schedules/{schedule_id}       delete schedule
    PUT    /v1/schedules/{schedule_id}/toggle enable/disable schedule
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.models import ScheduleCreate
from agent_bom.api.stores import _get_schedule_store
from agent_bom.api.tenant_quota import enforce_schedule_quota

router = APIRouter()


@router.post("/v1/schedules", tags=["schedules"], status_code=201)
async def create_schedule(request: Request, body: ScheduleCreate) -> dict:
    """Create a recurring scan schedule."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.schedule_store import ScanSchedule
    from agent_bom.api.scheduler import parse_cron_next

    tenant_id = getattr(request.state, "tenant_id", "default")
    actor = getattr(request.state, "api_key_name", "") or "system"
    if body.tenant_id not in ("default", tenant_id):
        raise HTTPException(status_code=403, detail="Forbidden — tenant_id must match the authenticated tenant")

    enforce_schedule_quota(tenant_id)
    now = datetime.now(timezone.utc)
    next_run = parse_cron_next(body.cron_expression, now)
    schedule = ScanSchedule(
        schedule_id=str(uuid.uuid4()),
        name=body.name,
        cron_expression=body.cron_expression,
        scan_config=body.scan_config,
        enabled=body.enabled,
        next_run=next_run.isoformat() if next_run else None,
        created_at=now.isoformat(),
        updated_at=now.isoformat(),
        tenant_id=tenant_id,
    )
    _get_schedule_store().put(schedule)
    log_action(
        "schedule.create",
        actor=actor,
        resource=f"schedule/{schedule.schedule_id}",
        tenant_id=tenant_id,
        cron_expression=body.cron_expression,
        enabled=body.enabled,
    )
    return schedule.model_dump()


@router.get("/v1/schedules", tags=["schedules"])
async def list_schedules(request: Request) -> list[dict]:
    """List all scan schedules."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    return [s.model_dump() for s in _get_schedule_store().list_all(tenant_id=tenant_id)]


@router.get("/v1/schedules/{schedule_id}", tags=["schedules"])
async def get_schedule(request: Request, schedule_id: str) -> dict:
    """Get a specific schedule."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    s = _get_schedule_store().get(schedule_id, tenant_id=tenant_id)
    if s is None:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    return s.model_dump()


@router.delete("/v1/schedules/{schedule_id}", tags=["schedules"], status_code=204)
async def delete_schedule(request: Request, schedule_id: str):
    """Delete a schedule."""
    from agent_bom.api.audit_log import log_action

    tenant_id = getattr(request.state, "tenant_id", "default")
    actor = getattr(request.state, "api_key_name", "") or "system"
    s = _get_schedule_store().get(schedule_id, tenant_id=tenant_id)
    if s is None:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    _get_schedule_store().delete(schedule_id, tenant_id=tenant_id)
    log_action("schedule.delete", actor=actor, resource=f"schedule/{schedule_id}", tenant_id=tenant_id)


@router.put("/v1/schedules/{schedule_id}/toggle", tags=["schedules"])
async def toggle_schedule(request: Request, schedule_id: str) -> dict:
    """Enable or disable a schedule."""
    from agent_bom.api.audit_log import log_action

    tenant_id = getattr(request.state, "tenant_id", "default")
    actor = getattr(request.state, "api_key_name", "") or "system"
    s = _get_schedule_store().get(schedule_id, tenant_id=tenant_id)
    if s is None:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    s.enabled = not s.enabled
    s.updated_at = datetime.now(timezone.utc).isoformat()
    _get_schedule_store().put(s)
    log_action(
        "schedule.toggle",
        actor=actor,
        resource=f"schedule/{schedule_id}",
        tenant_id=tenant_id,
        enabled=s.enabled,
    )
    return s.model_dump()
