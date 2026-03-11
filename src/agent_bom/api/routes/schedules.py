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

from fastapi import APIRouter, HTTPException

from agent_bom.api.models import ScheduleCreate
from agent_bom.api.stores import _get_schedule_store

router = APIRouter()


@router.post("/v1/schedules", tags=["schedules"], status_code=201)
async def create_schedule(body: ScheduleCreate) -> dict:
    """Create a recurring scan schedule."""
    from agent_bom.api.schedule_store import ScanSchedule
    from agent_bom.api.scheduler import parse_cron_next

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
        tenant_id=body.tenant_id,
    )
    _get_schedule_store().put(schedule)
    return schedule.model_dump()


@router.get("/v1/schedules", tags=["schedules"])
async def list_schedules() -> list[dict]:
    """List all scan schedules."""
    return [s.model_dump() for s in _get_schedule_store().list_all()]


@router.get("/v1/schedules/{schedule_id}", tags=["schedules"])
async def get_schedule(schedule_id: str) -> dict:
    """Get a specific schedule."""
    s = _get_schedule_store().get(schedule_id)
    if s is None:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    return s.model_dump()


@router.delete("/v1/schedules/{schedule_id}", tags=["schedules"], status_code=204)
async def delete_schedule(schedule_id: str):
    """Delete a schedule."""
    if not _get_schedule_store().delete(schedule_id):
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")


@router.put("/v1/schedules/{schedule_id}/toggle", tags=["schedules"])
async def toggle_schedule(schedule_id: str) -> dict:
    """Enable or disable a schedule."""
    s = _get_schedule_store().get(schedule_id)
    if s is None:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    s.enabled = not s.enabled
    s.updated_at = datetime.now(timezone.utc).isoformat()
    _get_schedule_store().put(s)
    return s.model_dump()
