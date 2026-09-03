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
from agent_bom.api.stores import _get_schedule_store, _get_source_store
from agent_bom.api.tenancy import require_body_tenant_match, require_request_tenant_id
from agent_bom.api.tenant_quota import enforce_schedule_quota, tenant_quota_guard

router = APIRouter()


def _validate_enabled_source_schedule(tenant_id: str, scan_config: dict) -> None:
    """Require an enabled source-backed schedule to reference a runnable source."""
    source_id = str(scan_config.get("source_id") or "").strip()
    raw_source_ids = scan_config.get("source_ids")
    if raw_source_ids is not None:
        if source_id or not isinstance(raw_source_ids, list):
            raise HTTPException(
                status_code=422,
                detail="Correlation schedules require an exact source_ids list without source_id",
            )
        source_ids = sorted(str(value).strip() for value in raw_source_ids)
        if not 2 <= len(source_ids) <= 32 or any(not value for value in source_ids) or len(set(source_ids)) != len(source_ids):
            raise HTTPException(status_code=422, detail="Correlation schedules require 2-32 distinct source ids")
        max_age_hours = scan_config.get("max_age_hours", 168)
        if isinstance(max_age_hours, bool) or not isinstance(max_age_hours, int) or not 1 <= max_age_hours <= 8760:
            raise HTTPException(status_code=422, detail="max_age_hours must be between 1 and 8760")

        from agent_bom.api.routes.sources import _request_for_source, _validate_credential_ref_for_tenant
        from agent_bom.api.scan_batches import scan_request_targets

        for member_source_id in source_ids:
            source = _get_source_store().get(member_source_id)
            if source is None or source.tenant_id != tenant_id or not source.enabled:
                raise HTTPException(status_code=409, detail="Scheduled source is not available in this tenant")
            _validate_credential_ref_for_tenant(tenant_id, source)
            request = _request_for_source(source)
            if len(scan_request_targets(request)) != 1:
                raise HTTPException(
                    status_code=422,
                    detail="Each correlation schedule source must resolve to exactly one scan target",
                )
        return
    if not source_id:
        return
    source = _get_source_store().get(source_id)
    if source is None or source.tenant_id != tenant_id or not source.enabled:
        raise HTTPException(status_code=409, detail="Scheduled source is not available in this tenant")

    # Keep schedule admission aligned with the canonical source execution
    # contract instead of letting an impossible run fail hours later.
    from agent_bom.api.routes.sources import _request_for_source, _validate_credential_ref_for_tenant

    _validate_credential_ref_for_tenant(tenant_id, source)
    _request_for_source(source)


@router.post("/schedules", tags=["schedules"], status_code=201)
async def create_schedule(request: Request, body: ScheduleCreate) -> dict:
    """Create a recurring scan schedule."""
    from agent_bom.api.managed_trial import require_managed_trial_feature

    require_managed_trial_feature("Scan schedules")
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.schedule_store import ScanSchedule
    from agent_bom.api.scheduler import parse_cron_next, validate_cron_expression

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    require_body_tenant_match(body.tenant_id, tenant_id)

    if not validate_cron_expression(body.cron_expression):
        raise HTTPException(status_code=422, detail="Invalid cron expression")

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
    # Per-tenant quota lock keeps (check + insert) atomic (audit-4 P1).
    with tenant_quota_guard(tenant_id, lambda: enforce_schedule_quota(tenant_id)):
        if schedule.enabled:
            _validate_enabled_source_schedule(tenant_id, schedule.scan_config)
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


@router.get("/schedules", tags=["schedules"])
async def list_schedules(request: Request) -> list[dict]:
    """List all scan schedules."""
    tenant_id = require_request_tenant_id(request)
    return [s.model_dump() for s in _get_schedule_store().list_all(tenant_id=tenant_id)]


@router.get("/schedules/{schedule_id}", tags=["schedules"])
async def get_schedule(request: Request, schedule_id: str) -> dict:
    """Get a specific schedule."""
    tenant_id = require_request_tenant_id(request)
    s = _get_schedule_store().get(schedule_id, tenant_id=tenant_id)
    if s is None:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    return s.model_dump()


@router.delete("/schedules/{schedule_id}", tags=["schedules"], status_code=204)
async def delete_schedule(request: Request, schedule_id: str) -> None:
    """Delete a schedule."""
    from agent_bom.api.audit_log import log_action

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    with tenant_quota_guard(tenant_id):
        s = _get_schedule_store().get(schedule_id, tenant_id=tenant_id)
        if s is None:
            raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
        _get_schedule_store().delete(schedule_id, tenant_id=tenant_id)
    log_action("schedule.delete", actor=actor, resource=f"schedule/{schedule_id}", tenant_id=tenant_id)


@router.put("/schedules/{schedule_id}/toggle", tags=["schedules"])
async def toggle_schedule(request: Request, schedule_id: str) -> dict:
    """Enable or disable a schedule."""
    from agent_bom.api.audit_log import log_action

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    with tenant_quota_guard(tenant_id):
        s = _get_schedule_store().get(schedule_id, tenant_id=tenant_id)
        if s is None:
            raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
        enabling = not s.enabled
        if enabling:
            _validate_enabled_source_schedule(tenant_id, s.scan_config)
        s.enabled = enabling
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
