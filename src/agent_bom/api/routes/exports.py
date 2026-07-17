"""Scheduled findings-export API routes (#4040).

Headless surface for the security-data-lake export: configure a connect-once
*destination* (object store / warehouse) whose single secret is encrypted at
rest and never echoed, then attach a cron *schedule* that streams the tenant's
findings to it on a cadence. A ``run`` endpoint fires a one-off export now.

    POST   /v1/exports/destinations                create a destination
    GET    /v1/exports/destinations                list destinations
    GET    /v1/exports/destinations/{id}           get a destination
    DELETE /v1/exports/destinations/{id}           revoke a destination
    POST   /v1/exports/destinations/{id}/run       run a one-off export now
    POST   /v1/exports/schedules                   create an export schedule
    GET    /v1/exports/schedules                   list export schedules
    DELETE /v1/exports/schedules/{id}              delete an export schedule
    PUT    /v1/exports/schedules/{id}/toggle       enable/disable a schedule
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from agent_bom.api.audit_log import log_action
from agent_bom.api.connection_crypto import ConnectionSecretError, connections_key_configured, encrypt_secret
from agent_bom.api.export_destination_store import (
    STATUS_PENDING,
    ExportDestinationRecord,
    get_export_destination_store,
    is_supported_kind,
)
from agent_bom.api.export_schedule_store import ExportSchedule, get_export_schedule_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.export.destinations import SUPPORTED_EXPORT_KINDS, ExportPublicationIndeterminateError
from agent_bom.rbac import require_authenticated_permission
from agent_bom.security import sanitize_error

router = APIRouter()
logger = logging.getLogger(__name__)

_READ_DEP = require_authenticated_permission("read")
_WRITE_DEP = require_authenticated_permission("scan")


class ExportDestinationCreate(BaseModel):
    kind: str = Field(
        ...,
        description="Destination kind: s3, azure-blob, gcs, clickhouse, snowflake, bigquery, or databricks",
    )
    display_name: str = Field(..., min_length=1, max_length=200)
    config: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Non-secret parameters: s3 (bucket/prefix/region), azure-blob (container/prefix/account_url), "
            "gcs (bucket/prefix), clickhouse (url/user/database/table), "
            "snowflake (account/user/role/warehouse/database/schema/table), bigquery (project/dataset/table), "
            "or databricks (server_hostname/http_path/catalog/schema/table)"
        ),
    )
    secret: str | None = Field(
        default=None,
        description=(
            "Write-only secret (warehouse access token, Snowflake/Databricks key or token, Azure connection "
            "string, or GCS service-account key JSON); encrypted at rest, never returned"
        ),
    )


class ExportScheduleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    cron_expression: str = Field(..., description="Five-field cron expression")
    destination_id: str
    sort: str = "effective_reach"
    severity: str | None = None
    since_days: int | None = Field(default=None, ge=1, le=3650)
    enabled: bool = True


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _actor(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or "system"


# ── Destinations ──────────────────────────────────────────────────────────
@router.post("/exports/destinations", tags=["exports"], status_code=201)
async def create_export_destination(request: Request, body: ExportDestinationCreate, _role: Any = _WRITE_DEP) -> dict[str, Any]:
    """Create a connect-once export destination; the secret is encrypted at rest."""
    tenant_id = require_request_tenant_id(request)
    kind = body.kind.strip().lower()
    if not is_supported_kind(kind):
        raise HTTPException(
            status_code=400, detail=f"Unsupported destination kind '{body.kind}'. Use one of: {', '.join(SUPPORTED_EXPORT_KINDS)}."
        )
    if kind in {"snowflake", "databricks"} and (not body.secret or not body.secret.strip()):
        raise HTTPException(status_code=422, detail=f"{kind.title()} export destination requires a write-only secret")

    secret_encrypted = ""
    if body.secret:
        if not connections_key_configured():
            raise HTTPException(
                status_code=503,
                detail="Destination secret encryption is not configured (AGENT_BOM_CONNECTIONS_KEY unset); refusing to store a secret.",
            )
        try:
            secret_encrypted = encrypt_secret(body.secret.strip())
        except ConnectionSecretError as exc:
            raise HTTPException(status_code=503, detail=sanitize_error(exc, generic=True)) from exc

    now = _now()
    record = ExportDestinationRecord(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        kind=kind,
        display_name=body.display_name.strip(),
        config=dict(body.config),
        secret_encrypted=secret_encrypted,
        status=STATUS_PENDING,
        created_at=now,
        updated_at=now,
    )
    get_export_destination_store().put(record)
    log_action(
        "export_destination.create", actor=_actor(request), resource=f"export-destination/{record.id}", tenant_id=tenant_id, kind=kind
    )
    return record.to_public_dict()


@router.get("/exports/destinations", tags=["exports"])
async def list_export_destinations(request: Request, _role: Any = _READ_DEP) -> list[dict[str, Any]]:
    tenant_id = require_request_tenant_id(request)
    return [r.to_public_dict() for r in get_export_destination_store().list_for_tenant(tenant_id)]


@router.get("/exports/destinations/{destination_id}", tags=["exports"])
async def get_export_destination(request: Request, destination_id: str, _role: Any = _READ_DEP) -> dict[str, Any]:
    tenant_id = require_request_tenant_id(request)
    record = get_export_destination_store().get(tenant_id, destination_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Export destination {destination_id} not found")
    return record.to_public_dict()


@router.delete("/exports/destinations/{destination_id}", tags=["exports"], status_code=204)
async def delete_export_destination(request: Request, destination_id: str, _role: Any = _WRITE_DEP):
    tenant_id = require_request_tenant_id(request)
    if not get_export_destination_store().delete(tenant_id, destination_id):
        raise HTTPException(status_code=404, detail=f"Export destination {destination_id} not found")
    log_action("export_destination.delete", actor=_actor(request), resource=f"export-destination/{destination_id}", tenant_id=tenant_id)


@router.post("/exports/destinations/{destination_id}/run", tags=["exports"], status_code=202)
async def run_export_destination(request: Request, destination_id: str, _role: Any = _WRITE_DEP) -> dict[str, Any]:
    """Fire a one-off findings export to this destination now (off the event loop)."""
    tenant_id = require_request_tenant_id(request)
    record = get_export_destination_store().get(tenant_id, destination_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Export destination {destination_id} not found")

    from agent_bom.api.pipeline import get_executor

    run_id = uuid.uuid4().hex
    get_executor().submit(_run_export_sync, tenant_id, destination_id, run_id)
    log_action(
        "export_destination.run", actor=_actor(request), resource=f"export-destination/{destination_id}", tenant_id=tenant_id, run_id=run_id
    )
    return {"status": "accepted", "destination_id": destination_id, "run_id": run_id}


def _run_export_sync(tenant_id: str, destination_id: str, run_id: str) -> None:
    """Blocking one-off export executed on the shared worker pool."""
    from agent_bom.api.connection_crypto import decrypt_secret
    from agent_bom.export.runner import run_findings_export

    store = get_export_destination_store()
    record = store.get(tenant_id, destination_id)
    if record is None:
        return
    try:
        secret = decrypt_secret(record.secret_encrypted) if record.secret_encrypted else None
        run_findings_export(
            tenant_id=tenant_id,
            kind=record.kind,
            config=record.config,
            secret=secret,
            destination_id=destination_id,
            run_id=run_id,
            actor="api",
        )
    except ExportPublicationIndeterminateError:
        record.status = "indeterminate"
        record.last_run_status = "indeterminate"
        record.status_detail = "Publication status is indeterminate; verify the destination marker before retrying"
        logger.warning("One-off export publication is indeterminate for destination %s", destination_id)
    except Exception as exc:  # noqa: BLE001 - worker must persist destination failure state
        record.status = "error"
        record.last_run_status = "error"
        record.status_detail = sanitize_error(exc)
        logger.warning("One-off export failed for destination %s", destination_id)
    else:
        record.status = "active"
        record.last_run_status = "success"
        record.status_detail = ""
    record.last_run_at = datetime.now(timezone.utc).isoformat()
    store.put(record)


# ── Schedules ─────────────────────────────────────────────────────────────
@router.post("/exports/schedules", tags=["exports"], status_code=201)
async def create_export_schedule(request: Request, body: ExportScheduleCreate, _role: Any = _WRITE_DEP) -> dict[str, Any]:
    from agent_bom.api.scheduler import parse_cron_next, validate_cron_expression

    tenant_id = require_request_tenant_id(request)
    if not validate_cron_expression(body.cron_expression):
        raise HTTPException(status_code=422, detail="Invalid cron expression")
    if get_export_destination_store().get(tenant_id, body.destination_id) is None:
        raise HTTPException(status_code=400, detail=f"Export destination {body.destination_id} not found")

    now = datetime.now(timezone.utc)
    next_run = parse_cron_next(body.cron_expression, now)
    schedule = ExportSchedule(
        schedule_id=str(uuid.uuid4()),
        name=body.name.strip(),
        cron_expression=body.cron_expression,
        destination_id=body.destination_id,
        tenant_id=tenant_id,
        enabled=body.enabled,
        sort=body.sort,
        severity=body.severity,
        since_days=body.since_days,
        next_run=next_run.isoformat() if next_run else None,
        created_at=now.isoformat(),
        updated_at=now.isoformat(),
    )
    get_export_schedule_store().put(schedule)
    log_action(
        "export_schedule.create",
        actor=_actor(request),
        resource=f"export-schedule/{schedule.schedule_id}",
        tenant_id=tenant_id,
        cron_expression=body.cron_expression,
    )
    return schedule.model_dump()


@router.get("/exports/schedules", tags=["exports"])
async def list_export_schedules(request: Request, _role: Any = _READ_DEP) -> list[dict[str, Any]]:
    tenant_id = require_request_tenant_id(request)
    return [s.model_dump() for s in get_export_schedule_store().list_all(tenant_id=tenant_id)]


@router.delete("/exports/schedules/{schedule_id}", tags=["exports"], status_code=204)
async def delete_export_schedule(request: Request, schedule_id: str, _role: Any = _WRITE_DEP):
    tenant_id = require_request_tenant_id(request)
    if not get_export_schedule_store().delete(schedule_id, tenant_id=tenant_id):
        raise HTTPException(status_code=404, detail=f"Export schedule {schedule_id} not found")
    log_action("export_schedule.delete", actor=_actor(request), resource=f"export-schedule/{schedule_id}", tenant_id=tenant_id)


@router.put("/exports/schedules/{schedule_id}/toggle", tags=["exports"])
async def toggle_export_schedule(request: Request, schedule_id: str, _role: Any = _WRITE_DEP) -> dict[str, Any]:
    tenant_id = require_request_tenant_id(request)
    store = get_export_schedule_store()
    schedule = store.get(schedule_id, tenant_id=tenant_id)
    if schedule is None:
        raise HTTPException(status_code=404, detail=f"Export schedule {schedule_id} not found")
    schedule.enabled = not schedule.enabled
    schedule.updated_at = _now()
    store.put(schedule)
    log_action(
        "export_schedule.toggle",
        actor=_actor(request),
        resource=f"export-schedule/{schedule_id}",
        tenant_id=tenant_id,
        enabled=schedule.enabled,
    )
    return schedule.model_dump()
