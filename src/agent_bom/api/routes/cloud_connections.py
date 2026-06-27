"""Per-tenant cloud connections plane — CRUD over read-only cloud connections.

A *connection* is a stored, encrypted, tenant-scoped record of how the control
plane reaches a customer's cloud account in read-only mode: the role it assumes
plus the encrypted ``ExternalId`` (or provider equivalent) the credential broker
presents. These endpoints manage that record; the secret is encrypted at rest
and is **never** returned in any response.

Every endpoint enforces the same gate the sibling cloud routes use:
``require_request_tenant_id`` plus the ``scan`` permission ({admin, analyst})
via the shared RBAC dependency, so there is no unauthenticated access and an
under-privileged role is rejected with 403. Reads and deletes are tenant-scoped:
a tenant can only see or remove its own connections.

Endpoints:
    POST   /v1/cloud/connections          create a connection (encrypts the secret)
    GET    /v1/cloud/connections          list this tenant's connections
    GET    /v1/cloud/connections/{id}     one connection (non-secret metadata)
    DELETE /v1/cloud/connections/{id}     remove a connection
    POST   /v1/cloud/connections/{id}/scan  launch a read-only scan via the broker

The ``/scan`` endpoint (Phase B) brokers the stored connection into a short-lived
read-only cloud session (``sts:AssumeRole`` with the decrypted ExternalId) and
runs the **same** inventory + CIS discovery the sibling ``cloud`` routes use,
against that session. Results persist through the existing scan/graph stores —
no parallel persistence path — and the connection's lifecycle status is updated
(``active`` + ``last_scan_at`` on success, ``error`` + ``status_detail`` on
failure, never carrying a secret). AWS is broker-enabled today; azure / gcp /
snowflake return a clear "planned" 501. A connection may also carry a
``scan_interval_minutes`` so the Phase B.2 background scheduler
(:mod:`agent_bom.api.connection_scheduler`) re-runs this same scan path when due.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from agent_bom.api.audit_log import log_action
from agent_bom.api.connection_crypto import ConnectionSecretError, connections_key_configured, encrypt_secret
from agent_bom.api.connection_store import (
    STATUS_ACTIVE,
    STATUS_ERROR,
    STATUS_PENDING,
    SUPPORTED_PROVIDERS,
    CloudConnectionRecord,
    get_connection_store,
)
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.config import CONNECTIONS_SCHEDULER_MIN_INTERVAL_MINUTES
from agent_bom.rbac import require_authenticated_permission
from agent_bom.security import sanitize_error

# Providers whose credential broker is not yet implemented (Phase B is AWS-only).
_PLANNED_SCAN_PROVIDERS: tuple[str, ...] = ("azure", "gcp", "snowflake")
# Cap the status_detail we persist so a verbose backend error can't bloat the row.
_MAX_STATUS_DETAIL = 300
# Upper bound on a recurring scan interval (1 week) so a typo can't park a
# connection effectively-never-scanning while still claiming to be scheduled.
_MAX_SCAN_INTERVAL_MINUTES = 7 * 24 * 60

router = APIRouter(tags=["cloud-connections"])
_logger = logging.getLogger(__name__)

# Same RBAC gate the sibling cloud scan routes use — a scan-class action.
_SCAN_DEP = require_authenticated_permission("scan")

_REGION_RE = re.compile(r"[a-z]{2}(-gov)?-[a-z]+-\d{1,2}")
_MAX_REGIONS = 50


class CloudConnectionCreate(BaseModel):
    """Request body for creating a connection. ``external_id`` is write-only.

    ``scan_interval_minutes`` opts the connection into recurring background scans
    (Phase B.2). Null (the default) means manual-only — the scheduler ignores it.
    """

    model_config = ConfigDict(extra="forbid")

    provider: str
    display_name: str = Field(min_length=1, max_length=200)
    role_ref: str = Field(min_length=1, max_length=2048)
    external_id: str = Field(min_length=1, max_length=1024)
    regions: list[str] = Field(default_factory=list)
    scan_interval_minutes: int | None = None


class CloudConnectionUpdate(BaseModel):
    """Request body for updating a connection's recurring scan schedule.

    ``scan_interval_minutes`` is set to the supplied value; null disables the
    recurring scan (back to manual-only).
    """

    model_config = ConfigDict(extra="forbid")

    scan_interval_minutes: int | None = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tenant(request: Request) -> str:
    return require_request_tenant_id(request)


def _actor(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "system"


def _validate_scan_interval(interval: int | None) -> int | None:
    """Validate a recurring scan interval (minutes).

    Null is allowed (manual-only). A set value must be at least the configured
    minimum so the scheduler never hammers a customer account, and at most one
    week so a typo cannot silently park a connection.
    """
    if interval is None:
        return None
    if interval < CONNECTIONS_SCHEDULER_MIN_INTERVAL_MINUTES:
        raise HTTPException(
            status_code=400,
            detail=f"scan_interval_minutes must be at least {CONNECTIONS_SCHEDULER_MIN_INTERVAL_MINUTES} minutes.",
        )
    if interval > _MAX_SCAN_INTERVAL_MINUTES:
        raise HTTPException(
            status_code=400,
            detail=f"scan_interval_minutes must be at most {_MAX_SCAN_INTERVAL_MINUTES} minutes.",
        )
    return interval


def _validate_regions(regions: list[str]) -> list[str]:
    cleaned = [r.strip() for r in regions if r.strip()]
    if len(cleaned) > _MAX_REGIONS:
        raise HTTPException(status_code=400, detail=f"Too many regions (max {_MAX_REGIONS}).")
    for region in cleaned:
        if not _REGION_RE.fullmatch(region):
            raise HTTPException(status_code=400, detail=f"Invalid region format: {region}")
    return cleaned


@router.post("/v1/cloud/connections", status_code=201)
async def create_connection(request: Request, body: CloudConnectionCreate, _role: Any = _SCAN_DEP) -> dict[str, Any]:
    """Create a read-only cloud connection for the authenticated tenant.

    The ``external_id`` secret is encrypted at rest before persistence and is
    never echoed back. If no encryption key is configured the request fails
    closed with 503 rather than storing the secret in plaintext.
    """
    tenant_id = _tenant(request)
    provider = body.provider.strip().lower()
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported provider '{body.provider}'. Use one of: {', '.join(SUPPORTED_PROVIDERS)}.",
        )

    regions = _validate_regions(body.regions)
    scan_interval_minutes = _validate_scan_interval(body.scan_interval_minutes)

    # Fail closed before doing anything if the store cannot encrypt the secret.
    if not connections_key_configured():
        raise HTTPException(
            status_code=503,
            detail="Connection secret encryption is not configured (AGENT_BOM_CONNECTIONS_KEY unset); refusing to store a secret.",
        )
    try:
        external_id_encrypted = encrypt_secret(body.external_id.strip())
    except ConnectionSecretError as exc:
        # Never echo the secret or key detail — only the failure mode.
        _logger.warning("Connection secret encryption unavailable")
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    now = _now()
    record = CloudConnectionRecord(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        provider=provider,
        display_name=body.display_name.strip(),
        role_ref=body.role_ref.strip(),
        external_id_encrypted=external_id_encrypted,
        regions=regions,
        status=STATUS_PENDING,
        status_detail="",
        created_at=now,
        updated_at=now,
        last_scan_at=None,
        scan_interval_minutes=scan_interval_minutes,
    )
    get_connection_store().put(record)
    log_action(
        "cloud_connection.create",
        actor=_actor(request),
        resource=f"cloud-connection/{record.id}",
        tenant_id=tenant_id,
        provider=record.provider,
    )
    return record.to_public_dict()


@router.get("/v1/cloud/connections")
async def list_connections(request: Request, _role: Any = _SCAN_DEP) -> dict[str, Any]:
    """List the authenticated tenant's connections (non-secret metadata only)."""
    tenant_id = _tenant(request)
    records = get_connection_store().list_for_tenant(tenant_id)
    return {
        "schema_version": "cloud.connections.v1",
        "tenant_id": tenant_id,
        "connections": [r.to_public_dict() for r in records],
        "count": len(records),
    }


def _require_connection(request: Request, connection_id: str) -> CloudConnectionRecord:
    tenant_id = _tenant(request)
    record = get_connection_store().get(tenant_id, connection_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Connection {connection_id} not found")
    return record


@router.get("/v1/cloud/connections/{connection_id}")
async def get_connection(request: Request, connection_id: str, _role: Any = _SCAN_DEP) -> dict[str, Any]:
    """Return one connection's non-secret metadata (tenant-scoped)."""
    return _require_connection(request, connection_id).to_public_dict()


@router.patch("/v1/cloud/connections/{connection_id}")
async def update_connection(
    request: Request,
    connection_id: str,
    body: CloudConnectionUpdate,
    _role: Any = _SCAN_DEP,
) -> dict[str, Any]:
    """Update a connection's recurring scan schedule (tenant-scoped).

    Sets ``scan_interval_minutes`` (null disables recurring scans). The encrypted
    secret is untouched and never returned.
    """
    record = _require_connection(request, connection_id)
    scan_interval_minutes = _validate_scan_interval(body.scan_interval_minutes)
    record.scan_interval_minutes = scan_interval_minutes
    record.updated_at = _now()
    get_connection_store().put(record)
    log_action(
        "cloud_connection.update",
        actor=_actor(request),
        resource=f"cloud-connection/{record.id}",
        tenant_id=record.tenant_id,
        provider=record.provider,
    )
    return record.to_public_dict()


@router.delete("/v1/cloud/connections/{connection_id}", status_code=204)
async def delete_connection(request: Request, connection_id: str, _role: Any = _SCAN_DEP) -> None:
    """Delete a connection owned by the authenticated tenant."""
    record = _require_connection(request, connection_id)
    get_connection_store().delete(record.tenant_id, record.id)
    log_action(
        "cloud_connection.delete",
        actor=_actor(request),
        resource=f"cloud-connection/{record.id}",
        tenant_id=record.tenant_id,
        provider=record.provider,
    )


def _mark_connection(
    record: CloudConnectionRecord,
    *,
    status: str,
    status_detail: str = "",
    last_scan_at: str | None = None,
) -> None:
    """Persist a connection lifecycle transition via the Phase A store's upsert.

    Reuses ``put`` (the store's update path) rather than a parallel mutator. The
    record was already fetched tenant-scoped, so this stays within the tenant.
    ``status_detail`` is capped and never carries a secret (the broker's error
    text is secret-free and is additionally sanitized by the caller).
    """
    record.status = status
    record.status_detail = status_detail[:_MAX_STATUS_DETAIL]
    record.updated_at = _now()
    if last_scan_at is not None:
        record.last_scan_at = last_scan_at
    get_connection_store().put(record)


def _run_aws_connection_scan(record: CloudConnectionRecord, tenant_id: str) -> dict[str, Any]:
    """Broker the connection into a read-only session and run inventory + CIS.

    Calls the **same** ``aws_inventory.discover_inventory`` and AWS CIS
    ``run_benchmark`` the sibling cloud routes use — passing the brokered session
    so the read-only code path runs against the assumed role — then persists the
    result through the existing scan/graph stores (the pipeline's persistence
    path), not a parallel one. Returns a non-secret scan summary.
    """
    import uuid as _uuid

    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.pipeline import _persist_graph_snapshot
    from agent_bom.api.stores import _get_store, _jobs_put
    from agent_bom.cloud import aws_inventory
    from agent_bom.cloud.aws_cis_benchmark import run_benchmark as run_aws_cis
    from agent_bom.cloud.connection_broker import broker_session
    from agent_bom.mcp_tools.posture import _summarize_inventory_payload
    from agent_bom.models import AIBOMReport
    from agent_bom.output import to_json

    region = record.regions[0] if record.regions else None
    session = broker_session(record, session_name=f"agent-bom-scan-{record.id[:8]}")

    # Same read-only discovery the cloud routes run, against the brokered role.
    inventory_payload = aws_inventory.discover_inventory(region=region, force=True, session=session)
    cis_report = run_aws_cis(region=region, session=session)
    cis_dict = cis_report.to_dict()

    scan_id = str(_uuid.uuid4())
    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id=scan_id)
    report.cloud_inventory_data = inventory_payload
    report.cis_benchmark_data = cis_dict
    report_json = to_json(report)

    now = _now()
    job = ScanJob(
        job_id=scan_id,
        tenant_id=tenant_id,
        created_at=now,
        started_at=now,
        completed_at=now,
        status=JobStatus.DONE,
        request=ScanRequest(),
        result=report_json,
        triggered_by=f"cloud-connection/{record.id}",
    )
    # Existing persistence path: durable scan store + in-memory job map + unified
    # graph snapshot (same calls the scan pipeline makes on completion).
    store = _get_store()
    store.put(job)
    _jobs_put(job.job_id, job, compact_terminal=True)
    _persist_graph_snapshot(job, report_json)

    inv_summary = _summarize_inventory_payload("aws", inventory_payload)
    return {
        "schema_version": "cloud.connections.scan.v1",
        "connection_id": record.id,
        "tenant_id": tenant_id,
        "provider": "aws",
        "scan_id": scan_id,
        "inventory": inv_summary,
        "cis_benchmark": {
            "benchmark": cis_dict.get("benchmark"),
            "benchmark_version": cis_dict.get("benchmark_version"),
            "passed": cis_dict.get("passed"),
            "failed": cis_dict.get("failed"),
            "total": cis_dict.get("total"),
            "pass_rate": cis_dict.get("pass_rate"),
        },
        "audit_metadata": {
            "read_only": True,
            "writes_performed": False,
            "note": (
                "Scan ran against a short-lived read-only role assumed from the stored connection. "
                "Inventory + CIS are read-only; no resource is mutated and no secret value is returned."
            ),
        },
    }


@router.post("/v1/cloud/connections/{connection_id}/scan")
async def scan_connection(request: Request, connection_id: str, _role: Any = _SCAN_DEP) -> dict[str, Any]:
    """Launch a read-only cloud scan for a stored connection via the broker.

    Resolves the tenant's connection (404 otherwise), uses the credential broker
    to assume a short-lived read-only session, and runs the same inventory + CIS
    discovery the sibling cloud routes use. Results persist through the existing
    scan/graph stores; the connection status moves to ``active`` + ``last_scan_at``
    on success or ``error`` + ``status_detail`` (no secret) on failure. AWS only
    today — azure / gcp / snowflake return a clear 501 ``planned`` response.
    """
    record = _require_connection(request, connection_id)
    tenant_id = record.tenant_id
    actor = _actor(request)

    if record.provider in _PLANNED_SCAN_PROVIDERS:
        # Recognized provider whose broker is not yet implemented — clear, not a crash.
        raise HTTPException(
            status_code=501,
            detail=(
                f"Cloud scan for provider '{record.provider}' is planned but not yet available (Phase B+). "
                "AWS read-only AssumeRole scanning is supported today."
            ),
        )
    if record.provider != "aws":
        raise HTTPException(status_code=400, detail=f"Unsupported provider '{record.provider}'.")

    try:
        summary = _run_aws_connection_scan(record, tenant_id)
    except Exception as exc:  # noqa: BLE001 - broker / discovery / persistence failure
        # Persist an error status with a sanitized, secret-free detail. Full
        # diagnostics go to the server log only; the client gets a generic message.
        detail = sanitize_error(exc)
        _mark_connection(record, status=STATUS_ERROR, status_detail=detail)
        _logger.exception("Cloud connection scan failed for connection %s", record.id)
        log_action(
            "cloud_connection.scan",
            actor=actor,
            resource=f"cloud-connection/{record.id}",
            tenant_id=tenant_id,
            provider=record.provider,
            outcome="failure",
        )
        raise HTTPException(status_code=502, detail="Cloud connection scan failed; see server logs.") from exc

    _mark_connection(record, status=STATUS_ACTIVE, status_detail="", last_scan_at=_now())
    log_action(
        "cloud_connection.scan",
        actor=actor,
        resource=f"cloud-connection/{record.id}",
        tenant_id=tenant_id,
        provider=record.provider,
        outcome="success",
        scan_id=summary["scan_id"],
    )
    summary["connection"] = record.to_public_dict()
    return summary
