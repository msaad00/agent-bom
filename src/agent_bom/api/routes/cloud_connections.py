"""Per-tenant cloud connections plane — CRUD over read-only cloud connections.

A *connection* is a stored, encrypted, tenant-scoped record of how the control
plane reaches a customer's cloud account in read-only mode: the role it assumes
plus the encrypted ``ExternalId`` (or provider equivalent) the credential broker
presents. These endpoints manage that record; the secret is encrypted at rest
and is **never** returned in any response.

Every endpoint enforces ``require_request_tenant_id`` plus RBAC via the shared
dependency. **Reads** (list/get) require the ``read`` permission (admin, analyst,
viewer). **Mutations** (create, update schedule, delete, test, scan) require
``scan`` (admin, analyst). Under-privileged roles are rejected with 403. Reads
and deletes are tenant-scoped: a tenant can only see or remove its own connections.

Endpoints:
    POST   /v1/cloud/connections          create a connection (encrypts the secret)
    GET    /v1/cloud/connections          list this tenant's connections
    GET    /v1/cloud/connections/{id}     one connection (non-secret metadata)
    DELETE /v1/cloud/connections/{id}     remove a connection
    POST   /v1/cloud/connections/{id}/test  validate brokered read-only auth
    POST   /v1/cloud/connections/{id}/scan  launch a read-only scan via the broker

The ``/scan`` endpoint brokers the stored connection into a short-lived read-only
cloud session / credential / connection (AWS ``sts:AssumeRole`` with the decrypted
ExternalId; Azure ``ClientSecretCredential``; GCP read-only service-account
credentials; Snowflake key-pair connection) and runs the **same** inventory + CIS
discovery the sibling ``cloud`` routes use, against that session. Results persist
through the existing scan/graph stores — no parallel persistence path — and the
connection's lifecycle status is updated (``active`` + ``last_scan_at`` on
success, ``error`` + ``status_detail`` on failure, never carrying a secret). All
four providers (AWS, Azure, GCP, Snowflake) are broker-enabled. A connection may
also carry a ``scan_interval_minutes`` so the background scheduler
(:mod:`agent_bom.api.connection_scheduler`) re-runs this same scan path when due.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Callable
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

# Cap the status_detail we persist so a verbose backend error can't bloat the row.
_MAX_STATUS_DETAIL = 300
# Bounds on the non-secret provider params blob so a caller can't bloat the row.
_MAX_AUTH_PARAMS = 20
_MAX_AUTH_PARAM_KEY_LEN = 64
_MAX_AUTH_PARAM_VALUE_LEN = 1024
# Upper bound on a recurring scan interval (1 week) so a typo can't park a
# connection effectively-never-scanning while still claiming to be scheduled.
_MAX_SCAN_INTERVAL_MINUTES = 7 * 24 * 60

router = APIRouter(tags=["cloud-connections"])
_logger = logging.getLogger(__name__)

# Read metadata (list/get) is viewer-safe; mutations stay scan-class.
_READ_DEP = require_authenticated_permission("read")
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
    external_id: str = Field(min_length=1, max_length=8192)
    regions: list[str] = Field(default_factory=list)
    scan_interval_minutes: int | None = None
    # Non-secret provider-specific params (Azure tenant/subscription, GCP
    # project, Snowflake user/role/warehouse). Never a secret — the one secret
    # is ``external_id``.
    auth_params: dict[str, str] = Field(default_factory=dict)


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


def _validate_auth_params(auth_params: dict[str, str]) -> dict[str, str]:
    """Validate the non-secret provider params blob (bounds + string coercion).

    Keeps the row small and predictable: caps the number of keys and the key /
    value lengths. Values are coerced to trimmed strings. These params are never
    secret (the one secret is ``external_id``), so they are stored and returned
    as-is.
    """
    if not auth_params:
        return {}
    if len(auth_params) > _MAX_AUTH_PARAMS:
        raise HTTPException(status_code=400, detail=f"Too many auth_params (max {_MAX_AUTH_PARAMS}).")
    cleaned: dict[str, str] = {}
    for key, value in auth_params.items():
        key_str = str(key).strip()
        if not key_str:
            continue
        if len(key_str) > _MAX_AUTH_PARAM_KEY_LEN:
            raise HTTPException(status_code=400, detail=f"auth_params key too long (max {_MAX_AUTH_PARAM_KEY_LEN}).")
        value_str = str(value).strip()
        if len(value_str) > _MAX_AUTH_PARAM_VALUE_LEN:
            raise HTTPException(status_code=400, detail=f"auth_params value too long (max {_MAX_AUTH_PARAM_VALUE_LEN}).")
        cleaned[key_str] = value_str
    return cleaned


def _validate_regions(regions: list[str]) -> list[str]:
    cleaned = [r.strip() for r in regions if r.strip()]
    if len(cleaned) > _MAX_REGIONS:
        raise HTTPException(status_code=400, detail=f"Too many regions (max {_MAX_REGIONS}).")
    for region in cleaned:
        if not _REGION_RE.fullmatch(region):
            raise HTTPException(status_code=400, detail=f"Invalid region format: {region}")
    return cleaned


@router.post("/cloud/connections", status_code=201)
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
    auth_params = _validate_auth_params(body.auth_params)

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
        raise HTTPException(status_code=503, detail=sanitize_error(exc, generic=True)) from exc

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
        auth_params=auth_params,
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


@router.get("/cloud/connections")
async def list_connections(request: Request, _role: Any = _READ_DEP) -> dict[str, Any]:
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


@router.get("/cloud/connections/{connection_id}")
async def get_connection(request: Request, connection_id: str, _role: Any = _READ_DEP) -> dict[str, Any]:
    """Return one connection's non-secret metadata (tenant-scoped)."""
    return _require_connection(request, connection_id).to_public_dict()


@router.patch("/cloud/connections/{connection_id}")
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


@router.delete("/cloud/connections/{connection_id}", status_code=204)
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
    last_scan_id: str | None = None,
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
    if last_scan_id is not None:
        record.last_scan_id = last_scan_id
    get_connection_store().put(record)


def _cis_summary(cis_dict: dict[str, Any]) -> dict[str, Any]:
    """Reduce a CIS report dict to the non-secret counts surfaced in the summary."""
    return {
        "benchmark": cis_dict.get("benchmark"),
        "benchmark_version": cis_dict.get("benchmark_version"),
        "passed": cis_dict.get("passed"),
        "failed": cis_dict.get("failed"),
        "total": cis_dict.get("total"),
        "pass_rate": cis_dict.get("pass_rate"),
    }


def _annotate_inventory_counts(inventory: Any) -> None:
    """Add UI-facing count fields to a persisted raw inventory payload in place.

    The persisted ``cloud_inventory`` keeps the raw provider resource lists the
    graph builder ingests, but those carry no top-level counts. The Scan-jobs
    pipeline panel and scan-result view read ``resource_count`` / ``identity_count``
    (with a ``node_summary`` fallback), so without these a completed cloud-connection
    scan surfaced empty resource/identity stats. Enrich the payload (non-destructive
    — raw lists are preserved) with the same counts ``_summarize_inventory_payload``
    computes so those stats populate honestly.
    """
    if not isinstance(inventory, dict):
        return
    if "resource_count" in inventory and "identity_count" in inventory:
        return
    from agent_bom.mcp_tools.posture import _summarize_inventory_payload

    summary = _summarize_inventory_payload(str(inventory.get("provider") or ""), inventory)
    inventory.setdefault("resource_count", summary["resource_count"])
    inventory.setdefault("identity_count", summary["identity_count"])
    inventory.setdefault("node_summary", summary["node_summary"])


def _persist_connection_report(record: CloudConnectionRecord, tenant_id: str, report: Any) -> str:
    """Persist a brokered-scan report through the existing scan/graph stores.

    Reuses the pipeline's persistence path (durable scan store + in-memory job
    map + unified graph snapshot) rather than a parallel one — the same calls the
    scan pipeline makes on completion. Returns the scan id.
    """
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.pipeline import _persist_graph_snapshot
    from agent_bom.api.stores import _get_store, _jobs_put
    from agent_bom.output import to_json

    report_json = to_json(report)
    _annotate_inventory_counts(report_json.get("cloud_inventory"))
    now = _now()
    job = ScanJob(
        job_id=report.scan_id,
        tenant_id=tenant_id,
        created_at=now,
        started_at=now,
        completed_at=now,
        status=JobStatus.DONE,
        request=ScanRequest(),
        result=report_json,
        triggered_by=f"cloud-connection/{record.id}",
    )
    store = _get_store()
    store.put(job)
    _jobs_put(job.job_id, job, compact_terminal=True)
    _persist_graph_snapshot(job, report_json)
    return str(report.scan_id)


def _mark_connection_report_sources(report: Any, provider: str) -> None:
    """Stamp connection-originated scans so downstream UI/compliance do not look local."""
    report.scan_sources = ["cloud_connection", f"cloud:{provider}"]


def _scan_audit_metadata(note: str) -> dict[str, Any]:
    """Read-only audit envelope attached to every connection-scan summary."""
    return {"read_only": True, "writes_performed": False, "note": note}


def _test_connection_broker(record: CloudConnectionRecord) -> None:
    """Validate that the broker can materialize read-only credentials.

    This deliberately does not run inventory, CIS, or persistence. It only proves
    that the encrypted connection secret can be decrypted and exchanged for the
    provider credential/session the scan path will later use.
    """

    from agent_bom.cloud.connection_broker import broker_session

    brokered = broker_session(record, session_name=f"agent-bom-test-{record.id[:8]}")
    if (record.provider or "").strip().lower() == "snowflake":
        try:
            brokered.close()
        except Exception:  # noqa: BLE001 - close best-effort; never mask broker success
            _logger.debug("Snowflake broker connection close failed for test connection %s", record.id)


def _reject_showcase_connection(record: CloudConnectionRecord) -> None:
    """Keep synthetic demo rows from entering a real credential or scan path."""
    if record.auth_params.get("demo") is True:
        raise HTTPException(
            status_code=409,
            detail="Showcase connections are synthetic and cannot run connection tests or scans.",
        )


def _run_aws_connection_scan(record: CloudConnectionRecord, tenant_id: str) -> dict[str, Any]:
    """Broker the connection into a read-only session and run inventory + CIS.

    Calls the **same** ``aws_inventory.discover_inventory`` and AWS CIS
    ``run_benchmark`` the sibling cloud routes use — passing the brokered session
    so the read-only code path runs against the assumed role — then persists the
    result through the existing scan/graph stores (the pipeline's persistence
    path), not a parallel one. Returns a non-secret scan summary.
    """
    import uuid as _uuid

    from agent_bom.cloud import aws_inventory
    from agent_bom.cloud.aws_cis_benchmark import run_benchmark as run_aws_cis
    from agent_bom.cloud.connection_broker import broker_session
    from agent_bom.mcp_tools.posture import _summarize_inventory_payload
    from agent_bom.models import AIBOMReport

    region = record.regions[0] if record.regions else None
    session = broker_session(record, session_name=f"agent-bom-scan-{record.id[:8]}")

    # Same read-only discovery the cloud routes run, against the brokered role.
    inventory_payload = aws_inventory.discover_inventory(region=region, force=True, session=session)
    cis_report = run_aws_cis(region=region, session=session)
    cis_dict = cis_report.to_dict()

    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id=str(_uuid.uuid4()))
    _mark_connection_report_sources(report, "aws")
    report.cloud_inventory_data = inventory_payload
    report.cis_benchmark_data = cis_dict
    scan_id = _persist_connection_report(record, tenant_id, report)

    return {
        "schema_version": "cloud.connections.scan.v1",
        "connection_id": record.id,
        "tenant_id": tenant_id,
        "provider": "aws",
        "scan_id": scan_id,
        "inventory": _summarize_inventory_payload("aws", inventory_payload),
        "cis_benchmark": _cis_summary(cis_dict),
        "audit_metadata": _scan_audit_metadata(
            "Scan ran against a short-lived read-only role assumed from the stored connection. "
            "Inventory + CIS are read-only; no resource is mutated and no secret value is returned."
        ),
    }


def _run_azure_connection_scan(record: CloudConnectionRecord, tenant_id: str) -> dict[str, Any]:
    """Broker an Azure read-only credential and run inventory + CIS.

    Uses the brokered ``ClientSecretCredential`` (Reader role) and the
    ``subscription_id`` from the connection's ``auth_params`` so the same
    ``azure_inventory.discover_inventory`` and Azure CIS ``run_benchmark`` the
    sibling cloud routes use run against the customer subscription. Read-only.
    """
    import uuid as _uuid

    from agent_bom.cloud import azure_inventory
    from agent_bom.cloud.azure_cis_benchmark import run_benchmark as run_azure_cis
    from agent_bom.cloud.connection_broker import broker_session
    from agent_bom.mcp_tools.posture import _summarize_inventory_payload
    from agent_bom.models import AIBOMReport

    credential = broker_session(record, session_name=f"agent-bom-scan-{record.id[:8]}")
    subscription_id = str(record.auth_params.get("subscription_id") or "").strip() or None

    inventory_payload = azure_inventory.discover_inventory(subscription_id=subscription_id, credential=credential, force=True)
    cis_report = run_azure_cis(subscription_id=subscription_id, credential=credential)
    cis_dict = cis_report.to_dict()

    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id=str(_uuid.uuid4()))
    _mark_connection_report_sources(report, "azure")
    report.cloud_inventory_data = inventory_payload
    report.azure_cis_benchmark_data = cis_dict
    scan_id = _persist_connection_report(record, tenant_id, report)

    return {
        "schema_version": "cloud.connections.scan.v1",
        "connection_id": record.id,
        "tenant_id": tenant_id,
        "provider": "azure",
        "scan_id": scan_id,
        "inventory": _summarize_inventory_payload("azure", inventory_payload),
        "cis_benchmark": _cis_summary(cis_dict),
        "audit_metadata": _scan_audit_metadata(
            "Scan ran against a read-only Azure Reader credential brokered from the stored connection. "
            "Inventory + CIS are read-only; no resource is mutated and no secret value is returned."
        ),
    }


def _run_gcp_connection_scan(record: CloudConnectionRecord, tenant_id: str) -> dict[str, Any]:
    """Broker GCP read-only service-account credentials and run inventory + CIS.

    Uses the brokered ``service_account.Credentials`` (cloud-platform.read-only
    scope) and the ``project_id`` from the connection's ``auth_params`` so the
    same ``gcp_inventory.discover_inventory`` and GCP CIS ``run_benchmark`` the
    sibling cloud routes use run against the customer project. Read-only.
    """
    import uuid as _uuid

    from agent_bom.cloud import gcp_inventory
    from agent_bom.cloud.connection_broker import broker_session
    from agent_bom.cloud.gcp_cis_benchmark import run_benchmark as run_gcp_cis
    from agent_bom.mcp_tools.posture import _summarize_inventory_payload
    from agent_bom.models import AIBOMReport

    credentials = broker_session(record, session_name=f"agent-bom-scan-{record.id[:8]}")
    project_id = str(record.auth_params.get("project_id") or "").strip() or None

    inventory_payload = gcp_inventory.discover_inventory(project_id=project_id, credentials=credentials, force=True)
    cis_report = run_gcp_cis(project_id=project_id, credentials=credentials)
    cis_dict = cis_report.to_dict()

    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id=str(_uuid.uuid4()))
    _mark_connection_report_sources(report, "gcp")
    report.cloud_inventory_data = inventory_payload
    report.gcp_cis_benchmark_data = cis_dict
    scan_id = _persist_connection_report(record, tenant_id, report)

    return {
        "schema_version": "cloud.connections.scan.v1",
        "connection_id": record.id,
        "tenant_id": tenant_id,
        "provider": "gcp",
        "scan_id": scan_id,
        "inventory": _summarize_inventory_payload("gcp", inventory_payload),
        "cis_benchmark": _cis_summary(cis_dict),
        "audit_metadata": _scan_audit_metadata(
            "Scan ran against read-only GCP service-account credentials (cloud-platform.read-only) brokered from the "
            "stored connection. Inventory + CIS are read-only; no resource is mutated and no secret value is returned."
        ),
    }


def _snowflake_estate_summary(report: Any, agent_count: int) -> dict[str, Any]:
    """Non-secret count roll-up of the swept Snowflake estate for the scan envelope.

    Mirrors the AWS/Azure/GCP ``_summarize_inventory_payload`` shape: object
    metadata counts only (warehouses, databases, schemas, roles, users,
    accounts) — never object contents or secrets.
    """
    services = getattr(report, "snowflake_services_data", None) or {}
    object_graph = getattr(report, "snowflake_object_graph_data", None) or {}
    organization = services.get("organization") or {}

    # Roles / users land as graph nodes from the roles/users lists AND from the
    # grants + role_memberships that reference them, so count the distinct union
    # the same way the graph builder materializes the nodes.
    def _name(item: Any) -> str:
        return str(item.get("name") if isinstance(item, dict) else item or "").strip()

    roles: set[str] = {_name(r) for r in (object_graph.get("roles") or [])}
    users: set[str] = {_name(u) for u in (object_graph.get("users") or [])}
    for grant in object_graph.get("grants") or []:
        if isinstance(grant, dict) and grant.get("role"):
            roles.add(str(grant["role"]).strip())
    for membership in object_graph.get("role_memberships") or []:
        if not isinstance(membership, dict):
            continue
        if membership.get("role"):
            roles.add(str(membership["role"]).strip())
        if membership.get("user"):
            users.add(str(membership["user"]).strip())
    roles.discard("")
    users.discard("")

    return {
        "provider": "snowflake",
        "status": "ok",
        "agent_count": agent_count,
        "warehouse_count": len(services.get("warehouses") or []),
        "database_count": len(services.get("databases") or []),
        "schema_count": len(services.get("schemas") or []),
        "role_count": len(roles),
        "user_count": len(users),
        "account_count": len(organization.get("accounts") or []),
    }


def _run_snowflake_connection_scan(record: CloudConnectionRecord, tenant_id: str) -> dict[str, Any]:
    """Broker a Snowflake read-only connection and run discovery + estate sweep + CIS.

    Opens one brokered key-pair connection and threads it into ``snowflake.discover``
    (agents), ``enrich_report_with_snowflake_estate`` (accounts / warehouses /
    databases / roles / users → typed graph nodes, parity with the AWS/Azure/GCP
    connection scans), and Snowflake CIS ``run_benchmark`` so a single read-only
    session backs the whole scan; the broker's connection is closed here once all
    have run. The estate sweep is best-effort: a failure still returns agent
    discovery + CIS. Read-only.
    """
    import uuid as _uuid

    from agent_bom.cloud import snowflake as snowflake_discovery
    from agent_bom.cloud.connection_broker import broker_session
    from agent_bom.cloud.snowflake_cis_benchmark import run_benchmark as run_snowflake_cis
    from agent_bom.models import AIBOMReport

    # The account rides on the stored connection (role_ref = "account" or
    # "account/user"), not process env — pass it so the estate discoveries, which
    # gate on a resolvable account, run against this connection's account.
    account = (record.role_ref or "").partition("/")[0].strip() or None

    conn = broker_session(record, session_name=f"agent-bom-scan-{record.id[:8]}")
    try:
        agents, _warnings = snowflake_discovery.discover(conn=conn)
        cis_report = run_snowflake_cis(conn=conn)
        report = AIBOMReport(agents=agents, blast_radii=[], findings=[], scan_id=str(_uuid.uuid4()))
        _mark_connection_report_sources(report, "snowflake")
        # Sweep the estate into the report's snowflake_*_data blocks so the graph
        # builder materializes accounts/warehouses/databases/roles/users the same
        # way AWS/Azure/GCP inventory is materialized. Best-effort — never fails
        # the scan; a raise here leaves agent discovery + CIS intact.
        try:
            snowflake_discovery.enrich_report_with_snowflake_estate(report, conn=conn, account=account)
        except Exception:  # noqa: BLE001 - estate sweep is best-effort; never mask the scan result
            _logger.warning(
                "Snowflake estate sweep failed for connection %s; returning agent discovery + CIS only",
                record.id,
                exc_info=True,
            )
    finally:
        # The broker connection is this function's to close (discover / CIS /
        # estate discoveries do not close an injected connection).
        try:
            conn.close()
        except Exception:  # noqa: BLE001 - close best-effort; never mask the scan result
            _logger.debug("Snowflake broker connection close failed for connection %s", record.id)
    cis_dict = cis_report.to_dict()

    inventory_summary = _snowflake_estate_summary(report, len(agents))
    report.cloud_inventory_data = inventory_summary
    report.snowflake_cis_benchmark_data = cis_dict
    scan_id = _persist_connection_report(record, tenant_id, report)

    return {
        "schema_version": "cloud.connections.scan.v1",
        "connection_id": record.id,
        "tenant_id": tenant_id,
        "provider": "snowflake",
        "scan_id": scan_id,
        "inventory": inventory_summary,
        "cis_benchmark": _cis_summary(cis_dict),
        "audit_metadata": _scan_audit_metadata(
            "Scan ran against a read-only Snowflake key-pair connection brokered from the stored connection. "
            "Discovery, estate sweep, and CIS are read-only; no object is mutated and no secret value is returned."
        ),
    }


# Per-provider brokered-scan dispatch. Every entry is broker-enabled and runs the
# same read-only inventory/discovery + CIS the sibling cloud routes use.
_SCAN_RUNNERS: dict[str, Callable[[CloudConnectionRecord, str], dict[str, Any]]] = {
    "aws": _run_aws_connection_scan,
    "azure": _run_azure_connection_scan,
    "gcp": _run_gcp_connection_scan,
    "snowflake": _run_snowflake_connection_scan,
}


def _run_connection_scan(record: CloudConnectionRecord, tenant_id: str) -> dict[str, Any]:
    """Dispatch a brokered read-only scan by provider.

    Raises ``ValueError`` for an unknown provider (the route validates the
    provider on create, so this is a defensive guard).
    """
    runner = _SCAN_RUNNERS.get((record.provider or "").strip().lower())
    if runner is None:
        raise ValueError(f"Unsupported provider '{record.provider}'.")
    return runner(record, tenant_id)


@router.post("/cloud/connections/{connection_id}/test")
async def test_connection(request: Request, connection_id: str, _role: Any = _SCAN_DEP) -> dict[str, Any]:
    """Validate a stored connection's brokered read-only credential.

    This is the pre-scan button for hosted POCs and self-hosted onboarding. It is
    tenant-scoped, uses the same RBAC gate as scans, and never runs inventory/CIS
    or writes findings. On success the connection becomes ``active``; on failure
    it becomes ``error`` with sanitized status detail.
    """

    record = _require_connection(request, connection_id)
    _reject_showcase_connection(record)
    tenant_id = record.tenant_id
    actor = _actor(request)

    if (record.provider or "").strip().lower() not in _SCAN_RUNNERS:
        raise HTTPException(status_code=400, detail=f"Unsupported provider '{record.provider}'.")

    try:
        _test_connection_broker(record)
    except Exception as exc:  # noqa: BLE001 - broker failure
        detail = sanitize_error(exc, generic=True)
        _mark_connection(record, status=STATUS_ERROR, status_detail=detail)
        _logger.exception("Cloud connection test failed for connection %s", record.id)
        log_action(
            "cloud_connection.test",
            actor=actor,
            resource=f"cloud-connection/{record.id}",
            tenant_id=tenant_id,
            provider=record.provider,
            outcome="failure",
        )
        raise HTTPException(status_code=502, detail="Cloud connection test failed; see server logs.") from exc

    _mark_connection(record, status=STATUS_ACTIVE, status_detail="")
    log_action(
        "cloud_connection.test",
        actor=actor,
        resource=f"cloud-connection/{record.id}",
        tenant_id=tenant_id,
        provider=record.provider,
        outcome="success",
    )
    return {
        "schema_version": "cloud.connections.test.v1",
        "connection_id": record.id,
        "tenant_id": tenant_id,
        "provider": record.provider,
        "status": "ok",
        "audit_metadata": _scan_audit_metadata(
            "Connection test brokered a read-only credential only; no inventory, CIS, findings, or resource writes ran."
        ),
        "connection": record.to_public_dict(),
    }


@router.post("/cloud/connections/{connection_id}/scan")
async def scan_connection(request: Request, connection_id: str, _role: Any = _SCAN_DEP) -> dict[str, Any]:
    """Launch a read-only cloud scan for a stored connection via the broker.

    Resolves the tenant's connection (404 otherwise), uses the credential broker
    to obtain a short-lived read-only session / credential / connection, and runs
    the same inventory + CIS discovery the sibling cloud routes use. Results
    persist through the existing scan/graph stores; the connection status moves to
    ``active`` + ``last_scan_at`` on success or ``error`` + ``status_detail`` (no
    secret) on failure. All four providers (AWS, Azure, GCP, Snowflake) are
    broker-enabled.
    """
    record = _require_connection(request, connection_id)
    _reject_showcase_connection(record)
    tenant_id = record.tenant_id
    actor = _actor(request)

    if (record.provider or "").strip().lower() not in _SCAN_RUNNERS:
        raise HTTPException(status_code=400, detail=f"Unsupported provider '{record.provider}'.")

    try:
        summary = _run_connection_scan(record, tenant_id)
    except Exception as exc:  # noqa: BLE001 - broker / discovery / persistence failure
        # Persist an error status with a sanitized, secret-free detail. Full
        # diagnostics go to the server log only; the client gets a generic message.
        detail = sanitize_error(exc, generic=True)
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

    scan_id = str(summary.get("scan_id") or "")
    _mark_connection(
        record,
        status=STATUS_ACTIVE,
        status_detail="",
        last_scan_at=_now(),
        last_scan_id=scan_id or None,
    )
    log_action(
        "cloud_connection.scan",
        actor=actor,
        resource=f"cloud-connection/{record.id}",
        tenant_id=tenant_id,
        provider=record.provider,
        outcome="success",
        scan_id=scan_id,
    )
    summary["connection"] = record.to_public_dict()
    return summary
