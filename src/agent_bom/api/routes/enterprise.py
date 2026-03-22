"""Enterprise API routes — auth, audit, exceptions, baselines, trends, SIEM.

Endpoints:
    POST   /v1/auth/keys                      create API key
    GET    /v1/auth/keys                      list API keys
    DELETE /v1/auth/keys/{key_id}             revoke API key
    GET    /v1/audit                          audit log entries
    GET    /v1/audit/integrity                verify audit HMAC integrity
    POST   /v1/exceptions                     create vuln exception
    GET    /v1/exceptions                     list exceptions
    GET    /v1/exceptions/{exception_id}      get exception
    PUT    /v1/exceptions/{exception_id}/approve  approve exception
    PUT    /v1/exceptions/{exception_id}/revoke   revoke exception
    DELETE /v1/exceptions/{exception_id}      delete exception
    POST   /v1/baseline/compare               compare two scan results
    GET    /v1/trends                         historical trend data
    GET    /v1/siem/connectors                list SIEM connector types
    POST   /v1/siem/test                      test SIEM connectivity
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.models import CreateKeyRequest, ExceptionRequest
from agent_bom.api.stores import _get_exception_store, _get_store, _get_trend_store
from agent_bom.security import sanitize_error

router = APIRouter()
_logger = logging.getLogger(__name__)


# ── API Key Management (RBAC) ───────────────────────────────────────────────


@router.post("/v1/auth/keys", tags=["enterprise"], status_code=201)
async def create_key(req: CreateKeyRequest) -> dict:
    """Create a new API key. Returns the raw key once — store it securely."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import Role, create_api_key, get_key_store

    try:
        role = Role(req.role)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid role: {req.role}. Must be admin, analyst, or viewer")

    raw_key, api_key = create_api_key(
        name=req.name,
        role=role,
        expires_at=req.expires_at,
        scopes=req.scopes,
    )
    get_key_store().add(api_key)

    log_action("auth.key_created", actor=req.name, resource=f"key/{api_key.key_id}", role=req.role)

    return {
        "raw_key": raw_key,
        "key_id": api_key.key_id,
        "key_prefix": api_key.key_prefix,
        "name": api_key.name,
        "role": api_key.role.value,
        "created_at": api_key.created_at,
        "expires_at": api_key.expires_at,
        "message": "Store the raw_key securely — it will not be shown again.",
    }


@router.get("/v1/auth/keys", tags=["enterprise"])
async def list_keys() -> dict:
    """List all API keys (without hashes or raw values)."""
    from agent_bom.api.auth import get_key_store

    keys = get_key_store().list_keys()
    return {"keys": [k.to_dict() for k in keys]}


@router.delete("/v1/auth/keys/{key_id}", tags=["enterprise"], status_code=204)
async def delete_key(key_id: str) -> None:
    """Revoke an API key."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import get_key_store

    if not get_key_store().remove(key_id):
        raise HTTPException(status_code=404, detail=f"Key {key_id} not found")

    log_action("auth.key_revoked", resource=f"key/{key_id}")


# ── Audit Log ────────────────────────────────────────────────────────────────


@router.get("/v1/audit", tags=["enterprise"])
async def list_audit_entries(
    action: str | None = None,
    resource: str | None = None,
    since: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """List audit log entries with optional filters."""
    from agent_bom.api.audit_log import get_audit_log

    store = get_audit_log()
    entries = store.list_entries(action=action, resource=resource, since=since, limit=limit, offset=offset)
    return {
        "entries": [e.to_dict() for e in entries],
        "total": store.count(action=action),
    }


@router.get("/v1/audit/integrity", tags=["enterprise"])
async def audit_integrity(limit: int = 1000) -> dict:
    """Verify HMAC integrity of audit log entries."""
    from agent_bom.api.audit_log import get_audit_log

    verified, tampered = get_audit_log().verify_integrity(limit=limit)
    return {"verified": verified, "tampered": tampered, "checked": verified + tampered}


# ── Exception / Waiver Management ────────────────────────────────────────────


@router.post("/v1/exceptions", tags=["enterprise"], status_code=201)
async def create_exception(request: Request, req: ExceptionRequest) -> dict:
    """Request a vulnerability exception / waiver."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import VulnException

    tenant_id = getattr(request.state, "tenant_id", "default")
    exc = VulnException(
        vuln_id=req.vuln_id,
        package_name=req.package_name,
        server_name=req.server_name,
        reason=req.reason,
        requested_by=req.requested_by,
        expires_at=req.expires_at,
        tenant_id=tenant_id,
    )
    _get_exception_store().put(exc)
    log_action(
        "exception_create", actor=req.requested_by, resource=f"exception/{exc.exception_id}", vuln_id=req.vuln_id, package=req.package_name
    )
    return exc.to_dict()


@router.get("/v1/exceptions", tags=["enterprise"])
async def list_exceptions(request: Request, status: str | None = None) -> dict:
    """List all vulnerability exceptions."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    exceptions = _get_exception_store().list_all(status=status, tenant_id=tenant_id)
    return {"exceptions": [e.to_dict() for e in exceptions], "total": len(exceptions)}


@router.get("/v1/exceptions/{exception_id}", tags=["enterprise"])
async def get_exception(exception_id: str) -> dict:
    """Get a specific exception."""
    exc = _get_exception_store().get(exception_id)
    if exc is None:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    return exc.to_dict()


@router.put("/v1/exceptions/{exception_id}/approve", tags=["enterprise"])
async def approve_exception(exception_id: str, approved_by: str = "") -> dict:
    """Approve a pending exception (admin only)."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import ExceptionStatus

    store = _get_exception_store()
    exc = store.get(exception_id)
    if exc is None:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    if exc.status != ExceptionStatus.PENDING:
        raise HTTPException(status_code=409, detail=f"Cannot approve exception in {exc.status.value} state")
    exc.status = ExceptionStatus.ACTIVE
    exc.approved_by = approved_by
    exc.approved_at = datetime.now(timezone.utc).isoformat()
    store.put(exc)
    log_action("exception_approve", actor=approved_by, resource=f"exception/{exception_id}")
    return exc.to_dict()


@router.put("/v1/exceptions/{exception_id}/revoke", tags=["enterprise"])
async def revoke_exception(exception_id: str, revoked_by: str = "") -> dict:
    """Revoke an active exception."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import ExceptionStatus

    store = _get_exception_store()
    exc = store.get(exception_id)
    if exc is None:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    exc.status = ExceptionStatus.REVOKED
    exc.revoked_at = datetime.now(timezone.utc).isoformat()
    store.put(exc)
    log_action("exception_revoke", actor=revoked_by, resource=f"exception/{exception_id}")
    return exc.to_dict()


@router.delete("/v1/exceptions/{exception_id}", tags=["enterprise"], status_code=204)
async def delete_exception(exception_id: str) -> None:
    """Delete an exception."""
    ok = _get_exception_store().delete(exception_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")


# ── Baseline Comparison & Trends ─────────────────────────────────────────────


@router.post("/v1/baseline/compare", tags=["enterprise"])
async def compare_baseline(previous_job_id: str = "", current_job_id: str = "") -> dict:
    """Compare two scan results to show new, resolved, and persistent vulnerabilities."""
    from agent_bom.baseline import compare_reports

    store = _get_store()
    prev_job = store.get(previous_job_id) if previous_job_id else None
    curr_job = store.get(current_job_id) if current_job_id else None

    prev_report = prev_job.result if prev_job and prev_job.result else {}
    curr_report = curr_job.result if curr_job and curr_job.result else {}

    if not prev_report and not curr_report:
        raise HTTPException(status_code=404, detail="At least one valid job_id required")

    diff = compare_reports(prev_report, curr_report)
    return diff.to_dict()


@router.get("/v1/trends", tags=["enterprise"])
async def get_trends(limit: int = 30) -> dict:
    """Get historical trend data — posture score and vuln counts over time."""
    history = _get_trend_store().get_history(limit=limit)
    return {
        "data_points": [p.to_dict() for p in history],
        "count": len(history),
    }


# ── SIEM Connectors ─────────────────────────────────────────────────────────


@router.get("/v1/siem/connectors", tags=["enterprise"])
async def list_siem_connectors() -> dict:
    """List available SIEM connector types."""
    from agent_bom.siem import list_connectors

    return {"connectors": list_connectors()}


@router.post("/v1/siem/test", tags=["enterprise"])
async def test_siem_connection(siem_type: str = "", url: str = "", token: str = "") -> dict:
    """Test SIEM connectivity."""
    from agent_bom.security import validate_url
    from agent_bom.siem import SIEMConfig, create_connector

    # Validate URL to prevent SSRF
    if url:
        try:
            validate_url(url)
        except Exception as url_exc:
            raise HTTPException(status_code=400, detail=f"Invalid URL: {sanitize_error(url_exc)}")

    try:
        connector = create_connector(siem_type, SIEMConfig(name=siem_type, url=url, token=token))
        healthy = connector.health_check()
        return {"siem_type": siem_type, "healthy": healthy}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(str(exc)))
    except Exception as exc:
        _logger.exception(
            "Unexpected error while testing SIEM connection: %s",
            sanitize_error(exc),
        )
        return {
            "siem_type": siem_type,
            "healthy": False,
            "error": "Failed to test SIEM connection",
        }
