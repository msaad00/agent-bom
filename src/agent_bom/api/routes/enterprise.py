"""Enterprise API routes — auth, audit, exceptions, baselines, trends, SIEM, Jira, FP.

Endpoints:
    POST   /v1/auth/keys                      create API key
    POST   /v1/auth/keys/{key_id}/rotate      rotate API key
    GET    /v1/auth/keys                      list API keys
    DELETE /v1/auth/keys/{key_id}             revoke API key
    GET    /v1/auth/saml/metadata             generate SP metadata for IdP setup
    POST   /v1/auth/saml/login                verify a SAML assertion and mint a short-lived API key
    GET    /v1/audit                          audit log entries
    GET    /v1/audit/integrity                verify audit HMAC integrity
    GET    /v1/audit/export                   export audit evidence packet
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
    POST   /v1/findings/jira                  create Jira ticket from finding
    POST   /v1/findings/false-positive        mark finding as false positive
    GET    /v1/findings/false-positives        list false positive entries
    DELETE /v1/findings/false-positive/{id}   un-mark false positive
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from agent_bom.api.models import (
    CreateKeyRequest,
    ExceptionRequest,
    FalsePositiveRequest,
    JiraTicketRequest,
    RotateKeyRequest,
    SAMLLoginRequest,
)
from agent_bom.api.stores import _get_exception_store, _get_store, _get_trend_store
from agent_bom.security import sanitize_error

router = APIRouter()
_logger = logging.getLogger(__name__)


# ── API Key Management (RBAC) ───────────────────────────────────────────────


@router.post("/v1/auth/keys", tags=["enterprise"], status_code=201)
async def create_key(request: Request, req: CreateKeyRequest) -> dict:
    """Create a new API key. Returns the raw key once — store it securely."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import Role, create_api_key, get_key_store

    tenant_id = getattr(request.state, "tenant_id", "default")
    actor = getattr(request.state, "api_key_name", "") or req.name

    try:
        role = Role(req.role)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid role: {req.role}. Must be admin, analyst, or viewer")

    try:
        raw_key, api_key = create_api_key(
            name=req.name,
            role=role,
            expires_at=req.expires_at,
            scopes=req.scopes,
            tenant_id=tenant_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    get_key_store().add(api_key)

    log_action(
        "auth.key_created",
        actor=actor,
        resource=f"key/{api_key.key_id}",
        role=req.role,
        tenant_id=tenant_id,
        expires_at=api_key.expires_at,
        rotation_policy="enforced",
    )

    return {
        "raw_key": raw_key,
        "key_id": api_key.key_id,
        "key_prefix": api_key.key_prefix,
        "name": api_key.name,
        "role": api_key.role.value,
        "tenant_id": api_key.tenant_id,
        "created_at": api_key.created_at,
        "expires_at": api_key.expires_at,
        "message": "Store the raw_key securely — it will not be shown again.",
    }


@router.post("/v1/auth/keys/{key_id}/rotate", tags=["enterprise"], status_code=201)
async def rotate_key(request: Request, key_id: str, req: RotateKeyRequest) -> dict:
    """Rotate an API key by minting a replacement and revoking the old key."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import create_api_key, get_key_store

    tenant_id = getattr(request.state, "tenant_id", "default")
    actor = getattr(request.state, "api_key_name", "") or "system"
    store = get_key_store()
    current_key = store.get(key_id)
    if current_key is None or current_key.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail=f"Key {key_id} not found")

    replacement_name = req.name or current_key.name
    try:
        raw_key, replacement = create_api_key(
            name=replacement_name,
            role=current_key.role,
            expires_at=req.expires_at,
            scopes=list(current_key.scopes),
            tenant_id=current_key.tenant_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    store.add(replacement)
    store.remove(current_key.key_id)
    log_action(
        "auth.key_rotated",
        actor=actor,
        resource=f"key/{current_key.key_id}",
        tenant_id=tenant_id,
        replacement_key_id=replacement.key_id,
        previous_expires_at=current_key.expires_at,
        replacement_expires_at=replacement.expires_at,
    )
    log_action(
        "auth.key_revoked",
        actor=actor,
        resource=f"key/{current_key.key_id}",
        tenant_id=tenant_id,
        reason="rotated",
        replacement_key_id=replacement.key_id,
    )

    return {
        "raw_key": raw_key,
        "key_id": replacement.key_id,
        "replaced_key_id": current_key.key_id,
        "key_prefix": replacement.key_prefix,
        "name": replacement.name,
        "role": replacement.role.value,
        "tenant_id": replacement.tenant_id,
        "created_at": replacement.created_at,
        "expires_at": replacement.expires_at,
        "message": "Store the raw_key securely — it will not be shown again. The previous key has been revoked.",
    }


@router.get("/v1/auth/keys", tags=["enterprise"])
async def list_keys(request: Request) -> dict:
    """List all API keys (without hashes or raw values)."""
    from agent_bom.api.auth import get_key_store

    tenant_id = getattr(request.state, "tenant_id", "default")
    keys = get_key_store().list_keys(tenant_id=tenant_id)
    return {"keys": [k.to_dict() for k in keys]}


@router.get("/v1/auth/policy", tags=["enterprise"])
async def auth_policy() -> dict:
    """Report API key and rate-limit key rotation policy + status.

    Operators surface this in dashboards and runbooks to confirm that
    rotation cadence is enforced and that no fingerprint key has aged
    past the configured maximum.
    """
    from agent_bom.api.auth import get_api_key_policy
    from agent_bom.api.middleware import get_rate_limit_key_status

    api_policy = get_api_key_policy()
    rl_status = get_rate_limit_key_status()
    return {
        "api_key": {
            "default_ttl_seconds": api_policy.default_ttl_seconds,
            "max_ttl_seconds": api_policy.max_ttl_seconds,
            "rotation_policy": "enforced",
            "rotation_endpoint": "/v1/auth/keys/{key_id}/rotate",
        },
        "rate_limit_key": rl_status,
    }


@router.get("/v1/auth/debug", tags=["enterprise"])
async def auth_debug(request: Request) -> dict:
    """Introspect how the current request was authenticated.

    Surfaces the auth method (``static_api_key`` / ``api_key`` / ``oidc`` /
    ``saml``), the resolved role + tenant, the request-scoped trace IDs, and
    the subject recorded for audit purposes. Intended for operator support
    flows — "why is my request being denied?" — and for client SDKs doing
    session introspection without issuing a shadow request.

    The response never contains the raw API key or OIDC token. Only
    non-secret identifying attributes (name, key_id prefix, role, tenant,
    auth method) so the endpoint is safe to log.
    """
    method = getattr(request.state, "auth_method", None)
    subject = getattr(request.state, "api_key_name", None)
    role = getattr(request.state, "api_key_role", None)
    tenant_id = getattr(request.state, "tenant_id", None) or "default"
    request_id = getattr(request.state, "request_id", None)
    trace_id = getattr(request.state, "trace_id", None)
    span_id = getattr(request.state, "span_id", None)
    issuer = getattr(request.state, "auth_issuer", None)
    key_id = getattr(request.state, "api_key_id", None)
    key_id_prefix = key_id[:8] if isinstance(key_id, str) else None

    authenticated = bool(method and role)
    return {
        "authenticated": authenticated,
        "auth_method": method,
        "subject": subject,
        "role": role,
        "tenant_id": tenant_id,
        "oidc_issuer_suffix": issuer,
        "api_key_id_prefix": key_id_prefix,
        "request_id": request_id,
        "trace_id": trace_id,
        "span_id": span_id,
    }


@router.delete("/v1/auth/keys/{key_id}", tags=["enterprise"], status_code=204)
async def delete_key(request: Request, key_id: str) -> None:
    """Revoke an API key."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import get_key_store

    tenant_id = getattr(request.state, "tenant_id", "default")
    actor = getattr(request.state, "api_key_name", "")
    store = get_key_store()
    key = store.get(key_id)
    if key is None or key.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail=f"Key {key_id} not found")
    store.remove(key_id)

    log_action("auth.key_revoked", actor=actor, resource=f"key/{key_id}")


@router.get("/v1/auth/saml/metadata", tags=["enterprise"])
async def saml_metadata() -> PlainTextResponse:
    """Return SP metadata XML for enterprise IdP configuration."""
    from agent_bom.api.saml import SAMLConfig, SAMLError

    try:
        metadata = SAMLConfig.from_env().metadata_xml()
    except SAMLError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return PlainTextResponse(content=metadata, media_type="application/samlmetadata+xml")


@router.post("/v1/auth/saml/login", tags=["enterprise"], status_code=201)
async def saml_login(req: SAMLLoginRequest) -> dict:
    """Verify a SAML assertion and return a short-lived API key."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import Role, create_api_key, get_key_store
    from agent_bom.api.saml import SAMLConfig, SAMLError

    try:
        cfg = SAMLConfig.from_env()
        assertion = cfg.verify_response(req.saml_response, relay_state=req.relay_state)
    except SAMLError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=cfg.session_ttl_seconds)).isoformat()
    raw_key, api_key = create_api_key(
        name=f"saml:{assertion.subject}",
        role=Role(assertion.role),
        expires_at=expires_at,
        scopes=["saml-session"],
        tenant_id=assertion.tenant_id,
    )
    get_key_store().add(api_key)
    log_action(
        "auth.saml_login",
        actor=assertion.subject,
        resource=f"key/{api_key.key_id}",
        role=assertion.role,
        tenant_id=assertion.tenant_id,
        session_index=assertion.session_index,
    )
    return {
        "raw_key": raw_key,
        "key_id": api_key.key_id,
        "role": api_key.role.value,
        "tenant_id": api_key.tenant_id,
        "subject": assertion.subject,
        "expires_at": api_key.expires_at,
        "attributes": assertion.attributes,
        "message": "Use this short-lived key as Authorization: Bearer <key> for the control-plane session.",
    }


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


@router.get("/v1/audit/export", tags=["enterprise"])
async def export_audit_entries(
    request: Request,
    action: str | None = None,
    resource: str | None = None,
    since: str | None = None,
    limit: int = 1000,
    offset: int = 0,
    format: str = "json",
):
    """Export audit entries as a signed evidence packet."""
    from agent_bom.api.audit_log import get_audit_log, log_action, sign_export_payload

    fmt = format.lower()
    if fmt not in {"json", "jsonl"}:
        raise HTTPException(status_code=400, detail="format must be one of: json, jsonl")

    tenant_id = getattr(request.state, "tenant_id", "default")
    actor = getattr(request.state, "api_key_name", "") or "system"
    store = get_audit_log()
    entries = store.list_entries(action=action, resource=resource, since=since, limit=limit, offset=offset)
    verified, tampered = store.verify_integrity(limit=min(limit, 10_000))

    log_action(
        "audit.export",
        actor=actor,
        resource="audit/export",
        tenant_id=tenant_id,
        format=fmt,
        exported=len(entries),
        action_filter=action,
        resource_filter=resource,
    )

    if fmt == "jsonl":
        lines = [json.dumps(entry.to_dict(), sort_keys=True) for entry in entries]
        payload = ("\n".join(lines) + ("\n" if lines else "")).encode()
        return PlainTextResponse(
            content=payload.decode(),
            media_type="application/x-ndjson",
            headers={
                "Content-Disposition": 'attachment; filename="agent-bom-audit-export.jsonl"',
                "X-Agent-Bom-Audit-Export-Signature": sign_export_payload(payload),
            },
        )

    body = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "filters": {
            "action": action,
            "resource": resource,
            "since": since,
            "limit": limit,
            "offset": offset,
        },
        "integrity": {
            "verified": verified,
            "tampered": tampered,
            "checked": verified + tampered,
        },
        "entries": [entry.to_dict() for entry in entries],
    }
    payload = json.dumps(body, sort_keys=True).encode()
    return JSONResponse(
        content=body,
        headers={
            "Content-Disposition": 'attachment; filename="agent-bom-audit-export.json"',
            "X-Agent-Bom-Audit-Export-Signature": sign_export_payload(payload),
        },
    )


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
async def get_exception(request: Request, exception_id: str) -> dict:
    """Get a specific exception."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    exc = _get_exception_store().get(exception_id)
    if exc is None or exc.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    return exc.to_dict()


@router.put("/v1/exceptions/{exception_id}/approve", tags=["enterprise"])
async def approve_exception(request: Request, exception_id: str, approved_by: str = "") -> dict:
    """Approve a pending exception (admin only)."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import ExceptionStatus

    tenant_id = getattr(request.state, "tenant_id", "default")
    actor = approved_by or getattr(request.state, "api_key_name", "")
    store = _get_exception_store()
    exc = store.get(exception_id)
    if exc is None or exc.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    if exc.status != ExceptionStatus.PENDING:
        raise HTTPException(status_code=409, detail=f"Cannot approve exception in {exc.status.value} state")
    exc.status = ExceptionStatus.ACTIVE
    exc.approved_by = actor
    exc.approved_at = datetime.now(timezone.utc).isoformat()
    store.put(exc)
    log_action("exception_approve", actor=actor, resource=f"exception/{exception_id}")
    return exc.to_dict()


@router.put("/v1/exceptions/{exception_id}/revoke", tags=["enterprise"])
async def revoke_exception(request: Request, exception_id: str, revoked_by: str = "") -> dict:
    """Revoke an active exception."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import ExceptionStatus

    tenant_id = getattr(request.state, "tenant_id", "default")
    actor = revoked_by or getattr(request.state, "api_key_name", "")
    store = _get_exception_store()
    exc = store.get(exception_id)
    if exc is None or exc.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    exc.status = ExceptionStatus.REVOKED
    exc.revoked_at = datetime.now(timezone.utc).isoformat()
    store.put(exc)
    log_action("exception_revoke", actor=actor, resource=f"exception/{exception_id}")
    return exc.to_dict()


@router.delete("/v1/exceptions/{exception_id}", tags=["enterprise"], status_code=204)
async def delete_exception(request: Request, exception_id: str) -> None:
    """Delete an exception."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    store = _get_exception_store()
    exc = store.get(exception_id)
    if exc is None or exc.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    ok = store.delete(exception_id)
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


# ── Jira Integration ────────────────────────────────────────────────────────


@router.post("/v1/findings/jira", tags=["enterprise"], status_code=201)
async def create_jira_ticket_route(
    req: JiraTicketRequest,
    jira_api_token: str | None = Header(default=None, alias="X-Jira-Api-Token"),
) -> dict:
    """Create a Jira ticket from a finding (admin/analyst only)."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.integrations.jira import create_jira_ticket
    from agent_bom.security import validate_url

    if not jira_api_token:
        raise HTTPException(status_code=400, detail="Missing X-Jira-Api-Token header")

    # Validate Jira URL to prevent SSRF
    try:
        validate_url(req.jira_url)
    except Exception as url_exc:
        raise HTTPException(status_code=400, detail=f"Invalid Jira URL: {sanitize_error(url_exc)}")

    try:
        ticket_key = await create_jira_ticket(
            jira_url=req.jira_url,
            email=req.email,
            api_token=jira_api_token,
            project_key=req.project_key,
            finding=req.finding,
        )
    except Exception as exc:
        _logger.exception("Jira ticket creation failed: %s", sanitize_error(exc))
        raise HTTPException(status_code=502, detail="Failed to create Jira ticket")

    if not ticket_key:
        raise HTTPException(status_code=502, detail="Jira API returned no ticket key")

    log_action(
        "findings.jira_ticket_created",
        resource=f"jira/{ticket_key}",
        vuln_id=req.finding.get("vulnerability_id", ""),
        package=req.finding.get("package", ""),
    )

    return {"ticket_key": ticket_key, "status": "created"}


# ── False Positive Management ────────────────────────────────────────────────


@router.post("/v1/findings/false-positive", tags=["enterprise"], status_code=201)
async def mark_false_positive(request: Request, req: FalsePositiveRequest) -> dict:
    """Mark a finding as false positive."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import ExceptionStatus, VulnException

    tenant_id = getattr(request.state, "tenant_id", "default")
    exc = VulnException(
        vuln_id=req.vulnerability_id,
        package_name=req.package,
        reason=f"[false_positive] {req.reason}",
        requested_by=req.marked_by,
        status=ExceptionStatus.ACTIVE,
        tenant_id=tenant_id,
    )
    _get_exception_store().put(exc)
    log_action(
        "findings.false_positive_marked",
        actor=req.marked_by,
        resource=f"fp/{exc.exception_id}",
        vuln_id=req.vulnerability_id,
        package=req.package,
    )
    return {
        "id": exc.exception_id,
        "vulnerability_id": req.vulnerability_id,
        "package": req.package,
        "reason": req.reason,
        "marked_by": req.marked_by,
        "status": "false_positive",
        "created_at": exc.created_at,
    }


@router.get("/v1/findings/false-positives", tags=["enterprise"])
async def list_false_positives(request: Request) -> dict:
    """List all false positive entries."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    all_exceptions = _get_exception_store().list_all(tenant_id=tenant_id)
    fps = [e for e in all_exceptions if e.reason.startswith("[false_positive]")]
    return {
        "false_positives": [
            {
                "id": e.exception_id,
                "vulnerability_id": e.vuln_id,
                "package": e.package_name,
                "reason": e.reason.removeprefix("[false_positive] "),
                "marked_by": e.requested_by,
                "status": "false_positive",
                "created_at": e.created_at,
            }
            for e in fps
        ],
        "total": len(fps),
    }


@router.delete("/v1/findings/false-positive/{fp_id}", tags=["enterprise"], status_code=204)
async def remove_false_positive(request: Request, fp_id: str) -> None:
    """Un-mark a false positive."""
    from agent_bom.api.audit_log import log_action

    tenant_id = getattr(request.state, "tenant_id", "default")
    store = _get_exception_store()
    exc = store.get(fp_id)
    if exc is None or exc.tenant_id != tenant_id or not exc.reason.startswith("[false_positive]"):
        raise HTTPException(status_code=404, detail=f"False positive {fp_id} not found")
    ok = store.delete(fp_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"False positive {fp_id} not found")
    log_action("findings.false_positive_removed", resource=f"fp/{fp_id}")
