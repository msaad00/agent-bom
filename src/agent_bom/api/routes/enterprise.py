"""Enterprise API routes — auth, audit, exceptions, baselines, trends, SIEM, Jira, FP.

Endpoints:
    POST   /v1/auth/keys                      create API key
    POST   /v1/auth/keys/{key_id}/rotate      rotate API key
    GET    /v1/auth/keys                      list API keys
    DELETE /v1/auth/keys/{key_id}             revoke API key
    GET    /v1/auth/saml/metadata             generate SP metadata for IdP setup
    POST   /v1/auth/saml/relay-state          issue one-time RelayState nonce
    POST   /v1/auth/saml/login                verify a SAML assertion and mint a short-lived API key
    GET    /v1/audit                          audit log entries
    GET    /v1/audit/integrity                verify audit HMAC integrity
    GET    /v1/audit/export                   export audit evidence packet
    POST   /v1/audit/export/verify            verify a signed audit export packet
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
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field

from agent_bom.api.models import (
    CreateKeyRequest,
    ExceptionRequest,
    FalsePositiveRequest,
    FindingFeedbackRequest,
    FindingTriageDecisionRequest,
    FindingTriageRequest,
    FindingTriageVexIngestRequest,
    IssueStatusUpdateRequest,
    JiraTicketRequest,
    RotateKeyRequest,
    SAMLLoginRequest,
    TenantQuotaUpdateRequest,
)
from agent_bom.api.stores import _get_exception_store, _get_issue_mapping_store, _get_store, _get_trend_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.security import sanitize_error, sanitize_text

router = APIRouter()
_logger = logging.getLogger(__name__)


class BrowserSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    api_key: str = Field(
        ...,
        min_length=1,
        description="API key to exchange for a same-origin httpOnly browser session cookie",
    )


class AuditExportVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    payload: Any = Field(..., description="Audit export payload object, JSON string, or JSONL text")
    signature: str = Field(..., min_length=64, max_length=128, description="X-Agent-Bom-Audit-Export-Signature value")


_FEEDBACK_PREFIX = "[finding_feedback:"
_TRIAGE_PREFIX = "[finding_triage]"
_LEGACY_FALSE_POSITIVE_PREFIX = "[false_positive]"


def _trusted_proxy_hops() -> int:
    raw = (os.environ.get("AGENT_BOM_TRUSTED_PROXY_HOPS") or "").strip()
    if not raw:
        return 0
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def _forwarded_for_trusted() -> bool:
    """Honor X-Forwarded-For only when a trusted reverse proxy is declared."""
    flag = os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH", "").strip().lower() in {"1", "true", "yes", "on"}
    return flag or _trusted_proxy_hops() > 0


def _client_fingerprint(request: Request) -> str:
    """Throttle identity for the API-key-exchange brute-force limiter.

    Defaults to the transport peer (``request.client.host``) so a hostile
    client cannot reset its brute-force window by spoofing a fresh
    ``X-Forwarded-For`` value on every attempt. The forwarded chain is only
    consulted when the deployment declares a trusted proxy via
    ``AGENT_BOM_TRUST_PROXY_AUTH`` or an explicit ``AGENT_BOM_TRUSTED_PROXY_HOPS``
    count; with a hop count we take the Nth-from-rightmost entry (the address
    the trusted proxy appended), never the attacker-controlled leftmost one.
    """
    host = request.client.host if request.client else "unknown"
    if _forwarded_for_trusted():
        forwarded = [part.strip() for part in (request.headers.get("x-forwarded-for") or "").split(",") if part.strip()]
        hops = _trusted_proxy_hops()
        if hops and len(forwarded) >= hops:
            host = forwarded[-hops]
        elif forwarded:
            host = forwarded[0]
    return (host or "unknown")[:128]


def _auth_session_limit() -> int:
    raw = (os.environ.get("AGENT_BOM_AUTH_SESSION_ATTEMPTS_PER_MINUTE") or "12").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return 12


def _check_auth_session_rate_limit(request: Request) -> None:
    """Reject when the per-fingerprint attempt counter exceeds the per-minute budget.

    Backed by :mod:`agent_bom.api.shared_auth_state` so a clustered
    deployment with ``AGENT_BOM_POSTGRES_URL`` set enforces the limit
    cross-replica via Postgres, instead of the per-process dict the
    pre-PR-C path used (audit-5 PR-A landed a runtime warning for
    that gap; this PR closes it).
    """
    from agent_bom.api.shared_auth_state import get_auth_state

    backend = get_auth_state()
    key = _client_fingerprint(request)
    if not backend.record_attempt(key, window_seconds=60, limit=_auth_session_limit()):
        raise HTTPException(status_code=429, detail="Too many browser session attempts")


def _saml_relay_ttl_seconds() -> int:
    raw = (os.environ.get("AGENT_BOM_SAML_RELAY_STATE_TTL_SECONDS") or "300").strip()
    try:
        return max(60, min(int(raw), 900))
    except ValueError:
        return 300


def _relay_state_digest(relay_state: str) -> str:
    import hashlib

    return hashlib.sha256(relay_state.encode("utf-8")).hexdigest()


def _saml_idp_initiated_allowed() -> bool:
    return os.environ.get("AGENT_BOM_SAML_ALLOW_IDP_INITIATED", "").strip().lower() in {"1", "true", "yes", "on"}


def _saml_relay_nonce(relay_state: str) -> str:
    return f"saml-relay:{_relay_state_digest(relay_state)}"


def _new_saml_relay_state() -> tuple[str, str]:
    from agent_bom.api.shared_auth_state import get_auth_state

    backend = get_auth_state()
    ttl = _saml_relay_ttl_seconds()
    now = int(time.time())
    expires_at = now + ttl
    for _ in range(3):
        relay_state = secrets.token_urlsafe(32)
        if backend.register_one_time_nonce(_saml_relay_nonce(relay_state), expires_at, now=now):
            return relay_state, (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat()
    raise HTTPException(status_code=503, detail="SAML relay_state issuance unavailable")


def _consume_saml_relay_state(relay_state: str | None) -> None:
    if not relay_state:
        if _saml_idp_initiated_allowed():
            return
        raise HTTPException(status_code=401, detail="SAML relay_state required")
    from agent_bom.api.shared_auth_state import get_auth_state

    backend = get_auth_state()
    now = int(time.time())
    if not backend.redeem_one_time_nonce(_saml_relay_nonce(relay_state), now=now):
        raise HTTPException(status_code=401, detail="Invalid or expired SAML relay_state")


def _consume_saml_response_once(saml_response: str, *, ttl_seconds: int) -> None:
    from agent_bom.api.shared_auth_state import get_auth_state

    digest = f"saml-response:{_relay_state_digest(saml_response)}"
    backend = get_auth_state()
    now = int(time.time())
    if not backend.consume_nonce_once(digest, now + max(60, int(ttl_seconds)), now=now):
        raise HTTPException(status_code=401, detail="SAML assertion replay detected")


def _request_actor(request: Request) -> str:
    return str(getattr(request.state, "api_key_name", None) or getattr(request.state, "auth_method", None) or "system")


def _feedback_reason(state: str, reason: str) -> str:
    clean_state = state.strip().lower().replace("-", "_")
    if clean_state == "not_applicable":
        clean_state = "not_affected"
    clean_reason = reason.strip()
    return f"{_FEEDBACK_PREFIX}{clean_state}] {clean_reason}".strip()


def _parse_feedback_reason(reason: str) -> tuple[str, str] | None:
    if reason.startswith(_FEEDBACK_PREFIX):
        close = reason.find("]")
        if close > len(_FEEDBACK_PREFIX):
            state = reason[len(_FEEDBACK_PREFIX) : close].strip().lower()
            if state == "not_applicable":
                state = "not_affected"
            return state, reason[close + 1 :].strip()
    if reason.startswith(_LEGACY_FALSE_POSITIVE_PREFIX):
        return "false_positive", reason.removeprefix(_LEGACY_FALSE_POSITIVE_PREFIX).strip()
    return None


def _validate_triage_decision(decision: str, justification: str | None) -> None:
    if decision == "not_affected" and not justification:
        raise HTTPException(status_code=400, detail="not_affected triage decisions require an OpenVEX justification")


def _triage_reason(payload: dict[str, Any]) -> str:
    return f"{_TRIAGE_PREFIX} {json.dumps(payload, sort_keys=True, separators=(',', ':'))}"


def _parse_triage_reason(reason: str) -> dict[str, Any] | None:
    if not reason.startswith(_TRIAGE_PREFIX):
        return None
    raw = reason.removeprefix(_TRIAGE_PREFIX).strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _feedback_response(exc: Any) -> dict[str, Any]:
    parsed = _parse_feedback_reason(str(exc.reason))
    state, reason = parsed if parsed else ("unknown", str(exc.reason))
    return {
        "id": exc.exception_id,
        "vulnerability_id": exc.vuln_id,
        "package": exc.package_name,
        "server_name": exc.server_name,
        "state": state,
        "reason": reason,
        "marked_by": exc.requested_by,
        "status": "suppressed" if state in {"false_positive", "accepted_risk", "not_affected", "fixed_verified"} else state,
        "created_at": exc.created_at,
        "expires_at": exc.expires_at,
        "tenant_id": exc.tenant_id,
    }


def _triage_response(exc: Any) -> dict[str, Any]:
    data = _parse_triage_reason(str(exc.reason)) or {}
    decision = str(data.get("decision") or "under_investigation")
    queue_state = str(data.get("queue_state") or "open")
    reviewed_at = str(data.get("reviewed_at") or exc.approved_at or "")
    return {
        "id": exc.exception_id,
        "vulnerability_id": exc.vuln_id,
        "package": exc.package_name,
        "server_name": exc.server_name,
        "queue_state": queue_state,
        "decision": decision,
        "justification": data.get("justification"),
        "decision_reason": str(data.get("decision_reason") or ""),
        "assignee": str(data.get("assignee") or exc.approved_by or ""),
        "created_by": exc.requested_by,
        "created_at": exc.created_at,
        "reviewed_at": reviewed_at,
        "expires_at": exc.expires_at,
        "tenant_id": exc.tenant_id,
        "vex_eligible": decision == "not_affected" and bool(data.get("justification")),
    }


def _jira_mapping_target(req: JiraTicketRequest) -> tuple[str, str]:
    target_kind = req.target_kind or "finding"
    if req.target_id:
        return target_kind, req.target_id
    finding = req.finding or {}
    if target_kind == "exposure_path":
        target_id = str(finding.get("exposure_path_id") or finding.get("path_id") or finding.get("id") or "")
    else:
        vuln_id = str(finding.get("vulnerability_id") or finding.get("cve_id") or finding.get("id") or "unknown")
        package = str(finding.get("package") or finding.get("package_name") or "*")
        server = str(finding.get("server_name") or finding.get("server") or "")
        target_id = "|".join(part for part in (vuln_id, package, server) if part)
    return target_kind, target_id[:256] or "unknown"


def _jira_issue_url(jira_url: str, ticket_key: str) -> str:
    return f"{jira_url.rstrip('/')}/browse/{ticket_key}"


def _auth_session_state(request: Request) -> dict:
    """Build the current request's auth/session state without leaking secrets."""
    from agent_bom.api.middleware import get_auth_runtime_status
    from agent_bom.rbac import summarize_role

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
    auth_runtime = get_auth_runtime_status()
    role_summary = summarize_role(role)

    sso_provider = None
    configured_modes = auth_runtime.get("configured_modes")
    if isinstance(configured_modes, list) and "oidc_browser" in configured_modes:
        from agent_bom.api.oidc_browser import configured_browser_sso_provider

        sso_provider = configured_browser_sso_provider()

    return {
        "authenticated": authenticated,
        "auth_required": auth_runtime["auth_required"],
        "configured_modes": auth_runtime["configured_modes"],
        "recommended_ui_mode": auth_runtime["recommended_ui_mode"],
        "sso_provider": sso_provider,
        "auth_method": method,
        "subject": subject,
        "role": role,
        "tenant_id": tenant_id,
        "oidc_issuer_suffix": issuer,
        "api_key_id_prefix": key_id_prefix,
        "request_id": request_id,
        "trace_id": trace_id,
        "span_id": span_id,
        "role_summary": role_summary,
    }


def _session_cookie_secure(request: Request) -> bool:
    raw = os.environ.get("AGENT_BOM_SESSION_COOKIE_SECURE", "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    from agent_bom.api.middleware import _production_or_clustered_control_plane

    if _production_or_clustered_control_plane():
        return True
    trusted_proxy = os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH", "").strip().lower() in {"1", "true", "yes", "on"}
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower() if trusted_proxy else ""
    return request.url.scheme == "https" or forwarded_proto == "https"


def _session_cookie_max_age() -> int:
    raw = os.environ.get("AGENT_BOM_SESSION_COOKIE_MAX_AGE_SECONDS", "").strip()
    if not raw:
        return 8 * 60 * 60
    try:
        parsed = int(raw)
    except ValueError:
        return 8 * 60 * 60
    return max(60, min(parsed, 24 * 60 * 60))


def _set_browser_session_cookie(
    response: Response,
    request: Request,
    *,
    subject: str,
    role: str,
    tenant_id: str,
    auth_method: str,
    key_id: str | None = None,
    scopes: list[str] | None = None,
) -> None:
    from agent_bom.api.browser_session import CSRF_COOKIE_NAME, SESSION_COOKIE_NAME, BrowserSessionError, create_browser_session_token

    max_age = _session_cookie_max_age()
    try:
        token, csrf = create_browser_session_token(
            subject=subject,
            role=role,
            tenant_id=tenant_id,
            auth_method=auth_method,
            key_id=key_id,
            scopes=scopes,
            max_age_seconds=max_age,
        )
    except BrowserSessionError as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc, generic=True)) from exc
    secure = _session_cookie_secure(request)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE_NAME,
        csrf,
        max_age=max_age,
        httponly=False,
        secure=secure,
        samesite="strict",
        path="/",
    )


def _clear_browser_session_cookie(response: Response, request: Request) -> None:
    from agent_bom.api.browser_session import CSRF_COOKIE_NAME, SESSION_COOKIE_NAME, revoke_browser_session_token

    secure = _session_cookie_secure(request)
    revoke_browser_session_token(request.cookies.get(SESSION_COOKIE_NAME, ""))
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
    )
    response.delete_cookie(
        CSRF_COOKIE_NAME,
        httponly=False,
        secure=secure,
        samesite="strict",
        path="/",
    )


# ── API Key Management (RBAC) ───────────────────────────────────────────────


@router.post("/auth/session", tags=["enterprise"], status_code=204)
async def create_browser_session(request: Request, response: Response, body: BrowserSessionRequest) -> None:
    """Exchange an API key for a same-origin httpOnly browser session cookie.

    This is the dashboard-safe fallback for deployments that are not fronted by
    reverse-proxy OIDC. The raw key is never returned and should be typed only
    into the first-party UI served from the same origin as the API.
    """
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import get_key_store

    _check_auth_session_rate_limit(request)
    raw_key = body.api_key.strip()
    if not raw_key:
        raise HTTPException(status_code=401, detail="Invalid API key")

    from agent_bom.api.secret_source import resolve_secret

    static_key = resolve_secret("AGENT_BOM_API_KEY")
    if static_key and secrets.compare_digest(raw_key, static_key):
        from agent_bom.api.middleware import static_api_key_allowed, static_api_key_rejection_message

        if not static_api_key_allowed():
            raise HTTPException(status_code=503, detail=static_api_key_rejection_message())
        _set_browser_session_cookie(
            response,
            request,
            subject="static-key",
            role="admin",
            tenant_id="default",
            auth_method="browser_session_static_api_key",
        )
        log_action(
            "auth.browser_session_created",
            actor="static-key",
            resource="auth/session",
            tenant_id="default",
            method="static_api_key",
        )
        return None

    store = get_key_store()
    if store.has_keys():
        api_key = store.verify(raw_key)
        if api_key:
            _set_browser_session_cookie(
                response,
                request,
                subject=api_key.name,
                role=api_key.role.value,
                tenant_id=api_key.tenant_id,
                auth_method="browser_session",
                key_id=api_key.key_id,
                scopes=list(api_key.scopes),
            )
            log_action(
                "auth.browser_session_created",
                actor=api_key.name,
                resource="auth/session",
                tenant_id=api_key.tenant_id,
                method="api_key",
                key_id=api_key.key_id,
                role=api_key.role.value,
            )
            return None

    raise HTTPException(status_code=401, detail="Invalid API key")


@router.delete("/auth/session", tags=["enterprise"], status_code=204)
async def delete_browser_session(request: Request, response: Response) -> None:
    """Clear the same-origin browser session cookie."""
    from agent_bom.api.audit_log import log_action

    _clear_browser_session_cookie(response, request)
    tenant_id = getattr(request.state, "tenant_id", None) or "default"
    actor = getattr(request.state, "api_key_name", "") or "browser-session"
    log_action("auth.browser_session_cleared", actor=actor, resource="auth/session", tenant_id=tenant_id)
    return None


@router.post("/auth/keys", tags=["enterprise"], status_code=201)
async def create_key(request: Request, req: CreateKeyRequest) -> dict:
    """Create a new API key. Returns the raw key once — store it securely."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import Role, create_api_key, get_key_store, resolve_scim_subject_binding

    tenant_id = require_request_tenant_id(request)
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
            scim_subject_id=resolve_scim_subject_binding(request, req.scim_subject_id),
            owner=req.owner,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
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
        "owner": api_key.owner,
        "message": "Store the raw_key securely — it will not be shown again.",
    }


@router.post("/auth/keys/{key_id}/rotate", tags=["enterprise"], status_code=201)
async def rotate_key(
    request: Request,
    key_id: str,
    req: RotateKeyRequest | None = None,
) -> dict:
    """Rotate an API key by minting a replacement and revoking the old key.

    Body is optional -- a rotation with no overrides accepts both `{}` and a
    completely missing body. All RotateKeyRequest fields default to None
    (inherit name from the current key, no expiry change, default overlap).
    """
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import create_api_key, get_api_key_policy, get_key_store, normalize_rotation_overlap_seconds

    if req is None:
        req = RotateKeyRequest()

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    store = get_key_store()
    current_key = store.get(key_id)
    if current_key is None or current_key.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail=f"Key {key_id} not found")

    overlap_seconds = normalize_rotation_overlap_seconds(req.overlap_seconds, policy=get_api_key_policy())
    overlap_until = (datetime.now(timezone.utc) + timedelta(seconds=overlap_seconds)).isoformat()

    replacement_name = req.name or current_key.name
    try:
        raw_key, replacement = create_api_key(
            name=replacement_name,
            role=current_key.role,
            expires_at=req.expires_at,
            scopes=list(current_key.scopes),
            tenant_id=current_key.tenant_id,
            scim_subject_id=current_key.scim_subject_id,
            owner=current_key.owner,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc

    store.add(replacement)
    if not store.mark_rotating(current_key.key_id, replacement_key_id=replacement.key_id, overlap_until=overlap_until):
        raise HTTPException(status_code=409, detail=f"Key {key_id} could not be marked for rotation")
    log_action(
        "auth.key_rotated",
        actor=actor,
        resource=f"key/{current_key.key_id}",
        tenant_id=tenant_id,
        replacement_key_id=replacement.key_id,
        previous_expires_at=current_key.expires_at,
        replacement_expires_at=replacement.expires_at,
        overlap_until=overlap_until,
        overlap_seconds=overlap_seconds,
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
        "overlap_until": overlap_until,
        "overlap_seconds": overlap_seconds,
        "message": (
            "Store the raw_key securely — it will not be shown again. The previous key remains valid until the overlap window ends."
        ),
    }


@router.get("/auth/keys", tags=["enterprise"])
async def list_keys(request: Request) -> dict:
    """List all API keys (without hashes or raw values)."""
    from agent_bom.api.auth import get_key_store

    tenant_id = require_request_tenant_id(request)
    keys = get_key_store().list_keys(tenant_id=tenant_id)
    # schema_version on terminal list response.
    return {"schema_version": "v1", "keys": [k.to_dict() for k in keys]}


@router.get("/auth/policy", tags=["enterprise"])
async def auth_policy(request: Request) -> dict:
    """Report control-plane operator posture for auth, rate-limit and runtime safety controls.

    Intended for operator runbooks and posture dashboards. The payload is the
    process-wide control-plane configuration (rotation policy, header gates,
    sandbox defaults, identity provisioning posture) — it is not a tenant-scoped
    record. The only tenant-scoped fields are ``tenant_quota_runtime`` (the
    effective quotas for the calling tenant) and the resolved tenant id used to
    derive them; everything else describes the deployment as a whole.
    """
    from agent_bom.api.audit_log import describe_audit_hmac_status
    from agent_bom.api.auth import get_api_key_policy
    from agent_bom.api.compliance_signing import describe_signing_posture
    from agent_bom.api.middleware import (
        describe_proxy_control_plane_mtls_posture,
        describe_security_header_posture,
        get_auth_runtime_status,
        get_rate_limit_key_status,
        get_rate_limit_runtime_status,
        get_trusted_proxy_auth_status,
    )
    from agent_bom.api.oidc import describe_oidc_posture
    from agent_bom.api.saml import describe_saml_posture
    from agent_bom.api.scim import describe_scim_posture
    from agent_bom.api.secret_lifecycle import describe_secret_lifecycle_posture
    from agent_bom.api.shared_auth_state import auth_state_posture
    from agent_bom.api.storage_schema import describe_control_plane_storage_schema
    from agent_bom.api.tenant_quota import default_tenant_quotas, get_tenant_quota_runtime
    from agent_bom.backpressure import describe_backpressure_posture
    from agent_bom.data_boundaries import describe_data_access_boundaries
    from agent_bom.proxy_sandbox import describe_proxy_sandbox_posture

    api_policy = get_api_key_policy()
    rl_status = get_rate_limit_key_status()
    rl_runtime = get_rate_limit_runtime_status()
    auth_runtime = get_auth_runtime_status()
    tenant_id = require_request_tenant_id(request)
    defaults = default_tenant_quotas()
    return {
        "api_key": {
            "default_ttl_seconds": api_policy.default_ttl_seconds,
            "max_ttl_seconds": api_policy.max_ttl_seconds,
            "default_overlap_seconds": api_policy.default_overlap_seconds,
            "max_overlap_seconds": api_policy.max_overlap_seconds,
            "rotation_policy": "enforced",
            "rotation_endpoint": "/v1/auth/keys/{key_id}/rotate",
        },
        "rate_limit_key": rl_status,
        "audit_hmac": describe_audit_hmac_status(),
        "ui": {
            "recommended_mode": auth_runtime["recommended_ui_mode"],
            "configured_modes": auth_runtime["configured_modes"],
            "browser_session": "signed_http_only_cookie",
            "session_storage_fallback": "disabled",
            "credentials_mode": "include",
            "trusted_proxy_headers": ["X-Agent-Bom-Role", "X-Agent-Bom-Tenant-ID", "X-Agent-Bom-Proxy-Secret"],
            "trusted_proxy_secret_env": "AGENT_BOM_TRUST_PROXY_AUTH_SECRET",
            "message": (
                "Recommended browser auth is same-origin reverse-proxy OIDC with the proxy injecting trusted "
                "X-Agent-Bom-* headers plus X-Agent-Bom-Proxy-Secret attestation. For single-user local or pilot "
                "access, the UI exchanges an API key for a signed, expiring, CSRF-bound httpOnly browser session cookie "
                "without storing the key in browser storage."
            ),
        },
        "rate_limit_runtime": rl_runtime,
        "trusted_proxy_auth": get_trusted_proxy_auth_status(),
        "proxy_control_plane_mtls": describe_proxy_control_plane_mtls_posture(),
        "security_headers": describe_security_header_posture(),
        "backpressure": describe_backpressure_posture(),
        "proxy_sandbox": describe_proxy_sandbox_posture(),
        "data_access_boundaries": describe_data_access_boundaries(),
        "auth_state_backend": auth_state_posture(),
        "secret_integrity": {
            "audit_hmac": describe_audit_hmac_status(),
            "compliance_signing": describe_signing_posture(),
        },
        "secret_lifecycle": describe_secret_lifecycle_posture(),
        "tenant_quotas": defaults,
        "tenant_quota_runtime": get_tenant_quota_runtime(tenant_id),
        "storage_schema": describe_control_plane_storage_schema(),
        "identity_provisioning": {
            "oidc": describe_oidc_posture(),
            "saml": describe_saml_posture(),
            "scim": describe_scim_posture(),
            "session_revocation": {
                "service_keys": "API key revocation takes effect immediately at the control-plane auth layer.",
                "session_api_key": (
                    "The browser fallback key is scoped to the current browser session and disappears when that local session is cleared."
                ),
                "browser_sessions": (
                    "OIDC or reverse-proxy browser sessions must be terminated at the upstream identity provider or trusted proxy."
                ),
            },
        },
    }


@router.get("/auth/scopes", tags=["enterprise"])
async def auth_scopes() -> dict:
    """Return the enforced RBAC scope catalog for operator tooling."""
    from agent_bom.api.middleware import APIKeyMiddleware

    scopes = APIKeyMiddleware.scope_catalog()
    return {
        "schema_version": "v1",
        "count": len(scopes),
        "wildcard_examples": ["*", "auth.*", "auth.keys:*"],
        "scopes": scopes,
    }


@router.get("/auth/secrets/lifecycle", tags=["enterprise"])
async def auth_secret_lifecycle() -> dict:
    """Return non-secret lifecycle posture for configured control-plane secrets."""
    from agent_bom.api.secret_lifecycle import describe_secret_lifecycle_posture

    return describe_secret_lifecycle_posture()


@router.get("/auth/secrets/rotation-plan", tags=["enterprise"])
async def auth_secret_rotation_plan() -> dict:
    """Return a non-secret operator plan for rotating control-plane secrets."""
    from agent_bom.api.secret_lifecycle import build_secret_rotation_plan

    return build_secret_rotation_plan()


@router.get("/auth/secrets/credential-expiry", tags=["enterprise"])
async def auth_secret_credential_expiry() -> dict:
    """Return non-secret credential expiry/rotation governance.

    Folds in any discovered non-human-identity (NHI) credentials so an
    operator's expiring Okta/Entra service-app / service-principal secrets are
    governed alongside control-plane secrets. NHI discovery is gated by its own
    ``*_DISCOVERY`` env flags and is a no-op (no network) when they are off, so
    this stays control-plane-only by default.
    """
    from agent_bom.api.credential_expiry import describe_credential_expiry_posture

    discovered = _discover_nhi_credentials()
    return describe_credential_expiry_posture(discovered or None)


def _discover_nhi_credentials() -> list[dict]:
    """Run gated NHI discovery and return reference-only credential records.

    Each record carries ``{id, name, credential_expires_at}`` for the expiry
    classifier — never secret material. Both providers self-gate on their
    ``*_DISCOVERY`` flag, so this returns an empty list (and makes no network
    call) when discovery is disabled. Never raises into the request path.
    """
    try:
        from agent_bom.graph.nhi_overlay import merge_discovery_results
        from agent_bom.identity import (
            discover_entra_non_human_identities,
            discover_okta_non_human_identities,
        )

        merged = merge_discovery_results([discover_okta_non_human_identities(), discover_entra_non_human_identities()])
        records: list[dict] = []
        for identity in merged.get("identities", []):
            if not isinstance(identity, dict):
                continue
            if not identity.get("credential_expires_at"):
                continue
            records.append(
                {
                    "id": identity.get("identity_id"),
                    "name": identity.get("name"),
                    "credential_expires_at": identity.get("credential_expires_at"),
                    "last_rotated": identity.get("last_rotated"),
                }
            )
        return records
    except Exception:  # noqa: BLE001 — credential-expiry posture must never fail on discovery
        return []


@router.get("/auth/scim/config", tags=["enterprise"])
async def auth_scim_config() -> dict:
    """Return the operator-facing SCIM configuration posture."""
    from agent_bom.api.scim import describe_scim_posture

    return describe_scim_posture()


@router.get("/auth/quota", tags=["enterprise"])
async def auth_quota(request: Request) -> dict:
    """Return the effective tenant quota runtime surface for the current tenant."""
    from agent_bom.api.tenant_quota import get_tenant_quota_runtime

    tenant_id = require_request_tenant_id(request)
    return get_tenant_quota_runtime(tenant_id)


@router.put("/auth/quota", tags=["enterprise"])
async def update_auth_quota(request: Request, req: TenantQuotaUpdateRequest) -> dict:
    """Update tenant-specific quota overrides for the current tenant."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.tenant_quota import (
        QUOTA_NAMES,
        get_tenant_quota_overrides,
        get_tenant_quota_runtime,
        set_tenant_quota_overrides,
    )

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    updates = {name: getattr(req, name) for name in QUOTA_NAMES if name in req.model_fields_set}
    if not updates:
        raise HTTPException(status_code=400, detail="Provide at least one quota field to update.")

    previous = get_tenant_quota_overrides(tenant_id)
    current = set_tenant_quota_overrides(tenant_id, updates)
    log_action(
        "tenant.quota_updated",
        actor=actor,
        resource=f"tenant/{tenant_id}",
        tenant_id=tenant_id,
        previous_overrides=previous,
        current_overrides=current,
        updated_fields=sorted(updates),
    )
    return get_tenant_quota_runtime(tenant_id)


@router.delete("/auth/quota", tags=["enterprise"], status_code=204)
async def reset_auth_quota(request: Request) -> None:
    """Clear all tenant-specific quota overrides for the current tenant."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.tenant_quota import clear_tenant_quota_overrides, get_tenant_quota_overrides

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    previous = get_tenant_quota_overrides(tenant_id)
    clear_tenant_quota_overrides(tenant_id)
    log_action(
        "tenant.quota_reset",
        actor=actor,
        resource=f"tenant/{tenant_id}",
        tenant_id=tenant_id,
        previous_overrides=previous,
    )


@router.get("/auth/debug", tags=["enterprise"])
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
    state = _auth_session_state(request)
    return {
        "authenticated": state["authenticated"],
        "auth_required": state["auth_required"],
        "configured_modes": state["configured_modes"],
        "recommended_ui_mode": state["recommended_ui_mode"],
        "auth_method": state["auth_method"],
        "subject": state["subject"],
        "role": state["role"],
        "tenant_id": state["tenant_id"],
        "oidc_issuer_suffix": state["oidc_issuer_suffix"],
        "api_key_id_prefix": state["api_key_id_prefix"],
        "request_id": state["request_id"],
        "trace_id": state["trace_id"],
        "span_id": state["span_id"],
    }


@router.get("/auth/me", tags=["enterprise"])
async def auth_me(request: Request) -> dict:
    """Return the current UI-facing actor/session contract for the active tenant."""
    state = _auth_session_state(request)
    role_summary = state["role_summary"]
    memberships = []
    if role_summary is not None:
        memberships.append(
            {
                "tenant_id": state["tenant_id"],
                "role": role_summary["role"],
                "ui_role": role_summary["ui_role"],
                "display_name": role_summary["display_name"],
                "active": True,
            }
        )

    return {
        "authenticated": state["authenticated"],
        "auth_required": state["auth_required"],
        "configured_modes": state["configured_modes"],
        "recommended_ui_mode": state["recommended_ui_mode"],
        "sso_provider": state["sso_provider"],
        "auth_method": state["auth_method"],
        "subject": state["subject"],
        "tenant_id": state["tenant_id"],
        "role": state["role"],
        "role_summary": role_summary,
        "memberships": memberships,
        "request_id": state["request_id"],
        "trace_id": state["trace_id"],
        "span_id": state["span_id"],
    }


@router.delete("/auth/keys/{key_id}", tags=["enterprise"], status_code=204)
async def delete_key(request: Request, key_id: str) -> None:
    """Revoke an API key."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import get_key_store

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "")
    store = get_key_store()
    key = store.get(key_id)
    if key is None or key.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail=f"Key {key_id} not found")
    store.remove(key_id)

    log_action("auth.key_revoked", actor=actor, resource=f"key/{key_id}", tenant_id=tenant_id)


def _oidc_login_nonce(state: str) -> str:
    return f"oidc-login:{_relay_state_digest(state)}"


def _new_oidc_login_state() -> str:
    from agent_bom.api.shared_auth_state import get_auth_state

    backend = get_auth_state()
    ttl = int(os.environ.get("AGENT_BOM_OIDC_LOGIN_STATE_TTL_SECONDS") or "300")
    try:
        ttl = max(60, min(ttl, 900))
    except (TypeError, ValueError):
        ttl = 300
    now = int(time.time())
    expires_at = now + ttl
    for _ in range(3):
        state = secrets.token_urlsafe(32)
        if backend.register_one_time_nonce(_oidc_login_nonce(state), expires_at, now=now):
            return state
    raise HTTPException(status_code=503, detail="OIDC login state issuance unavailable")


def _consume_oidc_login_state(state: str | None) -> None:
    if not state:
        raise HTTPException(status_code=401, detail="OIDC state required")
    from agent_bom.api.shared_auth_state import get_auth_state

    backend = get_auth_state()
    now = int(time.time())
    if not backend.redeem_one_time_nonce(_oidc_login_nonce(state), now=now):
        raise HTTPException(status_code=401, detail="Invalid or expired OIDC state")


def _safe_post_login_path(raw: str | None) -> str:
    normalized = (raw or "/").strip().replace("\\", "/") or "/"
    parsed = urlsplit(normalized)
    if parsed.scheme or parsed.netloc:
        return "/"
    local_path = parsed.path or "/"
    if not local_path.startswith("/") or local_path.startswith("//"):
        return "/"
    suffix = f"?{parsed.query}" if parsed.query else ""
    if parsed.fragment:
        suffix += f"#{parsed.fragment}"
    return f"{local_path}{suffix}"


def _allowed_post_login_path(raw: str | None) -> str:
    safe_path = _safe_post_login_path(raw)
    parsed = urlsplit(safe_path)
    base_path = parsed.path or "/"
    allowed_paths = {
        "/",
        "/dashboard",
        "/findings",
        "/exceptions",
        "/baselines",
        "/trends",
        "/settings",
    }
    if base_path not in allowed_paths:
        return "/"
    suffix = f"?{parsed.query}" if parsed.query else ""
    if parsed.fragment:
        suffix += f"#{parsed.fragment}"
    return f"{base_path}{suffix}"


@router.get("/auth/oidc/login", tags=["enterprise"])
async def oidc_browser_login(request: Request, return_to: str | None = None) -> RedirectResponse:
    """Start OIDC authorization-code + PKCE login for the dashboard."""
    from agent_bom.api.oidc import OIDCError
    from agent_bom.api.oidc_browser import (
        OIDC_PKCE_COOKIE_NAME,
        OIDCBrowserConfig,
        build_authorize_url,
        pkce_challenge_s256,
        pkce_verifier,
        seal_pkce_cookie,
    )

    _check_auth_session_rate_limit(request)
    try:
        cfg = OIDCBrowserConfig.from_env()
    except OIDCError as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc)) from exc
    if not cfg.enabled:
        raise HTTPException(
            status_code=503,
            detail="OIDC browser SSO requires AGENT_BOM_OIDC_ISSUER, AGENT_BOM_OIDC_CLIENT_ID, and AGENT_BOM_OIDC_REDIRECT_URI",
        )

    state = _new_oidc_login_state()
    nonce = secrets.token_urlsafe(32)
    verifier = pkce_verifier()
    challenge = pkce_challenge_s256(verifier)
    try:
        authorize_url = build_authorize_url(cfg, state=state, nonce=nonce, code_challenge=challenge)
        sealed = seal_pkce_cookie(
            code_verifier=verifier,
            nonce=nonce,
        )
    except OIDCError as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc)) from exc

    response = RedirectResponse(url=authorize_url, status_code=302)
    secure = _session_cookie_secure(request)
    response.set_cookie(
        OIDC_PKCE_COOKIE_NAME,
        sealed,
        max_age=300,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
    )
    return response


@router.get("/auth/oidc/callback", tags=["enterprise"])
async def oidc_browser_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> RedirectResponse:
    """Complete OIDC auth-code + PKCE login and mint a browser session cookie."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import Role, resolve_scim_user_role
    from agent_bom.api.oidc import OIDCError, claims_have_role_signal, claims_to_role
    from agent_bom.api.oidc_browser import (
        OIDC_PKCE_COOKIE_NAME,
        OIDCBrowserConfig,
        exchange_code_for_tokens,
        open_pkce_cookie,
        subject_from_claims,
        verify_browser_id_token,
    )

    _check_auth_session_rate_limit(request)
    if error:
        detail = sanitize_text(error_description or error)
        raise HTTPException(status_code=401, detail=f"OIDC login failed: {detail}")
    if not code:
        raise HTTPException(status_code=401, detail="OIDC authorization code required")

    _consume_oidc_login_state(state)
    sealed = request.cookies.get(OIDC_PKCE_COOKIE_NAME, "")
    if not sealed:
        raise HTTPException(status_code=401, detail="OIDC PKCE cookie missing")

    try:
        cfg = OIDCBrowserConfig.from_env()
        code_verifier, nonce, return_to = open_pkce_cookie(sealed)
        token_payload = exchange_code_for_tokens(cfg, code=code, code_verifier=code_verifier)
        id_token = str(token_payload.get("id_token") or "").strip()
        if not id_token:
            raise OIDCError("OIDC token response missing id_token")
        claims = verify_browser_id_token(cfg, id_token, nonce=nonce)
        if cfg.oidc.require_role_claim and not claims_have_role_signal(claims, cfg.oidc.role_claim):
            raise OIDCError(f"JWT missing required role claim '{cfg.oidc.role_claim}'")
        role = claims_to_role(claims, cfg.oidc.role_claim)
        tenant_id = cfg.oidc.resolve_tenant(claims)
        subject = subject_from_claims(claims)
    except OIDCError as exc:
        raise HTTPException(status_code=401, detail=sanitize_error(exc)) from exc

    scim_resolution = resolve_scim_user_role(tenant_id, subject)
    effective_role = scim_resolution.role.value if scim_resolution.role is not None else role
    try:
        role_value = Role(effective_role).value
    except ValueError:
        role_value = Role.VIEWER.value

    return_to = _allowed_post_login_path(return_to)
    response = RedirectResponse(url=return_to, status_code=302)
    _set_browser_session_cookie(
        response,
        request,
        subject=subject,
        role=role_value,
        tenant_id=tenant_id,
        auth_method="oidc_browser",
        scopes=["oidc-browser-session"],
    )
    secure = _session_cookie_secure(request)
    response.delete_cookie(OIDC_PKCE_COOKIE_NAME, httponly=True, secure=secure, samesite="lax", path="/")
    log_action(
        "auth.oidc_browser_login",
        actor=subject,
        resource="auth/oidc",
        tenant_id=tenant_id,
        details={"role": role_value, "auth_method": "oidc_browser"},
    )
    return response


def _snowflake_login_nonce(state: str) -> str:
    return f"snowflake-oauth-login:{_relay_state_digest(state)}"


def _new_snowflake_login_state() -> str:
    from agent_bom.api.shared_auth_state import get_auth_state

    backend = get_auth_state()
    ttl = int(os.environ.get("AGENT_BOM_OIDC_LOGIN_STATE_TTL_SECONDS") or "300")
    try:
        ttl = max(60, min(ttl, 900))
    except (TypeError, ValueError):
        ttl = 300
    now = int(time.time())
    expires_at = now + ttl
    for _ in range(3):
        state = secrets.token_urlsafe(32)
        if backend.register_one_time_nonce(_snowflake_login_nonce(state), expires_at, now=now):
            return state
    raise HTTPException(status_code=503, detail="Snowflake OAuth login state issuance unavailable")


def _consume_snowflake_login_state(state: str | None) -> None:
    if not state:
        raise HTTPException(status_code=401, detail="Snowflake OAuth state required")
    from agent_bom.api.shared_auth_state import get_auth_state

    backend = get_auth_state()
    now = int(time.time())
    if not backend.redeem_one_time_nonce(_snowflake_login_nonce(state), now=now):
        raise HTTPException(status_code=401, detail="Invalid or expired Snowflake OAuth state")


@router.get("/auth/snowflake/login", tags=["enterprise"])
async def snowflake_oauth_login(request: Request) -> RedirectResponse:
    """Start Snowflake OAuth authorization-code + PKCE sign-in for the dashboard."""
    from agent_bom.api.oidc import OIDCError
    from agent_bom.api.oidc_browser import (
        OIDC_PKCE_COOKIE_NAME,
        pkce_challenge_s256,
        pkce_verifier,
        seal_pkce_cookie,
    )
    from agent_bom.api.snowflake_oauth import SnowflakeOAuthConfig, build_authorize_url

    _check_auth_session_rate_limit(request)
    try:
        cfg = SnowflakeOAuthConfig.from_env()
    except OIDCError as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc)) from exc
    if not cfg.enabled:
        raise HTTPException(
            status_code=503,
            detail=(
                "Snowflake OAuth sign-in requires AGENT_BOM_SNOWFLAKE_OAUTH_ACCOUNT_URL, "
                "AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_ID, and AGENT_BOM_SNOWFLAKE_OAUTH_REDIRECT_URI"
            ),
        )

    state = _new_snowflake_login_state()
    verifier = pkce_verifier()
    challenge = pkce_challenge_s256(verifier)
    try:
        authorize_url = build_authorize_url(cfg, state=state, code_challenge=challenge)
        sealed = seal_pkce_cookie(code_verifier=verifier, nonce=secrets.token_urlsafe(16))
    except OIDCError as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc)) from exc

    response = RedirectResponse(url=authorize_url, status_code=302)
    secure = _session_cookie_secure(request)
    response.set_cookie(
        OIDC_PKCE_COOKIE_NAME,
        sealed,
        max_age=300,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
    )
    return response


@router.get("/auth/snowflake/callback", tags=["enterprise"])
async def snowflake_oauth_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> RedirectResponse:
    """Complete Snowflake OAuth sign-in and mint a browser session cookie.

    Snowflake's OAuth server is non-standard: no ID token, JWKS, or userinfo.
    Identity is the ``username`` returned by the token endpoint (fail closed if
    absent). Role defaults to the configured least-privilege role and is only
    elevated by an explicit SCIM mapping for the user.
    """
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import Role, resolve_scim_user_role
    from agent_bom.api.oidc import OIDCError
    from agent_bom.api.oidc_browser import OIDC_PKCE_COOKIE_NAME, open_pkce_cookie
    from agent_bom.api.snowflake_oauth import (
        SnowflakeOAuthConfig,
        exchange_code_for_tokens,
        username_from_token_response,
    )

    _check_auth_session_rate_limit(request)
    if error:
        detail = sanitize_text(error_description or error)
        raise HTTPException(status_code=401, detail=f"Snowflake OAuth login failed: {detail}")
    if not code:
        raise HTTPException(status_code=401, detail="Snowflake OAuth authorization code required")

    _consume_snowflake_login_state(state)
    sealed = request.cookies.get(OIDC_PKCE_COOKIE_NAME, "")
    if not sealed:
        raise HTTPException(status_code=401, detail="Snowflake OAuth PKCE cookie missing")

    try:
        cfg = SnowflakeOAuthConfig.from_env()
        code_verifier, _nonce, _return_to = open_pkce_cookie(sealed)
        token_payload = exchange_code_for_tokens(cfg, code=code, code_verifier=code_verifier)
        subject = username_from_token_response(token_payload)
    except OIDCError as exc:
        raise HTTPException(status_code=401, detail=sanitize_error(exc)) from exc

    tenant_id = cfg.tenant_id
    try:
        default_role = Role(cfg.default_role).value
    except ValueError:
        default_role = Role.VIEWER.value
    scim_resolution = resolve_scim_user_role(tenant_id, subject)
    effective_role = scim_resolution.role.value if scim_resolution.role is not None else default_role
    try:
        role_value = Role(effective_role).value
    except ValueError:
        role_value = Role.VIEWER.value

    response = RedirectResponse(url="/", status_code=302)
    _set_browser_session_cookie(
        response,
        request,
        subject=subject,
        role=role_value,
        tenant_id=tenant_id,
        auth_method="snowflake_oauth",
        scopes=["snowflake-oauth-session"],
    )
    secure = _session_cookie_secure(request)
    response.delete_cookie(OIDC_PKCE_COOKIE_NAME, httponly=True, secure=secure, samesite="lax", path="/")
    log_action(
        "auth.snowflake_oauth_login",
        actor=subject,
        resource="auth/snowflake",
        tenant_id=tenant_id,
        details={"role": role_value, "auth_method": "snowflake_oauth"},
    )
    return response


@router.get("/auth/saml/metadata", tags=["enterprise"])
async def saml_metadata() -> PlainTextResponse:
    """Return SP metadata XML for enterprise IdP configuration."""
    from agent_bom.api.saml import SAML_INSTALL_HINT, SAMLConfig, SAMLError, saml_runtime_available

    if not saml_runtime_available():
        raise HTTPException(
            status_code=503,
            detail=f"SAML SSO requires the optional [saml] extra. Install with: {SAML_INSTALL_HINT}",
        )
    try:
        metadata = SAMLConfig.from_env().metadata_xml()
    except SAMLError as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc)) from exc
    return PlainTextResponse(content=metadata, media_type="application/samlmetadata+xml")


@router.post("/auth/saml/relay-state", tags=["enterprise"])
async def saml_relay_state() -> dict:
    """Issue a one-time RelayState nonce for SP-initiated SAML login."""
    relay_state, expires_at = _new_saml_relay_state()
    return {
        "relay_state": relay_state,
        "expires_at": expires_at,
        "ttl_seconds": _saml_relay_ttl_seconds(),
    }


@router.post("/auth/saml/login", tags=["enterprise"], status_code=201)
async def saml_login(req: SAMLLoginRequest) -> dict:
    """Verify a SAML assertion and return a short-lived API key."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import Role, create_api_key, get_key_store, resolve_scim_user_role
    from agent_bom.api.saml import SAML_INSTALL_HINT, SAMLConfig, SAMLError, saml_runtime_available

    if not saml_runtime_available():
        raise HTTPException(
            status_code=503,
            detail=f"SAML SSO requires the optional [saml] extra. Install with: {SAML_INSTALL_HINT}",
        )
    try:
        _consume_saml_relay_state(req.relay_state)
        cfg = SAMLConfig.from_env()
        assertion = cfg.verify_response(req.saml_response, relay_state=req.relay_state)
        _consume_saml_response_once(req.saml_response, ttl_seconds=cfg.session_ttl_seconds)
    except SAMLError as exc:
        raise HTTPException(status_code=401, detail=sanitize_error(exc)) from exc

    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=cfg.session_ttl_seconds)).isoformat()
    scim_resolution = resolve_scim_user_role(assertion.tenant_id, assertion.subject)
    scim_subject_id = scim_resolution.user_id if scim_resolution.user_id else assertion.subject
    raw_key, api_key = create_api_key(
        name=f"saml:{assertion.subject}",
        role=Role(assertion.role),
        expires_at=expires_at,
        scopes=["saml-session"],
        tenant_id=assertion.tenant_id,
        scim_subject_id=scim_subject_id,
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


@router.get("/audit", tags=["enterprise"])
async def list_audit_entries(
    request: Request,
    action: str | None = None,
    resource: str | None = None,
    since: str | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    """List audit log entries with optional filters."""
    from agent_bom.api.audit_log import get_audit_log

    tenant_id = require_request_tenant_id(request)
    store = get_audit_log()
    entries = store.list_entries(action=action, resource=resource, since=since, limit=limit, offset=offset, tenant_id=tenant_id)
    return {
        # schema_version on terminal list response.
        "schema_version": "v1",
        "entries": [e.to_dict() for e in entries],
        "total": store.count(action=action, tenant_id=tenant_id),
        "limit": limit,
        "offset": offset,
    }


def _configured_runtime_audit_log_path() -> Path | None:
    """Return the configured runtime proxy JSONL audit log, when readable."""
    log_env = os.environ.get("AGENT_BOM_LOG")
    if not log_env:
        return None
    path = Path(log_env).resolve()
    if path.is_file() and path.suffix == ".jsonl":
        return path
    return None


@router.get("/audit/integrity", tags=["enterprise"])
async def audit_integrity(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=10_000)] = 1000,
    include_runtime: bool = True,
) -> dict:
    """Verify control-plane and runtime audit-chain integrity."""
    from agent_bom.api.audit_log import get_audit_log
    from agent_bom.audit_integrity import verify_audit_jsonl_chain

    tenant_id = require_request_tenant_id(request)
    verified, tampered = get_audit_log().verify_integrity(limit=limit, tenant_id=tenant_id)
    chains: list[dict[str, Any]] = [
        {
            "name": "control_plane",
            "algorithm": "hmac-sha256",
            "verified": verified,
            "tampered": tampered,
            "checked": verified + tampered,
            "tenant_scoped": True,
        }
    ]

    if include_runtime:
        runtime_log = _configured_runtime_audit_log_path()
        if runtime_log is not None:
            runtime = verify_audit_jsonl_chain(runtime_log, max_lines=limit)
            runtime_algorithms = list(runtime.get("algorithms") or ["unknown"])
            chains.append(
                {
                    "name": "runtime_proxy",
                    "algorithm": ",".join(runtime_algorithms),
                    "algorithms": runtime_algorithms,
                    "verified": int(runtime.get("verified", 0)),
                    "tampered": int(runtime.get("tampered", 0)),
                    "checked": int(runtime.get("checked", 0)),
                    "tenant_scoped": False,
                    "source": "AGENT_BOM_LOG",
                    "error": runtime.get("error", ""),
                }
            )

    total_verified = sum(int(chain["verified"]) for chain in chains)
    total_tampered = sum(int(chain["tampered"]) for chain in chains)
    algorithms = sorted({algorithm for chain in chains for algorithm in str(chain["algorithm"]).split(",") if algorithm})
    return {
        "verified": total_verified,
        "tampered": total_tampered,
        "checked": total_verified + total_tampered,
        "algorithms": algorithms,
        "chains": chains,
    }


@router.get("/audit/export", tags=["enterprise"])
async def export_audit_entries(
    request: Request,
    action: str | None = None,
    resource: str | None = None,
    since: str | None = None,
    limit: Annotated[int, Query(ge=1, le=10_000)] = 1000,
    offset: Annotated[int, Query(ge=0)] = 0,
    format: str = "json",
):
    """Export audit entries as a signed evidence packet."""
    from agent_bom.api.audit_log import get_audit_log, log_action, sign_export_payload

    fmt = format.lower()
    if fmt not in {"json", "jsonl"}:
        raise HTTPException(status_code=400, detail="format must be one of: json, jsonl")

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    store = get_audit_log()
    entries = store.list_entries(action=action, resource=resource, since=since, limit=limit, offset=offset, tenant_id=tenant_id)
    verified, tampered = store.verify_integrity(limit=min(limit, 10_000), tenant_id=tenant_id)

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


@router.post("/audit/export/verify", tags=["enterprise"])
async def verify_audit_export(request: Request, body: AuditExportVerifyRequest) -> dict:
    """Verify a signed audit export packet without returning HMAC key material."""
    from agent_bom.api.audit_log import log_action, verify_export_payload

    if isinstance(body.payload, str):
        payload = body.payload.encode("utf-8")
    else:
        payload = json.dumps(body.payload, sort_keys=True).encode("utf-8")

    valid = verify_export_payload(payload, body.signature)
    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    log_action(
        "audit.export_verify",
        actor=actor,
        resource="audit/export/verify",
        tenant_id=tenant_id,
        valid=valid,
        payload_bytes=len(payload),
    )
    return {"valid": valid, "payload_bytes": len(payload)}


# ── Exception / Waiver Management ────────────────────────────────────────────


@router.post("/exceptions", tags=["enterprise"], status_code=201)
async def create_exception(request: Request, req: ExceptionRequest) -> dict:
    """Request a vulnerability exception / waiver."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import VulnException

    tenant_id = require_request_tenant_id(request)
    actor = _request_actor(request)
    exc = VulnException(
        vuln_id=req.vuln_id,
        package_name=req.package_name,
        server_name=req.server_name,
        reason=req.reason,
        requested_by=actor,
        expires_at=req.expires_at,
        tenant_id=tenant_id,
    )
    _get_exception_store().put(exc)
    log_action(
        "exception_create",
        actor=actor,
        resource=f"exception/{exc.exception_id}",
        tenant_id=tenant_id,
        vuln_id=req.vuln_id,
        package=req.package_name,
    )
    return exc.to_dict()


@router.get("/exceptions", tags=["enterprise"])
async def list_exceptions(
    request: Request,
    status: str | None = None,
    # cap exception pagination to keep parity with /v1/audit.
    limit: Annotated[int, Query(ge=1, le=1000)] = 1000,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    """List all vulnerability exceptions."""
    tenant_id = require_request_tenant_id(request)
    all_exceptions = _get_exception_store().list_all(status=status, tenant_id=tenant_id)
    total = len(all_exceptions)
    page = all_exceptions[offset : offset + limit]
    return {
        # schema_version on terminal list response.
        "schema_version": "v1",
        "exceptions": [e.to_dict() for e in page],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/exceptions/{exception_id}", tags=["enterprise"])
async def get_exception(request: Request, exception_id: str) -> dict:
    """Get a specific exception."""
    tenant_id = require_request_tenant_id(request)
    exc = _get_exception_store().get(exception_id, tenant_id=tenant_id)
    if exc is None:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    return exc.to_dict()


@router.put("/exceptions/{exception_id}/approve", tags=["enterprise"])
async def approve_exception(request: Request, exception_id: str) -> dict:
    """Approve a pending exception (admin only)."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import ExceptionStatus

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    store = _get_exception_store()
    exc = store.get(exception_id, tenant_id=tenant_id)
    if exc is None:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    if exc.status != ExceptionStatus.PENDING:
        raise HTTPException(status_code=409, detail=f"Cannot approve exception in {exc.status.value} state")
    exc.status = ExceptionStatus.ACTIVE
    exc.approved_by = actor
    exc.approved_at = datetime.now(timezone.utc).isoformat()
    store.put(exc)
    log_action("exception_approve", actor=actor, resource=f"exception/{exception_id}", tenant_id=tenant_id)
    return exc.to_dict()


@router.put("/exceptions/{exception_id}/revoke", tags=["enterprise"])
async def revoke_exception(request: Request, exception_id: str) -> dict:
    """Revoke an active exception."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import ExceptionStatus

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    store = _get_exception_store()
    exc = store.get(exception_id, tenant_id=tenant_id)
    if exc is None:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    exc.status = ExceptionStatus.REVOKED
    exc.revoked_at = datetime.now(timezone.utc).isoformat()
    store.put(exc)
    log_action("exception_revoke", actor=actor, resource=f"exception/{exception_id}", tenant_id=tenant_id)
    return exc.to_dict()


@router.delete("/exceptions/{exception_id}", tags=["enterprise"], status_code=204)
async def delete_exception(request: Request, exception_id: str) -> None:
    """Delete an exception."""
    from agent_bom.api.audit_log import log_action

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    store = _get_exception_store()
    exc = store.get(exception_id, tenant_id=tenant_id)
    if exc is None:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    ok = store.delete(exception_id, tenant_id=tenant_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    log_action("exception_delete", actor=actor, resource=f"exception/{exception_id}", tenant_id=tenant_id)


# ── Baseline Comparison & Trends ─────────────────────────────────────────────


@router.post("/baseline/compare", tags=["enterprise"])
async def compare_baseline(
    request: Request,
    previous_job_id: Annotated[str, Query(min_length=1)],
    current_job_id: Annotated[str, Query(min_length=1)],
) -> dict:
    """Compare two scan results to show new, resolved, and persistent vulnerabilities."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.baseline import compare_reports

    store = _get_store()
    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    prev_job = store.get(previous_job_id, tenant_id=tenant_id)
    curr_job = store.get(current_job_id, tenant_id=tenant_id)
    if prev_job is None:
        raise HTTPException(status_code=404, detail="Previous job not found")
    if curr_job is None:
        raise HTTPException(status_code=404, detail="Current job not found")

    prev_report = prev_job.result or {}
    curr_report = curr_job.result or {}

    diff = compare_reports(prev_report, curr_report)
    log_action(
        "baseline.compare",
        actor=actor,
        resource="baseline/compare",
        tenant_id=tenant_id,
        previous_job_id=previous_job_id,
        current_job_id=current_job_id,
    )
    return diff.to_dict()


@router.get("/trends", tags=["enterprise"])
async def get_trends(request: Request, limit: int = 30) -> dict:
    """Get historical trend data — posture score and vuln counts over time."""
    from agent_bom.api.audit_log import log_action

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    history = _get_trend_store().get_history(limit=limit, tenant_id=tenant_id)
    log_action("trends.view", actor=actor, resource="trends", tenant_id=tenant_id, limit=limit)
    return {
        "data_points": [p.to_dict() for p in history],
        "count": len(history),
    }


# ── SIEM Connectors ─────────────────────────────────────────────────────────


@router.get("/siem/connectors", tags=["enterprise"])
async def list_siem_connectors() -> dict:
    """List available SIEM connector types."""
    from agent_bom.siem import list_connectors

    return {"connectors": list_connectors()}


@router.post("/siem/test", tags=["enterprise"])
async def test_siem_connection(
    request: Request,
    siem_type: str = "",
    url: str = "",
    token: str = Header(default="", alias="X-Siem-Token"),
) -> dict:
    """Test SIEM connectivity."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.security import validate_url
    from agent_bom.siem import SIEMConfig, create_connector

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"

    # Validate URL to prevent SSRF
    if url:
        try:
            validate_url(url)
        except Exception as url_exc:
            raise HTTPException(status_code=400, detail=f"Invalid URL: {sanitize_error(url_exc)}")

    try:
        connector = create_connector(siem_type, SIEMConfig(name=siem_type, url=url, token=token))
        healthy = connector.health_check()
        log_action(
            "siem.test",
            actor=actor,
            resource=f"siem/{siem_type or 'unknown'}",
            tenant_id=tenant_id,
            healthy=healthy,
            url=url,
        )
        return {"siem_type": siem_type, "healthy": healthy}
    except ValueError as exc:
        _logger.info("Invalid SIEM test request: %s", sanitize_error(exc))
        raise HTTPException(status_code=400, detail="Invalid SIEM connector request") from exc
    except Exception as exc:
        _logger.exception(
            "Unexpected error while testing SIEM connection: %s",
            sanitize_error(exc),
        )
        log_action(
            "siem.test",
            actor=actor,
            resource=f"siem/{siem_type or 'unknown'}",
            tenant_id=tenant_id,
            healthy=False,
            error="Failed to test SIEM connection",
            url=url,
        )
        return {
            "siem_type": siem_type,
            "healthy": False,
            "error": "Failed to test SIEM connection",
        }


# ── Jira Integration ────────────────────────────────────────────────────────


@router.post("/findings/jira", tags=["enterprise"], status_code=201)
async def create_jira_ticket_route(
    request: Request,
    req: JiraTicketRequest,
    jira_api_token: str | None = Header(default=None, alias="X-Jira-Api-Token"),
) -> dict:
    """Create a Jira ticket from a finding (admin/analyst only)."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.integrations.jira import create_jira_ticket
    from agent_bom.security import validate_url

    if not jira_api_token:
        raise HTTPException(status_code=400, detail="Missing X-Jira-Api-Token header")
    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or req.email or "system"
    target_kind, target_id = _jira_mapping_target(req)
    mapping_store = _get_issue_mapping_store()
    existing = mapping_store.find(tenant_id=tenant_id, target_kind=target_kind, target_id=target_id, provider="jira")
    if existing:
        return {
            "ticket_key": existing.external_id,
            "status": "existing",
            "mapping": existing.to_dict(),
        }

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

    mapping = mapping_store.put(
        tenant_id=tenant_id,
        target_kind=target_kind,
        target_id=target_id,
        provider="jira",
        external_id=ticket_key,
        external_url=_jira_issue_url(req.jira_url, ticket_key),
        status="open",
    )
    log_action(
        "findings.jira_ticket_created",
        actor=actor,
        resource=f"jira/{ticket_key}",
        tenant_id=tenant_id,
        vuln_id=req.finding.get("vulnerability_id", ""),
        package=req.finding.get("package", ""),
        issue_mapping_id=mapping.mapping_id,
        target_kind=target_kind,
        target_id=target_id,
    )

    return {"ticket_key": ticket_key, "status": "created", "mapping": mapping.to_dict()}


@router.put("/integrations/issues/{mapping_id}/status", tags=["enterprise"])
async def update_issue_mapping_status(request: Request, mapping_id: str, req: IssueStatusUpdateRequest) -> dict:
    """Update tenant-scoped external issue mapping status after provider sync."""
    from agent_bom.api.audit_log import log_action

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    mapping = _get_issue_mapping_store().update_status(mapping_id, tenant_id=tenant_id, status=req.status)
    if not mapping:
        raise HTTPException(status_code=404, detail="Issue mapping not found")
    log_action(
        "integrations.issue_status_updated",
        actor=actor,
        resource=f"{mapping.provider}/{mapping.external_id}",
        tenant_id=tenant_id,
        issue_mapping_id=mapping.mapping_id,
        status=mapping.status,
    )
    return {"mapping": mapping.to_dict()}


# ── False Positive Management ────────────────────────────────────────────────


@router.post("/findings/false-positive", tags=["enterprise"], status_code=201)
async def mark_false_positive(request: Request, req: FalsePositiveRequest) -> dict:
    """Mark a finding as false positive."""
    feedback = await create_finding_feedback(
        request,
        FindingFeedbackRequest(
            vulnerability_id=req.vulnerability_id,
            package=req.package,
            state="false_positive",
            reason=req.reason,
            server_name="",
            expires_at="",
        ),
    )
    return {
        "id": feedback["id"],
        "vulnerability_id": feedback["vulnerability_id"],
        "package": feedback["package"],
        "reason": feedback["reason"],
        "marked_by": feedback["marked_by"],
        "status": "false_positive",
        "created_at": feedback["created_at"],
    }


@router.post("/findings/feedback", tags=["enterprise"], status_code=201)
async def create_finding_feedback(request: Request, req: FindingFeedbackRequest) -> dict:
    """Record tenant-scoped finding feedback or suppression state."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import ExceptionStatus, VulnException

    tenant_id = require_request_tenant_id(request)
    actor = _request_actor(request)
    exc = VulnException(
        vuln_id=req.vulnerability_id,
        package_name=req.package,
        server_name=req.server_name,
        reason=_feedback_reason(req.state, req.reason),
        requested_by=actor,
        status=ExceptionStatus.ACTIVE,
        expires_at=req.expires_at,
        tenant_id=tenant_id,
    )
    _get_exception_store().put(exc)
    log_action(
        "findings.feedback_recorded",
        actor=actor,
        resource=f"finding-feedback/{exc.exception_id}",
        tenant_id=tenant_id,
        vuln_id=req.vulnerability_id,
        package=req.package,
        state=req.state,
        expires_at=req.expires_at,
    )
    return _feedback_response(exc)


@router.get("/findings/feedback", tags=["enterprise"])
async def list_finding_feedback(request: Request, state: str | None = None) -> dict:
    """List tenant-scoped finding feedback entries."""
    tenant_id = require_request_tenant_id(request)
    entries = []
    for exc in _get_exception_store().list_all(tenant_id=tenant_id):
        parsed = _parse_feedback_reason(exc.reason)
        if parsed is None:
            continue
        entry_state, _ = parsed
        if state and entry_state != state:
            continue
        entries.append(_feedback_response(exc))
    return {"feedback": entries, "total": len(entries)}


@router.post("/findings/triage", tags=["enterprise"], status_code=201)
async def create_finding_triage(request: Request, req: FindingTriageRequest) -> dict:
    """Create a tenant-scoped finding triage queue item."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import ExceptionStatus, VulnException

    _validate_triage_decision(req.decision, req.justification)
    tenant_id = require_request_tenant_id(request)
    actor = _request_actor(request)
    now = datetime.now(timezone.utc).isoformat()
    queue_state = "decided" if req.decision in {"affected", "not_affected"} else req.queue_state
    reviewed_at = now if queue_state == "decided" else ""
    exc = VulnException(
        vuln_id=req.vulnerability_id,
        package_name=req.package,
        server_name=req.server_name,
        reason=_triage_reason(
            {
                "queue_state": queue_state,
                "decision": req.decision,
                "justification": req.justification,
                "decision_reason": req.decision_reason,
                "assignee": req.assignee,
                "reviewed_at": reviewed_at,
            }
        ),
        requested_by=actor,
        approved_by=req.assignee,
        status=ExceptionStatus.ACTIVE,
        expires_at=req.expires_at,
        approved_at=reviewed_at,
        tenant_id=tenant_id,
    )
    _get_exception_store().put(exc)
    log_action(
        "findings.triage_created",
        actor=actor,
        resource=f"finding-triage/{exc.exception_id}",
        tenant_id=tenant_id,
        vuln_id=req.vulnerability_id,
        package=req.package,
        queue_state=queue_state,
        decision=req.decision,
    )
    return _triage_response(exc)


@router.get("/findings/triage", tags=["enterprise"])
async def list_finding_triage(
    request: Request,
    queue_state: str | None = None,
    decision: str | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 1000,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    """List tenant-scoped finding triage queue items."""
    tenant_id = require_request_tenant_id(request)
    entries = []
    for exc in _get_exception_store().list_all(tenant_id=tenant_id):
        data = _parse_triage_reason(exc.reason)
        if data is None:
            continue
        response = _triage_response(exc)
        if queue_state and response["queue_state"] != queue_state:
            continue
        if decision and response["decision"] != decision:
            continue
        entries.append(response)
    total = len(entries)
    return {
        "schema_version": "findings.triage.v1",
        "triage": entries[offset : offset + limit],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.put("/findings/triage/{triage_id}/decision", tags=["enterprise"])
async def update_finding_triage_decision(request: Request, triage_id: str, req: FindingTriageDecisionRequest) -> dict:
    """Record a finding triage decision and review timestamp."""
    from agent_bom.api.audit_log import log_action

    _validate_triage_decision(req.decision, req.justification)
    tenant_id = require_request_tenant_id(request)
    actor = _request_actor(request)
    store = _get_exception_store()
    exc = store.get(triage_id, tenant_id=tenant_id)
    if exc is None or _parse_triage_reason(exc.reason) is None:
        raise HTTPException(status_code=404, detail=f"Finding triage item {triage_id} not found")
    reviewed_at = datetime.now(timezone.utc).isoformat()
    current = _parse_triage_reason(exc.reason) or {}
    assignee = req.assignee if req.assignee is not None else str(current.get("assignee") or exc.approved_by or "")
    exc.reason = _triage_reason(
        {
            "queue_state": "decided",
            "decision": req.decision,
            "justification": req.justification,
            "decision_reason": req.decision_reason,
            "assignee": assignee,
            "reviewed_at": reviewed_at,
        }
    )
    exc.approved_by = assignee
    exc.approved_at = reviewed_at
    if req.expires_at is not None:
        exc.expires_at = req.expires_at
    store.put(exc)
    log_action(
        "findings.triage_decision_recorded",
        actor=actor,
        resource=f"finding-triage/{triage_id}",
        tenant_id=tenant_id,
        vuln_id=exc.vuln_id,
        package=exc.package_name,
        decision=req.decision,
    )
    return _triage_response(exc)


@router.get("/findings/triage/vex", tags=["enterprise"])
async def export_finding_triage_vex(request: Request) -> dict:
    """Export signed OpenVEX for eligible tenant-scoped not_affected triage decisions."""
    from agent_bom.api.compliance_signing import sign_compliance_bundle
    from agent_bom.vex import VexDocument, VexJustification, VexStatement, VexStatus, export_openvex

    tenant_id = require_request_tenant_id(request)
    statements = []
    for exc in _get_exception_store().list_all(tenant_id=tenant_id):
        data = _parse_triage_reason(exc.reason)
        if data is None:
            continue
        if data.get("decision") != "not_affected" or not data.get("justification"):
            continue
        statements.append(
            VexStatement(
                vulnerability_id=exc.vuln_id,
                status=VexStatus.NOT_AFFECTED,
                justification=VexJustification(str(data["justification"])),
                impact_statement=str(data.get("decision_reason") or ""),
                products=[] if exc.package_name in {"", "*"} else [exc.package_name],
                timestamp=str(data.get("reviewed_at") or exc.approved_at or exc.created_at),
                author=str(data.get("assignee") or exc.approved_by or exc.requested_by or "agent-bom"),
            )
        )
    doc = VexDocument(
        statements=statements,
        metadata={
            "id": f"urn:agent-bom:vex:{tenant_id}:{len(statements)}",
            "author": "agent-bom",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": 1,
        },
    )
    payload = export_openvex(doc)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = sign_compliance_bundle(canonical)
    return {
        "schema_version": "findings.triage.vex.v1",
        "tenant_id": tenant_id,
        "count": len(statements),
        "format": "openvex",
        "vex": payload,
        "signature": {
            "algorithm": signature.algorithm,
            "signature_hex": signature.signature_hex,
            "key_id": signature.key_id,
        },
    }


@router.post("/findings/triage/vex/ingest", tags=["enterprise"], status_code=201)
async def ingest_finding_triage_vex(request: Request, req: FindingTriageVexIngestRequest) -> dict:
    """Ingest an OpenVEX document and apply its statements as triage suppressions.

    ``not_affected`` statements become tenant-scoped triage decisions (round-tripping
    with :func:`export_finding_triage_vex`); ``fixed`` statements are recorded as
    ``fixed_verified`` suppressions. ``affected`` / ``under_investigation`` statements
    carry no suppression and are skipped. Re-ingesting the same document updates the
    matching entries in place (idempotent by vulnerability + product)."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import ExceptionStatus, VulnException
    from agent_bom.vex import VexStatus, parse_vex

    tenant_id = require_request_tenant_id(request)
    actor = _request_actor(request)
    try:
        doc = parse_vex(req.vex)
    except ValueError as parse_err:
        raise HTTPException(status_code=400, detail=f"Invalid VEX document: {sanitize_error(str(parse_err))}") from parse_err

    store = _get_exception_store()
    # Index existing tenant exceptions by (vuln_id, package) so re-ingest updates
    # in place rather than accumulating duplicates.
    existing: dict[tuple[str, str], Any] = {}
    for exc in store.list_all(tenant_id=tenant_id):
        existing[(exc.vuln_id, exc.package_name)] = exc

    now = datetime.now(timezone.utc).isoformat()
    applied = 0
    skipped: list[dict[str, str]] = []

    for stmt in doc.statements:
        if not stmt.vulnerability_id:
            continue
        products = stmt.products or [""]
        for product in products:
            package = product or "*"
            if stmt.status == VexStatus.NOT_AFFECTED:
                if stmt.justification is None:
                    skipped.append({"vulnerability_id": stmt.vulnerability_id, "reason": "missing_justification"})
                    continue
                reason = _triage_reason(
                    {
                        "queue_state": "decided",
                        "decision": "not_affected",
                        "justification": stmt.justification.value,
                        "decision_reason": stmt.impact_statement or stmt.action_statement or "",
                        "assignee": stmt.author or "",
                        "reviewed_at": now,
                        "source": "vex_ingest",
                    }
                )
            elif stmt.status == VexStatus.FIXED:
                reason = _feedback_reason("fixed_verified", stmt.impact_statement or stmt.action_statement or "")
            else:
                skipped.append({"vulnerability_id": stmt.vulnerability_id, "reason": f"status_{stmt.status.value}"})
                continue

            exc = existing.get((stmt.vulnerability_id, package))
            if exc is None:
                exc = VulnException(
                    vuln_id=stmt.vulnerability_id,
                    package_name=package,
                    reason=reason,
                    requested_by=actor,
                    status=ExceptionStatus.ACTIVE,
                    tenant_id=tenant_id,
                )
                existing[(stmt.vulnerability_id, package)] = exc
            else:
                exc.reason = reason
            if stmt.status == VexStatus.NOT_AFFECTED:
                exc.approved_by = stmt.author or actor
                exc.approved_at = now
            store.put(exc)
            applied += 1

    log_action(
        "findings.triage_vex_ingested",
        actor=actor,
        resource=f"finding-triage/vex/{tenant_id}",
        tenant_id=tenant_id,
        applied=applied,
        skipped=len(skipped),
    )
    return {
        "schema_version": "findings.triage.vex-ingest.v1",
        "tenant_id": tenant_id,
        "statements": len(doc.statements),
        "applied": applied,
        "skipped": skipped,
    }


@router.get("/findings/false-positives", tags=["enterprise"])
async def list_false_positives(request: Request) -> dict:
    """List all false positive entries."""
    tenant_id = require_request_tenant_id(request)
    all_exceptions = _get_exception_store().list_all(tenant_id=tenant_id)
    fps = [e for e in all_exceptions if (_parse_feedback_reason(e.reason) or ("", ""))[0] == "false_positive"]
    return {
        "false_positives": [
            {
                "id": e.exception_id,
                "vulnerability_id": e.vuln_id,
                "package": e.package_name,
                "reason": (_parse_feedback_reason(e.reason) or ("false_positive", e.reason))[1],
                "marked_by": e.requested_by,
                "status": "false_positive",
                "created_at": e.created_at,
            }
            for e in fps
        ],
        "total": len(fps),
    }


@router.delete("/findings/false-positive/{fp_id}", tags=["enterprise"], status_code=204)
async def remove_false_positive(request: Request, fp_id: str) -> None:
    """Un-mark a false positive."""
    from agent_bom.api.audit_log import log_action

    tenant_id = require_request_tenant_id(request)
    actor = _request_actor(request)
    store = _get_exception_store()
    exc = store.get(fp_id, tenant_id=tenant_id)
    if exc is None or (_parse_feedback_reason(exc.reason) or ("", ""))[0] != "false_positive":
        raise HTTPException(status_code=404, detail=f"False positive {fp_id} not found")
    ok = store.delete(fp_id, tenant_id=tenant_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"False positive {fp_id} not found")
    log_action("findings.false_positive_removed", actor=actor, resource=f"fp/{fp_id}", tenant_id=tenant_id)


@router.delete("/findings/feedback/{feedback_id}", tags=["enterprise"], status_code=204)
async def remove_finding_feedback(request: Request, feedback_id: str) -> None:
    """Remove tenant-scoped finding feedback without deleting audit history."""
    from agent_bom.api.audit_log import log_action

    tenant_id = require_request_tenant_id(request)
    actor = _request_actor(request)
    store = _get_exception_store()
    exc = store.get(feedback_id, tenant_id=tenant_id)
    if exc is None or _parse_feedback_reason(exc.reason) is None:
        raise HTTPException(status_code=404, detail=f"Finding feedback {feedback_id} not found")
    ok = store.delete(feedback_id, tenant_id=tenant_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Finding feedback {feedback_id} not found")
    log_action("findings.feedback_removed", actor=actor, resource=f"finding-feedback/{feedback_id}", tenant_id=tenant_id)
