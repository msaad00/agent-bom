"""API middleware — authentication, rate limiting, body size, trust headers."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import secrets
import sys
import time
import uuid
from functools import lru_cache
from typing import TYPE_CHECKING

from agent_bom import __version__
from agent_bom.api.auth import get_key_store
from agent_bom.api.tracing import configure_otel_tracing, make_request_trace

if TYPE_CHECKING:
    from datetime import datetime

    from agent_bom.api.oidc import OIDCConfig

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

_logger = logging.getLogger(__name__)
_RATE_LIMIT_FINGERPRINT_FALLBACK = secrets.token_bytes(32)
_AUTH_RUNTIME_STATUS: dict[str, object] = {
    "auth_required": False,
    "configured_modes": [],
    "recommended_ui_mode": "no_auth",
}
_API_CSP = "default-src 'self'"
_DASHBOARD_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)


def _content_security_policy(path: str, content_type: str) -> str:
    """Return a route-aware CSP that keeps the API strict and the dashboard usable."""
    if "text/html" in content_type and not path.startswith(("/v1/", "/docs", "/redoc", "/openapi.json")):
        return _DASHBOARD_CSP
    return _API_CSP


def configure_auth_runtime(
    *,
    api_key_configured: bool,
    oidc_enabled: bool,
    trusted_proxy_enabled: bool,
) -> None:
    """Track the active auth modes for operator/UI introspection surfaces."""
    configured_modes: list[str] = []
    if trusted_proxy_enabled:
        configured_modes.append("trusted_proxy")
    if oidc_enabled:
        configured_modes.append("oidc_bearer")
    if api_key_configured:
        configured_modes.append("api_key")

    recommended_ui_mode = "no_auth"
    if trusted_proxy_enabled:
        recommended_ui_mode = "reverse_proxy_oidc"
    elif oidc_enabled:
        recommended_ui_mode = "oidc_bearer"
    elif api_key_configured:
        recommended_ui_mode = "session_api_key"

    _AUTH_RUNTIME_STATUS.clear()
    _AUTH_RUNTIME_STATUS.update(
        {
            "auth_required": bool(configured_modes),
            "configured_modes": configured_modes,
            "recommended_ui_mode": recommended_ui_mode,
        }
    )


def get_auth_runtime_status() -> dict[str, object]:
    """Return the configured auth modes for UI and operator surfaces."""
    return dict(_AUTH_RUNTIME_STATUS)


class InMemoryRateLimitStore:
    """Process-local sliding-window limiter state."""

    _MAX_ENTRIES = 10_000

    def __init__(self, window_seconds: int = 60) -> None:
        self._window = window_seconds
        self._hits: dict[str, list[float]] = {}
        self._last_cleanup = time.time()

    def _cleanup(self, now: float) -> None:
        """Prune stale entries to prevent unbounded memory growth."""
        if now - self._last_cleanup < self._window:
            return
        self._last_cleanup = now
        stale = [k for k, v in self._hits.items() if not v or v[-1] < now - self._window]
        for k in stale:
            del self._hits[k]
        if len(self._hits) > self._MAX_ENTRIES:
            overflow = len(self._hits) - self._MAX_ENTRIES
            oldest_keys = sorted(self._hits, key=lambda key: self._hits[key][-1] if self._hits[key] else 0.0)[:overflow]
            for key in oldest_keys:
                del self._hits[key]
            _logger.warning(
                "In-memory rate limiter pruned %s oldest buckets to stay under %s entries",
                overflow,
                self._MAX_ENTRIES,
            )

    def hit(self, key: str, now: float) -> tuple[int, int]:
        """Record a request and return (hit_count, reset_epoch)."""
        self._cleanup(now)
        timestamps = [t for t in self._hits.get(key, []) if now - t < self._window]
        timestamps.append(now)
        self._hits[key] = timestamps
        reset_at = int((timestamps[0] if timestamps else now) + self._window)
        return len(timestamps), reset_at


class PostgresRateLimitStore:
    """Shared sliding-window limiter backed by Postgres for horizontal scaling."""

    def __init__(self, window_seconds: int = 60, pool=None) -> None:
        self._window = window_seconds
        if pool is None:
            from agent_bom.api.postgres_store import _get_pool

            pool = _get_pool()
        self._pool = pool
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_rate_limits (
                    bucket_key      TEXT NOT NULL,
                    window_started  INTEGER NOT NULL,
                    hits            INTEGER NOT NULL DEFAULT 0,
                    updated_at      TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                    PRIMARY KEY (bucket_key, window_started)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_rate_limits_updated ON api_rate_limits(updated_at)")

    def hit(self, key: str, now: float) -> tuple[int, int]:
        """Record a request and return (hit_count, reset_epoch)."""
        window_started = int(now // self._window) * self._window
        reset_at = window_started + self._window
        with self._pool.connection() as conn:
            # Trim stale windows opportunistically to keep the table bounded.
            conn.execute(
                "DELETE FROM api_rate_limits WHERE window_started < %s",
                (window_started - (self._window * 2),),
            )
            row = conn.execute(
                """
                INSERT INTO api_rate_limits (bucket_key, window_started, hits)
                VALUES (%s, %s, 1)
                ON CONFLICT (bucket_key, window_started)
                DO UPDATE SET hits = api_rate_limits.hits + 1,
                              updated_at = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                RETURNING hits
                """,
                (key, window_started),
            ).fetchone()
        count = int(row[0]) if row else 1
        return count, int(reset_at)


class TrustHeadersMiddleware(BaseHTTPMiddleware):
    """Add trust + standard security headers to every response."""

    async def dispatch(self, request: StarletteRequest, call_next):
        trace_meta = make_request_trace(dict(request.headers))
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        request.state.request_id = request_id
        request.state.trace_id = trace_meta["trace_id"]
        request.state.span_id = trace_meta["span_id"]
        request.state.parent_span_id = trace_meta["parent_span_id"]
        request.state.traceparent = trace_meta["traceparent"]
        request.state.tracestate = trace_meta["tracestate"]
        request.state.baggage = trace_meta["baggage"]
        if not hasattr(request.state, "tenant_id"):
            request.state.tenant_id = "default"
        tenant_token = None
        otel_cm = None
        span = None
        start = time.perf_counter()
        try:
            if configure_otel_tracing():
                from opentelemetry import trace

                tracer = trace.get_tracer("agent_bom.api")
                otel_cm = tracer.start_as_current_span(f"{request.method} {request.url.path}")
                span = otel_cm.__enter__()
                span.set_attribute("http.request.method", request.method)
                span.set_attribute("url.path", request.url.path)
                span.set_attribute("agent_bom.request_id", request_id)
                span.set_attribute("agent_bom.trace_id", str(trace_meta["trace_id"]))
                span.set_attribute("agent_bom.span_id", str(trace_meta["span_id"]))
                span.set_attribute("agent_bom.incoming_traceparent", bool(trace_meta["incoming_traceparent"]))
                if trace_meta["parent_span_id"]:
                    span.set_attribute("agent_bom.parent_span_id", str(trace_meta["parent_span_id"]))
                if trace_meta["tracestate"]:
                    span.set_attribute("agent_bom.tracestate_present", True)
                if trace_meta["baggage"]:
                    span.set_attribute("agent_bom.baggage_present", True)
            if os.environ.get("AGENT_BOM_POSTGRES_URL"):
                from agent_bom.api.postgres_store import set_current_tenant

                tenant_token = set_current_tenant(getattr(request.state, "tenant_id", "default"))
            response = await call_next(request)
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            _logger.info(
                "api request complete method=%s path=%s status=%s request_id=%s trace_id=%s span_id=%s tenant_id=%s duration_ms=%s",
                request.method,
                request.url.path,
                getattr(response, "status_code", "unknown"),
                request_id,
                trace_meta["trace_id"],
                trace_meta["span_id"],
                getattr(request.state, "tenant_id", "default"),
                elapsed_ms,
            )
            if span is not None:
                span.set_attribute("http.response.status_code", int(getattr(response, "status_code", 500)))
                span.set_attribute("agent_bom.tenant_id", str(getattr(request.state, "tenant_id", "default")))
                span.set_attribute("agent_bom.duration_ms", elapsed_ms)
                span.set_attribute("http.route", str(request.scope.get("path", request.url.path)))
                if getattr(request.state, "api_key_role", None):
                    span.set_attribute("agent_bom.auth.role", str(request.state.api_key_role))
                if getattr(request.state, "api_key_name", None):
                    span.set_attribute("agent_bom.auth.subject", str(request.state.api_key_name))
                if request.client and request.client.host:
                    span.set_attribute("client.address", str(request.client.host))
        except Exception as exc:
            if span is not None:
                from opentelemetry.trace import Status, StatusCode

                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR, str(exc)))
            raise
        finally:
            if tenant_token is not None:
                from agent_bom.api.postgres_store import reset_current_tenant

                reset_current_tenant(tenant_token)
            if otel_cm is not None:
                otel_cm.__exit__(*sys.exc_info())
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Trace-ID"] = str(trace_meta["trace_id"])
        response.headers["X-Span-ID"] = str(trace_meta["span_id"])
        response.headers["traceparent"] = str(trace_meta["traceparent"])
        if trace_meta["parent_span_id"]:
            response.headers["X-Parent-Span-ID"] = str(trace_meta["parent_span_id"])
        if trace_meta["tracestate"]:
            response.headers["tracestate"] = str(trace_meta["tracestate"])
        if trace_meta["baggage"]:
            response.headers["baggage"] = str(trace_meta["baggage"])
        response.headers["X-Agent-Bom-Read-Only"] = "true"
        response.headers["X-Agent-Bom-No-Credential-Storage"] = "true"
        response.headers["X-Agent-Bom-Version"] = __version__
        # Standard security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = _content_security_policy(
            request.url.path,
            response.headers.get("content-type", ""),
        )
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-API-Version"] = "v1"
        return response


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Optional API key authentication via Bearer token or X-API-Key header.

    Supports two modes:
    - Simple mode: single static API key (backward compatible)
    - RBAC mode: role-based access control via KeyStore with per-endpoint role checks
    """

    # Set AGENT_BOM_DISABLE_DOCS=1 in production to block /docs and /redoc
    _DOCS_DISABLED = os.environ.get("AGENT_BOM_DISABLE_DOCS", "").strip() in ("1", "true", "yes")
    _EXEMPT_PATHS = (
        {
            "/",
            "/health",
            "/readyz",
            "/version",
            "/metrics",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/v1/auth/saml/metadata",
            "/v1/auth/saml/login",
        }
        if not _DOCS_DISABLED
        else {
            "/",
            "/health",
            "/readyz",
            "/version",
            "/metrics",
            "/v1/auth/saml/metadata",
            "/v1/auth/saml/login",
        }
    )

    # Ordered route rules so narrower enterprise paths win over broad prefixes.
    _ROLE_RULES: tuple[tuple[str, str, str], ...] = (
        ("GET", "/v1/compliance", "viewer"),
        ("GET", "/v1/posture", "viewer"),
        ("GET", "/v1/auth/debug", "viewer"),
        ("GET", "/v1/auth/policy", "admin"),
        ("GET", "/v1/auth/keys", "admin"),
        ("POST", "/v1/auth/keys", "admin"),
        ("DELETE", "/v1/auth/keys/", "admin"),
        ("POST", "/v1/gateway/policies", "admin"),
        ("PUT", "/v1/gateway/policies/", "admin"),
        ("DELETE", "/v1/gateway/policies/", "admin"),
        ("POST", "/v1/fleet/sync", "admin"),
        ("DELETE", "/v1/sources/", "admin"),
        ("PUT", "/v1/fleet/", "admin"),
        ("PUT", "/v1/exceptions/", "admin"),
        ("DELETE", "/v1/exceptions/", "admin"),
        ("POST", "/v1/siem/test", "admin"),
        ("POST", "/v1/shield/start", "admin"),
        ("POST", "/v1/shield/unblock", "admin"),
        ("POST", "/v1/shield/break-glass", "admin"),
        ("DELETE", "/v1/scan/", "admin"),
        ("POST", "/v1/exceptions", "analyst"),
        ("POST", "/v1/findings/jira", "analyst"),
        ("POST", "/v1/findings/false-positive", "analyst"),
        ("DELETE", "/v1/findings/false-positive/", "analyst"),
        ("POST", "/v1/scan", "analyst"),
        ("POST", "/v1/gateway/evaluate", "analyst"),
        ("POST", "/v1/proxy/audit", "analyst"),
        ("POST", "/v1/traces", "analyst"),
        ("POST", "/v1/results/push", "analyst"),
        ("POST", "/v1/schedules", "analyst"),
        ("POST", "/v1/sources", "analyst"),
        ("POST", "/v1/sources/", "analyst"),
        ("DELETE", "/v1/schedules/", "analyst"),
        ("PUT", "/v1/schedules/", "analyst"),
        ("PUT", "/v1/sources/", "analyst"),
    )

    def __init__(self, app: ASGIApp, api_key: str) -> None:
        super().__init__(app)
        self._api_key = api_key
        self._trusted_proxy_auth = _env_flag("AGENT_BOM_TRUST_PROXY_AUTH")
        # OIDC config loaded lazily from env on first request
        self._oidc_config: OIDCConfig | None = None
        self._oidc_checked = False

    def _required_role(self, method: str, path: str) -> str:
        """Determine the minimum role required for a request."""
        for m, p, role in self._ROLE_RULES:
            if method == m and path.startswith(p):
                return role
        return "viewer"

    async def dispatch(self, request: StarletteRequest, call_next):
        if request.url.path in self._EXEMPT_PATHS:
            return await call_next(request)

        # Extract raw key from headers
        raw_key = ""
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            raw_key = auth[7:]
        if not raw_key:
            raw_key = request.headers.get("x-api-key", "")

        if not raw_key:
            proxy_response = await self._try_proxy_header_auth(request, call_next)
            if proxy_response is not None:
                return proxy_response
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized — provide API key via Authorization: Bearer <key> or X-API-Key header"},
            )

        # Simple mode: single static key (backward compatible, all access)
        if self._api_key and secrets.compare_digest(raw_key, self._api_key):
            request.state.api_key_name = "static-key"
            request.state.api_key_role = "admin"
            request.state.tenant_id = "default"
            request.state.auth_method = "static_api_key"
            return await self._call_with_tenant_context(request, call_next)

        # OIDC mode: try JWT verification when AGENT_BOM_OIDC_ISSUER is set
        if not self._oidc_checked:
            from agent_bom.api.oidc import OIDCConfig

            self._oidc_config = OIDCConfig.from_env()
            self._oidc_checked = True

        oidc_cfg = self._oidc_config
        if oidc_cfg is not None and getattr(oidc_cfg, "enabled", False) and auth.startswith("Bearer "):
            from agent_bom.api.oidc import OIDCError, record_oidc_decode_failure

            try:
                _claims, oidc_role = oidc_cfg.verify(raw_key)
                required = self._required_role(request.method, request.url.path)
                from agent_bom.api.auth import _ROLE_HIERARCHY, Role

                if _ROLE_HIERARCHY.get(Role(oidc_role), 0) >= _ROLE_HIERARCHY.get(Role(required), 0):
                    request.state.api_key_name = _claims.get("email") or _claims.get("sub", "oidc-user")
                    request.state.api_key_role = oidc_role
                    request.state.tenant_id = oidc_cfg.resolve_tenant(_claims)
                    request.state.auth_method = "oidc"
                    # Short issuer suffix helps operators recognize which IdP
                    # resolved the token without leaking the full URL to all
                    # request-scoped log fields.
                    issuer = str(_claims.get("iss") or "")
                    request.state.auth_issuer = issuer.rsplit("/", 1)[-1][:64] if issuer else None
                    return await self._call_with_tenant_context(request, call_next)
                return JSONResponse(
                    status_code=403,
                    content={"detail": f"Forbidden — requires {required} role, OIDC token has {oidc_role}"},
                )
            except OIDCError as exc:
                record_oidc_decode_failure()
                _logger.debug("OIDC verification failed: %s", exc)
                # Fall through to API key check — OIDC failure is non-fatal if keys also configured

        # RBAC mode: check against KeyStore
        from agent_bom.api.auth import Role, get_key_store

        store = get_key_store()
        if store.has_keys():
            api_key = store.verify(raw_key)
            if api_key:
                required = self._required_role(request.method, request.url.path)
                required_role = Role(required)
                if not api_key.has_role(required_role):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": f"Forbidden — requires {required} role, you have {api_key.role.value}"},
                    )
                request.state.api_key_name = api_key.name
                request.state.api_key_role = api_key.role.value
                request.state.tenant_id = api_key.tenant_id
                request.state.api_key_id = api_key.key_id
                # SAML-minted keys are named "saml:<subject>" — surface that
                # as a distinct auth method so operators can trace who came
                # in via which IdP path even after the key has been issued.
                request.state.auth_method = "saml" if api_key.name.startswith("saml:") else "api_key"
                return await self._call_with_tenant_context(request, call_next)

        return JSONResponse(
            status_code=401,
            content={"detail": "Unauthorized — invalid API key"},
        )

    async def _try_proxy_header_auth(self, request: StarletteRequest, call_next):
        if not self._trusted_proxy_auth:
            return None

        role_header = request.headers.get("x-agent-bom-role", "").strip().lower()
        tenant_id = request.headers.get("x-agent-bom-tenant-id", "").strip()
        if not role_header:
            return None
        if not tenant_id:
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required — trusted proxy requests must include X-Agent-Bom-Tenant-ID"},
            )

        from agent_bom.api.auth import _ROLE_HIERARCHY, Role

        try:
            proxy_role = Role(role_header)
        except ValueError:
            return JSONResponse(status_code=403, content={"detail": f"Invalid proxy role '{role_header}'"})

        required = Role(self._required_role(request.method, request.url.path))
        if _ROLE_HIERARCHY.get(proxy_role, 0) < _ROLE_HIERARCHY.get(required, 0):
            return JSONResponse(
                status_code=403,
                content={"detail": f"Forbidden — requires {required.value} role, proxy session has {proxy_role.value}"},
            )

        request.state.api_key_name = (
            request.headers.get("x-agent-bom-subject")
            or request.headers.get("x-forwarded-email")
            or request.headers.get("x-auth-request-email")
            or "proxy-header"
        )
        request.state.api_key_role = proxy_role.value
        request.state.tenant_id = tenant_id
        request.state.auth_method = "proxy_header"
        request.state.auth_issuer = request.headers.get("x-agent-bom-auth-issuer") or None
        return await self._call_with_tenant_context(request, call_next)

    async def _call_with_tenant_context(self, request: StarletteRequest, call_next):
        tenant_token = None
        try:
            if os.environ.get("AGENT_BOM_POSTGRES_URL"):
                from agent_bom.api.postgres_store import set_current_tenant

                tenant_token = set_current_tenant(getattr(request.state, "tenant_id", "default"))
            return await call_next(request)
        finally:
            if tenant_token is not None:
                from agent_bom.api.postgres_store import reset_current_tenant

                reset_current_tenant(tenant_token)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Tenant-aware sliding window rate limiter with bounded memory."""

    def __init__(self, app: ASGIApp, scan_rpm: int = 60, read_rpm: int = 300):
        super().__init__(app)
        self._scan_rpm = scan_rpm
        self._read_rpm = read_rpm
        self._window = 60
        self._store = self._build_store()

    def _build_store(self):
        if os.environ.get("AGENT_BOM_POSTGRES_URL"):
            try:
                return PostgresRateLimitStore(window_seconds=self._window)
            except Exception as exc:
                raise RuntimeError(
                    "Configured Postgres rate limiter could not initialize; refusing to fall back to process-local state"
                ) from exc
        if _shared_rate_limit_required():
            raise RuntimeError(
                "Shared rate limiting is required for multi-replica or fail-closed deployments. "
                "Configure AGENT_BOM_POSTGRES_URL before starting the API."
            )
        return InMemoryRateLimitStore(window_seconds=self._window)

    def _resolve_tenant_scope(self, request: StarletteRequest, raw_key: str) -> str | None:
        tenant_id = getattr(request.state, "tenant_id", "").strip() or None
        if tenant_id and tenant_id != "default":
            return tenant_id
        if raw_key:
            try:
                resolved = get_key_store().verify(raw_key)
            except Exception:
                resolved = None
            if resolved and resolved.tenant_id:
                return resolved.tenant_id
        return None

    def _bucket_key(self, request: StarletteRequest, is_scan: bool) -> str:
        bucket_type = "scan" if is_scan else "read"
        auth = request.headers.get("authorization", "")
        raw_key = auth[7:] if auth.startswith("Bearer ") else request.headers.get("x-api-key", "")
        tenant_scope = self._resolve_tenant_scope(request, raw_key)
        if tenant_scope:
            scope = f"tenant:{tenant_scope}"
        elif raw_key:
            auth_hash = _rate_limit_fingerprint(raw_key)
            scope = f"auth:{auth_hash}"
        else:
            client_ip = request.client.host if request.client else "unknown"
            scope = f"ip:{client_ip}"
        return f"{scope}:{bucket_type}"

    async def dispatch(self, request: StarletteRequest, call_next):
        now = time.time()

        is_scan = request.url.path.startswith("/v1/scan") and request.method == "POST"
        limit = self._scan_rpm if is_scan else self._read_rpm

        key = self._bucket_key(request, is_scan)
        hit_count, reset_at = await asyncio.to_thread(self._store.hit, key, now)
        remaining = max(0, limit - hit_count)

        if hit_count > limit:
            retry_after = max(int(reset_at - now), 1)
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_at),
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_at)
        return response


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _configured_api_replicas() -> int:
    raw = os.environ.get("AGENT_BOM_CONTROL_PLANE_REPLICAS", "").strip()
    if not raw:
        return 1
    try:
        return max(1, int(raw))
    except ValueError:
        _logger.warning("Invalid AGENT_BOM_CONTROL_PLANE_REPLICAS=%r; defaulting to 1", raw)
        return 1


def _shared_rate_limit_required() -> bool:
    return _env_flag("AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT") or _configured_api_replicas() > 1


def get_rate_limit_runtime_status() -> dict[str, object]:
    """Report whether API rate limiting is shared across replicas."""
    postgres_configured = bool(os.environ.get("AGENT_BOM_POSTGRES_URL", "").strip())
    replicas = _configured_api_replicas()
    shared_required = _shared_rate_limit_required()
    backend = "postgres_shared" if postgres_configured else "inmemory_single_process"
    return {
        "backend": backend,
        "postgres_configured": postgres_configured,
        "configured_api_replicas": replicas,
        "shared_required": shared_required,
        "shared_across_replicas": postgres_configured,
        "fail_closed": postgres_configured or shared_required,
        "message": (
            "Rate limiting uses Postgres-backed shared state across replicas."
            if postgres_configured
            else (
                "Rate limiting is process-local only because the API is configured for a single replica. "
                "Multi-replica deployments must configure AGENT_BOM_POSTGRES_URL."
            )
        ),
    }


def _rate_limit_fingerprint_key() -> bytes:
    key = (os.environ.get("AGENT_BOM_RATE_LIMIT_KEY") or os.environ.get("AGENT_BOM_AUDIT_HMAC_KEY") or "").strip()
    return key.encode() if key else _RATE_LIMIT_FINGERPRINT_FALLBACK


@lru_cache(maxsize=4096)
def _rate_limit_fingerprint(raw_key: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        raw_key.encode(),
        _rate_limit_fingerprint_key(),
        200_000,
        dklen=8,
    ).hex()


def get_rate_limit_key_status(now: "datetime | None" = None) -> dict:
    """Report rate-limit fingerprint key configuration and rotation status.

    Returns a structured dict suitable for surfacing in /v1/auth/policy and
    operator dashboards. Status values:

    - "ephemeral":         no key configured; using process-local random key
    - "ok":                key configured and within rotation interval
    - "rotation_due":      key age past AGENT_BOM_RATE_LIMIT_KEY_ROTATION_DAYS
    - "max_age_exceeded":  key age past AGENT_BOM_RATE_LIMIT_KEY_MAX_AGE_DAYS
    - "unknown_age":       key configured but no last-rotated timestamp set
    """
    from datetime import datetime as _dt
    from datetime import timezone as _tz

    from agent_bom.config import (
        RATE_LIMIT_KEY_LAST_ROTATED,
        RATE_LIMIT_KEY_MAX_AGE_DAYS,
        RATE_LIMIT_KEY_ROTATION_DAYS,
    )

    raw_key = (os.environ.get("AGENT_BOM_RATE_LIMIT_KEY") or os.environ.get("AGENT_BOM_AUDIT_HMAC_KEY") or "").strip()
    fallback_source = (
        "AGENT_BOM_AUDIT_HMAC_KEY"
        if not os.environ.get("AGENT_BOM_RATE_LIMIT_KEY") and os.environ.get("AGENT_BOM_AUDIT_HMAC_KEY")
        else None
    )

    if not raw_key:
        return {
            "status": "ephemeral",
            "rotation_days": RATE_LIMIT_KEY_ROTATION_DAYS,
            "max_age_days": RATE_LIMIT_KEY_MAX_AGE_DAYS,
            "fallback_source": None,
            "last_rotated": None,
            "age_days": None,
            "message": (
                "No AGENT_BOM_RATE_LIMIT_KEY configured. Rate-limit fingerprints use a "
                "process-local random key that resets on restart and breaks shared bucket "
                "scoping across replicas. Set AGENT_BOM_RATE_LIMIT_KEY for production."
            ),
        }

    if not RATE_LIMIT_KEY_LAST_ROTATED:
        return {
            "status": "unknown_age",
            "rotation_days": RATE_LIMIT_KEY_ROTATION_DAYS,
            "max_age_days": RATE_LIMIT_KEY_MAX_AGE_DAYS,
            "fallback_source": fallback_source,
            "last_rotated": None,
            "age_days": None,
            "message": (
                "Rate-limit key is configured but AGENT_BOM_RATE_LIMIT_KEY_LAST_ROTATED is "
                "unset. Set it to an ISO-8601 timestamp when the key was last rotated to "
                "enable rotation tracking."
            ),
        }

    try:
        rotated = _dt.fromisoformat(RATE_LIMIT_KEY_LAST_ROTATED)
    except ValueError:
        return {
            "status": "unknown_age",
            "rotation_days": RATE_LIMIT_KEY_ROTATION_DAYS,
            "max_age_days": RATE_LIMIT_KEY_MAX_AGE_DAYS,
            "fallback_source": fallback_source,
            "last_rotated": RATE_LIMIT_KEY_LAST_ROTATED,
            "age_days": None,
            "message": (
                "AGENT_BOM_RATE_LIMIT_KEY_LAST_ROTATED is set but is not a valid ISO-8601 "
                "timestamp. Use a value like '2026-04-17T00:00:00+00:00'."
            ),
        }

    if rotated.tzinfo is None:
        rotated = rotated.replace(tzinfo=_tz.utc)
    current = now or _dt.now(_tz.utc)
    age_days = max(0, int((current - rotated).total_seconds() // 86400))

    if age_days >= RATE_LIMIT_KEY_MAX_AGE_DAYS:
        status = "max_age_exceeded"
        message = (
            f"Rate-limit key is {age_days} days old, exceeding the configured maximum "
            f"({RATE_LIMIT_KEY_MAX_AGE_DAYS} days). Rotate AGENT_BOM_RATE_LIMIT_KEY now and "
            "update AGENT_BOM_RATE_LIMIT_KEY_LAST_ROTATED."
        )
    elif age_days >= RATE_LIMIT_KEY_ROTATION_DAYS:
        status = "rotation_due"
        message = (
            f"Rate-limit key is {age_days} days old, past the rotation interval ({RATE_LIMIT_KEY_ROTATION_DAYS} days). Schedule a rotation."
        )
    else:
        status = "ok"
        message = f"Rate-limit key is {age_days} days old; rotation interval is {RATE_LIMIT_KEY_ROTATION_DAYS} days."

    return {
        "status": status,
        "rotation_days": RATE_LIMIT_KEY_ROTATION_DAYS,
        "max_age_days": RATE_LIMIT_KEY_MAX_AGE_DAYS,
        "fallback_source": fallback_source,
        "last_rotated": rotated.isoformat(),
        "age_days": age_days,
        "message": message,
    }


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """Reject oversized bodies and enforce a per-request read timeout (slowloris mitigation).

    Two-layer protection:
    1. Content-Length fast-path: reject before reading if header exceeds limit.
    2. Streaming body drain with asyncio timeout: covers chunked/streaming uploads
       that omit Content-Length — a common slowloris vector.
    """

    # 30s to fully receive a request body; covers slow legitimate clients
    # while cutting off slowloris attacks that trickle bytes indefinitely.
    _BODY_TIMEOUT_SECONDS = 30

    def __init__(self, app: ASGIApp, max_bytes: int = 10 * 1024 * 1024):
        super().__init__(app)
        self._max_bytes = max_bytes

    async def dispatch(self, request: StarletteRequest, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                cl = int(content_length)
            except (ValueError, OverflowError):
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header"})
            if cl > self._max_bytes:
                return JSONResponse(
                    status_code=413,
                    content={"detail": f"Request body too large (max {self._max_bytes // (1024 * 1024)}MB)"},
                )
        elif request.method in ("POST", "PUT", "PATCH"):
            # No Content-Length — drain and check streaming body under timeout
            try:
                chunks: list[bytes] = []
                total = 0
                async with asyncio.timeout(self._BODY_TIMEOUT_SECONDS):
                    async for chunk in request.stream():
                        total += len(chunk)
                        if total > self._max_bytes:
                            return JSONResponse(
                                status_code=413,
                                content={"detail": f"Request body too large (max {self._max_bytes // (1024 * 1024)}MB)"},
                            )
                        chunks.append(chunk)
            except TimeoutError:
                return JSONResponse(status_code=408, content={"detail": "Request body read timed out"})

            # Re-inject the drained body so downstream handlers can read it
            body = b"".join(chunks)

            async def _receive():
                return {"type": "http.request", "body": body, "more_body": False}

            request._receive = _receive  # type: ignore[attr-defined]

        return await call_next(request)
