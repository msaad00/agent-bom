"""API middleware — authentication, rate limiting, body size, trust headers."""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import sys
import time
import uuid
from typing import TYPE_CHECKING

from agent_bom import __version__
from agent_bom.api.tracing import configure_otel_tracing, make_request_trace

if TYPE_CHECKING:
    from agent_bom.api.oidc import OIDCConfig

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

_logger = logging.getLogger(__name__)


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
            self._hits.clear()

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
        response.headers["Content-Security-Policy"] = "default-src 'self'"
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
        {"/", "/health", "/version", "/metrics", "/docs", "/redoc", "/openapi.json"}
        if not _DOCS_DISABLED
        else {"/", "/health", "/version", "/metrics"}
    )

    # Ordered route rules so narrower enterprise paths win over broad prefixes.
    _ROLE_RULES: tuple[tuple[str, str, str], ...] = (
        ("GET", "/v1/auth/keys", "admin"),
        ("POST", "/v1/auth/keys", "admin"),
        ("DELETE", "/v1/auth/keys/", "admin"),
        ("POST", "/v1/gateway/policies", "admin"),
        ("PUT", "/v1/gateway/policies/", "admin"),
        ("DELETE", "/v1/gateway/policies/", "admin"),
        ("POST", "/v1/fleet/sync", "admin"),
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
        ("POST", "/v1/traces", "analyst"),
        ("POST", "/v1/results/push", "analyst"),
        ("POST", "/v1/schedules", "analyst"),
        ("DELETE", "/v1/schedules/", "analyst"),
        ("PUT", "/v1/schedules/", "analyst"),
    )

    def __init__(self, app: ASGIApp, api_key: str) -> None:
        super().__init__(app)
        self._api_key = api_key
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
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized — provide API key via Authorization: Bearer <key> or X-API-Key header"},
            )

        # Simple mode: single static key (backward compatible, all access)
        if secrets.compare_digest(raw_key, self._api_key):
            request.state.api_key_name = "static-key"
            request.state.api_key_role = "admin"
            request.state.tenant_id = "default"
            return await self._call_with_tenant_context(request, call_next)

        # OIDC mode: try JWT verification when AGENT_BOM_OIDC_ISSUER is set
        if not self._oidc_checked:
            from agent_bom.api.oidc import OIDCConfig

            self._oidc_config = OIDCConfig.from_env()
            self._oidc_checked = True

        oidc_cfg = self._oidc_config
        if oidc_cfg is not None and getattr(oidc_cfg, "enabled", False) and auth.startswith("Bearer "):
            from agent_bom.api.oidc import OIDCError

            try:
                _claims, oidc_role = oidc_cfg.verify(raw_key)
                required = self._required_role(request.method, request.url.path)
                from agent_bom.api.auth import _ROLE_HIERARCHY, Role

                if _ROLE_HIERARCHY.get(Role(oidc_role), 0) >= _ROLE_HIERARCHY.get(Role(required), 0):
                    request.state.api_key_name = _claims.get("email") or _claims.get("sub", "oidc-user")
                    request.state.api_key_role = oidc_role
                    request.state.tenant_id = oidc_cfg.resolve_tenant(_claims)
                    return await self._call_with_tenant_context(request, call_next)
                return JSONResponse(
                    status_code=403,
                    content={"detail": f"Forbidden — requires {required} role, OIDC token has {oidc_role}"},
                )
            except OIDCError as exc:
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
                return await self._call_with_tenant_context(request, call_next)

        return JSONResponse(
            status_code=401,
            content={"detail": "Unauthorized — invalid API key"},
        )

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
    """Per-IP sliding window rate limiter with bounded memory."""

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
            except Exception:
                _logger.warning("Postgres rate limiter unavailable, falling back to in-memory store", exc_info=True)
        return InMemoryRateLimitStore(window_seconds=self._window)

    async def dispatch(self, request: StarletteRequest, call_next):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()

        is_scan = request.url.path.startswith("/v1/scan") and request.method == "POST"
        limit = self._scan_rpm if is_scan else self._read_rpm

        key = f"{client_ip}:{'scan' if is_scan else 'read'}"
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
