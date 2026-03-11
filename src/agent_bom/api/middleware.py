"""API middleware — authentication, rate limiting, body size, trust headers."""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from collections import defaultdict
from typing import TYPE_CHECKING

from agent_bom import __version__

if TYPE_CHECKING:
    from agent_bom.api.oidc import OIDCConfig

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

_logger = logging.getLogger(__name__)


class TrustHeadersMiddleware(BaseHTTPMiddleware):
    """Add trust + standard security headers to every response."""

    async def dispatch(self, request: StarletteRequest, call_next):
        response = await call_next(request)
        response.headers["X-Agent-Bom-Read-Only"] = "true"
        response.headers["X-Agent-Bom-No-Credential-Storage"] = "true"
        response.headers["X-Agent-Bom-Version"] = __version__
        # Standard security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Optional API key authentication via Bearer token or X-API-Key header.

    Supports two modes:
    - Simple mode: single static API key (backward compatible)
    - RBAC mode: role-based access control via KeyStore with per-endpoint role checks
    """

    _EXEMPT_PATHS = {"/", "/health", "/version", "/docs", "/redoc", "/openapi.json"}

    # Endpoints requiring ADMIN role (mutating / destructive operations)
    _ADMIN_PATHS: set[tuple[str, str]] = {
        ("DELETE", "/v1/scan/"),
        ("POST", "/v1/gateway/policies"),
        ("PUT", "/v1/gateway/policies/"),
        ("DELETE", "/v1/gateway/policies/"),
        ("POST", "/v1/fleet/sync"),
        ("PUT", "/v1/fleet/"),
        ("POST", "/v1/auth/keys"),
        ("DELETE", "/v1/auth/keys/"),
        ("POST", "/v1/exceptions"),
        ("PUT", "/v1/exceptions/"),
        ("DELETE", "/v1/exceptions/"),
    }

    # Endpoints requiring ANALYST role (scan + write operations)
    _ANALYST_PATHS: set[tuple[str, str]] = {
        ("POST", "/v1/scan"),
        ("POST", "/v1/gateway/evaluate"),
        ("POST", "/v1/traces"),
        ("POST", "/v1/results/push"),
        ("POST", "/v1/schedules"),
        ("DELETE", "/v1/schedules/"),
        ("PUT", "/v1/schedules/"),
    }

    def __init__(self, app: ASGIApp, api_key: str) -> None:
        super().__init__(app)
        self._api_key = api_key
        # OIDC config loaded lazily from env on first request
        self._oidc_config: OIDCConfig | None = None
        self._oidc_checked = False

    def _required_role(self, method: str, path: str) -> str:
        """Determine the minimum role required for a request."""
        for m, p in self._ADMIN_PATHS:
            if method == m and path.startswith(p):
                return "admin"
        for m, p in self._ANALYST_PATHS:
            if method == m and path.startswith(p):
                return "analyst"
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
            return await call_next(request)

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
                    return await call_next(request)
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
                return await call_next(request)

        return JSONResponse(
            status_code=401,
            content={"detail": "Unauthorized — invalid API key"},
        )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP sliding window rate limiter with bounded memory."""

    _MAX_ENTRIES = 10_000

    def __init__(self, app: ASGIApp, scan_rpm: int = 60, read_rpm: int = 300):
        super().__init__(app)
        self._scan_rpm = scan_rpm
        self._read_rpm = read_rpm
        self._window = 60
        self._hits: dict[str, list[float]] = defaultdict(list)
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

    async def dispatch(self, request: StarletteRequest, call_next):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()

        self._cleanup(now)

        is_scan = request.url.path.startswith("/v1/scan") and request.method == "POST"
        limit = self._scan_rpm if is_scan else self._read_rpm

        key = f"{client_ip}:{'scan' if is_scan else 'read'}"
        self._hits[key] = [t for t in self._hits[key] if now - t < self._window]

        if len(self._hits[key]) >= limit:
            retry_after = max(int(self._window - (now - self._hits[key][0])), 1)
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
                headers={"Retry-After": str(retry_after)},
            )

        self._hits[key].append(now)
        return await call_next(request)


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
