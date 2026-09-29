"""WebSocket handshake, tenant identity and live authorization for proxy streams."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, replace
from dataclasses import field as dataclass_field
from functools import partial
from threading import Lock
from typing import Any, Callable

import anyio.to_thread
from fastapi import WebSocket

from agent_bom.api.stream_authorization import StreamAuthorization

_logger = logging.getLogger(__name__)
_STREAM_SEND_TIMEOUT_SECONDS = 5.0

# WebSocket scopes bypass Starlette's BaseHTTPMiddleware stack. Bound handshake
# attempts separately so unauthenticated clients cannot accumulate an
# unbounded number of five-second first-message authentication waits.
WS_HANDSHAKE_RATE_LIMIT_RPM = 600
_WS_HANDSHAKE_RATE_LIMIT_WINDOW_SECONDS = 60
_ws_handshake_rate_limit_store: Any | None = None
_ws_handshake_rate_limit_lock = Lock()


def _reset_ws_handshake_rate_limit_for_tests() -> None:
    """Discard process-global WebSocket limiter state between test cases."""

    global _ws_handshake_rate_limit_store
    with _ws_handshake_rate_limit_lock:
        _ws_handshake_rate_limit_store = None


def _ws_header_token(websocket: WebSocket) -> str:
    """Extract non-URL WebSocket auth tokens from headers when present."""
    authorization = websocket.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    for protocol in websocket.headers.get("sec-websocket-protocol", "").split(","):
        value = protocol.strip()
        if value.startswith("agent-bom-token."):
            return value.removeprefix("agent-bom-token.").strip()
    return ""


@dataclass(frozen=True)
class _WebSocketAuthContext:
    tenant_id: str = "default"
    role: str = "viewer"
    auth_method: str = "no_auth"
    key_id: str = ""
    authorization: StreamAuthorization | None = dataclass_field(default=None, repr=False, compare=False)


def _ws_bind_authorization(context: _WebSocketAuthContext, validate: Callable[[], _WebSocketAuthContext | None]) -> _WebSocketAuthContext:
    async def check() -> bool:
        return await anyio.to_thread.run_sync(validate) == context

    return replace(context, authorization=StreamAuthorization(check))


async def _ws_stream_authorized(websocket: WebSocket, context: _WebSocketAuthContext) -> bool:
    if context.authorization is not None and await context.authorization.allowed():
        return True
    await websocket.close(code=4001)
    return False


async def send_stream_json(websocket: WebSocket, context: _WebSocketAuthContext, data: dict[str, Any]) -> bool:
    """Do not let a stalled consumer retain a stream indefinitely."""
    if not await _ws_stream_authorized(websocket, context):
        return False
    try:
        await asyncio.wait_for(websocket.send_json(data), timeout=_STREAM_SEND_TIMEOUT_SECONDS)
    except TimeoutError:
        await websocket.close(code=1013)
        return False
    return True


def _get_ws_handshake_rate_limit_store() -> Any:
    """Lazily share the configured rate-limit backend across WebSocket routes."""

    global _ws_handshake_rate_limit_store
    with _ws_handshake_rate_limit_lock:
        if _ws_handshake_rate_limit_store is None:
            from agent_bom.api.middleware import _build_rate_limit_store

            _ws_handshake_rate_limit_store = _build_rate_limit_store(_WS_HANDSHAKE_RATE_LIMIT_WINDOW_SECONDS)
        return _ws_handshake_rate_limit_store


def _consume_ws_handshake_budget(client_ip: str, now: float) -> bool:
    store = _get_ws_handshake_rate_limit_store()
    accepted, _count, _reset_at = store.consume_if_below(
        f"websocket-handshake:{client_ip}",
        now,
        WS_HANDSHAKE_RATE_LIMIT_RPM,
    )
    return bool(accepted)


async def _ws_handshake_within_rate_limit(websocket: WebSocket) -> bool:
    """Consume one peer-scoped handshake unit, failing closed on store errors."""

    client = getattr(websocket, "client", None)
    client_ip = str(getattr(client, "host", "unknown") or "unknown")
    try:
        accepted = await anyio.to_thread.run_sync(partial(_consume_ws_handshake_budget, client_ip, time.time()))
    except Exception:  # noqa: BLE001 - limiter failure must reject without exposing backend details
        _logger.warning("WebSocket handshake rate limiter unavailable; rejecting connection")
        return False
    if not accepted:
        from agent_bom.api.metrics import record_rate_limit_hit

        record_rate_limit_hit("websocket-handshake")
    return bool(accepted)


def _role_allows(actual: str, required: str = "viewer") -> bool:
    from agent_bom.rbac import Role, role_rank

    try:
        actual_role = Role(str(actual).strip().lower())
        required_role = Role(required)
    except ValueError:
        return False
    return role_rank(actual_role) >= role_rank(required_role)


def _ws_runtime_role(tenant_id: str, upstream_role: str, *subjects: object) -> str | None:
    """Apply the same active SCIM lifecycle role resolution used by HTTP."""
    from agent_bom.api.auth import Role, resolve_scim_user_role

    try:
        upstream = Role(str(upstream_role).strip().lower())
    except ValueError:
        return None
    resolution = resolve_scim_user_role(tenant_id, *subjects)
    if not resolution.matched:
        return upstream.value
    if not resolution.active or resolution.role is None:
        return None
    return resolution.role.value


def _ws_auth_required() -> bool:
    """Whether these websocket streams must authenticate before accepting.

    ``APIKeyMiddleware`` is a ``BaseHTTPMiddleware`` and never runs on websocket
    scopes, so this gate is the only thing standing in front of
    ``/ws/proxy/metrics`` and ``/ws/proxy/alerts`` — and a negative answer here
    accepts anonymously with the configured no-auth role. Two rules follow
    from that.

    **Use the applied shared posture, do not hand-roll a second one.** HTTP and
    WebSocket callers must consume the same explicit anonymous opt-in. A
    missing credential source is not itself permission to serve anonymously.

    **Fail closed.** The previous ``except Exception: return False`` turned a
    store outage into an anonymous admin stream — the moment a control plane is
    least able to afford one. An error means we could not establish that auth is
    unnecessary, which is not the same as establishing that it is.

    Explicit ``AGENT_BOM_ALLOW_UNAUTHENTICATED_API`` mode still streams with
    the configured no-auth role (viewer by default).
    """
    try:
        from agent_bom.api.middleware import get_auth_posture

        return get_auth_posture().auth_required
    except Exception:
        _logger.warning("websocket auth posture unavailable; requiring authentication", exc_info=False)
        return True


def _ws_auth_from_trusted_proxy(websocket: WebSocket) -> _WebSocketAuthContext | None:
    import hmac as _hmac
    import os as _os

    if _os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return None

    from agent_bom.api.secret_source import resolve_secret

    secret = resolve_secret("AGENT_BOM_TRUST_PROXY_AUTH_SECRET")
    presented_secret = websocket.headers.get("x-agent-bom-proxy-secret", "").strip()
    from agent_bom.api.middleware import _trusted_proxy_secret_is_strong

    if not _trusted_proxy_secret_is_strong(secret):
        return None
    if not secret or not presented_secret or not _hmac.compare_digest(presented_secret, secret):
        return None
    expected_issuer = _os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH_ISSUER", "").strip()
    presented_issuer = websocket.headers.get("x-agent-bom-auth-issuer", "").strip()
    if expected_issuer and not _hmac.compare_digest(presented_issuer, expected_issuer):
        return None
    role = websocket.headers.get("x-agent-bom-role", "").strip().lower()
    tenant_id = websocket.headers.get("x-agent-bom-tenant-id", "").strip()
    if not tenant_id:
        return None
    from agent_bom.platform_invariants import ReservedTenantIdError, validate_customer_tenant_id

    try:
        tenant_id = validate_customer_tenant_id(tenant_id)
    except ReservedTenantIdError:
        return None
    subject = (
        websocket.headers.get("x-forwarded-email", "").strip()
        or websocket.headers.get("x-auth-request-email", "").strip()
        or websocket.headers.get("x-agent-bom-subject", "").strip()
    )
    effective_role = _ws_runtime_role(tenant_id, role, subject)
    if effective_role is None or not _role_allows(effective_role, "viewer"):
        return None
    return _WebSocketAuthContext(tenant_id=tenant_id, role=effective_role, auth_method="proxy_header")


def _ws_auth_from_token(token: str, *, bearer: bool = True) -> _WebSocketAuthContext | None:
    import hmac as _hmac

    from agent_bom.api.secret_source import resolve_secret

    token = str(token or "").strip()
    if not token:
        return None

    static_key = resolve_secret("AGENT_BOM_API_KEY")
    if static_key and _hmac.compare_digest(token, static_key):
        return _WebSocketAuthContext(tenant_id="default", role="admin", auth_method="static_api_key")

    from agent_bom.api.auth import get_key_store

    api_key = get_key_store().verify(token)
    if api_key is not None:
        if not api_key.has_scope("runtime:read"):
            return None
        subjects = (api_key.name.removeprefix("saml:"), api_key.name, api_key.scim_subject_id)
        role = _ws_runtime_role(api_key.tenant_id, api_key.role.value, *subjects)
        if role is not None and _role_allows(role, "viewer"):
            return _WebSocketAuthContext(tenant_id=api_key.tenant_id, role=role, auth_method="api_key", key_id=api_key.key_id)
        return None

    # AGENT_BOM_API_KEYS is seeded into the shared store at startup. Never
    # authenticate it directly here: a failed store verification can mean
    # revocation, expiry, or an ended rotation overlap, not just an unknown key.

    if bearer:
        from agent_bom.api.oidc import oidc_enabled_from_env

        if not oidc_enabled_from_env():
            return None
        from agent_bom.api.oidc import OIDCConfig, OIDCError

        oidc_cfg = OIDCConfig.from_env()
        if oidc_cfg is not None and getattr(oidc_cfg, "enabled", False):
            try:
                claims, oidc_role = oidc_cfg.verify(token)
            except OIDCError:
                return None
            tenant_id = oidc_cfg.resolve_tenant(claims)
            role = _ws_runtime_role(
                tenant_id,
                oidc_role,
                claims.get("email"),
                claims.get("preferred_username"),
                claims.get("upn"),
                claims.get("sub"),
            )
            if role is not None and _role_allows(role, "viewer"):
                return _WebSocketAuthContext(tenant_id=tenant_id, role=role, auth_method="oidc")
    return None


async def _ws_accept_and_check_auth(websocket: WebSocket) -> _WebSocketAuthContext | None:
    """Accept the WebSocket only into an authenticated streaming state.

    API keys in query strings are intentionally rejected because URLs are
    commonly captured by browser history, access logs, and reverse proxies.
    Browser callers should send ``{"type":"auth","token":"..."}`` as the first
    message after connect. Non-browser callers may use ``Authorization:
    Bearer`` or ``Sec-WebSocket-Protocol: agent-bom-token.<token>``.
    """
    import asyncio as _asyncio

    if not await _ws_handshake_within_rate_limit(websocket):
        await websocket.close(code=4008)
        return None

    auth_required = _ws_auth_required()
    if not auth_required:
        from agent_bom.api.auth import get_key_store
        from agent_bom.api.secret_source import resolve_secret
        from agent_bom.rbac import effective_no_auth_role

        await websocket.accept()
        credentials_configured = bool(resolve_secret("AGENT_BOM_API_KEY") or get_key_store().has_keys())
        context = _WebSocketAuthContext(role=effective_no_auth_role(credentials_configured=credentials_configured).value)
        return _ws_bind_authorization(context, lambda: context if not _ws_auth_required() else None)

    if websocket.query_params.get("token"):
        await websocket.close(code=4001)
        return None

    proxy_context = _ws_auth_from_trusted_proxy(websocket)
    if proxy_context is not None:
        await websocket.accept()
        return _ws_bind_authorization(proxy_context, partial(_ws_auth_from_trusted_proxy, websocket))

    token = _ws_header_token(websocket)
    # ``_ws_auth_from_token`` runs a scrypt derivation (or a blocking store
    # read) inside ``store.verify``. This handshake happens before the socket
    # is authenticated, so keep it off the event loop.
    header_context = await anyio.to_thread.run_sync(partial(_ws_auth_from_token, token, bearer=True))
    if header_context is not None:
        await websocket.accept()
        return _ws_bind_authorization(header_context, partial(_ws_auth_from_token, token, bearer=True))

    await websocket.accept()
    try:
        payload = await _asyncio.wait_for(websocket.receive_json(), timeout=5.0)
    except Exception:  # noqa: BLE001 - auth handshake failures all close the stream
        await websocket.close(code=4001)
        return None

    if isinstance(payload, dict) and payload.get("type") == "auth":
        token = str(payload.get("token", ""))
        message_context = await anyio.to_thread.run_sync(partial(_ws_auth_from_token, token, bearer=False))
        if message_context is not None:
            await websocket.send_json({"type": "auth", "status": "ok"})
            return _ws_bind_authorization(message_context, partial(_ws_auth_from_token, token, bearer=False))

    await websocket.close(code=4001)
    return None
