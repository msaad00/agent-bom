"""Gateway HTTP authentication and explicit listener/profile posture checks."""

from __future__ import annotations

import hmac
import ipaddress
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException, Request

from agent_bom.api.auth import Role, get_key_store
from agent_bom.api.gateway_request import _sanitize_for_log
from agent_bom.core.tenancy import require_explicit_tenant_id
from agent_bom.runtime.gateway_settings import GatewaySettings
from agent_bom.security import sanitize_text

logger = logging.getLogger("agent_bom.gateway_server")
_GATEWAY_RELAY_SCOPE = "gateway:relay"


def _parse_gateway_token_expiry(value: str | None) -> datetime:
    """Require a bounded absolute deadline; process restarts cannot renew it."""
    requirement = "AGENT_BOM_GATEWAY_BEARER_TOKEN_EXPIRES_AT must be a timezone-aware ISO-8601 expiry in the next hour"
    if not value or not value.strip():
        raise ValueError(requirement)
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError(requirement)
        parsed = parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise ValueError(requirement) from None
    now = datetime.now(timezone.utc)
    if not now < parsed <= now + timedelta(hours=1):
        raise ValueError(requirement)
    return parsed


def _request_has_expected_token(request: Request, expected_token: str) -> bool:
    return hmac.compare_digest(_extract_request_token(request).encode(), expected_token.encode())


def _extract_request_token(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer ") :].strip()
    return request.headers.get("x-api-key", "").strip()


def _gateway_requires_auth(settings: GatewaySettings) -> bool:
    if settings.bearer_token:
        return True
    try:
        return get_key_store().has_keys()
    except Exception as exc:
        logger.warning("Gateway key store status unavailable: %s", sanitize_text(_sanitize_for_log(exc)))
        return True


def _is_loopback_host(host: str) -> bool:
    normalized = (host or "").strip().strip("[]").lower()
    if normalized in {"localhost", "127.0.0.1", "::1"}:
        return True
    if not normalized:
        return False
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _env_flag_enabled(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _enforce_gateway_auth_posture(settings: GatewaySettings) -> None:
    if _gateway_requires_auth(settings):
        return
    if _is_loopback_host(settings.listener_host):
        return
    if settings.allow_insecure_no_auth or _env_flag_enabled("AGENT_BOM_GATEWAY_ALLOW_INSECURE_NO_AUTH"):
        logger.warning(
            "Gateway starting without incoming authentication on non-loopback listener %s due to explicit insecure override",
            _sanitize_for_log(settings.listener_host),
        )
        return
    raise RuntimeError(
        "Refusing to start gateway on a non-loopback listener without incoming authentication. "
        "Configure AGENT_BOM_GATEWAY_BEARER_TOKEN or API keys, bind to loopback, "
        "or set AGENT_BOM_GATEWAY_ALLOW_INSECURE_NO_AUTH=1 for an explicit insecure override."
    )


def _gateway_allows_anonymous_agents(settings: GatewaySettings) -> bool:
    """Return True when a fully-MISSING agent identity may proceed.

    Permissive on a loopback listener (local development), and on a non-loopback
    listener only when the operator sets the explicit opt-out — mirroring the
    ``allow_insecure_no_auth`` precedent for incoming transport auth. An invalid
    or revoked token is NEVER governed by this function; it always fails closed.
    """
    if _is_loopback_host(settings.listener_host):
        return True
    return settings.allow_anonymous_agents or _env_flag_enabled("AGENT_BOM_GATEWAY_ALLOW_ANONYMOUS_AGENTS")


def _enforce_gateway_anonymous_agents_posture(settings: GatewaySettings) -> None:
    """Emit a loud startup warning when anonymous callers are permitted on a
    non-loopback listener via the explicit opt-out, paralleling the transport
    auth posture warning."""
    if _is_loopback_host(settings.listener_host):
        return
    if settings.allow_anonymous_agents or _env_flag_enabled("AGENT_BOM_GATEWAY_ALLOW_ANONYMOUS_AGENTS"):
        logger.warning(
            "SECURITY: gateway relay accepting anonymous (unidentified) agent callers on non-loopback "
            "listener %s due to explicit opt-out (AGENT_BOM_GATEWAY_ALLOW_ANONYMOUS_AGENTS / "
            "--allow-anonymous-agents). Invalid/revoked tokens are still denied. Use only when an "
            "upstream trust boundary already authenticates callers.",
            _sanitize_for_log(settings.listener_host),
        )


def _validate_runtime_profile_posture(settings: GatewaySettings) -> str:
    """Validate and return the canonical profile-enforcement mode."""
    mode = settings.runtime_profile_enforcement_mode.strip().lower()
    if mode not in {"off", "warn", "enforce"}:
        raise RuntimeError("runtime profile enforcement mode must be off, warn, or enforce")
    if mode != "off" and not settings.runtime_profile_environment.strip():
        raise RuntimeError("runtime profile enforcement requires an operator-controlled profile environment")
    if mode != "off" and not settings.runtime_profile_issuer.strip():
        raise RuntimeError("runtime profile enforcement requires a trusted profile issuer")
    if settings.allow_runtime_profile_dev_bypass and not _is_loopback_host(settings.listener_host):
        raise RuntimeError("runtime profile development bypass is permitted only on a loopback listener")
    return mode


def _role_allows_gateway_relay(role: object) -> bool:
    try:
        normalized = role if isinstance(role, Role) else Role(str(role).lower())
    except ValueError:
        return False
    return normalized in {Role.ADMIN, Role.ANALYST}


def _api_key_allows_gateway_relay(api_key: Any) -> tuple[bool, str]:
    if not _role_allows_gateway_relay(getattr(api_key, "role", None)):
        role_value = getattr(getattr(api_key, "role", None), "value", getattr(api_key, "role", "unknown"))
        return False, f"gateway relay requires analyst role or higher; key has {role_value}"
    has_scope = getattr(api_key, "has_scope", None)
    if callable(has_scope) and not has_scope(_GATEWAY_RELAY_SCOPE):
        return False, f"gateway relay requires {_GATEWAY_RELAY_SCOPE} scope"
    return True, ""


def _configured_gateway_tenant_id() -> str:
    return os.environ.get("AGENT_BOM_TENANT_ID", "default").strip() or "default"


def _authenticate_gateway_request(request: Request, settings: GatewaySettings) -> tuple[str, str]:
    raw_token = _extract_request_token(request)
    if settings.bearer_token:
        if (
            settings._bearer_token_deadline is None
            or datetime.now(timezone.utc) >= settings._bearer_token_deadline
            or not raw_token
            or not _request_has_expected_token(request, settings.bearer_token)
        ):
            raise HTTPException(status_code=401, detail="gateway authentication required")
        return _configured_gateway_tenant_id(), "static_gateway_token"

    try:
        store = get_key_store()
        has_keys = store.has_keys()
    except Exception as exc:
        logger.warning("Gateway key store unavailable: %s", sanitize_text(_sanitize_for_log(exc)))
        raise HTTPException(status_code=503, detail="gateway authentication unavailable") from exc

    if has_keys:
        try:
            api_key = store.verify(raw_token) if raw_token else None
        except Exception as exc:
            logger.warning("Gateway key verification unavailable: %s", sanitize_text(_sanitize_for_log(exc)))
            raise HTTPException(status_code=503, detail="gateway authentication unavailable") from exc
        if api_key is None:
            raise HTTPException(status_code=401, detail="gateway authentication required")
        allowed, reason = _api_key_allows_gateway_relay(api_key)
        if not allowed:
            raise HTTPException(status_code=403, detail=reason)
        try:
            return require_explicit_tenant_id(getattr(api_key, "tenant_id", None)), "api_key"
        except ValueError:
            raise HTTPException(status_code=401, detail="gateway authentication required") from None

    return _configured_gateway_tenant_id(), "none"
