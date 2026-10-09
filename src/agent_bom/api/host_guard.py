"""Host-header allowlist and browser-origin checks for the control-plane API.

A browser decides which cookies and same-origin privileges a request carries
from the *name* in the URL, not from the IP it connects to. A page served from
an attacker-controlled name that later resolves to 127.0.0.1 (DNS rebinding)
is therefore "same-origin" with a loopback API under that name. Rejecting any
Host header that is not a name this listener is meant to answer to closes that
path before routing, cookie issuance, or authentication run.

Policy modes:

``loopback``
    The listener is bound to a loopback address and no allowlist is
    configured. Only ``localhost`` and loopback IP literals are accepted.
``allowlist``
    ``AGENT_BOM_API_ALLOWED_HOSTS`` is set. Its entries plus loopback names
    are accepted; ``*.example.com`` matches subdomains of ``example.com``.
    Liveness/readiness probes are exempt so orchestrators that connect by
    pod IP keep working.
``any``
    Non-loopback (or undeclared) listener with no allowlist. Every Host is
    accepted for backward compatibility; such listeners already require real
    authentication, and the dev-session bootstrap is never available on them.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from agent_bom.core.settings import env_str

_logger = logging.getLogger(__name__)

PolicyMode = Literal["loopback", "allowlist", "any"]

PROBE_PATHS = frozenset({"/health", "/healthz", "/livez", "/readyz", "/ping"})


def hostname_from_authority(authority: str) -> str | None:
    """Return the lower-cased hostname from a Host/authority value, or None if malformed."""
    value = (authority or "").strip().lower()
    if not value or any(ch.isspace() for ch in value) or "@" in value or "/" in value:
        return None
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            return None
        host, rest = value[1:end], value[end + 1 :]
        if rest and not rest.startswith(":"):
            return None
        port = rest[1:]
    else:
        host, _, port = value.partition(":")
        if ":" in port:
            return None
    if port and not port.isdigit():
        return None
    return host or None


def is_loopback_hostname(hostname: str | None) -> bool:
    if not hostname:
        return False
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _normalize_entry(entry: str) -> str | None:
    cleaned = entry.strip().lower()
    if cleaned.startswith("*."):
        suffix = hostname_from_authority(cleaned[2:])
        return f"*.{suffix}" if suffix else None
    return hostname_from_authority(cleaned)


@dataclass(frozen=True)
class HostPolicy:
    mode: PolicyMode
    allowed: frozenset[str] = frozenset()
    trusted_origins: frozenset[str] = frozenset()

    def allows(self, hostname: str | None) -> bool:
        if self.mode == "any":
            return True
        if not hostname:
            return False
        if is_loopback_hostname(hostname) or hostname in self.allowed:
            return True
        return any(entry.startswith("*.") and hostname.endswith(entry[1:]) for entry in self.allowed)


def build_host_policy(listener_host: str | None, allowed_raw: str, *, trusted_origins: Iterable[str]) -> HostPolicy:
    """Derive the Host policy from the bind address and the configured allowlist."""
    origins = frozenset(o.strip().lower().rstrip("/") for o in trusted_origins if o.strip() and o.strip() != "*")
    entries = [e for e in (allowed_raw or "").split(",") if e.strip()]
    if any(e.strip() == "*" for e in entries):
        return HostPolicy(mode="any", trusted_origins=origins)
    normalized = [_normalize_entry(entry) for entry in entries]
    if any(entry is None for entry in normalized):
        raise ValueError("AGENT_BOM_API_ALLOWED_HOSTS must contain host names, not URLs or malformed authorities")
    allowed = frozenset(entry for entry in normalized if entry is not None)
    if allowed:
        return HostPolicy(mode="allowlist", allowed=allowed, trusted_origins=origins)
    listener = (listener_host or "").strip().strip("[]").lower()
    if is_loopback_hostname(listener):
        return HostPolicy(mode="loopback", trusted_origins=origins)
    return HostPolicy(mode="any", trusted_origins=origins)


_policy = HostPolicy(mode="any")


def set_host_policy(policy: HostPolicy) -> None:
    global _policy
    _policy = policy


def get_host_policy() -> HostPolicy:
    return _policy


def configure_host_policy(listener_host: str | None, trusted_origins: Iterable[str]) -> HostPolicy:
    """Rebuild the active policy from the listener and ``AGENT_BOM_API_ALLOWED_HOSTS``."""
    policy = build_host_policy(listener_host, env_str("AGENT_BOM_API_ALLOWED_HOSTS"), trusted_origins=trusted_origins)
    set_host_policy(policy)
    return policy


def log_host_policy(policy: HostPolicy | None = None) -> None:
    """Log the effective policy once at serving start; warn when every Host is accepted."""
    active = policy or _policy
    if active.mode == "any":
        _logger.warning(
            "SECURITY: the API accepts requests for any Host header. Set AGENT_BOM_API_ALLOWED_HOSTS to the public "
            "hostname(s) this control plane is served under (comma-separated) to reject unexpected Host values."
        )
    else:
        _logger.info("API Host allowlist active (mode=%s, %d configured host(s))", active.mode, len(active.allowed))


def _first_header(headers: Mapping[str, str], name: str) -> str:
    return (headers.get(name) or "").split(",")[0].strip().lower()


def browser_origin_trusted(headers: Mapping[str, str], policy: HostPolicy | None = None) -> bool:
    """Return whether a cookie-authenticated unsafe request comes from a trusted page.

    Browsers attach ``Origin`` to every non-GET request. Without it, only
    ``Sec-Fetch-Site: same-origin`` is accepted; a request with neither is not
    a browser form/fetch the dashboard would send and is refused.
    """
    active = policy or _policy
    origin = (headers.get("origin") or "").strip().lower()
    if not origin:
        return _first_header(headers, "sec-fetch-site") == "same-origin"
    if origin == "null":
        return False
    if origin.rstrip("/") in active.trusted_origins:
        return True
    try:
        parts = urlsplit(origin)
    except ValueError:
        return False
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return False
    if active.mode != "any":
        return active.allows(hostname_from_authority(parts.netloc))
    return parts.netloc in {_first_header(headers, "host"), _first_header(headers, "x-forwarded-host")} - {""}


def _scope_host(scope: Scope) -> str:
    for key, value in scope.get("headers") or ():
        if key == b"host":
            return str(value.decode("latin-1"))
    return ""


class HostAllowlistMiddleware:
    """Reject requests whose Host header the active policy does not allow."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return
        policy = _policy
        if policy.mode == "any" or policy.allows(hostname_from_authority(_scope_host(scope))):
            await self.app(scope, receive, send)
            return
        if policy.mode == "allowlist" and scope["type"] == "http" and scope.get("path") in PROBE_PATHS:
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await receive()
            await send({"type": "websocket.close", "code": 1008})
            return
        response: Any = JSONResponse(status_code=400, content={"detail": "Invalid Host header"})
        await response(scope, receive, send)
