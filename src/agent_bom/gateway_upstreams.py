"""Multi-MCP gateway upstream registry.

Loads ``upstreams.yaml`` and exposes an ``UpstreamRegistry`` that the
gateway server uses to route client requests to the right upstream MCP
server and inject per-upstream credentials.

Design doc: docs/design/MULTI_MCP_GATEWAY.md.

The registry is intentionally simple — no dynamic reload, no network
discovery. Upstream config is operator-authored and mounted from a
ConfigMap or Secret. Reload = redeploy.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class UpstreamConfigError(ValueError):
    """Raised when ``upstreams.yaml`` is malformed or references missing env vars."""


SUPPORTED_AUTH_MODES: tuple[str, ...] = ("none", "bearer", "oauth2_client_credentials")


# Process-wide cache for OAuth2 client-credentials access tokens. Keyed by
# ``(token_url, client_id, scopes)`` so two upstreams pointing at the same
# IdP with the same credentials share a token.
_oauth_cache_lock = threading.Lock()
_oauth_cache: dict[tuple[str, str, tuple[str, ...]], tuple[str, float]] = {}
_oauth_singleflight_lock = threading.Lock()
_oauth_singleflight_locks: dict[tuple[str, str, tuple[str, ...]], asyncio.Lock] = {}


def _cached_oauth_token(key: tuple[str, str, tuple[str, ...]]) -> str | None:
    with _oauth_cache_lock:
        entry = _oauth_cache.get(key)
        if entry is None:
            return None
        token, expires_at = entry
        if expires_at - 60.0 <= time.time():
            return None  # expire early so we refresh before the token actually dies
        return token


def _store_oauth_token(key: tuple[str, str, tuple[str, ...]], token: str, expires_in: int) -> None:
    with _oauth_cache_lock:
        _oauth_cache[key] = (token, time.time() + max(30, expires_in))


def _oauth_singleflight_for(key: tuple[str, str, tuple[str, ...]]) -> asyncio.Lock:
    with _oauth_singleflight_lock:
        lock = _oauth_singleflight_locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            _oauth_singleflight_locks[key] = lock
        return lock


def reset_oauth_cache_for_tests() -> None:
    """Drop the process-wide OAuth2 token cache — test-only entry point."""
    with _oauth_cache_lock:
        _oauth_cache.clear()
    with _oauth_singleflight_lock:
        _oauth_singleflight_locks.clear()


@dataclass(frozen=True)
class UpstreamConfig:
    """A single upstream MCP server the gateway fronts.

    Attributes
    ----------
    name:
        Stable identifier used in request routing (``/mcp/{name}``).
    url:
        Base URL of the upstream MCP server. Must be HTTPS in production.
    auth:
        One of ``SUPPORTED_AUTH_MODES`` — ``none``, ``bearer``, or
        ``oauth2_client_credentials``.
    token_env:
        Env var containing the bearer token (used when ``auth == "bearer"``).
    oauth_token_url / oauth_client_id_env / oauth_client_secret_env / oauth_scopes:
        OAuth2 client-credentials parameters. Tokens are fetched on first
        use and cached until ~60 s before expiry.
    headers:
        Additional static headers to inject on every upstream request.
    tenant_id:
        Optional tenant owner for this upstream. When set, the gateway must
        only route requests from that tenant to this upstream. When unset, the
        upstream is treated as a legacy/global entry for single-tenant deploys.
    """

    name: str
    url: str
    tenant_id: str | None = None
    auth: str = "none"
    token_env: str | None = None
    oauth_token_url: str | None = None
    oauth_client_id_env: str | None = None
    oauth_client_secret_env: str | None = None
    oauth_scopes: tuple[str, ...] = ()
    headers: dict[str, str] = field(default_factory=dict)

    def resolved_static_headers(self) -> dict[str, str]:
        """Return the per-upstream static headers with bearer tokens resolved from env.

        OAuth2 client-credentials tokens are NOT included here because they
        require a network fetch + refresh loop — use ``resolve_auth_headers``
        for those (async, token-cache-aware).
        """
        resolved = dict(self.headers)
        if self.auth == "bearer":
            if not self.token_env:
                raise UpstreamConfigError(f"upstream {self.name!r}: auth=bearer requires token_env")
            token = os.environ.get(self.token_env, "")
            if not token:
                raise UpstreamConfigError(f"upstream {self.name!r}: token_env {self.token_env!r} is not set")
            resolved["Authorization"] = f"Bearer {token}"
        return resolved

    async def resolve_auth_headers(self) -> dict[str, str]:
        """Return the full per-request header set, fetching OAuth2 tokens if needed."""
        headers = self.resolved_static_headers()
        if self.auth == "oauth2_client_credentials":
            headers["Authorization"] = f"Bearer {await self._fetch_oauth2_token()}"
        return headers

    async def _fetch_oauth2_token(self) -> str:
        if not self.oauth_token_url:
            raise UpstreamConfigError(f"upstream {self.name!r}: auth=oauth2_client_credentials requires oauth_token_url")
        if not self.oauth_client_id_env or not self.oauth_client_secret_env:
            raise UpstreamConfigError(
                f"upstream {self.name!r}: auth=oauth2_client_credentials requires oauth_client_id_env and oauth_client_secret_env"
            )
        client_id = os.environ.get(self.oauth_client_id_env, "")
        client_secret = os.environ.get(self.oauth_client_secret_env, "")
        if not client_id or not client_secret:
            raise UpstreamConfigError(
                f"upstream {self.name!r}: OAuth2 client credentials env vars "
                f"({self.oauth_client_id_env}, {self.oauth_client_secret_env}) are not set"
            )

        cache_key = (self.oauth_token_url, client_id, self.oauth_scopes)
        cached = _cached_oauth_token(cache_key)
        if cached is not None:
            return cached

        async with _oauth_singleflight_for(cache_key):
            cached = _cached_oauth_token(cache_key)
            if cached is not None:
                return cached
            return await self._fetch_and_store_oauth2_token(cache_key, self.oauth_token_url, client_id, client_secret)

    async def _fetch_and_store_oauth2_token(
        self,
        cache_key: tuple[str, str, tuple[str, ...]],
        token_url: str,
        client_id: str,
        client_secret: str,
    ) -> str:
        import httpx

        form: dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if self.oauth_scopes:
            form["scope"] = " ".join(self.oauth_scopes)

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                token_url,
                data=form,
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            payload = response.json()

        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise UpstreamConfigError(f"upstream {self.name!r}: OAuth2 token endpoint {self.oauth_token_url!r} returned no access_token")
        expires_in = int(payload.get("expires_in") or 3600)
        _store_oauth_token(cache_key, access_token, expires_in)
        logger.info(
            "gateway: fetched OAuth2 access token for upstream=%s token_url=%s (expires_in=%ds)",
            self.name,
            self.oauth_token_url,
            expires_in,
        )
        return access_token


class UpstreamRegistry:
    """Registry of upstream MCP servers the gateway can route to."""

    def __init__(self, upstreams: list[UpstreamConfig]) -> None:
        self._by_name: dict[tuple[str | None, str], UpstreamConfig] = {}
        self._tenant_presence_by_name: dict[str, set[str]] = {}
        for upstream in upstreams:
            key = (upstream.tenant_id, upstream.name)
            if key in self._by_name:
                tenant_label = upstream.tenant_id or "global"
                raise UpstreamConfigError(f"duplicate upstream name for tenant {tenant_label!r}: {upstream.name!r}")
            self._by_name[key] = upstream
            if upstream.tenant_id:
                self._tenant_presence_by_name.setdefault(upstream.name, set()).add(upstream.tenant_id)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "UpstreamRegistry":
        """Load + validate an ``upstreams.yaml`` config."""
        path = Path(path)
        if not path.exists():
            raise UpstreamConfigError(f"upstreams config not found: {path}")
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError as exc:
            raise UpstreamConfigError(f"malformed YAML in {path}: {exc}") from exc

        raw_upstreams = data.get("upstreams")
        if not isinstance(raw_upstreams, list) or not raw_upstreams:
            raise UpstreamConfigError(f"{path} must define a non-empty 'upstreams' list")

        upstreams = [_parse_upstream(raw, source=str(path)) for raw in raw_upstreams]
        logger.info("gateway: loaded %d upstreams from %s", len(upstreams), path)
        return cls(upstreams)

    @classmethod
    def from_discovery_response(cls, payload: dict[str, Any]) -> "UpstreamRegistry":
        """Build a registry from a ``/v1/gateway/upstreams/discovered`` response.

        The control plane returns upstreams with ``auth: none`` because
        discovery sees URLs but not credentials. Operators who need bearer
        tokens layer them on via their local ``upstreams.yaml`` overlay
        (see ``merge_with_overlay``).
        """
        raw_upstreams = payload.get("upstreams") or []
        if not isinstance(raw_upstreams, list):
            raise UpstreamConfigError("discovery response must contain an 'upstreams' list")
        response_tenant_id = payload.get("tenant_id")
        upstreams = [
            _parse_upstream(
                raw,
                source="control-plane discovery",
                default_tenant_id=response_tenant_id if isinstance(response_tenant_id, str) and response_tenant_id else None,
            )
            for raw in raw_upstreams
        ]
        logger.info("gateway: loaded %d upstreams from control-plane discovery", len(upstreams))
        return cls(upstreams)

    def merged_with(self, overlay: "UpstreamRegistry") -> "UpstreamRegistry":
        """Merge another registry on top of this one — overlay wins per name.

        Used when the gateway pulls auto-discovered upstreams from the
        control plane AND the operator wants to override a subset (typically
        to attach bearer-token auth to an upstream discovery can't infer).
        """
        merged: dict[tuple[str | None, str], UpstreamConfig] = dict(self._by_name)
        for key, upstream in overlay._by_name.items():
            merged[key] = upstream
        new = UpstreamRegistry.__new__(UpstreamRegistry)
        new._by_name = merged
        new._tenant_presence_by_name = {}
        for upstream in merged.values():
            if upstream.tenant_id:
                new._tenant_presence_by_name.setdefault(upstream.name, set()).add(upstream.tenant_id)
        return new

    def get(self, name: str, tenant_id: str | None = None) -> UpstreamConfig | None:
        if tenant_id:
            exact = self._by_name.get((tenant_id, name))
            if exact is not None:
                return exact
            # Fail closed when this name has any tenant-bound entries. Falling
            # back to a legacy/global entry here would let one tenant
            # accidentally route into another tenant's administrative surface.
            if tenant_id in self._tenant_presence_by_name.get(name, set()) or self._tenant_presence_by_name.get(name):
                return None
        global_match = self._by_name.get((None, name))
        if global_match is not None:
            return global_match
        tenant_ids = self._tenant_presence_by_name.get(name, set())
        if len(tenant_ids) == 1:
            only_tenant = next(iter(tenant_ids))
            return self._by_name.get((only_tenant, name))
        return None

    def names(self, tenant_id: str | None = None) -> list[str]:
        if tenant_id:
            names = {name for (entry_tenant, name) in self._by_name if entry_tenant == tenant_id}
            # Only include global names when there is no tenant-bound variant
            # for this name anywhere. That keeps single-tenant compatibility
            # without silently advertising cross-tenant shared routes.
            for (entry_tenant, name), _upstream in self._by_name.items():
                if entry_tenant is None and name not in self._tenant_presence_by_name:
                    names.add(name)
            return sorted(names)
        return sorted({name for (_tenant, name) in self._by_name})

    def __len__(self) -> int:
        return len(self._by_name)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and ((None, name) in self._by_name or name in self._tenant_presence_by_name)


def fetch_discovered_upstreams(
    control_plane_url: str,
    *,
    token: str | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Pull auto-discovered upstreams from an agent-bom control plane.

    Returns the JSON body of ``GET /v1/gateway/upstreams/discovered``.
    Callers typically wrap this in ``UpstreamRegistry.from_discovery_response``.

    Kept dependency-light (httpx is already a core dep) so the gateway
    startup path doesn't pull extra packages.
    """
    import httpx

    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = httpx.get(
        control_plane_url.rstrip("/") + "/v1/gateway/upstreams/discovered",
        headers=headers,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def _parse_upstream(raw: Any, *, source: str, default_tenant_id: str | None = None) -> UpstreamConfig:
    if not isinstance(raw, dict):
        raise UpstreamConfigError(f"{source}: every upstream entry must be a mapping, got {type(raw).__name__}")

    name = raw.get("name")
    if not isinstance(name, str) or not name:
        raise UpstreamConfigError(f"{source}: every upstream requires a non-empty 'name'")

    url = raw.get("url")
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        raise UpstreamConfigError(f"{source}: upstream {name!r} requires an http(s) 'url'")

    auth = raw.get("auth", "none")
    if auth not in SUPPORTED_AUTH_MODES:
        raise UpstreamConfigError(
            f"{source}: upstream {name!r} has unsupported auth={auth!r} — supported: {', '.join(SUPPORTED_AUTH_MODES)}"
        )

    headers = raw.get("headers") or {}
    if not isinstance(headers, dict):
        raise UpstreamConfigError(f"{source}: upstream {name!r} headers must be a mapping")

    scopes_raw = raw.get("scopes") or []
    if not isinstance(scopes_raw, list):
        raise UpstreamConfigError(f"{source}: upstream {name!r} scopes must be a list")

    tenant_id = raw.get("tenant_id", default_tenant_id)
    if tenant_id is not None and not isinstance(tenant_id, str):
        raise UpstreamConfigError(f"{source}: upstream {name!r} tenant_id must be a string")

    return UpstreamConfig(
        name=name,
        url=url.rstrip("/"),
        tenant_id=tenant_id,
        auth=auth,
        token_env=raw.get("token_env"),
        oauth_token_url=raw.get("oauth_token_url"),
        oauth_client_id_env=raw.get("oauth_client_id_env"),
        oauth_client_secret_env=raw.get("oauth_client_secret_env"),
        oauth_scopes=tuple(str(s) for s in scopes_raw),
        headers={str(k): str(v) for k, v in headers.items()},
    )
