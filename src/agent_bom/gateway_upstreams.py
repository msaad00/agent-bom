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

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class UpstreamConfigError(ValueError):
    """Raised when ``upstreams.yaml`` is malformed or references missing env vars."""


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
        One of ``"none"``, ``"bearer"``, ``"oauth2_client_credentials"``.
    token_env:
        Env var containing the bearer token (used when ``auth == "bearer"``).
    oauth_token_url / oauth_client_id_env / oauth_client_secret_env / oauth_scopes:
        Parameters for ``oauth2_client_credentials`` — fetched lazily on first
        upstream call and cached until expiry.
    headers:
        Additional static headers to inject on every upstream request.
    """

    name: str
    url: str
    auth: str = "none"
    token_env: str | None = None
    oauth_token_url: str | None = None
    oauth_client_id_env: str | None = None
    oauth_client_secret_env: str | None = None
    oauth_scopes: tuple[str, ...] = ()
    headers: dict[str, str] = field(default_factory=dict)

    def resolved_static_headers(self) -> dict[str, str]:
        """Return the per-upstream headers with bearer tokens resolved from env."""
        resolved = dict(self.headers)
        if self.auth == "bearer":
            if not self.token_env:
                raise UpstreamConfigError(f"upstream {self.name!r}: auth=bearer requires token_env")
            token = os.environ.get(self.token_env, "")
            if not token:
                raise UpstreamConfigError(f"upstream {self.name!r}: token_env {self.token_env!r} is not set")
            resolved["Authorization"] = f"Bearer {token}"
        return resolved


class UpstreamRegistry:
    """Registry of upstream MCP servers the gateway can route to."""

    def __init__(self, upstreams: list[UpstreamConfig]) -> None:
        self._by_name: dict[str, UpstreamConfig] = {}
        for upstream in upstreams:
            if upstream.name in self._by_name:
                raise UpstreamConfigError(f"duplicate upstream name: {upstream.name!r}")
            self._by_name[upstream.name] = upstream

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

    def get(self, name: str) -> UpstreamConfig | None:
        return self._by_name.get(name)

    def names(self) -> list[str]:
        return sorted(self._by_name.keys())

    def __len__(self) -> int:
        return len(self._by_name)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._by_name


def _parse_upstream(raw: Any, *, source: str) -> UpstreamConfig:
    if not isinstance(raw, dict):
        raise UpstreamConfigError(f"{source}: every upstream entry must be a mapping, got {type(raw).__name__}")

    name = raw.get("name")
    if not isinstance(name, str) or not name:
        raise UpstreamConfigError(f"{source}: every upstream requires a non-empty 'name'")

    url = raw.get("url")
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        raise UpstreamConfigError(f"{source}: upstream {name!r} requires an http(s) 'url'")

    auth = raw.get("auth", "none")
    if auth not in {"none", "bearer", "oauth2_client_credentials"}:
        raise UpstreamConfigError(f"{source}: upstream {name!r} has unsupported auth={auth!r}")

    headers = raw.get("headers") or {}
    if not isinstance(headers, dict):
        raise UpstreamConfigError(f"{source}: upstream {name!r} headers must be a mapping")

    scopes_raw = raw.get("scopes") or []
    if not isinstance(scopes_raw, list):
        raise UpstreamConfigError(f"{source}: upstream {name!r} scopes must be a list")

    return UpstreamConfig(
        name=name,
        url=url.rstrip("/"),
        auth=auth,
        token_env=raw.get("token_env"),
        oauth_token_url=raw.get("oauth_token_url"),
        oauth_client_id_env=raw.get("oauth_client_id_env"),
        oauth_client_secret_env=raw.get("oauth_client_secret_env"),
        oauth_scopes=tuple(str(s) for s in scopes_raw),
        headers={str(k): str(v) for k, v in headers.items()},
    )
