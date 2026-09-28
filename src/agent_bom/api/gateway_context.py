"""Bind conditional-access header authority to explicitly configured proxy peers."""

from __future__ import annotations

import os
from collections.abc import Mapping
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

from fastapi import FastAPI, Request
from starlette.types import Lifespan

from agent_bom.runtime.gateway_settings import GatewaySettings

Network = IPv4Network | IPv6Network


def trusted_context_networks(settings: GatewaySettings) -> tuple[Network, ...]:
    """Resolve once at startup: explicit settings override environment; empty denies."""
    configured = settings.trusted_context_proxy_cidrs
    if configured is None:
        raw = os.environ.get("AGENT_BOM_GATEWAY_TRUSTED_CONTEXT_PROXY_CIDRS", "").strip()
        configured = tuple(raw.split(",")) if raw else ()
    error = "Gateway trusted context proxy CIDRs must be a bounded list of explicit networks"
    if not isinstance(configured, (tuple, list)) or len(configured) > 32:
        raise ValueError(error)
    networks: list[Network] = []
    for value in configured:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(error)
        try:
            network = ip_network(value.strip(), strict=False)
        except ValueError:
            raise ValueError(error) from None
        if network.prefixlen == 0:
            raise ValueError(error)
        networks.append(network)
    return tuple(networks)


def _trusted_peer(request: Request, networks: tuple[Network, ...]) -> bool:
    try:
        peer = ip_address(request.client.host if request.client else "")
    except ValueError:
        return False
    return any(peer in network for network in networks)


def authorized_context_headers(request: Request) -> Mapping[str, str]:
    """Caller headers and body fields cannot set the transport's verified state."""
    return request.headers if getattr(request.state, "gateway_context_authorized", False) is True else {}


def create_gateway_http_app(settings: GatewaySettings, lifespan: Lifespan[FastAPI]) -> FastAPI:
    networks = trusted_context_networks(settings)
    app = FastAPI(title="agent-bom gateway", version="1", lifespan=lifespan)

    @app.middleware("http")
    async def bind_context_authority(request: Request, call_next):
        request.state.gateway_context_authorized = _trusted_peer(request, networks)
        return await call_next(request)

    return app
