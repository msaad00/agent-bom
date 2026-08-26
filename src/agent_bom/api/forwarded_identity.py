"""Trusted reverse-proxy client identity resolution.

Forwarded address headers are caller-controlled unless the transport peer and
proxy depth are both explicitly configured.  Keep that invariant in one place
so authentication throttles and runtime conditional-access policy cannot drift.
"""

from __future__ import annotations

import os
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network


def trusted_proxy_hops() -> int:
    """Return the configured positive proxy depth, or zero when invalid."""
    raw = (os.environ.get("AGENT_BOM_TRUSTED_PROXY_HOPS") or "").strip()
    if not raw:
        return 0
    try:
        value = int(raw)
    except ValueError:
        return 0
    return value if 1 <= value <= 32 else 0


def trusted_proxy_networks() -> tuple[IPv4Network | IPv6Network, ...]:
    """Return explicitly trusted transport-peer networks, or none on error."""
    raw = (os.environ.get("AGENT_BOM_TRUSTED_PROXY_CIDRS") or "").strip()
    if not raw:
        return ()
    try:
        return tuple(ip_network(part.strip(), strict=False) for part in raw.split(",") if part.strip())
    except ValueError:
        return ()


def resolve_forwarded_client_ip(*, peer_host: str, forwarded_for: str, fallback: str = "") -> str:
    """Resolve a client address only through a declared trusted proxy chain.

    The direct transport peer remains authoritative unless it belongs to an
    allowlisted proxy CIDR and a bounded positive hop count is configured.
    Malformed, oversized, or shorter-than-declared chains fall back to the
    transport peer instead of trusting caller-supplied input.
    """
    host = str(peer_host or fallback)
    hops = trusted_proxy_hops()
    networks = trusted_proxy_networks()
    try:
        peer = ip_address(host)
    except ValueError:
        peer = None
    if hops > 0 and networks and peer is not None and any(peer in network for network in networks):
        forwarded = [part.strip() for part in str(forwarded_for or "").split(",") if part.strip()]
        if hops <= len(forwarded) <= 32:
            candidate = forwarded[-hops]
            try:
                host = str(ip_address(candidate))
            except ValueError:
                pass
    return host
