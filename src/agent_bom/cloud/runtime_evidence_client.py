"""CLI/MCP ingestion through the existing authenticated control-plane client."""

from __future__ import annotations

import ipaddress
import os
from typing import Any
from urllib.parse import urlsplit

from agent_bom.client import AgentBomClient
from agent_bom.cloud.runtime_source_auth import SourceAuthenticationError


def push_runtime_evidence(
    *, source_id: str, payload: Any, reason: str, validate_only: bool = False, tenant_id: str | None = None
) -> dict[str, Any]:
    """Resolve credentials from server configuration, never tool arguments."""
    origin = os.environ.get("AGENT_BOM_API_URL", "").strip()
    api_key = os.environ.get("AGENT_BOM_API_KEY", "").strip() or None
    token = os.environ.get("AGENT_BOM_API_TOKEN", "").strip() or None
    try:
        parsed = urlsplit(origin)
        # Credentials require TLS except for an explicit loopback control plane.
        host = parsed.hostname or ""
        loopback = host == "localhost"
        if not loopback:
            try:
                loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                pass
        _ = parsed.port
    except ValueError:
        raise SourceAuthenticationError("Configure a valid control-plane API origin") from None
    if (
        parsed.scheme not in {"https", "http"}
        or (parsed.scheme == "http" and not loopback)
        or parsed.path not in {"", "/"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not (api_key or token)
        or (api_key and token)
    ):
        raise SourceAuthenticationError("Configure an API origin and one source-scoped API credential in the server environment")
    signals = payload.get("signals") if isinstance(payload, dict) else payload
    if not isinstance(signals, list) or len(signals) > 1000 or not all(isinstance(row, dict) for row in signals):
        raise ValueError("Runtime evidence must contain at most 1000 signal objects")
    with AgentBomClient(
        base_url=origin,
        api_key=api_key,
        bearer_token=token,
        tenant_id=tenant_id or os.environ.get("AGENT_BOM_TENANT_ID"),
    ) as client:
        return client.ingest_runtime_evidence(source_id=source_id, signals=signals, reason=reason, validate_only=validate_only)
