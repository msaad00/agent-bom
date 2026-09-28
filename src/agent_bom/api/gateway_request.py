"""Bounded HTTP request context and JSON-RPC credential stripping for the gateway."""

from __future__ import annotations

import math
from typing import Any

from fastapi import HTTPException, Request

from agent_bom.api.forwarded_identity import resolve_forwarded_client_ip
from agent_bom.api.gateway_context import authorized_context_headers
from agent_bom.runtime.gateway_relay_contract import MAX_GATEWAY_RELAY_MESSAGE_BYTES
from agent_bom.security import sanitize_text

_MAX_GATEWAY_MESSAGE_BYTES = MAX_GATEWAY_RELAY_MESSAGE_BYTES


def _sanitize_for_log(value: Any) -> str:
    """Return a single-line representation safe for plain-text logs."""
    return sanitize_text(value).replace("\r", "").replace("\n", "")


def _request_source_ip(request: Request) -> str:
    """Resolve the caller IP for conditional-access CIDR conditions.

    The transport peer is authoritative unless the deployment declares both a
    bounded proxy depth and trusted transport-peer CIDRs.  This prevents a
    direct caller from satisfying an allowlisted CIDR by spoofing
    ``X-Forwarded-For``.
    """
    client = getattr(request, "client", None)
    return resolve_forwarded_client_ip(
        peer_host=getattr(client, "host", "") or "",
        forwarded_for=request.headers.get("x-forwarded-for", ""),
    )


def _request_environment(request: Request) -> str:
    """Resolve the trusted-proxy environment for conditional-access conditions."""
    return (authorized_context_headers(request).get("x-agent-environment", "") or "").strip()[:60]


def _request_risk_score(request: Request) -> float | None:
    """Resolve a trusted-proxy risk score for conditional-access gates.

    Read from the ``x-agent-risk-score`` header (set by an upstream risk engine
    or trust proxy). Missing/untrusted evidence is ``None``; configured risk
    constraints deny when a finite score is unavailable.
    """
    raw = (authorized_context_headers(request).get("x-agent-risk-score", "") or "").strip()
    if not raw:
        return None
    try:
        score = float(raw)
        return score if math.isfinite(score) else None
    except ValueError:
        return None


def _request_context_attributes(request: Request) -> dict[str, str]:
    """Resolve required-context attributes for conditional-access gates.

    Attributes arrive as ``x-agent-ctx-<name>`` headers (e.g.
    ``x-agent-ctx-mfa: true``) so a policy can require ``{"mfa": "true"}``.
    Bounded to keep the decision context small and deterministic.
    """
    attributes: dict[str, str] = {}
    for header, value in authorized_context_headers(request).items():
        lowered = header.lower()
        if lowered.startswith("x-agent-ctx-"):
            key = lowered[len("x-agent-ctx-") :]
            if key:
                attributes[key] = str(value).strip()[:200]
        if len(attributes) >= 32:
            break
    return attributes


def _request_device_id(request: Request) -> str:
    """Resolve the caller device/workstation id for device ABAC conditions.

    Read from the ``x-agent-device-id`` header (set by the endpoint agent / MDM
    posture broker). Empty when unset, in which case a device condition simply
    fails closed for policies that require one.
    """
    return (authorized_context_headers(request).get("x-agent-device-id", "") or "").strip()[:200]


def _request_groups(request: Request) -> list[str]:
    """Resolve the caller's directory groups for group ABAC conditions.

    Groups arrive comma-separated in the ``x-agent-groups`` header (asserted by
    the IdP / trust proxy after authentication). Bounded and de-duplicated.
    """
    raw = (authorized_context_headers(request).get("x-agent-groups", "") or "").strip()
    if not raw:
        return []
    seen: list[str] = []
    for part in raw.split(","):
        value = part.strip()[:120]
        if value and value not in seen:
            seen.append(value)
        if len(seen) >= 64:
            break
    return seen


def _request_client_id(request: Request) -> str:
    """Resolve the MCP client application id for client ABAC conditions.

    Read from the ``x-agent-client-id`` header (the client app making the call).
    Empty when unset; a client condition fails closed for policies requiring one.
    """
    return (authorized_context_headers(request).get("x-agent-client-id", "") or "").strip()[:200]


def _request_cost_center(request: Request, message: dict[str, Any]) -> str:
    """Resolve the chargeback cost-center this call is allocated to.

    Mirrors how cost-center flows elsewhere (OTLP span attrs / allocation tags):
    the caller declares it via the ``x-cost-center`` header or the JSON-RPC
    ``_meta.cost_center`` field. Empty when unset, in which case cost-center
    budget enforcement is a no-op and existing per-agent/tenant semantics are
    untouched.
    """
    header_cc = (request.headers.get("x-cost-center", "") or "").strip()
    if header_cc:
        return header_cc[:120]
    # The caller declares allocation in the MCP ``_meta`` block (the same place
    # ``agent_identity`` lives, under ``params``); also accept a top-level
    # ``_meta`` for callers that flatten it.
    params = message.get("params")
    metas = []
    if isinstance(params, dict) and isinstance(params.get("_meta"), dict):
        metas.append(params["_meta"])
    if isinstance(message.get("_meta"), dict):
        metas.append(message["_meta"])
    for meta in metas:
        meta_cc = meta.get("cost_center")
        if isinstance(meta_cc, str) and meta_cc.strip():
            return meta_cc.strip()[:120]
    return ""


def _strip_gateway_identity_metadata(message: dict[str, Any]) -> dict[str, Any]:
    """Remove the gateway caller credential before crossing the upstream boundary."""
    params = message.get("params")
    if not isinstance(params, dict):
        return message
    raw_meta = params.get("_meta")
    if not isinstance(raw_meta, dict) or "agent_identity" not in raw_meta:
        return message
    forwarded = dict(message)
    forwarded_params = dict(params)
    forwarded_meta = dict(raw_meta)
    forwarded_meta.pop("agent_identity", None)
    if forwarded_meta:
        forwarded_params["_meta"] = forwarded_meta
    else:
        forwarded_params.pop("_meta", None)
    forwarded["params"] = forwarded_params
    return forwarded


async def _read_bounded_gateway_body(request: Any) -> bytes:
    """Read a gateway request without buffering past the JSON-RPC limit."""
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > _MAX_GATEWAY_MESSAGE_BYTES:
            raise HTTPException(status_code=413, detail="gateway request exceeds maximum JSON-RPC message size")
        body.extend(chunk)
    return bytes(body)
