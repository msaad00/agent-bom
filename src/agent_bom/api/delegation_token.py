"""Scoped, verifiable, expiring delegation tokens for multi-agent handoffs.

Today A2A delegation is only *posture-scanned* (``a2a_auth_posture``) and
mutual-auth enforced. This module issues a first-class **delegation token** that
a delegating agent hands to a delegatee and that the receiver cryptographically
verifies before acting on-behalf-of the delegator:

* **Scoped** — the token carries an explicit list of delegated capabilities
  (tool names / scopes). A receiver validating for a capability outside that
  list is rejected (over-scoped call), so a token is never bearer-all.
* **Verifiable** — the token is an HMAC-SHA256 signature over its payload using
  a control-plane signing key (``AGENT_BOM_DELEGATION_SIGNING_KEY``). The
  receiver validates the signature with a constant-time compare; a tampered
  payload or scope fails closed. No shared database lookup is required.
* **Expiring** — an ``exp`` claim bounds the token's lifetime. An expired token
  is rejected fail-closed.
* **Chain-aware** — the token records the ``delegation_chain`` (ordered hops)
  and a remaining-depth budget. Propagating to the next hop can only *narrow*
  the scope and *never* extend the expiry or the depth budget, so authority
  cannot be amplified as it flows down the chain.

The token format mirrors the browser-session token (``payload_b64.sig_b64``)
and reuses the same file/env secret-source resolution.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

# A delegation chain deeper than this is refused at issue/propagate time so a
# token cannot fan out authority indefinitely.
MAX_DELEGATION_DEPTH = 8
# Hard ceiling on token lifetime so an issuer cannot mint a long-lived bearer.
MAX_DELEGATION_TTL_SECONDS = 3600
_EPHEMERAL_SIGNING_KEY = secrets.token_bytes(32)


class DelegationTokenError(Exception):
    """Raised when a delegation token cannot be verified (fails closed)."""


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _signing_key() -> bytes:
    """Resolve the delegation signing key from the control-plane secret source.

    Derives a 32-byte key from ``AGENT_BOM_DELEGATION_SIGNING_KEY`` (file or env)
    via PBKDF2. When unset, falls back to a per-process ephemeral key so
    single-node/dev flows still work; tokens then become invalid after restart
    (and across replicas), which is the safe default for a signing secret.
    """
    from agent_bom.api.secret_source import resolve_secret

    configured = resolve_secret("AGENT_BOM_DELEGATION_SIGNING_KEY")
    if configured:
        return hashlib.pbkdf2_hmac(
            "sha256",
            configured.encode("utf-8"),
            b"agent-bom-delegation-signing-key:v1",
            600_000,
            dklen=32,
        )
    return _EPHEMERAL_SIGNING_KEY


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_scopes(scopes: list[str] | tuple[str, ...] | None) -> list[str]:
    out: list[str] = []
    for scope in scopes or []:
        value = str(scope).strip()[:200]
        if value and value not in out:
            out.append(value)
        if len(out) >= 100:
            break
    return sorted(out)


@dataclass(frozen=True)
class DelegationToken:
    """The verified claims of a delegation token."""

    jti: str
    tenant_id: str
    delegator: str
    delegatee: str
    scopes: list[str]
    chain: list[str]
    remaining_depth: int
    iat: int
    exp: int

    def allows(self, scope: str) -> bool:
        """True when ``scope`` is within the delegated capability set."""
        return str(scope).strip() in set(self.scopes)


def issue_delegation_token(
    *,
    tenant_id: str,
    delegator: str,
    delegatee: str,
    scopes: list[str],
    ttl_seconds: int,
    chain: list[str] | None = None,
    remaining_depth: int = MAX_DELEGATION_DEPTH,
    at: datetime | None = None,
) -> tuple[str, DelegationToken]:
    """Mint a scoped, signed, expiring delegation token.

    ``scopes`` MUST be non-empty — a scopeless token would be bearer-all and is
    refused. Returns ``(token_string, claims)``.
    """
    normalized_scopes = _normalize_scopes(scopes)
    if not normalized_scopes:
        raise ValueError("a delegation token must carry at least one scope")
    if not tenant_id:
        raise ValueError("tenant_id is required")
    if not delegator or not delegatee:
        raise ValueError("delegator and delegatee are required")
    depth = max(0, min(int(remaining_depth), MAX_DELEGATION_DEPTH))
    if depth <= 0:
        raise ValueError("delegation depth budget is exhausted")
    now = at or _now()
    ttl = max(1, min(int(ttl_seconds), MAX_DELEGATION_TTL_SECONDS))
    hops = [str(h).strip()[:200] for h in (chain or []) if str(h).strip()][:MAX_DELEGATION_DEPTH]
    hops = [*hops, str(delegatee).strip()[:200]]
    claims = DelegationToken(
        jti=f"dlg_{secrets.token_hex(8)}",
        tenant_id=tenant_id,
        delegator=str(delegator)[:200],
        delegatee=str(delegatee)[:200],
        scopes=normalized_scopes,
        chain=hops,
        remaining_depth=depth,
        iat=int(now.timestamp()),
        exp=int((now + timedelta(seconds=ttl)).timestamp()),
    )
    return _encode(claims), claims


def _encode(claims: DelegationToken) -> str:
    payload: dict[str, Any] = {
        "v": 1,
        "jti": claims.jti,
        "tenant_id": claims.tenant_id,
        "delegator": claims.delegator,
        "delegatee": claims.delegatee,
        "scopes": claims.scopes,
        "chain": claims.chain,
        "depth": claims.remaining_depth,
        "iat": claims.iat,
        "exp": claims.exp,
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    encoded_payload = _b64encode(payload_bytes)
    signature = hmac.new(_signing_key(), encoded_payload.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded_payload}.{_b64encode(signature)}"


def verify_delegation_token(
    token: str,
    *,
    tenant_id: str | None = None,
    required_scope: str | None = None,
    at: datetime | None = None,
) -> DelegationToken:
    """Verify a delegation token and return its claims, or raise fail-closed.

    Checks (in order): structural shape, signature (constant-time), expiry,
    optional ``tenant_id`` binding, and — when ``required_scope`` is supplied —
    that the requested capability is within the token's delegated scope. An
    over-scoped call (capability not delegated) is rejected.
    """
    if not token or "." not in token:
        raise DelegationTokenError("delegation token is missing or malformed")
    encoded_payload, encoded_signature = token.split(".", 1)
    expected = hmac.new(_signing_key(), encoded_payload.encode("ascii"), hashlib.sha256).digest()
    try:
        supplied = _b64decode(encoded_signature)
    except Exception as exc:  # noqa: BLE001
        raise DelegationTokenError("delegation token signature is malformed") from exc
    if not hmac.compare_digest(supplied, expected):
        raise DelegationTokenError("delegation token signature is invalid")
    try:
        payload = json.loads(_b64decode(encoded_payload).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise DelegationTokenError("delegation token payload is invalid") from exc
    if not isinstance(payload, dict):
        raise DelegationTokenError("delegation token payload is invalid")
    now = int((at or _now()).timestamp())
    exp = int(payload.get("exp") or 0)
    if exp <= now:
        raise DelegationTokenError("delegation token is expired")
    token_tenant = str(payload.get("tenant_id") or "")
    if tenant_id is not None and token_tenant != tenant_id:
        raise DelegationTokenError("delegation token tenant does not match")
    scopes = [str(s) for s in (payload.get("scopes") or []) if str(s)]
    claims = DelegationToken(
        jti=str(payload.get("jti") or ""),
        tenant_id=token_tenant,
        delegator=str(payload.get("delegator") or ""),
        delegatee=str(payload.get("delegatee") or ""),
        scopes=scopes,
        chain=[str(h) for h in (payload.get("chain") or []) if str(h)],
        remaining_depth=int(payload.get("depth") or 0),
        iat=int(payload.get("iat") or 0),
        exp=exp,
    )
    if required_scope is not None and not claims.allows(required_scope):
        raise DelegationTokenError(f"delegation token does not grant scope '{required_scope}'")
    return claims


def propagate_delegation_token(
    token: str,
    *,
    next_delegatee: str,
    scopes: list[str] | None = None,
    tenant_id: str | None = None,
    at: datetime | None = None,
) -> tuple[str, DelegationToken]:
    """Re-issue a token for the next hop, narrowing scope and decrementing depth.

    The parent token is verified first (fail-closed). The child token:

    * may only carry a **subset** of the parent's scopes (requesting a broader
      scope raises — authority cannot be amplified down the chain),
    * inherits the parent's ``exp`` (never extended),
    * decrements the remaining-depth budget (refused when exhausted),
    * appends ``next_delegatee`` to the delegation chain.
    """
    parent = verify_delegation_token(token, tenant_id=tenant_id, at=at)
    if parent.remaining_depth <= 1:
        raise DelegationTokenError("delegation depth budget is exhausted")
    requested = _normalize_scopes(scopes) if scopes is not None else list(parent.scopes)
    if not requested:
        raise DelegationTokenError("a propagated delegation token must retain at least one scope")
    broadened = set(requested) - set(parent.scopes)
    if broadened:
        raise DelegationTokenError("a propagated delegation token cannot broaden scope")
    child = DelegationToken(
        jti=f"dlg_{secrets.token_hex(8)}",
        tenant_id=parent.tenant_id,
        delegator=parent.delegatee,
        delegatee=str(next_delegatee)[:200],
        scopes=requested,
        chain=[*parent.chain, str(next_delegatee).strip()[:200]],
        remaining_depth=parent.remaining_depth - 1,
        iat=parent.iat,
        exp=parent.exp,
    )
    return _encode(child), child
