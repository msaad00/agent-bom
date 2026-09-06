"""Resolve runtime source authority from existing API authentication."""

from __future__ import annotations

from datetime import datetime
from typing import Any, cast

from agent_bom.cloud.runtime_source_auth import RuntimeSourcePrincipal, SourceAuthenticationError


def _epoch(value: str | None) -> float:
    if not value:
        raise ValueError("missing credential timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("credential timestamp requires timezone")
    return parsed.timestamp()


def runtime_source_principal(request: Any) -> RuntimeSourcePrincipal:
    """Accept verified, expiring API keys/SAML keys or verified OIDC JWTs.

    Static keys, proxy assertions and unbound browser sessions cannot establish
    source authority. Key state is re-read so revocation/rotation remain active.
    """
    from agent_bom.api.auth import get_key_store

    state = request.state
    tenant = str(getattr(state, "tenant_id", "") or "")
    method = getattr(state, "auth_method", "")
    try:
        key_id = getattr(state, "api_key_id", None)
        if method in {"api_key", "saml", "browser_session"} and key_id:
            key = get_key_store().get(str(key_id))
            if key is None or not key.is_usable() or key.tenant_id != tenant:
                raise ValueError("inactive credential")
            return RuntimeSourcePrincipal(
                subject=f"api-key:{key.key_id}",
                tenant_id=tenant,
                scopes=tuple(key.scopes),
                issued_at=_epoch(key.created_at),
                expires_at=_epoch(key.expires_at),
            )
        if method == "oidc":
            claims = getattr(state, "verified_oidc_claims", None)
            if not isinstance(claims, dict) or not claims.get("iss") or not claims.get("sub"):
                raise ValueError("missing verified identity")
            scopes = claims.get("scope", claims.get("scp", []))
            if isinstance(scopes, str):
                scopes = scopes.split()
            if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
                raise ValueError("invalid credential scopes")
            issued, expires = claims.get("iat"), claims.get("exp")
            if type(issued) not in (int, float) or type(expires) not in (int, float):
                raise ValueError("missing credential lifetime")
            return RuntimeSourcePrincipal(
                subject=f"oidc:{claims['iss']}:{claims['sub']}",
                tenant_id=tenant,
                scopes=tuple(scopes),
                issued_at=cast(float, issued),
                expires_at=cast(float, expires),
            )
    except (ValueError, TypeError, OverflowError):
        pass
    raise SourceAuthenticationError("runtime evidence source authentication failed")
