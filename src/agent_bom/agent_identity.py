"""Agent identity extraction and validation for the MCP proxy.

Reads caller identity from the MCP ``_meta.agent_identity`` field, resolves
it to a stable ``agent_id`` string, and optionally enforces that a valid
identity is present.

Two supported token formats:
- **JWT** (three base64url parts): payload decoded, ``sub`` claim used as
  ``agent_id``.  When ``jwks_uri`` is set in policy, the signature is
  cryptographically verified (RS256/ES256/RS384/ES384).  Expiry (``exp``) is
  always checked.  The ``none`` algorithm is always rejected.  Enforced
  identity mode requires JWT verification; unsigned JWTs are only accepted in
  non-blocking audit mode.
- **Opaque token**: looked up in ``policy.agent_tokens`` dict
  (``{token: agent_id}``).

Policy keys:
- ``jwks_uri``: URL to a JWKS endpoint for signature verification
- ``oidc_issuer``: OIDC issuer base URL; ``jwks_uri`` auto-discovered via
  ``{issuer}/.well-known/openid-configuration``
- ``require_agent_identity``: if true, calls without a valid identity are
  blocked
- ``agent_tokens``: opaque token → agent_id mapping

If no identity is present the proxy records ``"anonymous"`` in the audit log.
If ``require_agent_identity: true`` is set in policy the call is blocked.
"""

from __future__ import annotations

import base64
import json
import logging
import threading
import time
from collections.abc import Callable
from typing import Any

from agent_bom.security import sanitize_log_label

logger = logging.getLogger(__name__)

# Sentinel used when no identity token is provided
ANONYMOUS = "anonymous"

# Accepted JWT algorithms — "none" is explicitly excluded
_ACCEPTED_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]

# JWKS cache: url → (jwks_data, fetched_at_epoch)
_jwks_cache: dict[str, tuple[dict, float]] = {}
_jwks_lock = threading.Lock()
_JWKS_CACHE_TTL = 3600.0  # 1 hour


def _sanitize_identity_error(error: str) -> str:
    """Return a bounded single-line identity validation reason."""

    sanitized = sanitize_log_label(error, max_len=240)
    sanitized = sanitized.replace("\\r", " ").replace("\\n", " ").replace("\\t", " ")
    return sanitize_log_label(sanitized, max_len=240) or "identity validation failed"


# ─── JWKS helpers ────────────────────────────────────────────────────────────


def _fetch_jwks(jwks_uri: str) -> dict | None:
    """Fetch a JWKS document with a 1-hour in-process cache.

    Returns the JWKS dict on success, None on network/parse failure.
    SSRF-safe: only called with URLs that have already been resolved from
    trusted policy or OIDC discovery documents.
    """
    with _jwks_lock:
        cached = _jwks_cache.get(jwks_uri)
        if cached and time.time() - cached[1] < _JWKS_CACHE_TTL:
            return cached[0]

    try:
        import httpx  # optional dep; graceful if missing
    except ImportError:
        logger.debug("httpx not available; JWKS signature verification skipped")
        return None

    try:
        resp = httpx.get(jwks_uri, timeout=10.0, follow_redirects=False)
        resp.raise_for_status()
        data: dict = resp.json()
    except Exception as e:  # noqa: BLE001
        logger.debug("JWKS fetch failed for %s: %s", jwks_uri, e)
        return None

    with _jwks_lock:
        _jwks_cache[jwks_uri] = (data, time.time())
    return data


def _discover_jwks_uri(oidc_issuer: str) -> str | None:
    """Resolve JWKS URI from an OIDC discovery document."""
    try:
        import httpx
    except ImportError:
        return None

    discovery_url = oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        resp = httpx.get(discovery_url, timeout=10.0, follow_redirects=False)
        resp.raise_for_status()
        return resp.json().get("jwks_uri")
    except Exception as e:  # noqa: BLE001
        logger.debug("OIDC discovery failed for %s: %s", oidc_issuer, e)
        return None


def _resolve_jwks_uri(policy: dict) -> str | None:
    """Return the JWKS URI from policy (direct or via oidc_issuer discovery)."""
    if uri := policy.get("jwks_uri"):
        return str(uri)
    if issuer := policy.get("oidc_issuer"):
        return _discover_jwks_uri(str(issuer))
    return None


def _verify_jwt_signature(token: str, jwks_uri: str) -> tuple[bool, str | None]:
    """Cryptographically verify a JWT signature using a JWKS endpoint.

    Returns (verified, error_message).  On library-unavailable or network
    failure, returns (False, reason) so the caller can decide whether to
    block or warn based on ``require_agent_identity``.
    """
    try:
        import jwt as pyjwt
        from jwt.algorithms import ECAlgorithm, RSAAlgorithm
    except ImportError:
        logger.debug("PyJWT not installed; cannot verify JWT signature — install 'agent-bom[oidc]'")
        return False, "PyJWT not available (install agent-bom[oidc])"

    # Reject 'none' algorithm before touching the key
    try:
        header: dict[str, Any] = pyjwt.get_unverified_header(token)
    except Exception as e:  # noqa: BLE001
        return False, f"Cannot decode JWT header: {e}"

    alg = header.get("alg", "")
    if alg.lower() == "none" or alg not in _ACCEPTED_ALGORITHMS:
        return False, f"JWT algorithm '{alg}' not accepted"

    kid: str | None = header.get("kid")

    jwks = _fetch_jwks(jwks_uri)
    if jwks is None:
        return False, "JWKS endpoint unreachable"

    keys: list[dict] = jwks.get("keys", [])
    candidates = [k for k in keys if not kid or k.get("kid") == kid]

    if not candidates:
        return False, f"No JWKS key matches kid={kid!r}"

    for jwk in candidates:
        try:
            kty = jwk.get("kty", "")
            if kty == "RSA":
                public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))
            elif kty == "EC":
                public_key = ECAlgorithm.from_jwk(json.dumps(jwk))  # type: ignore[assignment]
            else:
                continue
            # Verify signature only; expiry is checked separately
            pyjwt.decode(
                token,
                public_key,  # type: ignore[arg-type]
                algorithms=[alg],
                options={"verify_exp": False, "verify_aud": False},
            )
            return True, None
        except (ValueError, KeyError, TypeError, pyjwt.PyJWTError):
            continue

    return False, "JWT signature verification failed (no matching key succeeded)"


# ─── Token parsing ────────────────────────────────────────────────────────────


def _decode_jwt_payload(token: str) -> dict | None:
    """Decode the payload of a JWT without verifying the signature.

    Returns the claims dict, or None if the token is malformed.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload_b64 = parts[1]
    # Re-pad to a multiple of 4 for base64 decoding
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    try:
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, KeyError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _looks_like_jwt(token: str) -> bool:
    """Return True if the token has the three-part JWT structure."""
    return token.count(".") == 2


# ─── Public API ───────────────────────────────────────────────────────────────


_LOCAL_IDENTITY_VERIFIER: Callable[[str], tuple[str, str | None]] | None = None


def set_local_identity_verifier(verifier: Callable[[str], tuple[str, str | None]] | None) -> None:
    """Register a resolver for agent-bom-issued ``abi_`` identity tokens.

    The control-plane identity lifecycle store registers this so issued tokens
    resolve to their agent_id and revoked/expired ones fail closed, without this
    low-level module importing the API layer.
    """
    global _LOCAL_IDENTITY_VERIFIER
    _LOCAL_IDENTITY_VERIFIER = verifier


def extract_identity_token(msg: dict) -> str | None:
    """Extract the agent identity token from an MCP JSON-RPC message.

    The token is expected in ``params._meta.agent_identity``.
    Returns None if not present or structurally invalid.
    """
    params = msg.get("params")
    if not isinstance(params, dict):
        return None
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        return None
    token = meta.get("agent_identity")
    if not isinstance(token, str) or not token.strip():
        return None
    return token.strip()


def resolve_agent_id(token: str, policy: dict) -> tuple[str, str | None]:
    """Resolve a raw identity token to a stable ``agent_id`` string.

    Args:
        token: Raw identity token from the message.
        policy: Policy dict (may contain ``jwks_uri``, ``oidc_issuer``,
                ``agent_tokens`` map).

    Returns:
        ``(agent_id, error)`` — error is None on success, a message string
        if the token is structurally invalid, expired, or signature-invalid.
    """
    if _looks_like_jwt(token):
        claims = _decode_jwt_payload(token)
        if claims is None:
            return ANONYMOUS, "Malformed JWT payload"

        # Check expiry
        exp = claims.get("exp")
        if exp is not None:
            try:
                if time.time() > float(exp):
                    return ANONYMOUS, f"JWT expired at {exp}"
            except (TypeError, ValueError):
                return ANONYMOUS, "Invalid JWT exp claim"

        # Cryptographic signature verification when JWKS is configured. In
        # enforced mode, a JWT without verification policy is not an identity.
        jwks_uri = _resolve_jwks_uri(policy)
        if jwks_uri:
            verified, sig_err = _verify_jwt_signature(token, jwks_uri)
            if not verified:
                return ANONYMOUS, f"JWT signature invalid: {sig_err}"
        elif policy.get("require_agent_identity"):
            return ANONYMOUS, "JWT signature verification required: configure jwks_uri or oidc_issuer"

        agent_id = claims.get("sub") or claims.get("agent_id") or claims.get("name")
        if not agent_id or not isinstance(agent_id, str):
            return ANONYMOUS, "JWT missing sub/agent_id/name claim"
        return agent_id.strip(), None

    # agent-bom-issued lifecycle token: resolve via the registered verifier so
    # revoked/expired identities fail closed (provisioning/rotation/revocation).
    if token.startswith("abi_") and _LOCAL_IDENTITY_VERIFIER is not None:
        agent_id, error = _LOCAL_IDENTITY_VERIFIER(token)
        if error is not None:
            return ANONYMOUS, error
        return agent_id, None

    # Opaque token: look up in policy.agent_tokens
    agent_tokens: dict = policy.get("agent_tokens", {})
    if token in agent_tokens:
        agent_id = agent_tokens[token]
        if isinstance(agent_id, str) and agent_id.strip():
            return agent_id.strip(), None
        return ANONYMOUS, "policy.agent_tokens entry is empty"

    # Token present but not recognised
    return ANONYMOUS, "Unknown identity token (not in agent_tokens and not a JWT)"


def check_identity(
    msg: dict,
    policy: dict,
) -> tuple[str, str | None]:
    """Full identity check for a single MCP message.

    Extracts the token, resolves to agent_id, and enforces
    ``require_agent_identity`` policy if set.

    Returns:
        ``(agent_id, block_reason)`` — block_reason is None when the call
        should proceed, a string when it should be blocked.
    """
    token = extract_identity_token(msg)

    if token is None:
        if policy.get("require_agent_identity"):
            return ANONYMOUS, "Identity required: no agent_identity token in _meta"
        return ANONYMOUS, None

    agent_id, error = resolve_agent_id(token, policy)

    if error is not None:
        safe_error = _sanitize_identity_error(error)
        logger.debug("Identity token error: %s", safe_error)
        if policy.get("require_agent_identity"):
            return agent_id, f"Identity required: {safe_error}"
        return ANONYMOUS, None

    return agent_id, None


def identity_token_scopes(token: str) -> set[str]:
    """Extract OAuth scopes from a JWT identity token's claims.

    Reads the standard ``scope`` (space-delimited string) or ``scp`` (string or
    list) claim. Returns an empty set for opaque tokens or tokens without a
    scope claim. The token's signature is NOT (re)verified here — callers must
    have already validated the token (the gateway verifies via JWKS / the AS
    before reading scopes), so this only parses the already-trusted payload.
    """
    if not _looks_like_jwt(token):
        return set()
    claims = _decode_jwt_payload(token)
    if not isinstance(claims, dict):
        return set()
    return scopes_from_claims(claims)


def scopes_from_claims(claims: dict) -> set[str]:
    """Return the OAuth scope set declared in a JWT claims dict."""
    scopes: set[str] = set()
    raw_scope = claims.get("scope")
    if isinstance(raw_scope, str):
        scopes |= {s for s in raw_scope.replace(",", " ").split() if s}
    scp = claims.get("scp")
    if isinstance(scp, str):
        scopes |= {s for s in scp.replace(",", " ").split() if s}
    elif isinstance(scp, (list, tuple)):
        scopes |= {str(s) for s in scp if str(s).strip()}
    return scopes


def check_caller_identity(
    msg: dict,
    policy: dict,
) -> tuple[str, bool, str | None]:
    """Resolve caller identity while preserving the token-present signal.

    Unlike :func:`check_identity` — which collapses a present-but-invalid token
    and a fully-absent token to the same ``(ANONYMOUS, None)`` result when
    ``require_agent_identity`` is unset — this returns enough information for a
    caller (e.g. the gateway relay) to fail closed on an invalid/revoked token
    while still treating a fully-missing identity as a separate, configurable
    case.

    Returns:
        ``(agent_id, token_present, invalid_reason)`` where:
        - ``token_present`` is True when a structurally-present identity token
          was supplied in ``_meta.agent_identity`` (whether or not it resolved).
        - ``invalid_reason`` is a sanitized string when a token *was* present
          but failed to resolve (malformed / expired / unsigned / unknown /
          revoked); None when no token was present or the token resolved
          cleanly. A non-None ``invalid_reason`` means the caller must fail
          closed regardless of ``require_agent_identity``.
    """
    token = extract_identity_token(msg)
    if token is None:
        return ANONYMOUS, False, None

    agent_id, error = resolve_agent_id(token, policy)
    if error is not None:
        return ANONYMOUS, True, _sanitize_identity_error(error)
    return agent_id, True, None
