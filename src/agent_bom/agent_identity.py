"""Agent identity extraction and validation for the MCP proxy.

Reads caller identity from the MCP ``_meta.agent_identity`` field, resolves
it to a stable ``agent_id`` string, and optionally enforces that a valid
identity is present.

Two supported token formats:
- **JWT** (three base64url parts): payload decoded, ``sub`` claim used as
  ``agent_id``.  Signature is *not* cryptographically verified here — that
  requires a JWKS endpoint (see issue #392).  Expiry (``exp``) is checked.
- **Opaque token**: looked up in ``policy.agent_tokens`` dict
  (``{token: agent_id}``).

If no identity is present the proxy records ``"anonymous"`` in the audit log.
If ``require_agent_identity: true`` is set in policy the call is blocked.
"""

from __future__ import annotations

import base64
import json
import logging
import time

logger = logging.getLogger(__name__)

# Sentinel used when no identity token is provided
ANONYMOUS = "anonymous"


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
    except Exception:  # noqa: BLE001
        return None


def _looks_like_jwt(token: str) -> bool:
    """Return True if the token has the three-part JWT structure."""
    return token.count(".") == 2


# ─── Public API ───────────────────────────────────────────────────────────────


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
        policy: Policy dict (may contain ``agent_tokens`` map).

    Returns:
        ``(agent_id, error)`` — error is None on success, a message string
        if the token is structurally invalid or expired.
    """
    if _looks_like_jwt(token):
        claims = _decode_jwt_payload(token)
        if claims is None:
            return ANONYMOUS, "Malformed JWT payload"
        # Check expiry if present
        exp = claims.get("exp")
        if exp is not None:
            try:
                if time.time() > float(exp):
                    return ANONYMOUS, f"JWT expired at {exp}"
            except (TypeError, ValueError):
                return ANONYMOUS, "Invalid JWT exp claim"
        agent_id = claims.get("sub") or claims.get("agent_id") or claims.get("name")
        if not agent_id or not isinstance(agent_id, str):
            return ANONYMOUS, "JWT missing sub/agent_id/name claim"
        return agent_id.strip(), None

    # Opaque token: look up in policy.agent_tokens
    agent_tokens: dict = policy.get("agent_tokens", {})
    if token in agent_tokens:
        agent_id = agent_tokens[token]
        if isinstance(agent_id, str) and agent_id.strip():
            return agent_id.strip(), None
        return ANONYMOUS, "policy.agent_tokens entry is empty"

    # Token present but not recognised — not necessarily an error unless
    # require_agent_identity is set; caller decides whether to block.
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
        logger.debug("Identity token error: %s", error)
        # If the token is present but invalid/unknown, block only when required
        if policy.get("require_agent_identity"):
            return agent_id, f"Identity required: {error}"
        # Otherwise log anonymously without blocking
        return ANONYMOUS, None

    return agent_id, None
