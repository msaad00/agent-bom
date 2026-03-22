"""OIDC/SSO JWT verification for agent-bom API.

Enables enterprise SSO by accepting JWTs issued by any standard OIDC provider
(Okta, Google Workspace, GitHub OIDC, Auth0, Azure AD, etc.) alongside the
existing API key authentication.

Configuration via environment variables::

    AGENT_BOM_OIDC_ISSUER   = "https://accounts.google.com"
    AGENT_BOM_OIDC_AUDIENCE = "agent-bom"            # optional, defaults to ISSUER
    AGENT_BOM_OIDC_ROLE_CLAIM = "agent_bom_role"      # optional JWT claim for role

Role mapping (claim value → agent-bom Role):

    "admin"   → Role.ADMIN
    "analyst" → Role.ANALYST
    any other → Role.VIEWER  (default when claim absent)

Install the optional dependency::

    pip install "agent-bom[oidc]"

Closes #278.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Optional
from urllib.error import URLError
from urllib.request import urlopen

logger = logging.getLogger(__name__)

_JWKS_CACHE_TTL = 3600  # seconds — re-fetch public keys every hour
_OIDC_TIMEOUT = 5  # seconds for HTTP requests to OIDC provider


# ── JWKS key cache ──────────────────────────────────────────────────────────────


class _JwksCache:
    """Thread-safe cache for OIDC JWKS (JSON Web Key Sets)."""

    def __init__(self) -> None:
        self._cache: dict[str, tuple[dict, float]] = {}  # url → (jwks, fetched_at)
        self._lock = threading.Lock()

    def get(self, jwks_uri: str) -> dict:
        """Return cached JWKS or fetch fresh copy if stale/absent."""
        with self._lock:
            entry = self._cache.get(jwks_uri)
            if entry and (time.monotonic() - entry[1]) < _JWKS_CACHE_TTL:
                return entry[0]

        # Fetch outside lock to avoid blocking other threads
        jwks = _fetch_json(jwks_uri)
        with self._lock:
            self._cache[jwks_uri] = (jwks, time.monotonic())
        return jwks

    def invalidate(self, jwks_uri: str) -> None:
        with self._lock:
            self._cache.pop(jwks_uri, None)


_jwks_cache = _JwksCache()


# ── Discovery ──────────────────────────────────────────────────────────────────


def _fetch_json(url: str) -> dict:
    # Defense-in-depth: validate even operator-supplied URLs to block SSRF
    # via misconfigured AGENT_BOM_OIDC_ISSUER pointing at internal services.
    from agent_bom.security import validate_url

    validate_url(url)
    try:
        with urlopen(url, timeout=_OIDC_TIMEOUT) as resp:  # noqa: S310  # nosec B310 — validated above
            return json.loads(resp.read())
    except (URLError, OSError, json.JSONDecodeError) as exc:
        raise OIDCError(f"Failed to fetch {url}: {exc}") from exc


def discover_oidc(issuer: str) -> dict:
    """Fetch the OIDC discovery document for ``issuer``.

    Args:
        issuer: OIDC issuer URL (e.g. ``https://accounts.google.com``).

    Returns:
        Parsed discovery document dict.

    Raises:
        OIDCError: If the discovery endpoint is unreachable or returns invalid JSON.
    """
    discovery_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    doc = _fetch_json(discovery_url)
    if "jwks_uri" not in doc:
        raise OIDCError(f"Discovery document at {discovery_url} missing 'jwks_uri'")
    return doc


# ── JWT verification ───────────────────────────────────────────────────────────


class OIDCError(Exception):
    """Raised when OIDC configuration or JWT verification fails."""


def _check_pyjwt() -> None:
    try:
        import cryptography  # noqa: F401
        import jwt  # noqa: F401
    except ImportError as exc:
        raise OIDCError("OIDC support requires PyJWT and cryptography: pip install 'agent-bom[oidc]'") from exc


def verify_oidc_token(
    token: str,
    issuer: str,
    audience: Optional[str] = None,
    jwks_uri: Optional[str] = None,
) -> dict:
    """Verify an OIDC JWT and return its claims.

    Fetches the issuer's JWKS (cached for 1 hour) and verifies the token
    signature, issuer, audience, and expiry.

    Args:
        token: Raw JWT string (without "Bearer " prefix).
        issuer: Expected issuer (``iss`` claim). Must match exactly.
        audience: Expected audience (``aud`` claim). If None, not verified.
        jwks_uri: Override JWKS URI. If None, fetched from OIDC discovery.

    Returns:
        Decoded JWT claims dict.

    Raises:
        OIDCError: On any verification failure.
    """
    _check_pyjwt()
    import jwt
    from jwt import PyJWKClient, PyJWTError

    if not jwks_uri:
        try:
            discovery = discover_oidc(issuer)
            jwks_uri = discovery["jwks_uri"]
        except OIDCError:
            raise

    try:
        jwks_client = PyJWKClient(jwks_uri, cache_jwk_set=True, lifespan=_JWKS_CACHE_TTL)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
    except Exception as exc:
        raise OIDCError(f"Failed to resolve signing key: {exc}") from exc

    decode_kwargs: dict = {
        "algorithms": ["RS256", "ES256", "RS384", "ES384", "RS512"],
        "issuer": issuer,
        "options": {"require": ["exp", "iat", "iss"]},
    }
    if audience:
        decode_kwargs["audience"] = audience

    try:
        claims = jwt.decode(token, signing_key.key, **decode_kwargs)
    except PyJWTError as exc:
        raise OIDCError(f"JWT verification failed: {exc}") from exc

    return claims


# ── Role mapping ───────────────────────────────────────────────────────────────


def claims_to_role(claims: dict, role_claim: str = "agent_bom_role") -> str:
    """Map OIDC JWT claims to an agent-bom role string.

    Checks ``role_claim`` in the JWT, then falls back to ``roles`` and
    ``groups`` arrays. Defaults to ``"viewer"`` if no role signal found.

    Args:
        claims: Decoded JWT claims.
        role_claim: JWT claim name to look up for the role (default: ``agent_bom_role``).

    Returns:
        One of ``"admin"``, ``"analyst"``, or ``"viewer"``.
    """
    admin_values = {"admin", "administrator", "superuser"}
    analyst_values = {"analyst", "security-analyst", "engineer", "developer"}

    # Direct role claim
    role_val = claims.get(role_claim, "")
    if isinstance(role_val, str) and role_val:
        v = role_val.lower()
        if v in admin_values:
            return "admin"
        if v in analyst_values:
            return "analyst"

    # roles / groups array (common in Okta, Azure AD, GitHub OIDC)
    for array_claim in ("roles", "groups", "permissions"):
        values = claims.get(array_claim, [])
        if isinstance(values, list):
            lowered = {str(v).lower() for v in values}
            if lowered & admin_values:
                return "admin"
            if lowered & analyst_values:
                return "analyst"

    return "viewer"


# ── OIDCConfig helper ──────────────────────────────────────────────────────────


class OIDCConfig:
    """OIDC configuration loaded from environment variables.

    Environment variables:

    - ``AGENT_BOM_OIDC_ISSUER`` — OIDC provider issuer URL (required to enable OIDC)
    - ``AGENT_BOM_OIDC_AUDIENCE`` — Expected JWT audience (defaults to issuer)
    - ``AGENT_BOM_OIDC_ROLE_CLAIM`` — JWT claim name for role (default: ``agent_bom_role``)
    - ``AGENT_BOM_OIDC_JWKS_URI`` — Override JWKS URI (optional, auto-discovered if absent)
    """

    def __init__(
        self,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        role_claim: str = "agent_bom_role",
        jwks_uri: Optional[str] = None,
    ) -> None:
        self.issuer = issuer or os.environ.get("AGENT_BOM_OIDC_ISSUER", "")
        self.audience = audience or os.environ.get("AGENT_BOM_OIDC_AUDIENCE", self.issuer) or None
        self.role_claim = role_claim or os.environ.get("AGENT_BOM_OIDC_ROLE_CLAIM", "agent_bom_role")
        self.jwks_uri = jwks_uri or os.environ.get("AGENT_BOM_OIDC_JWKS_URI", "") or None
        self.enabled = bool(self.issuer)

    def verify(self, token: str) -> tuple[dict, str]:
        """Verify a JWT and return ``(claims, role)``.

        Raises:
            OIDCError: On verification failure.
        """
        if not self.enabled or not self.issuer:
            raise OIDCError("OIDC is not configured (set AGENT_BOM_OIDC_ISSUER)")
        claims = verify_oidc_token(token, self.issuer, self.audience, self.jwks_uri)
        role = claims_to_role(claims, self.role_claim)
        return claims, role

    @classmethod
    def from_env(cls) -> "OIDCConfig":
        """Build config from environment variables."""
        return cls()
