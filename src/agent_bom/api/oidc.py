"""OIDC/SSO JWT verification for agent-bom API.

Enables enterprise SSO by accepting JWTs issued by any standard OIDC provider
(Okta, Google Workspace, GitHub OIDC, Auth0, Azure AD, etc.) alongside the
existing API key authentication.

Configuration via environment variables::

    AGENT_BOM_OIDC_ISSUER   = "https://accounts.google.com"
    AGENT_BOM_OIDC_AUDIENCE = "agent-bom"            # required when OIDC is enabled
    AGENT_BOM_OIDC_ROLE_CLAIM = "agent_bom_role"      # optional JWT claim for role
    AGENT_BOM_OIDC_TENANT_CLAIM = "tenant_id"         # optional JWT claim for tenant
    AGENT_BOM_OIDC_REQUIRE_TENANT_CLAIM = "1"         # fail closed when claim absent
    AGENT_BOM_OIDC_REQUIRED_NONCE = "random-nonce"    # optional fail-closed nonce check
    AGENT_BOM_OIDC_REQUIRE_ROLE_CLAIM = "1"           # optional fail-closed role requirement

Role mapping (claim value → agent-bom Role):

    "admin"   → Role.ADMIN
    "analyst" → Role.ANALYST
    any other → Role.VIEWER  (default when claim absent unless strict mode enabled)

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
_oidc_failure_lock = threading.Lock()
_oidc_decode_failures = 0


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


def record_oidc_decode_failure() -> None:
    """Increment the control-plane OIDC decode failure counter."""
    global _oidc_decode_failures
    with _oidc_failure_lock:
        _oidc_decode_failures += 1


def oidc_decode_failure_count() -> int:
    """Return the number of failed OIDC decode/verify attempts."""
    with _oidc_failure_lock:
        return _oidc_decode_failures


def reset_oidc_decode_failures() -> None:
    """Reset the OIDC decode failure counter for tests."""
    global _oidc_decode_failures
    with _oidc_failure_lock:
        _oidc_decode_failures = 0


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
    required_nonce: Optional[str] = None,
) -> dict:
    """Verify an OIDC JWT and return its claims.

    Fetches the issuer's JWKS (cached for 1 hour) and verifies the token
    signature, issuer, audience, and expiry.

    Args:
        token: Raw JWT string (without "Bearer " prefix).
        issuer: Expected issuer (``iss`` claim). Must match exactly.
        audience: Expected audience (``aud`` claim). Required for production OIDC use.
        jwks_uri: Override JWKS URI. If None, fetched from OIDC discovery.
        required_nonce: Optional nonce value that must match the token ``nonce`` claim.

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

    if required_nonce is not None:
        token_nonce = claims.get("nonce")
        if token_nonce != required_nonce:
            raise OIDCError("JWT verification failed: nonce claim mismatch")

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


def claims_have_role_signal(claims: dict, role_claim: str = "agent_bom_role") -> bool:
    """Return True when claims include an explicit recognizable role signal."""
    admin_values = {"admin", "administrator", "superuser"}
    analyst_values = {"analyst", "security-analyst", "engineer", "developer"}

    role_val = claims.get(role_claim, "")
    if isinstance(role_val, str) and role_val and role_val.lower() in (admin_values | analyst_values):
        return True

    for array_claim in ("roles", "groups", "permissions"):
        values = claims.get(array_claim, [])
        if isinstance(values, list):
            lowered = {str(v).lower() for v in values}
            if lowered & (admin_values | analyst_values):
                return True

    return False


def claims_to_tenant(claims: dict, tenant_claim: str = "tenant_id") -> str | None:
    """Map OIDC JWT claims to a tenant identifier."""
    tenant_val = claims.get(tenant_claim)
    if tenant_val not in (None, ""):
        return str(tenant_val)

    if tenant_claim == "tenant_id":
        for alias in ("tid", "tenant", "org_id", "organization_id"):
            alias_val = claims.get(alias)
            if alias_val not in (None, ""):
                return str(alias_val)
    return None


# ── OIDCConfig helper ──────────────────────────────────────────────────────────


class OIDCConfig:
    """OIDC configuration loaded from environment variables.

    Environment variables:

    - ``AGENT_BOM_OIDC_ISSUER`` — OIDC provider issuer URL (required to enable OIDC)
    - ``AGENT_BOM_OIDC_AUDIENCE`` — Expected JWT audience (required when OIDC is enabled)
    - ``AGENT_BOM_OIDC_ROLE_CLAIM`` — JWT claim name for role (default: ``agent_bom_role``)
    - ``AGENT_BOM_OIDC_JWKS_URI`` — Override JWKS URI (optional, auto-discovered if absent)
    - ``AGENT_BOM_OIDC_REQUIRED_NONCE`` — Optional expected ``nonce`` claim for fail-closed checks
    - ``AGENT_BOM_OIDC_REQUIRE_ROLE_CLAIM`` — Fail closed when no explicit mapped role claim is present
    """

    def __init__(
        self,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        role_claim: str = "agent_bom_role",
        jwks_uri: Optional[str] = None,
        tenant_claim: str = "tenant_id",
        require_tenant_claim: Optional[bool] = None,
        required_nonce: Optional[str] = None,
        require_role_claim: Optional[bool] = None,
    ) -> None:
        self.issuer = issuer or os.environ.get("AGENT_BOM_OIDC_ISSUER", "")
        self.audience = audience or os.environ.get("AGENT_BOM_OIDC_AUDIENCE") or None
        self.role_claim = role_claim or os.environ.get("AGENT_BOM_OIDC_ROLE_CLAIM", "agent_bom_role")
        self.jwks_uri = jwks_uri or os.environ.get("AGENT_BOM_OIDC_JWKS_URI", "") or None
        self.tenant_claim = tenant_claim or os.environ.get("AGENT_BOM_OIDC_TENANT_CLAIM", "tenant_id")
        self.required_nonce = required_nonce or os.environ.get("AGENT_BOM_OIDC_REQUIRED_NONCE", "") or None
        if require_tenant_claim is None:
            require_tenant_claim = os.environ.get("AGENT_BOM_OIDC_REQUIRE_TENANT_CLAIM", "").strip().lower() in {
                "1",
                "true",
                "yes",
            }
        self.require_tenant_claim = require_tenant_claim
        if require_role_claim is None:
            require_role_claim = os.environ.get("AGENT_BOM_OIDC_REQUIRE_ROLE_CLAIM", "").strip().lower() in {
                "1",
                "true",
                "yes",
            }
        self.require_role_claim = require_role_claim
        self.enabled = bool(self.issuer)

    def verify(self, token: str) -> tuple[dict, str]:
        """Verify a JWT and return ``(claims, role)``.

        Raises:
            OIDCError: On verification failure.
        """
        if not self.enabled or not self.issuer:
            raise OIDCError("OIDC is not configured (set AGENT_BOM_OIDC_ISSUER)")
        if not self.audience:
            raise OIDCError("OIDC is configured but AGENT_BOM_OIDC_AUDIENCE is not set")
        claims = verify_oidc_token(token, self.issuer, self.audience, self.jwks_uri, self.required_nonce)
        if self.require_role_claim and not claims_have_role_signal(claims, self.role_claim):
            raise OIDCError(f"JWT missing required role claim '{self.role_claim}'")
        role = claims_to_role(claims, self.role_claim)
        return claims, role

    def resolve_tenant(self, claims: dict) -> str:
        """Resolve tenant context from claims or fail closed when required."""
        tenant_id = claims_to_tenant(claims, self.tenant_claim)
        if tenant_id:
            return tenant_id
        if self.require_tenant_claim:
            raise OIDCError(f"JWT missing required tenant claim '{self.tenant_claim}'")
        return "default"

    @classmethod
    def from_env(cls) -> "OIDCConfig":
        """Build config from environment variables."""
        return cls()
