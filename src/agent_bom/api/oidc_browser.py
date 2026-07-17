"""Browser OIDC authorization-code + PKCE helpers (dashboard SSO foundation).

Bearer JWT verification stays in ``oidc.py``. This module adds the auth-code
redirect path: PKCE S256, sealed one-time login cookie, and token exchange.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from agent_bom.api.oidc import OIDCConfig, OIDCError, discover_oidc, verify_oidc_token
from agent_bom.security import sanitize_error, validate_url

_logger = logging.getLogger(__name__)
_OIDC_TIMEOUT = 10
OIDC_PKCE_COOKIE_NAME = "agent_bom_oidc_pkce"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def pkce_verifier() -> str:
    return secrets.token_urlsafe(64)[:128]


def pkce_challenge_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return _b64url(digest)


def _login_ttl_seconds() -> int:
    raw = (os.environ.get("AGENT_BOM_OIDC_LOGIN_STATE_TTL_SECONDS") or "300").strip()
    try:
        return max(60, min(int(raw), 900))
    except ValueError:
        return 300


@dataclass(frozen=True)
class OIDCBrowserConfig:
    """Auth-code + PKCE settings layered on bearer OIDC issuer config."""

    oidc: OIDCConfig
    client_id: str
    redirect_uri: str
    scopes: str = "openid profile email"
    client_secret: str | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.oidc.enabled and self.client_id and self.redirect_uri and self.oidc.issuer)

    @classmethod
    def from_env(cls) -> OIDCBrowserConfig:
        oidc = OIDCConfig.from_env()
        client_id = os.environ.get("AGENT_BOM_OIDC_CLIENT_ID", "").strip()
        redirect_uri = os.environ.get("AGENT_BOM_OIDC_REDIRECT_URI", "").strip()
        scopes = os.environ.get("AGENT_BOM_OIDC_SCOPES", "openid profile email").strip() or "openid profile email"
        secret = os.environ.get("AGENT_BOM_OIDC_CLIENT_SECRET", "").strip() or None
        if redirect_uri:
            from urllib.parse import urlparse

            parsed = urlparse(redirect_uri)
            if parsed.scheme not in {"https", "http"} or not parsed.netloc:
                raise OIDCError("AGENT_BOM_OIDC_REDIRECT_URI must be an absolute http(s) URL")
            if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
                raise OIDCError("AGENT_BOM_OIDC_REDIRECT_URI may use http only for localhost")
        return cls(
            oidc=oidc,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scopes=scopes,
            client_secret=secret,
        )


def _pkce_signing_key() -> bytes:
    from agent_bom.api.browser_session import BrowserSessionError
    from agent_bom.api.secret_source import resolve_secret

    configured = resolve_secret("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY")
    if not configured:
        # Local single-replica: derive from ephemeral browser-session path by hashing a fixed label.
        # Clustered deployments already require the persistent signing key for sessions.
        try:
            from agent_bom.api.browser_session import persistent_browser_session_signing_required

            if persistent_browser_session_signing_required():
                raise BrowserSessionError("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY is required for OIDC PKCE cookies")
        except BrowserSessionError:
            raise
        configured = "agent-bom-oidc-pkce-ephemeral"
    return hashlib.pbkdf2_hmac(
        "sha256",
        configured.encode("utf-8"),
        b"agent-bom-oidc-pkce-cookie:v1",
        200_000,
        dklen=32,
    )


def seal_pkce_cookie(*, code_verifier: str, nonce: str, max_age_seconds: int | None = None) -> str:
    ttl = max_age_seconds if max_age_seconds is not None else _login_ttl_seconds()
    payload = {
        "v": 1,
        "code_verifier": code_verifier,
        "nonce": nonce,
        "exp": int(time.time()) + ttl,
    }
    body = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    sig = _b64url(hmac.new(_pkce_signing_key(), body.encode("ascii"), hashlib.sha256).digest())
    return f"{body}.{sig}"


def open_pkce_cookie(value: str) -> tuple[str, str, str]:
    try:
        body, sig = value.split(".", 1)
    except ValueError as exc:
        raise OIDCError("Invalid OIDC PKCE cookie") from exc
    expected = _b64url(hmac.new(_pkce_signing_key(), body.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        raise OIDCError("OIDC PKCE cookie signature mismatch")
    try:
        payload = json.loads(_b64url_decode(body))
    except (json.JSONDecodeError, ValueError) as exc:
        raise OIDCError("OIDC PKCE cookie payload invalid") from exc
    if int(payload.get("exp") or 0) < int(time.time()):
        raise OIDCError("OIDC PKCE cookie expired")
    verifier = str(payload.get("code_verifier") or "")
    nonce = str(payload.get("nonce") or "")
    if not verifier or not nonce:
        raise OIDCError("OIDC PKCE cookie missing verifier/nonce")
    return verifier, nonce, "/"


def build_authorize_url(
    cfg: OIDCBrowserConfig,
    *,
    state: str,
    nonce: str,
    code_challenge: str,
) -> str:
    if not cfg.enabled or not cfg.oidc.issuer:
        raise OIDCError("OIDC browser SSO is not configured")
    discovery = discover_oidc(cfg.oidc.issuer)
    authorize = str(discovery.get("authorization_endpoint") or "").strip()
    if not authorize:
        raise OIDCError("OIDC discovery missing authorization_endpoint")
    validate_url(authorize)
    query = urlencode(
        {
            "response_type": "code",
            "client_id": cfg.client_id,
            "redirect_uri": cfg.redirect_uri,
            "scope": cfg.scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{authorize}?{query}"


def exchange_code_for_tokens(
    cfg: OIDCBrowserConfig,
    *,
    code: str,
    code_verifier: str,
) -> dict[str, Any]:
    if not cfg.oidc.issuer:
        raise OIDCError("OIDC browser SSO is not configured")
    discovery = discover_oidc(cfg.oidc.issuer)
    token_url = str(discovery.get("token_endpoint") or "").strip()
    if not token_url:
        raise OIDCError("OIDC discovery missing token_endpoint")
    validate_url(token_url)
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": cfg.redirect_uri,
        "client_id": cfg.client_id,
        "code_verifier": code_verifier,
    }
    if cfg.client_secret:
        form["client_secret"] = cfg.client_secret
    body = urlencode(form).encode("utf-8")
    request = Request(
        token_url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=_OIDC_TIMEOUT) as resp:  # noqa: S310  # nosec B310 — validated above
            payload = json.loads(resp.read())
    except Exception as exc:  # noqa: BLE001
        raise OIDCError(f"OIDC token exchange failed: {sanitize_error(exc)}") from exc
    if not isinstance(payload, dict):
        raise OIDCError("OIDC token endpoint returned a non-object payload")
    return payload


def verify_browser_id_token(cfg: OIDCBrowserConfig, id_token: str, *, nonce: str) -> dict[str, Any]:
    """Verify the ID token from the auth-code flow (aud = client_id)."""
    provider = cfg.oidc
    if not provider.issuer:
        raise OIDCError("OIDC issuer is not configured")
    claims = verify_oidc_token(
        id_token,
        provider.issuer,
        cfg.client_id,
        provider.jwks_uri,
        nonce,
        provider.allowed_jwks_uris,
    )
    return claims


def subject_from_claims(claims: dict[str, Any]) -> str:
    for key in ("email", "preferred_username", "name", "sub"):
        value = str(claims.get(key) or "").strip()
        if value:
            return value[:256]
    return "oidc-user"


def oidc_browser_enabled_from_env() -> bool:
    try:
        return OIDCBrowserConfig.from_env().enabled
    except OIDCError:
        return False


def sso_provider_from_issuer(issuer: str) -> str:
    """Map an OIDC issuer URL to a known SSO provider brand for /login presets.

    Pure display helper: returns one of ``"okta"``, ``"entra"``, ``"google"``,
    or ``"generic"`` from the issuer host. Detection is host-based and never
    forks the auth flow — an unrecognized (or custom-domain) issuer falls back
    to ``"generic"`` so the sign-in button stays honestly un-branded rather than
    guessing a vendor.
    """
    from urllib.parse import urlparse

    host = ""
    try:
        host = (urlparse(issuer.strip()).hostname or "").lower()
    except (ValueError, AttributeError):
        host = ""
    if not host:
        return "generic"
    if host == "accounts.google.com":
        return "google"
    if host.endswith((".okta.com", ".oktapreview.com", ".okta-emea.com")):
        return "okta"
    if host == "login.microsoftonline.com" or host.endswith((".microsoftonline.com", ".windows.net")):
        return "entra"
    return "generic"


def configured_browser_sso_provider() -> str | None:
    """Return the SSO provider brand for the configured browser-OIDC issuer.

    ``None`` when browser OIDC is not enabled (no branded button applies).
    """
    try:
        cfg = OIDCBrowserConfig.from_env()
    except OIDCError:
        return None
    issuer = cfg.oidc.issuer
    if not cfg.enabled or not issuer:
        return None
    return sso_provider_from_issuer(issuer)
