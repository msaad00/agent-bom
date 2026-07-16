"""Snowflake OAuth authorization-code + PKCE sign-in for the dashboard.

Snowflake exposes a *non-standard* OAuth 2.0 authorization server: it has no
OIDC discovery document, no JWKS, and no ``userinfo`` endpoint. The generic
OIDC browser flow in :mod:`agent_bom.api.oidc_browser` therefore cannot be
reused wholesale — it relies on discovery + JWKS ID-token verification. This
module implements the parts Snowflake *does* document, verified against the
official docs (https://docs.snowflake.com/en/user-guide/oauth-custom):

* Authorization endpoint ``<account_url>/oauth/authorize`` (GET) with
  ``response_type=code``, ``client_id``, ``redirect_uri``, optional ``scope``,
  ``state``, and PKCE ``code_challenge`` + ``code_challenge_method=S256``.
* Token endpoint ``<account_url>/oauth/token-request`` (POST,
  ``application/x-www-form-urlencoded``) with HTTP Basic auth
  ``Authorization: Basic base64(client_id:client_secret)`` and a body of
  ``grant_type=authorization_code``, ``code``, ``redirect_uri``, and
  ``code_verifier``.
* Identity: the token response's ``username`` field — "Username that the access
  token belongs to. Currently only returned when exchanging an authorization
  code for an access token." There is no ID token to verify, so identity is the
  ``username`` the Snowflake token endpoint returns; a missing ``username`` is a
  hard failure (fail closed).

PKCE helpers and the sealed one-time login cookie are shared with
:mod:`agent_bom.api.oidc_browser` so this path does not fork the generic flow
more than the protocol difference requires.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from agent_bom.api.oidc import OIDCError
from agent_bom.security import sanitize_error, validate_url

_logger = logging.getLogger(__name__)
_SNOWFLAKE_TIMEOUT = 10

# Snowflake account hostnames. ``.snowflakecomputing.com`` covers commercial and
# PrivateLink (``<account>.privatelink.snowflakecomputing.com``); ``.cn`` covers
# the China regions. Enforcing the suffix is defence-in-depth on top of
# ``validate_url`` (which only blocks private/loopback IPs): it stops an operator
# misconfiguration or header-injection from pointing the token exchange — which
# carries the client secret via Basic auth — at an arbitrary host.
_SNOWFLAKE_HOST_SUFFIXES = (".snowflakecomputing.com", ".snowflakecomputing.cn")


def _valid_snowflake_account_url(raw: str) -> str:
    """Validate and normalise a Snowflake account URL, or raise ``OIDCError``."""
    account_url = (raw or "").strip().rstrip("/")
    if not account_url:
        raise OIDCError("AGENT_BOM_SNOWFLAKE_OAUTH_ACCOUNT_URL is required")
    parsed = urlparse(account_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise OIDCError("AGENT_BOM_SNOWFLAKE_OAUTH_ACCOUNT_URL must be an absolute https URL")
    if parsed.path or parsed.query or parsed.fragment:
        raise OIDCError("AGENT_BOM_SNOWFLAKE_OAUTH_ACCOUNT_URL must not include a path or query")
    host = parsed.hostname.lower()
    if not any(host.endswith(suffix) for suffix in _SNOWFLAKE_HOST_SUFFIXES):
        raise OIDCError("AGENT_BOM_SNOWFLAKE_OAUTH_ACCOUNT_URL must be a *.snowflakecomputing.com host")
    return f"https://{host}"


@dataclass(frozen=True)
class SnowflakeOAuthConfig:
    """Snowflake OAuth authorization-code + PKCE settings (config-driven)."""

    account_url: str
    client_id: str
    redirect_uri: str
    client_secret: str | None = None
    scope: str = ""
    default_role: str = "viewer"
    tenant_id: str = "default"

    @property
    def enabled(self) -> bool:
        return bool(self.account_url and self.client_id and self.redirect_uri)

    @property
    def authorize_endpoint(self) -> str:
        return f"{self.account_url}/oauth/authorize"

    @property
    def token_endpoint(self) -> str:
        return f"{self.account_url}/oauth/token-request"

    @classmethod
    def from_env(cls) -> SnowflakeOAuthConfig:
        from agent_bom.api.secret_source import resolve_secret

        account_raw = os.environ.get("AGENT_BOM_SNOWFLAKE_OAUTH_ACCOUNT_URL", "").strip()
        account_url = _valid_snowflake_account_url(account_raw) if account_raw else ""
        client_id = os.environ.get("AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_ID", "").strip()
        redirect_uri = os.environ.get("AGENT_BOM_SNOWFLAKE_OAUTH_REDIRECT_URI", "").strip()
        if redirect_uri:
            parsed = urlparse(redirect_uri)
            if parsed.scheme not in {"https", "http"} or not parsed.netloc:
                raise OIDCError("AGENT_BOM_SNOWFLAKE_OAUTH_REDIRECT_URI must be an absolute http(s) URL")
            if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
                raise OIDCError("AGENT_BOM_SNOWFLAKE_OAUTH_REDIRECT_URI may use http only for localhost")
        try:
            secret = resolve_secret("AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_SECRET") or None
        except ValueError as exc:
            raise OIDCError(sanitize_error(exc)) from exc
        scope = os.environ.get("AGENT_BOM_SNOWFLAKE_OAUTH_SCOPE", "").strip()
        default_role = os.environ.get("AGENT_BOM_SNOWFLAKE_OAUTH_DEFAULT_ROLE", "viewer").strip().lower() or "viewer"
        tenant_id = os.environ.get("AGENT_BOM_SNOWFLAKE_OAUTH_TENANT_ID", "default").strip() or "default"
        return cls(
            account_url=account_url,
            client_id=client_id,
            redirect_uri=redirect_uri,
            client_secret=secret,
            scope=scope,
            default_role=default_role,
            tenant_id=tenant_id,
        )


def build_authorize_url(cfg: SnowflakeOAuthConfig, *, state: str, code_challenge: str) -> str:
    """Build the Snowflake ``/oauth/authorize`` redirect URL (PKCE S256)."""
    if not cfg.enabled:
        raise OIDCError("Snowflake OAuth sign-in is not configured")
    authorize = cfg.authorize_endpoint
    validate_url(authorize)
    params = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": cfg.redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if cfg.scope:
        params["scope"] = cfg.scope
    return f"{authorize}?{urlencode(params)}"


def exchange_code_for_tokens(cfg: SnowflakeOAuthConfig, *, code: str, code_verifier: str) -> dict[str, Any]:
    """Exchange an authorization code at ``/oauth/token-request`` (Basic auth)."""
    if not cfg.enabled:
        raise OIDCError("Snowflake OAuth sign-in is not configured")
    if not cfg.client_secret:
        raise OIDCError("AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_SECRET is required for the token exchange")
    token_url = cfg.token_endpoint
    validate_url(token_url)
    form = urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": cfg.redirect_uri,
            "code_verifier": code_verifier,
        }
    ).encode("utf-8")
    basic = base64.b64encode(f"{cfg.client_id}:{cfg.client_secret}".encode()).decode("ascii")
    request = Request(
        token_url,
        data=form,
        headers={
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=_SNOWFLAKE_TIMEOUT) as resp:  # noqa: S310  # nosec B310 — validated above
            payload = json.loads(resp.read())
    except Exception as exc:  # noqa: BLE001
        raise OIDCError(f"Snowflake OAuth token exchange failed: {sanitize_error(exc)}") from exc
    if not isinstance(payload, dict):
        raise OIDCError("Snowflake OAuth token endpoint returned a non-object payload")
    return payload


def username_from_token_response(payload: dict[str, Any]) -> str:
    """Return the authenticated Snowflake username, failing closed if absent.

    Snowflake returns ``username`` only when exchanging an authorization code
    for an access token; there is no ID token or userinfo endpoint. A response
    without a usable ``username`` cannot establish identity, so we reject it.
    """
    username = str(payload.get("username") or "").strip()
    if not username:
        raise OIDCError("Snowflake OAuth token response did not include a username")
    return username[:256]


def snowflake_oauth_enabled_from_env() -> bool:
    try:
        return SnowflakeOAuthConfig.from_env().enabled
    except OIDCError:
        return False
