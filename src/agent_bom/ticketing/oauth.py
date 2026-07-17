"""Atlassian OAuth 2.0 (3LO) helpers for the Jira ticketing connection.

Connect-once, OAuth-first: an admin clicks "Connect Jira", authorizes once in
Atlassian, and agent-bom seals the returned token bundle. No API token is ever
typed for the OAuth path, and nothing is re-entered per action.

Verified against the official Atlassian 3LO docs:
https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/

* Authorize   ``GET https://auth.atlassian.com/authorize`` (audience=api.atlassian.com)
* Token       ``POST https://auth.atlassian.com/oauth/token`` (authorization_code / refresh_token)
* Cloud id    ``GET https://api.atlassian.com/oauth/token/accessible-resources`` (Bearer)

The app's ``client_id`` / ``client_secret`` are operator-configured secrets (env
or file), never entered by an end user. All HTTP is injectable for tests.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode

AUTHORIZE_URL = "https://auth.atlassian.com/authorize"
TOKEN_URL = "https://auth.atlassian.com/oauth/token"
ACCESSIBLE_RESOURCES_URL = "https://api.atlassian.com/oauth/token/accessible-resources"

# Least-privilege scopes: create issues + read status, plus offline_access so we
# receive a refresh token (no re-consent for background status sync).
DEFAULT_SCOPES = ("read:jira-work", "write:jira-work", "read:me", "offline_access")

CLIENT_ID_ENV = "AGENT_BOM_JIRA_OAUTH_CLIENT_ID"
CLIENT_SECRET_ENV = "AGENT_BOM_JIRA_OAUTH_CLIENT_SECRET"


class TicketingOAuthError(RuntimeError):
    """Raised when the OAuth exchange cannot complete. Never carries a token."""


def _resolve_client_id() -> str:
    from agent_bom.api.secret_source import resolve_secret

    return (resolve_secret(CLIENT_ID_ENV) or os.environ.get(CLIENT_ID_ENV, "")).strip()


def _resolve_client_secret() -> str:
    from agent_bom.api.secret_source import resolve_secret

    return (resolve_secret(CLIENT_SECRET_ENV) or "").strip()


def oauth_configured() -> bool:
    """Whether the Atlassian OAuth app credentials are configured."""
    from agent_bom.api.secret_source import secret_is_configured

    return bool(_resolve_client_id()) and secret_is_configured(CLIENT_SECRET_ENV)


def build_authorize_url(*, redirect_uri: str, state: str, scopes: tuple[str, ...] = DEFAULT_SCOPES) -> str:
    """Build the Atlassian authorize URL the admin's browser is sent to."""
    client_id = _resolve_client_id()
    if not client_id:
        raise TicketingOAuthError(f"Jira OAuth is not configured ({CLIENT_ID_ENV} unset).")
    if not redirect_uri:
        raise TicketingOAuthError("A redirect URI is required to start the Jira OAuth flow.")
    if not state:
        raise TicketingOAuthError("An anti-CSRF state value is required to start the Jira OAuth flow.")
    query = urlencode(
        {
            "audience": "api.atlassian.com",
            "client_id": client_id,
            "scope": " ".join(scopes),
            "redirect_uri": redirect_uri,
            "state": state,
            "response_type": "code",
            "prompt": "consent",
        }
    )
    return f"{AUTHORIZE_URL}?{query}"


def _default_client_factory(timeout: float = 15.0) -> Any:
    from agent_bom.http_client import create_client

    return create_client(timeout=timeout)


async def exchange_code(
    *,
    code: str,
    redirect_uri: str,
    client_factory: Callable[..., Any] = _default_client_factory,
) -> dict[str, Any]:
    """Exchange an authorization code for a token bundle (access/refresh)."""
    client_id = _resolve_client_id()
    client_secret = _resolve_client_secret()
    if not client_id or not client_secret:
        raise TicketingOAuthError("Jira OAuth app credentials are not configured.")
    body = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
    }
    bundle = await _post_token(body, client_factory)
    if not bundle.get("access_token"):
        raise TicketingOAuthError("Atlassian token exchange did not return an access token.")
    return bundle


async def refresh_tokens(
    *,
    refresh_token: str,
    client_factory: Callable[..., Any] = _default_client_factory,
) -> dict[str, Any]:
    """Refresh an access token using a stored refresh token."""
    client_id = _resolve_client_id()
    client_secret = _resolve_client_secret()
    if not client_id or not client_secret:
        raise TicketingOAuthError("Jira OAuth app credentials are not configured.")
    body = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
    }
    return await _post_token(body, client_factory)


async def resolve_accessible_resource(
    *,
    access_token: str,
    site_url: str = "",
    client_factory: Callable[..., Any] = _default_client_factory,
) -> dict[str, str]:
    """Resolve the granted site's cloud id + URL from accessible-resources.

    When ``site_url`` is given, the matching resource is chosen; otherwise the
    first granted resource is used.
    """
    from agent_bom.http_client import request_with_retry

    async with client_factory(timeout=15.0) as client:
        resp = await request_with_retry(
            client,
            "GET",
            ACCESSIBLE_RESOURCES_URL,
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            max_retries=2,
        )
    if resp is None or resp.status_code != 200:
        raise TicketingOAuthError("Could not resolve the Jira site from Atlassian accessible-resources.")
    try:
        resources = resp.json()
    except Exception as exc:  # noqa: BLE001
        raise TicketingOAuthError("Atlassian accessible-resources returned a non-JSON response.") from exc
    if not isinstance(resources, list) or not resources:
        raise TicketingOAuthError("The Jira OAuth grant has no accessible Jira sites.")
    chosen = None
    wanted = (site_url or "").rstrip("/").lower()
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        if wanted and str(resource.get("url") or "").rstrip("/").lower() == wanted:
            chosen = resource
            break
    if chosen is None:
        chosen = next((r for r in resources if isinstance(r, dict)), None)
    if not chosen or not chosen.get("id"):
        raise TicketingOAuthError("Atlassian accessible-resources did not include a cloud id.")
    return {
        "cloud_id": str(chosen["id"]),
        "site_url": str(chosen.get("url") or "").rstrip("/"),
        "site_name": str(chosen.get("name") or ""),
    }


async def _post_token(body: dict[str, str], client_factory: Callable[..., Any]) -> dict[str, Any]:
    from agent_bom.http_client import request_with_retry

    async with client_factory(timeout=15.0) as client:
        resp = await request_with_retry(
            client,
            "POST",
            TOKEN_URL,
            json=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            max_retries=2,
        )
    if resp is None:
        raise TicketingOAuthError("No response from the Atlassian token endpoint.")
    if resp.status_code != 200:
        raise TicketingOAuthError(f"Atlassian token endpoint returned HTTP {resp.status_code}.")
    try:
        bundle = resp.json()
    except Exception as exc:  # noqa: BLE001
        raise TicketingOAuthError("Atlassian token endpoint returned a non-JSON response.") from exc
    if not isinstance(bundle, dict):
        raise TicketingOAuthError("Atlassian token endpoint returned an unexpected shape.")
    return bundle
