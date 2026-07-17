"""Direct Jira Cloud REST v3 transport (fallback when no ITSM MCP server).

Verified against the official Jira Cloud platform REST v3 docs:

* Create issue — ``POST /rest/api/3/issue`` with ``{"fields": {...}}``; the
  response carries ``id``, ``key``, ``self``.
  https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/
* Read issue status — ``GET /rest/api/3/issue/{issueIdOrKey}?fields=status``;
  status is at ``fields.status`` with a ``statusCategory`` whose ``key`` is one
  of ``new`` / ``indeterminate`` / ``done``.
  https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-search/

Auth is resolved **only** from the stored connection — never from the caller:

* ``oauth`` (3LO, primary): the site is reached at
  ``https://api.atlassian.com/ex/jira/{cloudId}`` with an ``Authorization:
  Bearer <access_token>`` header (the OAuth bundle is the sealed secret).
  https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/
* ``api_token`` (secondary fallback): Basic auth ``base64(email:api_token)``
  against the customer site URL (``endpoint``).
  https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from typing import Any

from agent_bom.security import validate_url
from agent_bom.ticketing.models import (
    AUTH_API_TOKEN,
    AUTH_OAUTH,
    PROVIDER_JIRA,
    TicketDraft,
    TicketingConnectionRecord,
    TicketRef,
    TicketStatus,
)
from agent_bom.ticketing.transport import TicketingTransport, TicketingTransportError, map_jira_status

# Atlassian-hosted API gateway used with OAuth 2.0 (3LO) access tokens.
_ATLASSIAN_API_BASE = "https://api.atlassian.com"


def _default_client_factory(timeout: float = 15.0) -> Any:
    from agent_bom.http_client import create_client

    return create_client(timeout=timeout)


class JiraRestTransport(TicketingTransport):
    """Create/read Jira issues over REST using the stored connection's auth."""

    def __init__(
        self,
        record: TicketingConnectionRecord,
        secret: str,
        *,
        client_factory: Callable[..., Any] = _default_client_factory,
    ) -> None:
        self._record = record
        self._secret = secret
        self._client_factory = client_factory
        self._api_base, self._browse_base, self._headers = self._resolve_auth(record, secret)

    # — auth resolution (from the stored connection only) —

    @staticmethod
    def _resolve_auth(record: TicketingConnectionRecord, secret: str) -> tuple[str, str, dict[str, str]]:
        method = (record.auth_method or "").strip().lower()
        if method == AUTH_OAUTH:
            bundle = _load_oauth_bundle(secret)
            access_token = str(bundle.get("access_token") or "").strip()
            cloud_id = str(record.auth_params.get("cloud_id") or "").strip()
            if not access_token:
                raise TicketingTransportError("Jira OAuth connection is missing an access token; reconnect Jira.")
            if not cloud_id:
                raise TicketingTransportError("Jira OAuth connection is missing its cloud id; reconnect Jira.")
            api_base = f"{_ATLASSIAN_API_BASE}/ex/jira/{cloud_id}"
            browse_base = str(record.auth_params.get("site_url") or record.endpoint or "").rstrip("/")
            headers = {"Authorization": f"Bearer {access_token}"}
            return api_base, browse_base, headers
        if method == AUTH_API_TOKEN:
            email = str(record.auth_params.get("email") or "").strip()
            if not email:
                raise TicketingTransportError("Jira API-token connection is missing its account email.")
            if not secret:
                raise TicketingTransportError("Jira API-token connection has no stored token; reconnect Jira.")
            base = (record.endpoint or "").rstrip("/")
            if not base:
                raise TicketingTransportError("Jira API-token connection is missing its site URL.")
            validate_url(base)
            auth = base64.b64encode(f"{email}:{secret}".encode()).decode()
            return base, base, {"Authorization": f"Basic {auth}"}
        raise TicketingTransportError(f"Unsupported Jira auth method '{record.auth_method}'.")

    def _headers_with_content(self) -> dict[str, str]:
        return {**self._headers, "Content-Type": "application/json", "Accept": "application/json"}

    # — transport interface —

    async def create_ticket(self, draft: TicketDraft) -> TicketRef:
        if not draft.project:
            raise TicketingTransportError("A target Jira project key is required to create an issue.")
        payload = _issue_payload(draft)
        url = f"{self._api_base}/rest/api/3/issue"
        data = await self._request("POST", url, json_body=payload, expected=(200, 201))
        key = str(data.get("key") or "").strip()
        issue_id = str(data.get("id") or "").strip()
        if not key and not issue_id:
            raise TicketingTransportError("Jira did not return an issue key.")
        browse = f"{self._browse_base}/browse/{key}" if (self._browse_base and key) else ""
        return TicketRef(
            provider=PROVIDER_JIRA,
            external_id=issue_id or key,
            key=key,
            url=browse,
            status=TicketStatus.OPEN,
        )

    async def get_status(self, ref: TicketRef) -> TicketStatus:
        handle = (ref.key or ref.external_id).strip()
        if not handle:
            raise TicketingTransportError("A Jira issue key or id is required to read status.")
        url = f"{self._api_base}/rest/api/3/issue/{handle}?fields=status"
        data = await self._request("GET", url, expected=(200,))
        status_obj = (data.get("fields") or {}).get("status") or {}
        category = status_obj.get("statusCategory") or {}
        return map_jira_status(str(category.get("key") or ""), str(category.get("name") or ""))

    # — one HTTP round-trip through the shared resilient client —

    async def _request(
        self,
        method: str,
        url: str,
        *,
        json_body: dict[str, Any] | None = None,
        expected: tuple[int, ...],
    ) -> dict[str, Any]:
        from agent_bom.http_client import request_with_retry

        kwargs: dict[str, Any] = {"headers": self._headers_with_content(), "max_retries": 2}
        if json_body is not None:
            kwargs["json"] = json_body
        async with self._client_factory(timeout=15.0) as client:
            resp = await request_with_retry(client, method, url, **kwargs)
        if resp is None:
            raise TicketingTransportError("No response from Jira.")
        if resp.status_code not in expected:
            raise TicketingTransportError(f"Jira returned HTTP {resp.status_code}.")
        try:
            body = resp.json()
        except Exception as exc:  # noqa: BLE001 - non-JSON body
            raise TicketingTransportError("Jira returned a non-JSON response.") from exc
        if not isinstance(body, dict):
            raise TicketingTransportError("Jira returned an unexpected response shape.")
        return body


def _load_oauth_bundle(secret: str) -> dict[str, Any]:
    try:
        bundle = json.loads(secret)
    except (ValueError, TypeError) as exc:
        raise TicketingTransportError("Jira OAuth token bundle is malformed; reconnect Jira.") from exc
    if not isinstance(bundle, dict):
        raise TicketingTransportError("Jira OAuth token bundle is malformed; reconnect Jira.")
    return bundle


def _issue_payload(draft: TicketDraft) -> dict[str, Any]:
    """Build the Jira v3 create-issue body (Atlassian Document Format description)."""
    fields: dict[str, Any] = {
        "project": {"key": draft.project},
        "summary": draft.title[:255],
        "description": {
            "type": "doc",
            "version": 1,
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": draft.description or draft.title}]}],
        },
        "issuetype": {"name": draft.issue_type or "Bug"},
        "labels": [_sanitize_label(label) for label in draft.labels if label],
    }
    return {"fields": fields}


def _sanitize_label(label: str) -> str:
    # Jira labels may not contain spaces.
    return "".join(ch if not ch.isspace() else "-" for ch in str(label))
