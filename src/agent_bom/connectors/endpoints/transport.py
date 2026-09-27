"""Bounded OAuth transport. No redirects, ambient proxies, or provider error bodies."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from agent_bom.http_client import OfflineModeError, check_offline

from .models import ConnectionSpec


class CollectionError(RuntimeError):
    """Stable public error code; never includes an upstream response or credential."""


class EndpointClient:
    def __init__(self, spec: ConnectionSpec, secret: str, *, transport: httpx.BaseTransport | None = None) -> None:
        self._deadline = time.monotonic() + 100
        self.spec = spec
        self._secret = secret
        self._token = ""
        self._expires = 0.0
        self._client = httpx.Client(timeout=10, follow_redirects=False, trust_env=False, transport=transport)

    def close(self) -> None:
        self._token = ""
        self._secret = ""
        self._client.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            check_offline()
        except OfflineModeError:
            raise CollectionError("offline_collection_disabled") from None
        for attempt in range(3):
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise CollectionError("collection_time_budget_exceeded")
            try:
                with self._client.stream(method, self.spec.origin + path, timeout=min(10, remaining), **kwargs) as response:
                    status = response.status_code
                    retry_after = response.headers.get("Retry-After", "")
                    if status == 401:
                        raise CollectionError("authentication_failed")
                    if status == 403:
                        raise CollectionError("permission_denied")
                    retry = status == 429 or status >= 500
                    if not retry:
                        if status != 200:
                            raise CollectionError("provider_request_rejected")
                        return self._read_response(response)
            except httpx.HTTPError:
                retry_after = ""
            if attempt < 2:
                # Do not retry sooner than a long provider throttle; surface it for a later resume.
                if retry_after and (not retry_after.isdigit() or int(retry_after) > 5):
                    raise CollectionError("rate_limited_retry_later")
                time.sleep(max(2**attempt, int(retry_after or "0")))
        raise CollectionError("provider_unavailable_or_rate_limited")

    def _read_response(self, response: httpx.Response) -> dict[str, Any]:
        body = bytearray()
        for chunk in response.iter_bytes(chunk_size=65536):
            if time.monotonic() >= self._deadline:
                raise CollectionError("collection_time_budget_exceeded")
            body.extend(chunk)
            if len(body) > 8 * 1024 * 1024:
                raise CollectionError("response_limit_exceeded")
        try:
            value = json.loads(body)
        except (ValueError, UnicodeError):
            raise CollectionError("invalid_provider_response") from None
        if not isinstance(value, dict) or value.get("errors"):
            raise CollectionError("invalid_or_partial_provider_response")
        return value

    def _authenticate(self) -> None:
        path = "/api/v1/oauth/token" if self.spec.provider == "jamf" else "/oauth2/token"
        form = {"client_id": self.spec.client_id, "client_secret": self._secret}
        if self.spec.provider == "jamf":
            form["grant_type"] = "client_credentials"
        value = self._request("POST", path, data=form)
        token, expires = value.get("access_token"), value.get("expires_in")
        if not isinstance(token, str) or not token or not isinstance(expires, (int, float)) or expires <= 0:
            raise CollectionError("invalid_token_response")
        self._token = token
        self._expires = time.monotonic() + max(1, expires - 15)

    def get(self, path: str, params: list[tuple[str, str]]) -> dict[str, Any]:
        for attempt in range(2):
            if time.monotonic() >= self._expires:
                self._authenticate()
            try:
                return self._request("GET", path, params=params, headers={"Authorization": f"Bearer {self._token}"})
            except CollectionError as exc:
                if exc.args != ("authentication_failed",) or attempt:
                    raise
                self._expires = 0
        raise CollectionError("authentication_failed")
