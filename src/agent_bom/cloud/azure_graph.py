"""Read-only Microsoft Graph reader for Azure identity posture evidence.

The Azure Resource Manager (ARM) management APIs do not expose Microsoft Entra
directory state — Conditional Access policies, the tenant authorization policy,
security defaults, and access reviews all live behind Microsoft Graph. This thin,
read-only client acquires a token for the ``azure-identity`` credential already
threaded through the CIS benchmark and issues ``GET`` requests against the
**stable Graph v1.0** endpoints, following ``@odata.nextLink`` pagination.

Honesty contract (issue #4120):

* Every read is read-only (``GET`` only). No directory state is mutated.
* A denied, unauthenticated, or otherwise unreadable response raises a typed
  error so the calling control reports ``unevaluable`` (fail closed) rather than
  assuming a pass. Missing Graph permission is never a silent PASS.
* No benchmark text is redistributed; controls reference their CIS identifier by
  number only and source the technical requirement from Microsoft's own baseline
  documentation.

Required delegated/application permissions (all read-only):
    Policy.Read.All            (authorization policy, security defaults, CA policies)
    AccessReview.Read.All      (identity governance access review definitions)
"""

from __future__ import annotations

from typing import Any, Final

GRAPH_BASE_URL: Final = "https://graph.microsoft.com/v1.0"
GRAPH_TOKEN_SCOPE: Final = "https://graph.microsoft.com/.default"

# Stable v1.0 resource paths (verified against Microsoft Graph v1.0 reference).
AUTHORIZATION_POLICY_PATH: Final = "/policies/authorizationPolicy"
SECURITY_DEFAULTS_PATH: Final = "/policies/identitySecurityDefaultsEnforcementPolicy"
CONDITIONAL_ACCESS_POLICIES_PATH: Final = "/identity/conditionalAccess/policies"
ACCESS_REVIEW_DEFINITIONS_PATH: Final = "/identityGovernance/accessReviews/definitions"

# Well-known Microsoft Entra identifiers (fixed across all tenants).
# Restricted Guest User role template — the most restrictive guest permission set.
RESTRICTED_GUEST_ROLE_TEMPLATE_ID: Final = "2af84b1e-32c8-42b7-82bc-daa82404023b"
# Windows Azure Service Management API (the "Microsoft Azure Management" cloud app).
AZURE_MANAGEMENT_APP_ID: Final = "797f4846-ba00-4fd7-ba43-dac1f8f63013"


class GraphError(Exception):
    """Base class for a Microsoft Graph read that could not be trusted."""


class GraphPermissionDeniedError(GraphError):
    """The credential lacks permission to read the requested directory evidence."""


class GraphUnavailableError(GraphError):
    """The Graph endpoint could not be reached or returned an unusable response."""


class AzureGraphClient:
    """Minimal read-only Microsoft Graph v1.0 client.

    Wraps an ``azure-identity`` credential; acquires a bearer token lazily and
    reuses it (the credential caches until near expiry). Only ``GET`` is
    supported — this client can never write to the directory.
    """

    def __init__(
        self,
        credential: Any,
        *,
        http_client: Any = None,
        base_url: str = GRAPH_BASE_URL,
        timeout: float = 30.0,
    ) -> None:
        self._credential = credential
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._http = http_client
        self._owns_http = http_client is None

    def _client(self) -> Any:
        if self._http is None:
            import httpx

            self._http = httpx.Client(timeout=self._timeout)
        return self._http

    def _token(self) -> str:
        try:
            token = self._credential.get_token(GRAPH_TOKEN_SCOPE)
        except Exception as exc:  # noqa: BLE001 — any auth failure is fail-closed unevaluable
            raise GraphUnavailableError(f"Could not acquire a Microsoft Graph token: {exc}") from exc
        value = getattr(token, "token", None)
        if not value:
            raise GraphUnavailableError("Microsoft Graph token acquisition returned no token.")
        return str(value)

    def _request(self, url: str, token: str) -> dict[str, Any]:
        import httpx

        try:
            response = self._client().get(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise GraphUnavailableError(f"Microsoft Graph request failed: {exc}") from exc
        status = response.status_code
        if status in (401, 403):
            raise GraphPermissionDeniedError(f"Microsoft Graph denied access ({status}).")
        if status >= 400:
            raise GraphUnavailableError(f"Microsoft Graph returned HTTP {status}.")
        try:
            payload = response.json()
        except Exception as exc:  # noqa: BLE001 — a non-JSON body is unusable evidence
            raise GraphUnavailableError(f"Microsoft Graph returned a non-JSON body: {exc}") from exc
        if not isinstance(payload, dict):
            raise GraphUnavailableError("Microsoft Graph returned an unexpected (non-object) body.")
        return payload

    def get(self, path: str) -> dict[str, Any]:
        """GET a single Graph resource, returning its JSON object."""
        token = self._token()
        url = path if path.startswith("http") else f"{self._base_url}{path}"
        return self._request(url, token)

    def list(self, path: str) -> list[dict[str, Any]]:
        """GET a Graph collection, following ``@odata.nextLink`` pagination."""
        token = self._token()
        url: str | None = path if path.startswith("http") else f"{self._base_url}{path}"
        items: list[dict[str, Any]] = []
        seen = 0
        while url:
            payload = self._request(url, token)
            values = payload.get("value")
            if isinstance(values, list):
                items.extend(v for v in values if isinstance(v, dict))
            next_link = payload.get("@odata.nextLink")
            url = str(next_link) if next_link else None
            seen += 1
            if seen > 1000:  # defensive bound against a pathological pagination loop
                raise GraphUnavailableError("Microsoft Graph pagination exceeded the safety bound.")
        return items

    def close(self) -> None:
        if self._owns_http and self._http is not None:
            try:
                self._http.close()
            except Exception:  # noqa: BLE001 — best-effort cleanup
                pass
