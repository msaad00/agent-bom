"""Microsoft Entra ID (Azure AD) non-human-identity (NHI) discovery.

Enumerates the *machine* identities in an Entra tenant — service principals and
their backing application registrations (client-credentials / workload apps) —
and returns them as normalized :class:`DiscoveredNonHumanIdentity` records (the
same shape the Okta connector produces). Each record carries the credential
*expiry* derived from the app's password (secret) and key (certificate)
credential end dates so an operator can spot stale or long-lived secrets — the
secret values themselves are never read. The
``agent_bom.graph.nhi_overlay`` projects those records into the unified graph as
``managed_identity`` nodes, alongside the Okta-discovered ones.

Trust posture (mirrors the Okta connector and the cloud read-only providers):

* **Read-only / reference-only.** Only ``GET`` Microsoft Graph list endpoints
  are called; no Graph write API is ever invoked and no secret material (client
  secrets, certificate private keys) is read — only references, metadata, and
  credential *end dates*.
* **Token-authenticated.** A bearer token is read from the
  ``AGENT_BOM_ENTRA_TOKEN`` environment variable (no passwords, per the
  tokens-only policy). The tenant id comes from ``AGENT_BOM_ENTRA_TENANT_ID``
  (optional — informational only).
* **Gated, default OFF.** Discovery only runs when
  ``AGENT_BOM_ENTRA_DISCOVERY`` is set to a truthy value. Otherwise it returns a
  ``DISABLED`` status without touching the network.
* **Never raises.** A missing client, missing credentials, or an API error
  degrades to a populated :class:`NHIDiscoveryResult` carrying a clear status
  and a user-safe warning — discovery callers never have to wrap this in a
  ``try``/``except``.

The :class:`DiscoveredNonHumanIdentity` / :class:`NHIDiscoveryResult` /
:class:`NHIDiscoveryStatus` types are reused from :mod:`agent_bom.identity.okta_nhi`
so every connector normalizes to a single record shape.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable, Iterator
from typing import Any

from agent_bom.identity.okta_nhi import (
    DiscoveredNonHumanIdentity,
    NHIDiscoveryResult,
    NHIDiscoveryStatus,
)

logger = logging.getLogger(__name__)

_DISCOVERY_FLAG_ENV = "AGENT_BOM_ENTRA_DISCOVERY"
_TOKEN_ENV = "AGENT_BOM_ENTRA_TOKEN"
_TENANT_ID_ENV = "AGENT_BOM_ENTRA_TENANT_ID"

_GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"

# Read-only Microsoft Graph application permissions this connector exercises.
# Kept here so the per-run trust contract stays honest — the producer owns the
# catalog. Both are *.Read.All (no write/manage scope is ever needed).
ENTRA_READ_PERMISSIONS: tuple[str, ...] = (
    "Application.Read.All",
    "Directory.Read.All",
)

_MAX_RESULTS = 2000
_PAGE_LIMIT = 999

_TRUTHY = frozenset({"1", "true", "yes", "on"})


class EntraClient:
    """Minimal read-only Microsoft Graph client (no third-party SDK required).

    Issues only ``GET`` list calls with a bearer token. Tests inject a fake
    client exposing the same ``list_service_principals`` / ``list_applications``
    methods, so no live call is ever made under test.
    """

    def __init__(self, token: str, *, base_url: str = _GRAPH_BASE_URL) -> None:
        self._token = token
        self._base_url = base_url.rstrip("/")

    def _get(self, path: str) -> list[dict[str, Any]]:
        from agent_bom.http_client import fetch_json

        items: list[dict[str, Any]] = []
        url: str | None = f"{self._base_url}{path}"
        # Follow @odata.nextLink pagination, bounded so a hostile/huge tenant
        # cannot make discovery run unbounded.
        while url and len(items) < _MAX_RESULTS:
            payload = fetch_json(
                url,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Accept": "application/json",
                },
                timeout=30,
            )
            if not isinstance(payload, dict):
                break
            for item in payload.get("value", []) or []:
                if isinstance(item, dict):
                    items.append(item)
            next_link = payload.get("@odata.nextLink")
            url = next_link if isinstance(next_link, str) and next_link else None
        return items

    def list_service_principals(self) -> list[dict[str, Any]]:
        """List service principals (the directory presence of an NHI)."""
        return self._get(f"/servicePrincipals?$top={_PAGE_LIMIT}")

    def list_applications(self) -> list[dict[str, Any]]:
        """List application registrations (carry credential end dates)."""
        return self._get(f"/applications?$top={_PAGE_LIMIT}")


def _is_truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() in _TRUTHY


def _opt_str(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def _earliest_credential_expiry(*credential_lists: Any) -> str | None:
    """Return the earliest ``endDateTime`` across password + key credentials.

    The earliest expiring credential is the one that matters for rotation
    hygiene, so it is what we surface. Only end *dates* are read — never the
    secret/cert material itself.
    """
    end_dates: list[str] = []
    for creds in credential_lists:
        if not isinstance(creds, list):
            continue
        for cred in creds:
            if not isinstance(cred, dict):
                continue
            end = _opt_str(cred.get("endDateTime"))
            if end:
                end_dates.append(end)
    if not end_dates:
        return None
    # ISO-8601 UTC timestamps sort lexically; the minimum is the soonest expiry.
    return min(end_dates)


def _app_scopes(app: dict[str, Any]) -> tuple[str, ...]:
    """Required resource access scope ids declared by the app registration.

    These are references (scope/role ids), never secrets. Used by the overlay to
    match against tool nodes the same way Okta OAuth grant types are.
    """
    scopes: list[str] = []
    required = app.get("requiredResourceAccess")
    if isinstance(required, list):
        for entry in required:
            if not isinstance(entry, dict):
                continue
            for access in entry.get("resourceAccess", []) or []:
                if isinstance(access, dict):
                    ref = _opt_str(access.get("id"))
                    if ref:
                        scopes.append(ref)
    return tuple(scopes)


def _is_service_principal_nhi(sp: dict[str, Any]) -> bool:
    """A non-human service principal: an application (workload) identity.

    Entra service principals come in several flavours. ``Application`` and
    ``ManagedIdentity`` are machine identities; ``Legacy`` / ``SocialIdp`` and
    human-assigned SSO entries are excluded.
    """
    sp_type = str(sp.get("servicePrincipalType") or "").strip().lower()
    return sp_type in {"application", "managedidentity"}


def _normalize_service_principal(
    sp: dict[str, Any],
    apps_by_appid: dict[str, dict[str, Any]],
) -> DiscoveredNonHumanIdentity | None:
    sp_id = str(sp.get("id") or "").strip()
    if not sp_id:
        return None
    app_id = str(sp.get("appId") or "").strip()
    backing_app = apps_by_appid.get(app_id, {})

    # Credential expiry comes from the backing app registration where available;
    # fall back to any credentials carried on the service principal itself.
    expiry = _earliest_credential_expiry(
        backing_app.get("passwordCredentials"),
        backing_app.get("keyCredentials"),
        sp.get("passwordCredentials"),
        sp.get("keyCredentials"),
    )
    scopes = _app_scopes(backing_app) or _app_scopes(sp)
    enabled = sp.get("accountEnabled")
    status = "active" if enabled is None or bool(enabled) else "inactive"

    owners = sp.get("owners")
    owner = None
    if isinstance(owners, list) and owners:
        first = owners[0]
        if isinstance(first, dict):
            owner = _opt_str(first.get("id"))

    return DiscoveredNonHumanIdentity(
        identity_id=sp_id,
        name=str(sp.get("displayName") or backing_app.get("displayName") or sp_id),
        identity_type="service_principal",
        provider="entra",
        status=status,
        owner=owner,
        created_at=_opt_str(sp.get("createdDateTime") or backing_app.get("createdDateTime")),
        credential_expires_at=expiry,
        scopes=scopes,
        raw_identity={
            "id": sp_id,
            "app_id": app_id,
            "service_principal_type": str(sp.get("servicePrincipalType") or ""),
            "has_backing_app": bool(backing_app),
        },
    )


def _normalize_orphan_application(app: dict[str, Any]) -> DiscoveredNonHumanIdentity | None:
    """App registration with no materialized service principal in the tenant.

    Still a credential-bearing NHI (a client-credentials app), so it is reported
    so its secret/cert expiry is not invisible.
    """
    obj_id = str(app.get("id") or "").strip()
    if not obj_id:
        return None
    app_id = str(app.get("appId") or "").strip()
    expiry = _earliest_credential_expiry(app.get("passwordCredentials"), app.get("keyCredentials"))
    return DiscoveredNonHumanIdentity(
        identity_id=app_id or obj_id,
        name=str(app.get("displayName") or app_id or obj_id),
        identity_type="app_registration",
        provider="entra",
        status="active",
        created_at=_opt_str(app.get("createdDateTime")),
        credential_expires_at=expiry,
        scopes=_app_scopes(app),
        raw_identity={
            "id": obj_id,
            "app_id": app_id,
            "orphan_app_registration": True,
        },
    )


def _iter_normalized(
    raw_service_principals: Iterable[dict[str, Any]],
    raw_applications: Iterable[dict[str, Any]],
) -> Iterator[DiscoveredNonHumanIdentity]:
    apps_list = [a for a in raw_applications if isinstance(a, dict)]
    apps_by_appid: dict[str, dict[str, Any]] = {}
    for app in apps_list:
        app_id = str(app.get("appId") or "").strip()
        if app_id:
            apps_by_appid[app_id] = app

    matched_app_ids: set[str] = set()
    for sp in raw_service_principals:
        if not isinstance(sp, dict) or not _is_service_principal_nhi(sp):
            continue
        identity = _normalize_service_principal(sp, apps_by_appid)
        if identity is not None:
            app_id = str(sp.get("appId") or "").strip()
            if app_id:
                matched_app_ids.add(app_id)
            yield identity

    # Client-credentials app registrations with no service principal materialized
    # are still credential-bearing NHIs — surface them so expiry is not hidden.
    for app in apps_list:
        app_id = str(app.get("appId") or "").strip()
        if app_id and app_id in matched_app_ids:
            continue
        if not (app.get("passwordCredentials") or app.get("keyCredentials")):
            continue
        identity = _normalize_orphan_application(app)
        if identity is not None:
            yield identity


def discover_entra_non_human_identities(
    *,
    client: Any = None,
    token: str | None = None,
    tenant_id: str | None = None,
    force: bool = False,
) -> NHIDiscoveryResult:
    """Discover non-human identities (service principals + apps) from Entra ID.

    Read-only and gated: unless ``force`` is set (used by tests / explicit
    callers that already supply a ``client``), discovery only runs when the
    ``AGENT_BOM_ENTRA_DISCOVERY`` flag is truthy. Returns a result envelope and
    never raises.

    Args:
        client: An injected Graph client exposing ``list_service_principals()``
            and ``list_applications()``. When ``None`` a read-only
            :class:`EntraClient` is built from the bearer token.
        token: Microsoft Graph bearer token; falls back to
            ``AGENT_BOM_ENTRA_TOKEN``.
        tenant_id: Entra tenant id (informational); falls back to
            ``AGENT_BOM_ENTRA_TENANT_ID``.
        force: Bypass the feature-flag gate (when a client is injected directly).
    """
    flag_on = force or client is not None or _is_truthy(os.environ.get(_DISCOVERY_FLAG_ENV))
    if not flag_on:
        return NHIDiscoveryResult(
            status=NHIDiscoveryStatus.DISABLED,
            warnings=(f"Entra NHI discovery is disabled. Set {_DISCOVERY_FLAG_ENV}=1 to enable.",),
        )

    resolved_tenant = (tenant_id or os.environ.get(_TENANT_ID_ENV) or "").strip()

    if client is None:
        resolved_token = (token or os.environ.get(_TOKEN_ENV) or "").strip()
        if not resolved_token:
            return NHIDiscoveryResult(
                status=NHIDiscoveryStatus.MISSING_CREDENTIALS,
                org_url=resolved_tenant or None,
                warnings=(f"Entra NHI discovery enabled but missing: {_TOKEN_ENV}.",),
            )
        try:
            client = EntraClient(resolved_token)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not construct Entra client: %s", exc)
            return NHIDiscoveryResult(
                status=NHIDiscoveryStatus.MISSING_CLIENT,
                org_url=resolved_tenant or None,
                warnings=("Could not initialise the Microsoft Graph client for NHI discovery.",),
            )

    warnings: list[str] = []
    raw_sps: list[dict[str, Any]] = []
    raw_apps: list[dict[str, Any]] = []
    failures = 0

    try:
        raw_sps = list(client.list_service_principals() or [])
    except Exception as exc:  # noqa: BLE001
        failures += 1
        warnings.append(f"Entra service-principal listing failed: {exc}")
    try:
        raw_apps = list(client.list_applications() or [])
    except Exception as exc:  # noqa: BLE001
        failures += 1
        warnings.append(f"Entra application listing failed: {exc}")

    identities = tuple(_iter_normalized(raw_sps, raw_apps))[:_MAX_RESULTS]

    if failures and not identities:
        return NHIDiscoveryResult(
            status=NHIDiscoveryStatus.ERROR,
            org_url=resolved_tenant or None,
            warnings=tuple(warnings),
        )

    return NHIDiscoveryResult(
        status=NHIDiscoveryStatus.OK,
        identities=identities,
        warnings=tuple(warnings),
        org_url=resolved_tenant or None,
    )


__all__ = [
    "ENTRA_READ_PERMISSIONS",
    "EntraClient",
    "discover_entra_non_human_identities",
]
