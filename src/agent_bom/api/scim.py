"""SCIM configuration posture for enterprise auth surfaces."""

from __future__ import annotations

import os
from typing import Any

from agent_bom.platform_invariants import normalize_tenant_id

_SCIM_ROLE_VALUES = ("admin", "analyst", "viewer")
_SCIM_ROLE_ALIASES = {
    "contributor": "analyst",
    "read_only": "viewer",
    "read-only": "viewer",
    "readonly": "viewer",
}


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def scim_base_path() -> str:
    """Return the configured SCIM base path, normalized for prefix checks."""
    raw = os.environ.get("AGENT_BOM_SCIM_BASE_PATH", "").strip() or "/scim/v2"
    path = "/" + raw.strip("/")
    return path.rstrip("/") or "/scim/v2"


def scim_enabled_from_env() -> bool:
    """Return whether the dedicated SCIM bearer token is configured."""
    return bool(os.environ.get("AGENT_BOM_SCIM_BEARER_TOKEN", "").strip())


def scim_tenant_id_from_env() -> str:
    """Return the tenant bound to inbound SCIM provisioning requests."""
    raw = os.environ.get("AGENT_BOM_SCIM_TENANT_ID", "").strip() or os.environ.get("AGENT_BOM_TENANT_ID", "").strip() or "default"
    return normalize_tenant_id(raw)


def scim_role_attribute() -> str:
    """Return the SCIM payload attribute used for Agent BOM roles."""
    return os.environ.get("AGENT_BOM_SCIM_ROLE_ATTRIBUTE", "").strip() or "agent_bom_role"


def scim_default_role() -> str:
    """Return the role assigned to SCIM users when an IdP omits role data."""
    candidate = os.environ.get("AGENT_BOM_SCIM_DEFAULT_ROLE", "").strip().lower() or "viewer"
    normalized = _SCIM_ROLE_ALIASES.get(candidate, candidate)
    return normalized if normalized in _SCIM_ROLE_VALUES else "viewer"


def normalize_scim_role(value: object) -> str | None:
    """Normalize an IdP-provided role into the Agent BOM RBAC vocabulary."""
    candidate = str(value or "").strip().lower()
    if not candidate:
        return None
    normalized = _SCIM_ROLE_ALIASES.get(candidate, candidate)
    return normalized if normalized in _SCIM_ROLE_VALUES else None


def _role_candidates(value: object) -> list[object]:
    if isinstance(value, list):
        candidates: list[object] = []
        for item in value:
            candidates.extend(_role_candidates(item))
        return candidates
    if isinstance(value, dict):
        candidates = []
        for key in ("value", "display", "type", "role"):
            if key in value:
                candidates.extend(_role_candidates(value[key]))
        return candidates
    return [value]


def extract_scim_roles(
    payload: dict[str, Any],
    *,
    existing_roles: list[str] | None = None,
) -> list[str]:
    """Extract normalized SCIM user roles without allowing tenant steering."""
    role_attribute = scim_role_attribute()
    raw_values: list[object] = []
    if role_attribute in payload:
        raw_values.append(payload[role_attribute])
    if "roles" in payload and role_attribute != "roles":
        raw_values.append(payload["roles"])
    for value in payload.values():
        if isinstance(value, dict) and role_attribute in value:
            raw_values.append(value[role_attribute])

    roles: list[str] = []
    for raw in raw_values:
        for candidate in _role_candidates(raw):
            role = normalize_scim_role(candidate)
            if role and role not in roles:
                roles.append(role)

    if roles:
        return roles
    if existing_roles:
        return existing_roles
    return [scim_default_role()]


def configured_api_replicas() -> int:
    """Return configured API replica count for SCIM storage posture."""
    raw = os.environ.get("AGENT_BOM_CONTROL_PLANE_REPLICAS", "").strip()
    if not raw:
        return 1
    try:
        return max(1, int(raw))
    except ValueError:
        return 1


def scim_requires_shared_store() -> bool:
    """Return whether SCIM state must use a shared backend."""
    return configured_api_replicas() > 1 or _env_flag("AGENT_BOM_REQUIRE_SHARED_SCIM_STORE")


def describe_scim_posture() -> dict[str, object]:
    """Return operator-facing SCIM configuration posture.

    This intentionally reports deployment readiness without exposing token
    material or trusting tenant information supplied by the IdP payload.
    """

    configured = scim_enabled_from_env()
    base_path = scim_base_path()
    role_attribute = scim_role_attribute()
    tenant_attribute = os.environ.get("AGENT_BOM_SCIM_TENANT_ATTRIBUTE", "").strip() or "tenant_id"
    external_id_attribute = os.environ.get("AGENT_BOM_SCIM_EXTERNAL_ID_ATTRIBUTE", "").strip() or "externalId"
    groups_required = _env_flag("AGENT_BOM_SCIM_REQUIRE_GROUPS")
    if os.environ.get("AGENT_BOM_POSTGRES_URL", "").strip():
        storage_backend = "postgres"
    elif os.environ.get("AGENT_BOM_DB", "").strip():
        storage_backend = "sqlite"
    else:
        storage_backend = "memory"
    replicas = configured_api_replicas()
    shared_required = scim_requires_shared_store()
    multi_node_ready = storage_backend == "postgres"
    status = "disabled"
    if configured:
        status = "configured" if (multi_node_ready or not shared_required) else "misconfigured"

    return {
        "supported": True,
        "configured": configured,
        "status": status,
        "base_path": base_path,
        "token_configured": configured,
        "tenant_id": scim_tenant_id_from_env() if configured else None,
        "tenant_id_source": "AGENT_BOM_SCIM_TENANT_ID",
        "storage_backend": storage_backend,
        "configured_api_replicas": replicas,
        "shared_store_required": shared_required,
        "multi_node_ready": multi_node_ready,
        "lifecycle_endpoints": {
            "users": f"{base_path}/Users",
            "groups": f"{base_path}/Groups",
            "service_provider_config": f"{base_path}/ServiceProviderConfig",
        },
        "external_id_attribute": external_id_attribute,
        "role_attribute": role_attribute,
        "default_role": scim_default_role(),
        "role_values": list(_SCIM_ROLE_VALUES),
        "tenant_attribute": tenant_attribute,
        "tenant_assignment": {
            "source": "AGENT_BOM_SCIM_TENANT_ID",
            "payload_tenant_attributes_ignored": True,
        },
        "provisioning_authority": "scim_lifecycle_store",
        "auth_authority": "api_key_oidc_saml_or_trusted_proxy",
        "runtime_auth_enforced": False,
        "deprovisioning_boundary": (
            "SCIM deactivate/delete updates provisioned lifecycle state and audit evidence. Runtime OIDC, SAML, "
            "reverse-proxy, and API-key sessions are revoked by their own upstream auth path."
        ),
        "groups_required": groups_required,
        "verified_idp_templates": [
            {
                "idp": "okta",
                "status": "contract_tested",
                "notes": "Accepts Okta-style User and Group lifecycle payloads with externalId, emails, groups, and active patches.",
            },
            {
                "idp": "microsoft_entra_id",
                "status": "contract_tested",
                "notes": (
                    "Accepts Microsoft Entra ID SCIM replace patches with value objects and standard userName/displayName/email fields."
                ),
            },
            {
                "idp": "google_cloud_identity",
                "status": "contract_tested",
                "notes": (
                    "Accepts Google Cloud Identity-style name.formatted fallback, externalId, active state, and group membership payloads."
                ),
            },
        ],
        "message": (
            (
                "SCIM lifecycle provisioning is configured with Postgres-backed shared state."
                if multi_node_ready
                else (
                    "SCIM lifecycle provisioning requires Postgres-backed shared state for this replica count. "
                    "Configure AGENT_BOM_POSTGRES_URL before enabling clustered SCIM."
                    if shared_required
                    else "SCIM lifecycle provisioning is configured for a single-node pilot. Use Postgres-backed storage "
                    "for clustered or EKS deployments."
                )
            )
            if configured
            else "SCIM provisioning is not configured. User and group lifecycle still depends on the upstream identity "
            "provider, reverse proxy, or manual API-key administration."
        ),
    }
