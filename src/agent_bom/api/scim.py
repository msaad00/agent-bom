"""SCIM configuration posture for enterprise auth surfaces."""

from __future__ import annotations

import os

from agent_bom.platform_invariants import normalize_tenant_id


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
    role_attribute = os.environ.get("AGENT_BOM_SCIM_ROLE_ATTRIBUTE", "").strip() or "agent_bom_role"
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
        "tenant_attribute": tenant_attribute,
        "groups_required": groups_required,
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
