"""SCIM configuration posture for enterprise auth surfaces."""

from __future__ import annotations

import json
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from json import JSONDecodeError
from typing import Any

from agent_bom.platform_invariants import ReservedTenantIdError, validate_customer_tenant_id

_SCIM_ROLE_VALUES = ("admin", "analyst", "viewer")
_SCIM_ROLE_ALIASES = {
    "contributor": "analyst",
    "read_only": "viewer",
    "read-only": "viewer",
    "readonly": "viewer",
}
_SCIM_SINGLE_TOKEN_ENV = "AGENT_BOM_SCIM_BEARER_TOKEN"
_SCIM_TOKEN_MAPPING_ENV = "AGENT_BOM_SCIM_BEARER_TOKENS_JSON"
_SCIM_SINGLE_TENANT_ENV = "AGENT_BOM_SCIM_TENANT_ID"


class SCIMConfigurationError(RuntimeError):
    """Raised when SCIM bearer-token configuration is invalid."""


@dataclass(frozen=True)
class SCIMBearerTokenBinding:
    """A server-side SCIM bearer token to tenant binding."""

    tenant_id: str
    token: str
    source: str
    token_id: str | None = None


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def scim_base_path() -> str:
    """Return the configured SCIM base path, normalized for prefix checks."""
    raw = os.environ.get("AGENT_BOM_SCIM_BASE_PATH", "").strip() or "/scim/v2"
    path = "/" + raw.strip("/")
    return path.rstrip("/") or "/scim/v2"


def scim_enabled_from_env() -> bool:
    """Return whether any dedicated SCIM bearer token source is configured."""
    return bool(os.environ.get(_SCIM_SINGLE_TOKEN_ENV, "").strip() or os.environ.get(_SCIM_TOKEN_MAPPING_ENV, "").strip())


def scim_tenant_id_from_env() -> str:
    """Return the tenant bound to inbound SCIM provisioning requests."""
    raw = os.environ.get(_SCIM_SINGLE_TENANT_ENV, "").strip() or os.environ.get("AGENT_BOM_TENANT_ID", "").strip() or "default"
    return _validate_scim_tenant_id(raw, source=_SCIM_SINGLE_TENANT_ENV)


def _validate_scim_tenant_id(raw: str, *, source: str) -> str:
    try:
        return validate_customer_tenant_id(raw)
    except ReservedTenantIdError as exc:
        raise SCIMConfigurationError(f"{source} contains a blank or reserved SCIM tenant id") from exc


def _token_from_mapping_value(tenant_id: str, value: object) -> tuple[str, str | None]:
    token: object
    token_id: object = None
    if isinstance(value, str):
        token = value
    elif isinstance(value, Mapping):
        token = value.get("token") or value.get("bearer_token") or value.get("bearerToken")
        token_id = value.get("token_id") or value.get("key_id") or value.get("id")
    else:
        raise SCIMConfigurationError(f"{_SCIM_TOKEN_MAPPING_ENV} value for tenant {tenant_id!r} must be a token string or object")

    if not isinstance(token, str):
        raise SCIMConfigurationError(f"{_SCIM_TOKEN_MAPPING_ENV} token for tenant {tenant_id!r} must be a string")
    stripped = token.strip()
    if not stripped:
        raise SCIMConfigurationError(f"{_SCIM_TOKEN_MAPPING_ENV} token for tenant {tenant_id!r} must not be blank")
    token_id_text = str(token_id).strip() if token_id is not None else ""
    return stripped, token_id_text or None


def _mapping_scim_bearer_token_bindings() -> list[SCIMBearerTokenBinding]:
    raw = os.environ.get(_SCIM_TOKEN_MAPPING_ENV, "").strip()
    if not raw:
        return []
    try:
        payload = json.loads(raw)
    except JSONDecodeError as exc:
        raise SCIMConfigurationError(f"{_SCIM_TOKEN_MAPPING_ENV} must be a JSON object mapping tenant id to token config") from exc
    if not isinstance(payload, dict):
        raise SCIMConfigurationError(f"{_SCIM_TOKEN_MAPPING_ENV} must be a JSON object mapping tenant id to token config")

    bindings: list[SCIMBearerTokenBinding] = []
    for raw_tenant_id, value in payload.items():
        tenant_id = _validate_scim_tenant_id(str(raw_tenant_id).strip(), source=_SCIM_TOKEN_MAPPING_ENV)
        token, token_id = _token_from_mapping_value(tenant_id, value)
        bindings.append(
            SCIMBearerTokenBinding(
                tenant_id=tenant_id,
                token=token,
                token_id=token_id,
                source=_SCIM_TOKEN_MAPPING_ENV,
            )
        )
    return bindings


def configured_scim_bearer_token_bindings() -> list[SCIMBearerTokenBinding]:
    """Return configured SCIM bearer token bindings without exposing them to callers."""
    bindings: list[SCIMBearerTokenBinding] = []
    single_token = os.environ.get(_SCIM_SINGLE_TOKEN_ENV, "").strip()
    if single_token:
        bindings.append(
            SCIMBearerTokenBinding(
                tenant_id=scim_tenant_id_from_env(),
                token=single_token,
                token_id=os.environ.get("AGENT_BOM_SCIM_BEARER_TOKEN_ID", "").strip() or None,
                source=_SCIM_SINGLE_TOKEN_ENV,
            )
        )
    bindings.extend(_mapping_scim_bearer_token_bindings())

    seen_tokens: set[str] = set()
    for binding in bindings:
        if binding.token in seen_tokens:
            raise SCIMConfigurationError("SCIM bearer token configuration contains duplicate token values")
        seen_tokens.add(binding.token)
    return bindings


def resolve_scim_bearer_token(raw_token: str) -> SCIMBearerTokenBinding | None:
    """Resolve a presented SCIM bearer token to its server-side tenant binding."""
    candidate = raw_token.strip()
    if not candidate:
        return None
    for binding in configured_scim_bearer_token_bindings():
        if secrets.compare_digest(candidate, binding.token):
            return binding
    return None


def _scim_token_binding_posture() -> dict[str, object]:
    if not scim_enabled_from_env():
        return {
            "configured": False,
            "status": "disabled",
            "mode": "none",
            "token_count": 0,
            "tenant_count": 0,
            "tenant_id": None,
            "tenant_ids": [],
            "tenant_id_source": _SCIM_SINGLE_TENANT_ENV,
        }
    try:
        bindings = configured_scim_bearer_token_bindings()
    except SCIMConfigurationError:
        return {
            "configured": True,
            "status": "misconfigured",
            "mode": "invalid",
            "token_count": 0,
            "tenant_count": 0,
            "tenant_id": None,
            "tenant_ids": [],
            "tenant_id_source": None,
            "message": "SCIM bearer token configuration is invalid. Check control-plane logs and SCIM environment settings.",
        }

    sources = {binding.source for binding in bindings}
    tenant_ids = sorted({binding.tenant_id for binding in bindings})
    mode = "multi_tenant" if _SCIM_TOKEN_MAPPING_ENV in sources else "single_tenant"
    return {
        "configured": bool(bindings),
        "status": "configured" if bindings else "disabled",
        "mode": mode,
        "token_count": len(bindings),
        "tenant_count": len(tenant_ids),
        "tenant_id": tenant_ids[0] if len(tenant_ids) == 1 else None,
        "tenant_ids": tenant_ids,
        "tenant_id_source": _SCIM_TOKEN_MAPPING_ENV if _SCIM_TOKEN_MAPPING_ENV in sources else _SCIM_SINGLE_TENANT_ENV,
    }


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

    token_posture = _scim_token_binding_posture()
    configured = bool(token_posture["configured"])
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
    if token_posture["status"] == "misconfigured":
        status = "misconfigured"
    elif configured:
        status = "configured" if (multi_node_ready or not shared_required) else "misconfigured"

    return {
        "supported": True,
        "configured": configured,
        "status": status,
        "base_path": base_path,
        "token_configured": configured,
        "token_binding_mode": token_posture["mode"],
        "token_binding_count": token_posture["token_count"],
        "tenant_count": token_posture["tenant_count"],
        "tenant_id": token_posture["tenant_id"],
        "tenant_ids": token_posture["tenant_ids"],
        "tenant_id_source": token_posture["tenant_id_source"],
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
            "source": token_posture["tenant_id_source"] or "AGENT_BOM_SCIM_TENANT_ID",
            "payload_tenant_attributes_ignored": True,
        },
        "provisioning_authority": "scim_lifecycle_store",
        "auth_authority": "api_key_oidc_saml_trusted_proxy_with_scim_role_overlay",
        "runtime_auth_enforced": configured,
        "deprovisioning_boundary": (
            "SCIM deactivate/delete updates provisioned lifecycle state, constrains runtime OIDC, SAML, "
            "browser, and trusted reverse-proxy roles when the authenticated subject matches a tenant-local "
            "SCIM user, and revokes API keys whose name matches the SCIM userName, id, or externalId."
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
            "SCIM bearer token configuration is invalid. Check control-plane logs and SCIM environment settings."
            if token_posture["status"] == "misconfigured"
            else (
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
            )
        ),
    }


SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


def scim_error_body(*, status_code: int, detail: str) -> dict[str, Any]:
    """RFC 7644 Error response body for non-bulk SCIM failures."""
    return {
        "schemas": [SCIM_ERROR_SCHEMA],
        "status": str(status_code),
        "detail": detail,
    }


def revoke_credentials_for_scim_user(tenant_id: str, user: Any) -> int:
    """Revoke tenant API keys whose display name matches a deprovisioned SCIM user."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import get_key_store

    store = get_key_store()
    subjects = {str(user.user_name), str(user.user_id)}
    external_id = getattr(user, "external_id", None)
    if external_id:
        subjects.add(str(external_id))
    subject_ids = {str(user.user_id)}
    if external_id:
        subject_ids.add(str(external_id))
    subjects_lower = {entry.lower() for entry in subjects if entry}
    revoked = 0
    for key in store.list_keys(tenant_id):
        if key.scim_subject_id and key.scim_subject_id in subject_ids:
            store.remove(key.key_id)
            revoked += 1
            log_action(
                "scim.api_key_revoked",
                actor="scim-provisioner",
                resource=f"key/{key.key_id}",
                tenant_id=tenant_id,
                user_name=user.user_name,
                match="scim_subject_id",
            )
            continue
        if key.name in subjects or key.name.lower() in subjects_lower:
            store.remove(key.key_id)
            revoked += 1
            log_action(
                "scim.api_key_revoked",
                actor="scim-provisioner",
                resource=f"key/{key.key_id}",
                tenant_id=tenant_id,
                user_name=user.user_name,
            )
    return revoked
