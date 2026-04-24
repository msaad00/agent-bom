"""SCIM configuration posture for enterprise auth surfaces."""

from __future__ import annotations

import os


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def describe_scim_posture() -> dict[str, object]:
    """Return operator-facing SCIM configuration posture.

    This is intentionally a control-plane posture surface, not a claim that
    full SCIM provisioning is implemented end to end.
    """

    token = os.environ.get("AGENT_BOM_SCIM_BEARER_TOKEN", "").strip()
    base_path = os.environ.get("AGENT_BOM_SCIM_BASE_PATH", "").strip() or "/scim/v2"
    role_attribute = os.environ.get("AGENT_BOM_SCIM_ROLE_ATTRIBUTE", "").strip() or "agent_bom_role"
    tenant_attribute = os.environ.get("AGENT_BOM_SCIM_TENANT_ATTRIBUTE", "").strip() or "tenant_id"
    external_id_attribute = os.environ.get("AGENT_BOM_SCIM_EXTERNAL_ID_ATTRIBUTE", "").strip() or "externalId"
    groups_required = _env_flag("AGENT_BOM_SCIM_REQUIRE_GROUPS")

    configured = bool(token)
    return {
        "supported": True,
        "configured": configured,
        "status": "configured" if configured else "disabled",
        "base_path": base_path,
        "token_configured": configured,
        "external_id_attribute": external_id_attribute,
        "role_attribute": role_attribute,
        "tenant_attribute": tenant_attribute,
        "groups_required": groups_required,
        "message": (
            "SCIM provisioning bootstrap is configured. Control-plane posture now exposes the expected token and attribute "
            "mapping contract, but full user and group lifecycle enforcement is still a follow-on."
            if configured
            else "SCIM provisioning is not configured. User and group lifecycle still depends on the upstream identity "
            "provider, reverse proxy, or manual API-key administration."
        ),
    }
