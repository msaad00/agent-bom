"""Environment an operator sets to bind the API host's live discovery to one tenant."""

from __future__ import annotations


def host_bound_to(tenant_id: str) -> dict[str, str]:
    return {"AGENT_BOM_API_LOCAL_PATH_SCANS": "enabled", "AGENT_BOM_API_HOST_DISCOVERY_TENANT": tenant_id}
