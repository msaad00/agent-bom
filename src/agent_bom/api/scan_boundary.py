"""Operator-owned permission for ambient host discovery by API workers."""

from __future__ import annotations

import os

from agent_bom.security import SecurityError


def require_host_discovery_for_tenant(tenant_id: str) -> None:
    """Fail closed unless this host is explicitly assigned to this tenant.

    Ambient discovery is not confined by the relative-path scan jail. Enabling
    jailed filesystem scans alone must therefore never enable ambient reads.
    Recheck at execution time so queued jobs cannot outlive revoked permission.
    """
    local_scans = os.getenv("AGENT_BOM_API_LOCAL_PATH_SCANS", os.getenv("AGENT_BOM_ENABLE_LOCAL_PATH_SCANS", "disabled"))
    bound_tenant = os.getenv("AGENT_BOM_API_HOST_DISCOVERY_TENANT", "").strip()
    if local_scans.strip().lower() not in {"1", "true", "yes", "on", "enabled"} or not bound_tenant or bound_tenant != tenant_id:
        raise SecurityError("Host discovery is not enabled for this tenant")
