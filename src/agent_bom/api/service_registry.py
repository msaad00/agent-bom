"""Tenant service registry — lock / connect / live states for product surfaces.

Derived from real records (connections, sources, fleet, manifest, cost) plus
deployment-context flags already computed for nav visibility. Returned on
``GET /v1/posture/counts`` under ``services`` so nav, page headers, and connect
flows share one contract.
"""

from __future__ import annotations

from typing import Any, Literal

from agent_bom.agent_manifest import build_control_plane_agent_manifest
from agent_bom.api.connection_store import get_connection_store
from agent_bom.api.cost_store import get_cost_store
from agent_bom.api.stores import _get_fleet_store, _get_mcp_observation_store, _get_source_store

ServiceState = Literal["locked", "connected", "live"]
SERVICE_REGISTRY_SCHEMA = "agent-bom.services/v1"


def _entry(
    state: ServiceState,
    *,
    count: int = 0,
    requires: list[str] | None = None,
    detail: str = "",
) -> dict[str, Any]:
    payload: dict[str, Any] = {"state": state, "count": count}
    if requires:
        payload["requires"] = requires
    if detail:
        payload["detail"] = detail
    return payload


def _cloud_accounts(tenant_id: str) -> dict[str, Any]:
    connections = get_connection_store().list_for_tenant(tenant_id)
    if not connections:
        return _entry("locked")
    scanned = sum(1 for record in connections if record.last_scan_at)
    providers = sorted({record.provider for record in connections if record.provider})
    if scanned > 0:
        return _entry("live", count=len(connections), detail=",".join(providers))
    active = sum(1 for record in connections if record.status == "active")
    if active > 0:
        return _entry("connected", count=len(connections), detail=",".join(providers))
    return _entry("connected", count=len(connections), detail=",".join(providers))


def _data_sources(tenant_id: str) -> dict[str, Any]:
    try:
        source_store = _get_source_store()
    except RuntimeError:
        return _entry("locked")
    sources = [source for source in source_store.list_all(tenant_id=tenant_id) if source.enabled]
    if not sources:
        return _entry("locked")
    live = sum(
        1
        for source in sources
        if source.last_run_at or (source.last_run_status or "").lower() in {"success", "ok", "done"}
    )
    if live > 0:
        return _entry("live", count=len(sources))
    return _entry("connected", count=len(sources))


def _local_agents(tenant_id: str, deployment: dict[str, Any]) -> dict[str, Any]:
    fleet_agents = _get_fleet_store().list_by_tenant(tenant_id)
    observations = _get_mcp_observation_store().list_by_tenant(tenant_id)
    manifest = build_control_plane_agent_manifest(fleet_agents, observations, tenant_id=tenant_id)
    summary = manifest.get("summary")
    agent_count = int(summary.get("agents") or 0) if isinstance(summary, dict) else 0
    if agent_count > 0 or deployment.get("has_local_scan"):
        return _entry("live", count=agent_count)
    if fleet_agents:
        return _entry("connected", count=len(fleet_agents))
    return _entry("locked")


def _fleet(tenant_id: str, deployment: dict[str, Any]) -> dict[str, Any]:
    count = len(_get_fleet_store().list_by_tenant(tenant_id))
    if deployment.get("has_fleet_ingest") or count > 0:
        return _entry("live", count=count)
    return _entry("locked")


def _runtime_flag(deployment: dict[str, Any], key: str) -> dict[str, Any]:
    if deployment.get(key):
        return _entry("live", count=1)
    return _entry("locked")


def _ai_spend(tenant_id: str, deployment: dict[str, Any]) -> dict[str, Any]:
    records = get_cost_store().list_records(tenant_id, limit=1)
    if records:
        return _entry("live", count=len(records))
    if deployment.get("has_proxy") or deployment.get("has_gateway"):
        return _entry("connected", requires=["runtime_proxy"])
    return _entry("locked", requires=["runtime_proxy"])


def _compliance(deployment: dict[str, Any]) -> dict[str, Any]:
    scan_count = int(deployment.get("scan_count") or 0)
    if scan_count > 0:
        return _entry("live", count=scan_count)
    return _entry("locked")


def derive_service_registry(tenant_id: str, deployment: dict[str, Any]) -> dict[str, Any]:
    """Build the tenant-scoped service registry from stores and deployment flags."""

    services = {
        "cloud_accounts": _cloud_accounts(tenant_id),
        "data_sources": _data_sources(tenant_id),
        "local_agents": _local_agents(tenant_id, deployment),
        "fleet": _fleet(tenant_id, deployment),
        "runtime_proxy": _runtime_flag(deployment, "has_proxy"),
        "runtime_gateway": _runtime_flag(deployment, "has_gateway"),
        "runtime_traces": _runtime_flag(deployment, "has_traces"),
        "ai_spend": _ai_spend(tenant_id, deployment),
        "compliance": _compliance(deployment),
    }
    return {"schema_version": SERVICE_REGISTRY_SCHEMA, "services": services}
