"""Agent BOM manifest API routes."""

from __future__ import annotations

from fastapi import APIRouter, Request

from agent_bom.agent_manifest import build_control_plane_agent_manifest
from agent_bom.api.stores import _get_fleet_store, _get_mcp_observation_store

router = APIRouter(prefix="/v1/agent-bom", tags=["Agent BOM"])


@router.get("/manifest")
async def get_agent_bom_manifest(request: Request) -> dict[str, object]:
    """Return the tenant-scoped Agent BOM manifest from fleet/runtime stores."""

    tenant_id = getattr(request.state, "tenant_id", "default")
    fleet_agents = _get_fleet_store().list_by_tenant(tenant_id)
    observations = _get_mcp_observation_store().list_by_tenant(tenant_id)
    return build_control_plane_agent_manifest(fleet_agents, observations, tenant_id=tenant_id)
