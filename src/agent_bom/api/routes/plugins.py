"""Plugin registry status routes."""

from __future__ import annotations

from fastapi import APIRouter

from agent_bom.plugin_entrypoints import plugin_registry_status

router = APIRouter()


@router.get("/plugins/status", tags=["plugins"])
def get_plugin_registry_status() -> dict[str, object]:
    """Return metadata-only plugin registry status for operator dashboards."""

    return plugin_registry_status()
