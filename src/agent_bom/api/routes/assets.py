"""Asset tracking API routes.

Endpoints:
    GET /v1/assets       list tracked vulnerability assets
    GET /v1/assets/stats  aggregate asset statistics + MTTR
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request

from agent_bom.api.tenancy import require_request_tenant_id

router = APIRouter()
_logger = logging.getLogger(__name__)

_ASSET_SCOPE = "vulnerability_asset_lifecycle"
_ASSET_COUNT_DEFINITION = "tracked vulnerability-package records after lifecycle filters; not unified estate assets"
_ASSET_STATS_COUNT_DEFINITION = "tracked vulnerability-package records across lifecycle states; not unified estate assets"


@router.get("/assets", tags=["assets"])
async def list_assets(
    request: Request,
    status: str | None = None,
    severity: str | None = None,
    limit: int = 500,
) -> dict:
    """List tracked vulnerability assets with first_seen / last_seen / status.

    The asset tracker persists across scans so you can see when a vulnerability
    was first discovered, when it was last seen, and when it was resolved.

    Use ``--save`` on CLI scans or the API to populate the tracker.
    """
    try:
        from agent_bom.asset_tracker import AssetTracker

        with AssetTracker(tenant_id=require_request_tenant_id(request)) as tracker:
            assets = tracker.list_assets(status=status, severity=severity, limit=limit)
            stats = tracker.stats()
            mttr = tracker.mttr_days()
        return {
            "schema_version": "vulnerability-assets.v1",
            "scope": _ASSET_SCOPE,
            "count_definition": _ASSET_COUNT_DEFINITION,
            "assets": assets,
            "count": len(assets),
            "stats": stats,
            "mttr_days": mttr,
        }
    except Exception:
        _logger.error("Failed to list assets")
        return {
            "schema_version": "vulnerability-assets.v1",
            "scope": _ASSET_SCOPE,
            "count_definition": _ASSET_COUNT_DEFINITION,
            "assets": [],
            "count": 0,
            "stats": {},
            "mttr_days": None,
            "error": "Asset tracker unavailable",
        }


@router.get("/assets/stats", tags=["assets"])
async def get_asset_stats(request: Request) -> dict:
    """Return aggregate asset tracking statistics including MTTR."""
    try:
        from agent_bom.asset_tracker import AssetTracker

        with AssetTracker(tenant_id=require_request_tenant_id(request)) as tracker:
            stats = tracker.stats()
            mttr = tracker.mttr_days()
        return {
            "schema_version": "vulnerability-assets.stats.v1",
            "scope": _ASSET_SCOPE,
            "count_definition": _ASSET_STATS_COUNT_DEFINITION,
            "stats": stats,
            "mttr_days": mttr,
        }
    except Exception:
        _logger.error("Failed to get asset stats")
        return {
            "schema_version": "vulnerability-assets.stats.v1",
            "scope": _ASSET_SCOPE,
            "count_definition": _ASSET_STATS_COUNT_DEFINITION,
            "stats": {},
            "mttr_days": None,
            "error": "Asset tracker unavailable",
        }
