"""Asset tracking API routes.

Endpoints:
    GET /v1/assets       list tracked vulnerability assets
    GET /v1/assets/stats  aggregate asset statistics + MTTR
"""

from __future__ import annotations

import logging

from fastapi import APIRouter

router = APIRouter()
_logger = logging.getLogger(__name__)


@router.get("/v1/assets", tags=["assets"])
async def list_assets(
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

        tracker = AssetTracker()
        assets = tracker.list_assets(status=status, severity=severity, limit=limit)
        stats = tracker.stats()
        mttr = tracker.mttr_days()
        tracker.close()
        return {
            "assets": assets,
            "count": len(assets),
            "stats": stats,
            "mttr_days": mttr,
        }
    except Exception:
        _logger.exception("Failed to list assets")
        return {
            "assets": [],
            "count": 0,
            "stats": {},
            "mttr_days": None,
            "error": "Asset tracker unavailable",
        }


@router.get("/v1/assets/stats", tags=["assets"])
async def get_asset_stats() -> dict:
    """Return aggregate asset tracking statistics including MTTR."""
    try:
        from agent_bom.asset_tracker import AssetTracker

        tracker = AssetTracker()
        stats = tracker.stats()
        mttr = tracker.mttr_days()
        tracker.close()
        return {"stats": stats, "mttr_days": mttr}
    except Exception:
        _logger.exception("Failed to get asset stats")
        return {
            "stats": {},
            "mttr_days": None,
            "error": "Asset tracker unavailable",
        }
