"""Framework catalog metadata endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from agent_bom.mitre_fetch import get_catalog_metadata

router = APIRouter()


@router.get("/v1/frameworks/catalogs", tags=["frameworks"])
def framework_catalogs() -> dict:
    """Return active framework catalog metadata used by scans and outputs."""
    return {
        "frameworks": {
            "mitre_attack": get_catalog_metadata(),
        }
    }
