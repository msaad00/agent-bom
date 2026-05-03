"""Framework catalog metadata endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from agent_bom.atlas import curated_total
from agent_bom.atlas_fetch import get_catalog_metadata as get_atlas_metadata
from agent_bom.mitre_fetch import get_catalog_metadata

router = APIRouter()


@router.get("/v1/frameworks/catalogs", tags=["frameworks"])
def framework_catalogs() -> dict:
    """Return active framework catalog metadata used by scans and outputs."""
    atlas_meta = get_atlas_metadata()
    atlas_meta["curated_count"] = curated_total()
    return {
        "frameworks": {
            "mitre_attack": get_catalog_metadata(),
            "mitre_atlas": atlas_meta,
        }
    }
