"""Threat-intel lookup and inventory match routes."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from agent_bom.intel_lookup import list_intel_sources, lookup_advisory, match_packages

router = APIRouter()


class IntelPackageMatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    packages: list[dict[str, Any]] = Field(min_length=1, max_length=500)
    limit: int = Field(default=100, ge=1, le=500)


@router.get("/v1/intel/sources", tags=["intel"])
async def get_intel_sources() -> dict[str, Any]:
    """Return canonical threat-intel source and feed-run metadata."""

    return list_intel_sources()


@router.get("/v1/intel/advisories/{advisory_id}", tags=["intel"])
async def get_intel_advisory(advisory_id: str) -> dict[str, Any]:
    """Look up one CVE/GHSA/OSV advisory from local intel."""

    try:
        return lookup_advisory(advisory_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/v1/intel/match", tags=["intel"])
async def post_intel_match(
    body: IntelPackageMatchRequest,
    include_unmatched: Annotated[bool, Query(description="Return packages with zero matched advisories.")] = True,
) -> dict[str, Any]:
    """Match inventory package coordinates to local advisory intel."""

    try:
        result = match_packages(body.packages, limit=body.limit)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not include_unmatched:
        result["matches"] = [item for item in result["matches"] if item["match_count"] > 0]
    return result
