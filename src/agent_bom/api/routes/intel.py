"""Threat-intel lookup and inventory match routes."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from agent_bom.intel_lookup import build_daily_brief, list_intel_sources, lookup_advisory, match_packages
from agent_bom.security import sanitize_error

router = APIRouter()


class IntelPackageMatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    packages: list[dict[str, Any]] = Field(min_length=1, max_length=500)
    limit: int = Field(default=100, ge=1, le=500)


class IntelDailyBriefRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    packages: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    telemetry_indicators: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    campaign_activity: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    ransomware_claims: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    tenant_profile: dict[str, Any] = Field(default_factory=dict)
    epss_threshold: float = Field(default=0.7, ge=0, le=1)
    kev_window_hours: int = Field(default=24, ge=1, le=168)
    limit: int = Field(default=100, ge=1, le=500)


@router.get("/intel/sources", tags=["intel"])
async def get_intel_sources() -> dict[str, Any]:
    """Return canonical threat-intel source and feed-run metadata."""

    return list_intel_sources()


@router.get("/intel/advisories/{advisory_id}", tags=["intel"])
async def get_intel_advisory(advisory_id: str) -> dict[str, Any]:
    """Look up one CVE/GHSA/OSV advisory from local intel."""

    try:
        return lookup_advisory(advisory_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=sanitize_error(exc)) from exc


@router.post("/intel/match", tags=["intel"])
async def post_intel_match(
    body: IntelPackageMatchRequest,
    include_unmatched: Annotated[bool, Query(description="Return packages with zero matched advisories.")] = True,
) -> dict[str, Any]:
    """Match inventory package coordinates to local advisory intel."""

    try:
        result = match_packages(body.packages, limit=body.limit)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=sanitize_error(exc)) from exc
    if not include_unmatched:
        result["matches"] = [item for item in result["matches"] if item["match_count"] > 0]
    return result


@router.post("/intel/daily-brief", tags=["intel"])
async def post_intel_daily_brief(body: IntelDailyBriefRequest) -> dict[str, Any]:
    """Return a local analyst threat brief from governed intel sources."""

    try:
        return build_daily_brief(
            body.packages,
            telemetry_indicators=body.telemetry_indicators,
            campaign_activity=body.campaign_activity,
            ransomware_claims=body.ransomware_claims,
            tenant_profile=body.tenant_profile,
            epss_threshold=body.epss_threshold,
            kev_window_hours=body.kev_window_hours,
            limit=body.limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=sanitize_error(exc)) from exc
