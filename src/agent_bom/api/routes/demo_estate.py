"""Read-only API for the explicitly enabled synthetic enterprise demo."""

from __future__ import annotations

import os
from typing import Any, cast

from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.demo_estate.presentation import EnterpriseDemoStory, build_enterprise_demo_story
from agent_bom.rbac import require_authenticated_permission

router = APIRouter(dependencies=[cast(Any, require_authenticated_permission("read"))])
_TRUTHY = {"1", "true", "yes", "on"}


def _demo_estate_enabled() -> bool:
    """Read the opt-in flag without importing the stateful bootstrap path."""
    return os.environ.get("AGENT_BOM_DEMO_ESTATE", "").strip().lower() in _TRUTHY


@router.get(
    "/demo-estate/story",
    response_model=EnterpriseDemoStory,
    tags=["demo-estate"],
)
async def get_enterprise_demo_story(request: Request) -> EnterpriseDemoStory:
    """Return tenant-scoped normalized evidence only in explicit demo mode."""

    if not _demo_estate_enabled():
        raise HTTPException(status_code=404, detail="Demo estate is not enabled")
    tenant_id = require_request_tenant_id(request)
    return build_enterprise_demo_story(tenant_id=tenant_id)


__all__ = ["get_enterprise_demo_story", "router"]
