"""Read-only API for the explicitly enabled synthetic enterprise demo."""

from __future__ import annotations

import functools
import os
import threading
from typing import Any, cast

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.demo_estate.presentation import EnterpriseDemoStory, build_enterprise_demo_story
from agent_bom.rbac import require_authenticated_permission

router = APIRouter(dependencies=[cast(Any, require_authenticated_permission("read"))])
_TRUTHY = {"1", "true", "yes", "on"}

# The bound is a memory guard, not a tuning knob: entries are keyed by tenant,
# and a measured entry retains ~1.5 MB, so an unbounded cache would grow with
# the tenant count. The demo serves one tenant; 8 caps the worst case at ~12 MB
# while still covering a multi-tenant self-host.
DEMO_STORY_CACHE_MAXSIZE = 8

# Serialises *cold* builds. The story is pure CPU under the GIL, so letting N
# concurrent callers each start their own build buys no parallelism and N times
# the latency; the first caller builds, the rest wait and then read the cache.
_STORY_BUILD_LOCK = threading.Lock()


def _demo_estate_enabled() -> bool:
    """Read the opt-in flag without importing the stateful bootstrap path."""
    return os.environ.get("AGENT_BOM_DEMO_ESTATE", "").strip().lower() in _TRUTHY


@functools.lru_cache(maxsize=DEMO_STORY_CACHE_MAXSIZE)
def _cached_demo_story(tenant_id: str) -> EnterpriseDemoStory:
    """Build one tenant's story once and reuse it.

    ``build_enterprise_demo_story`` is a pure function of ``tenant_id`` over a
    bundled fixture — it publishes its own ``story_content_hash`` to say so — and
    returns a frozen model, so a cached value can never drift from a rebuilt one.
    Keying on ``tenant_id`` is load-bearing: the payload embeds the tenant and a
    tenant-specific ``estate_content_hash``, so a shared entry would be a
    cross-tenant disclosure rather than a stale read.
    """
    return build_enterprise_demo_story(tenant_id=tenant_id)


def _build_demo_story_blocking(tenant_id: str) -> EnterpriseDemoStory:
    """Cache-or-build under the single-flight lock. Runs in a worker thread."""
    with _STORY_BUILD_LOCK:
        return _cached_demo_story(tenant_id)


def reset_demo_story_cache() -> None:
    """Drop every cached story. For tests and for reseeded demo bootstraps."""
    _cached_demo_story.cache_clear()


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
    # Composing the incident into an enterprise-sized population took this build
    # to ~1.6s (measured: 2,068 assets / 6,159 observations, almost all of it in
    # correlate-and-redact). Called inline from an ``async def`` it parked the
    # event loop for the whole request, so four concurrent callers serialised
    # into 6.6s on one worker. Offload it; the loop stays free either way.
    return await anyio.to_thread.run_sync(_build_demo_story_blocking, tenant_id)


__all__ = [
    "DEMO_STORY_CACHE_MAXSIZE",
    "get_enterprise_demo_story",
    "reset_demo_story_cache",
    "router",
]
