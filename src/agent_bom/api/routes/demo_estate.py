"""Read-only API for the explicitly enabled synthetic enterprise demo."""

from __future__ import annotations

import os
import threading
from collections import OrderedDict
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

# The cache proper. An explicit bounded LRU rather than ``functools.lru_cache``
# because the read path needs to *peek* — a warm request must be answerable
# without entering the builder, and ``lru_cache`` exposes no lookup that does
# not also build on a miss. That missing peek is what forced every warm read
# through the worker thread and the build lock.
_STORY_CACHE: OrderedDict[str, EnterpriseDemoStory] = OrderedDict()

# Guards the mapping *only*, never a build. Held for the duration of a dict
# operation, so no caller can ever wait on it for measurable time.
_STORY_CACHE_LOCK = threading.Lock()

# Serialises *cold* builds. The story is pure CPU under the GIL, so letting N
# concurrent callers each start their own build buys no parallelism and N times
# the latency; the first caller builds, the rest wait and then read the cache.
# It must never span the cache lookup: doing so made a warm read for one tenant
# wait 1,853 ms behind an unrelated tenant's cold build (31 ms served alone),
# which is both the opposite of what the cache is for and a multi-tenant
# fairness bug — nothing about tenant B's build bears on tenant A's cached value.
_STORY_BUILD_LOCK = threading.Lock()

# One token, re-derived from measurement rather than from the thread-pool
# argument that originally set it to 2.
#
# The original reasoning — anyio's default limiter has 40 SHARED tokens, and
# API-key verification offloads its scrypt through the same pool, so an
# unbounded burst would starve authentication — is still why a dedicated
# limiter exists at all. What did not hold is the value. A second token cannot
# buy parallelism, because the build is pure Python under the GIL and
# ``_STORY_BUILD_LOCK`` serialises it regardless; all the second token can do is
# park another worker thread on that lock. Measured on an 8-tenant cold burst:
# total wall time is unchanged between 1 and 2 tokens (the lock, not the
# limiter, sets it), so the extra token is pure cost.
_STORY_THREAD_LIMITER = anyio.CapacityLimiter(1)


def _demo_estate_enabled() -> bool:
    """Read the opt-in flag without importing the stateful bootstrap path."""
    return os.environ.get("AGENT_BOM_DEMO_ESTATE", "").strip().lower() in _TRUTHY


def _peek_demo_story(tenant_id: str) -> EnterpriseDemoStory | None:
    """Return a already-built story, or ``None``. Never builds, never blocks.

    Safe to call straight from the event loop: the only lock it takes guards a
    dictionary operation.
    """
    with _STORY_CACHE_LOCK:
        story = _STORY_CACHE.get(tenant_id)
        if story is not None:
            _STORY_CACHE.move_to_end(tenant_id)
        return story


def _remember_demo_story(tenant_id: str, story: EnterpriseDemoStory) -> None:
    """Publish a freshly built story, evicting the least recently used entry.

    ``tenant_id`` is request-controlled, so the bound is a security property
    (memory DoS), not a tuning knob.
    """
    with _STORY_CACHE_LOCK:
        _STORY_CACHE[tenant_id] = story
        _STORY_CACHE.move_to_end(tenant_id)
        while len(_STORY_CACHE) > DEMO_STORY_CACHE_MAXSIZE:
            _STORY_CACHE.popitem(last=False)


def _cached_demo_story(tenant_id: str) -> EnterpriseDemoStory:
    """Cache-or-build one tenant's story. Runs in a worker thread.

    ``build_enterprise_demo_story`` is a pure function of ``tenant_id`` over a
    bundled fixture — it publishes its own ``story_content_hash`` to say so — and
    returns a frozen model, so a cached value can never drift from a rebuilt one.
    Keying on ``tenant_id`` is load-bearing: the payload embeds the tenant and a
    tenant-specific ``estate_content_hash``, so a shared entry would be a
    cross-tenant disclosure rather than a stale read.

    The lock covers the build and nothing else. The lookup that precedes it is
    deliberately outside, and it is repeated once the lock is held so that the
    callers queued behind a build read its result instead of repeating it.
    """
    story = _peek_demo_story(tenant_id)
    if story is not None:
        return story

    with _STORY_BUILD_LOCK:
        story = _peek_demo_story(tenant_id)
        if story is not None:
            return story
        built = build_enterprise_demo_story(tenant_id=tenant_id)
        # Published before the lock is released. Publishing after it would
        # reopen the double-build this lock exists to prevent: the next waiter
        # would take the lock, re-peek, and still miss.
        _remember_demo_story(tenant_id, built)

    return built


def demo_story_cache_size() -> int:
    """Number of cached tenant stories. For tests and memory assertions."""
    with _STORY_CACHE_LOCK:
        return len(_STORY_CACHE)


def reset_demo_story_cache() -> None:
    """Drop every cached story. For tests and for reseeded demo bootstraps."""
    with _STORY_CACHE_LOCK:
        _STORY_CACHE.clear()


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

    # Warm path: a dictionary lookup, answered on the loop. It must not reach
    # the worker pool at all — offloading a cache hit costs a limiter token and
    # a thread hop for nothing, and while the limiter is busy with cold builds
    # it would queue the hit behind them.
    cached = _peek_demo_story(tenant_id)
    if cached is not None:
        return cached

    # Cold path only. Composing the incident into an enterprise-sized population
    # took this build to ~1.6s (measured: 2,068 assets / 6,159 observations,
    # almost all of it in correlate-and-redact). Called inline from an
    # ``async def`` it parked the event loop for the whole request, so four
    # concurrent callers serialised into 6.6s on one worker. Offload it.
    return await anyio.to_thread.run_sync(_cached_demo_story, tenant_id, limiter=_STORY_THREAD_LIMITER)


__all__ = [
    "DEMO_STORY_CACHE_MAXSIZE",
    "demo_story_cache_size",
    "get_enterprise_demo_story",
    "reset_demo_story_cache",
    "router",
]
