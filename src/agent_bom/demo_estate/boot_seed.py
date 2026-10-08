"""Run demo-estate seeding off the API startup path.

Liveness answers as soon as the process is up; readiness reports the seed in
flight until the showcase evidence has landed. The maintenance loop can reseed
concurrently with the startup seed, so every seed run is serialized.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import threading
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

_logger = logging.getLogger(__name__)

_F = TypeVar("_F", bound=Callable[..., Any])
_seed_run_lock = threading.Lock()
_boot_seed_done = threading.Event()
_boot_seed_done.set()


def serialized_seed(fn: _F) -> _F:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        with _seed_run_lock:
            return fn(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


def demo_estate_seeding() -> bool:
    return not _boot_seed_done.is_set()


def wait_for_demo_estate_boot_seed(timeout: float | None = None) -> bool:
    return _boot_seed_done.wait(timeout)


_POSTURE_PRECOMPUTE_READY_TIMEOUT_SECONDS = 120.0


def _run_boot_seed() -> None:
    from agent_bom.api.posture_counts_cache import wait_for_posture_precompute
    from agent_bom.demo_estate import bootstrap

    try:
        bootstrap.maybe_bootstrap_demo_estate()
        # The seed's scan writes schedule the posture-count precompute; stay
        # not-ready until it lands so the first read does not repeat it.
        if not wait_for_posture_precompute(_POSTURE_PRECOMPUTE_READY_TIMEOUT_SECONDS):
            _logger.warning("demo estate posture precompute still running at readiness")
    finally:
        _boot_seed_done.set()


async def _seed_then(after: Callable[[], Awaitable[None]] | None) -> None:
    try:
        await asyncio.to_thread(_run_boot_seed)
    except Exception:  # noqa: BLE001
        _logger.warning("demo estate bootstrap skipped", exc_info=False)
    if after is not None:
        from agent_bom.api import foreground_activity

        await asyncio.to_thread(foreground_activity.defer_until_idle)
        await after()


def start_demo_estate_boot_seed(after: Callable[[], Awaitable[None]] | None = None) -> asyncio.Task[None]:
    """Schedule the startup seed; readiness reports seeding from this call on."""
    _boot_seed_done.clear()
    return asyncio.create_task(_seed_then(after))


async def drain_demo_estate_boot_seed(task: asyncio.Task[None] | None, timeout: float) -> None:
    """Let an in-flight seed finish writing before stores close; its thread cannot be cancelled."""
    if task is not None and not task.done():
        await asyncio.wait({task}, timeout=timeout)


__all__ = [
    "demo_estate_seeding",
    "drain_demo_estate_boot_seed",
    "serialized_seed",
    "start_demo_estate_boot_seed",
    "wait_for_demo_estate_boot_seed",
]
