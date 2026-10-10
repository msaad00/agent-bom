"""Shared execution helpers for the dedicated AI-asset scan endpoints."""

from __future__ import annotations

from collections.abc import Callable
from functools import partial
from typing import Any

import anyio.to_thread
from fastapi import HTTPException

from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure


async def _ai_scan_call(fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
    """Run blocking dedicated AI-scan work off-loop under shared backpressure."""
    try:
        async with adaptive_backpressure("ai_scan"):
            return await anyio.to_thread.run_sync(partial(fn, *args, **kwargs))
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


def _dataclass_to_dict(obj: object) -> object:
    """Convert a dataclass to dict, handling nested dataclasses."""
    import dataclasses

    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _dataclass_to_dict(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [_dataclass_to_dict(i) for i in obj]
    return obj
