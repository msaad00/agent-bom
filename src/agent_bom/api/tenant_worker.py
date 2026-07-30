"""Tenant-safe execution helpers for background and pooled work."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import Executor, Future
from typing import ParamSpec, TypeVar

from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

P = ParamSpec("P")
R = TypeVar("R")


def run_tenant_bound(
    tenant_id: str,
    function: Callable[P, R],
    /,
    *args: P.args,
    **kwargs: P.kwargs,
) -> R:
    """Run one callable under ``tenant_id`` and always restore prior context."""

    token = set_current_tenant(tenant_id)
    try:
        return function(*args, **kwargs)
    finally:
        reset_current_tenant(token)


def submit_tenant_bound(
    executor: Executor,
    tenant_id: str,
    function: Callable[P, R],
    /,
    *args: P.args,
    **kwargs: P.kwargs,
) -> Future[R]:
    """Submit work whose worker thread is explicitly tenant-bound."""

    return executor.submit(run_tenant_bound, tenant_id, function, *args, **kwargs)


__all__ = ["run_tenant_bound", "submit_tenant_bound"]
