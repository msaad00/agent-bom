"""Tenant-safe execution helpers for background and pooled work."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import Executor, Future
from typing import ParamSpec, TypeVar

from agent_bom.api.postgres_common import _bypass_tenant_rls, reset_current_tenant, set_current_tenant
from agent_bom.core.tenancy import require_explicit_tenant_id

P = ParamSpec("P")
R = TypeVar("R")


def run_tenant_bound(
    tenant_id: str,
    function: Callable[P, R],
    /,
    *args: P.args,
    **kwargs: P.kwargs,
) -> R:
    """Run tenant work without inherited maintenance privileges; restore on exit."""

    token = set_current_tenant(require_explicit_tenant_id(tenant_id))
    bypass_token = _bypass_tenant_rls.set(False)
    try:
        return function(*args, **kwargs)
    finally:
        _bypass_tenant_rls.reset(bypass_token)
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

    return executor.submit(run_tenant_bound, require_explicit_tenant_id(tenant_id), function, *args, **kwargs)


__all__ = ["run_tenant_bound", "submit_tenant_bound"]
