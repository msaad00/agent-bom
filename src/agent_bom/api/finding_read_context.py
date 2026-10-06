"""Reuse retained scan work only within one synchronous aggregate read.

Nothing survives the request: approvals, expiry, tenant filters and evidence
changes are evaluated again on the next read. The context is thread/task-local.
"""

from contextvars import ContextVar
from functools import wraps
from typing import Any, Callable, ParamSpec, TypeVar, cast

_P = ParamSpec("_P")
_T = TypeVar("_T")
_read_cache: ContextVar[dict[tuple[str, str], Any] | None] = ContextVar("finding_read_cache", default=None)


def read_once(key: tuple[str, str], load: Callable[[], _T]) -> _T:
    cache = _read_cache.get()
    if cache is None:
        return load()
    if key not in cache:
        cache[key] = load()
    return cast(_T, cache[key])


def finding_read_snapshot(fn: Callable[_P, _T]) -> Callable[_P, _T]:
    @wraps(fn)
    def read(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        if _read_cache.get() is not None:
            return fn(*args, **kwargs)
        token = _read_cache.set({})
        try:
            return fn(*args, **kwargs)
        finally:
            _read_cache.reset(token)

    return read
