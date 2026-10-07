"""Reuse retained scan work only within one synchronous aggregate read.

Nothing survives the request: approvals, expiry, tenant filters and evidence
changes are evaluated again on the next read. The context is thread/task-local.
"""

from collections.abc import Iterator
from contextlib import contextmanager
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


@contextmanager
def finding_read_scope() -> Iterator[None]:
    """Keep one evidence context across synchronous calls or awaited route work."""
    if _read_cache.get() is not None:
        yield
        return
    token = _read_cache.set({})
    try:
        yield
    finally:
        _read_cache.reset(token)


def finding_read_snapshot(fn: Callable[_P, _T]) -> Callable[_P, _T]:
    @wraps(fn)
    def read(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        with finding_read_scope():
            return fn(*args, **kwargs)

    return read
