"""Reuse retained scan work only within one synchronous aggregate read.

Nothing survives the request: approvals, expiry, tenant filters and evidence
changes are evaluated again on the next read. The context is thread/task-local.
"""

import threading
import weakref
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


_shared_lock = threading.Lock()
_shared_values: weakref.WeakValueDictionary[tuple[str, str], Any] = weakref.WeakValueDictionary()
_inflight: dict[tuple[str, str], threading.Lock] = {}


def read_once_shared(key: tuple[str, str], load: Callable[[], _T]) -> _T:
    """``read_once`` that also coalesces concurrent scopes on the same key.

    For keys that fully identify their value, such as exact stored payload
    text. Concurrent aggregate reads (one page fires several) then run one
    ``load`` and share its result instead of each repeating it. Values are held
    weakly, so nothing outlives the last scope using it, and calls outside a
    scope still get an independent value.
    """
    if _read_cache.get() is None:
        return load()
    return read_once(key, lambda: _single_flight(key, load))


def _single_flight(key: tuple[str, str], load: Callable[[], _T]) -> _T:
    value = _shared_values.get(key)
    if value is not None:
        return cast(_T, value)
    with _shared_lock:
        gate = _inflight.setdefault(key, threading.Lock())
    try:
        with gate:
            value = _shared_values.get(key)
            if value is None:
                value = load()
                try:
                    _shared_values[key] = value
                except TypeError:
                    pass
            return cast(_T, value)
    finally:
        with _shared_lock:
            if _inflight.get(key) is gate and not gate.locked():
                del _inflight[key]


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
