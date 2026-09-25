"""Bounded retention for immutable, generation-scoped graph summaries."""

from __future__ import annotations

import json
import threading
import time
from collections import OrderedDict
from typing import Any, cast

_MAX_BYTES = 4 * 1024 * 1024
_MAX_ENTRY_BYTES = 128 * 1024
_MAX_ENTRIES = 32
_TTL_SECONDS = 30
_LOCK = threading.Lock()
_CACHE: OrderedDict[tuple[Any, ...], tuple[float, bytes]] = OrderedDict()


def get(key: tuple[Any, ...]) -> dict[str, Any] | None:
    if len(repr(key)) > 4096:
        return None
    with _LOCK:
        now = time.monotonic()
        for old_key, (expires, _) in list(_CACHE.items()):
            if expires <= now:
                del _CACHE[old_key]
        entry = _CACHE.get(key)
        if entry is None:
            return None
        _CACHE.move_to_end(key)
        payload = entry[1]
    return cast(dict[str, Any], json.loads(payload))


def put(key: tuple[Any, ...], value: dict[str, Any]) -> None:
    if len(repr(key)) > 4096:
        return
    payload = json.dumps(value, separators=(",", ":")).encode()
    if len(payload) > _MAX_ENTRY_BYTES:
        return
    with _LOCK:
        _CACHE[key] = (time.monotonic() + _TTL_SECONDS, payload)
        _CACHE.move_to_end(key)
        while len(_CACHE) > _MAX_ENTRIES or sum(len(entry[1]) for entry in _CACHE.values()) > _MAX_BYTES:
            _CACHE.popitem(last=False)
