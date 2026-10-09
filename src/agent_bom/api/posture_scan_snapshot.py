"""Bounded, detached posture inputs keyed by the durable tenant job revision."""

from __future__ import annotations

import copy
import json
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

from fastapi import HTTPException

from agent_bom.core.tenancy import require_explicit_tenant_id

_CACHE: OrderedDict[tuple[Any, str, str], tuple[float, dict | None]] = OrderedDict()
_LOCK = threading.Lock()
_TTL = 15.0
_MAX_ENTRIES = 64
_MAX_BYTES = 256 * 1024


def scan_posture_inputs(store: Any, tenant_id: str, load_current: Callable[[], Any]) -> dict | None:
    """Keep only summary/scorecard fields; callers never share mutable job objects.

    The caller selects authoritative evidence; this cache stores only projections.
    Legacy stores without revision tokens compute on every call. Durable stores
    validate the token around reads and reject continuously changing evidence.
    The short TTL also bounds changes to time-dependent scan eligibility.
    """
    require_explicit_tenant_id(tenant_id)
    reader = getattr(store, "overview_evidence_revision", None)

    def compute() -> dict | None:
        job = load_current()
        if job is None or job.result is None:
            return None
        return copy.deepcopy({key: job.result.get(key) for key in ("summary", "posture_scorecard")})

    if not callable(reader):
        return compute()
    for _ in range(3):
        before = str(reader(tenant_id))
        key = (store, tenant_id, before)
        with _LOCK:
            hit = _CACHE.get(key)
            if hit is not None and hit[0] > time.monotonic():
                _CACHE.move_to_end(key)
                return copy.deepcopy(hit[1])
        value = compute()
        if str(reader(tenant_id)) != before:
            continue
        if len(json.dumps(value).encode()) <= _MAX_BYTES:
            with _LOCK:
                _CACHE[key] = (time.monotonic() + _TTL, copy.deepcopy(value))
                _CACHE.move_to_end(key)
                while len(_CACHE) > _MAX_ENTRIES:
                    _CACHE.popitem(last=False)
        return value
    raise HTTPException(status_code=503, detail="Posture evidence changed during read; retry the request.")
