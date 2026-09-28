"""Per-tenant, per-session shield protection engines.

Zero trust: one tenant/session's CRITICAL threat cannot block or reveal another
tenant/session's tool calls. Route handlers run in the threadpool, so compound
check / evict / insert sequences must hold ``_shield_engines_lock``.
"""

from __future__ import annotations

from threading import Lock
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.runtime.protection import ProtectionEngine

_ShieldKey = tuple[str, str]
_shield_engines: dict[_ShieldKey, ProtectionEngine] = {}
_shield_engines_lock = Lock()
_MAX_SHIELD_SESSIONS = 64  # bound memory; evict oldest idle session


def _shield_key(tenant_id: str, session_id: str) -> _ShieldKey:
    return (tenant_id or "default", session_id or "default")


def _get_engine(tenant_id: str, session_id: str) -> ProtectionEngine | None:
    return _shield_engines.get(_shield_key(tenant_id, session_id))
