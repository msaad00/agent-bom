"""Per-tenant graph snapshot retention resolution."""

from __future__ import annotations

import json
import os
from typing import Any

from agent_bom.api.stores import _get_tenant_graph_retention_store, set_tenant_graph_retention_store


def _env_graph_retention_overrides() -> dict[str, int]:
    """Parse deploy-time tenant retention overrides from ``AGENT_BOM_GRAPH_RETENTION_OVERRIDES``."""
    raw = os.environ.get("AGENT_BOM_GRAPH_RETENTION_OVERRIDES", "").strip()
    if not raw:
        return {}
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(loaded, dict):
        return {}
    overrides: dict[str, int] = {}
    for key, value in loaded.items():
        tenant_id = str(key).strip()
        if not tenant_id:
            continue
        try:
            overrides[tenant_id] = max(1, int(value))
        except (TypeError, ValueError):
            continue
    return overrides


def resolve_graph_retention_days(tenant_id: str | None = None) -> int:
    """Return the effective graph retention window for *tenant_id*.

    Precedence: API config store override, then env JSON overrides, then the
    global ``AGENT_BOM_GRAPH_RETENTION_DAYS`` default.
    """
    from agent_bom.db.graph_store import _graph_retention_days, normalize_graph_tenant_id

    tid = normalize_graph_tenant_id(tenant_id)
    stored = _get_tenant_graph_retention_store().get(tid)
    if stored is not None:
        return max(1, int(stored))
    env_overrides = _env_graph_retention_overrides()
    if tid in env_overrides:
        return env_overrides[tid]
    return _graph_retention_days()


def get_tenant_graph_retention_override(tenant_id: str) -> int | None:
    """Return the persisted override for *tenant_id*, if any."""
    from agent_bom.db.graph_store import normalize_graph_tenant_id

    return _get_tenant_graph_retention_store().get(normalize_graph_tenant_id(tenant_id))


def set_tenant_graph_retention_override(tenant_id: str, retention_days: int) -> int:
    """Persist a tenant-specific graph retention override."""
    from agent_bom.db.graph_store import normalize_graph_tenant_id

    normalized = normalize_graph_tenant_id(tenant_id)
    days = max(1, int(retention_days))
    _get_tenant_graph_retention_store().put(normalized, days)
    return days


def clear_tenant_graph_retention_override(tenant_id: str) -> bool:
    """Remove a tenant-specific graph retention override."""
    from agent_bom.db.graph_store import normalize_graph_tenant_id

    return _get_tenant_graph_retention_store().delete(normalize_graph_tenant_id(tenant_id))


def graph_retention_overrides_snapshot() -> dict[str, Any]:
    """Return env + store override sources for policy reporting."""
    return {
        "env_overrides": _env_graph_retention_overrides(),
        "per_tenant_overrides": True,
    }


__all__ = [
    "clear_tenant_graph_retention_override",
    "get_tenant_graph_retention_override",
    "graph_retention_overrides_snapshot",
    "resolve_graph_retention_days",
    "set_tenant_graph_retention_override",
    "set_tenant_graph_retention_store",
]
