"""Per-tenant executive risk-score config helpers (#3940).

Thin persistence facade over :func:`agent_bom.api.stores._get_tenant_score_config_store`
that mirrors ``tenant_quota``: read the persisted (partial) override, merge it
onto process defaults + env policy, and expose an operator-facing runtime view.
Every write is canonicalized/clamped by :mod:`agent_bom.exec_score` first, so
the store never holds invalid weights or thresholds.
"""

from __future__ import annotations

from typing import Any, Mapping

from agent_bom.api.stores import _get_tenant_score_config_store
from agent_bom.exec_score import (
    DEFAULT_DISPLAY_FORMAT,
    DEFAULT_EXEC_SCORE_WEIGHTS,
    DEFAULT_GRADE_THRESHOLDS,
    DISPLAY_FORMATS,
    DRIVER_LABELS,
    DRIVER_ORDER,
    ExecScoreConfig,
    canonicalize_config,
    load_exec_score_config,
)


def get_exec_score_overrides(tenant_id: str) -> dict[str, Any]:
    """Return the persisted (canonicalized) override for a tenant, or ``{}``."""
    raw = _get_tenant_score_config_store().get(tenant_id)
    if not isinstance(raw, dict) or not raw:
        return {}
    return canonicalize_config(raw)


def resolve_exec_score_config(tenant_id: str) -> ExecScoreConfig:
    """Resolve the effective config (defaults < env < persisted override)."""
    overrides = _get_tenant_score_config_store().get(tenant_id)
    return load_exec_score_config(overrides if isinstance(overrides, dict) else None)


def set_exec_score_config(tenant_id: str, updates: Mapping[str, Any]) -> dict[str, Any]:
    """Merge + canonicalize an override update and persist it.

    Never raises on bad input — :func:`canonicalize_config` clamps/normalizes.
    Only the fields present in ``updates`` change; the rest of the existing
    override is preserved.
    """
    current = _get_tenant_score_config_store().get(tenant_id)
    merged: dict[str, Any] = dict(current) if isinstance(current, dict) else {}
    if isinstance(updates.get("weights"), Mapping):
        base_weights = dict(merged.get("weights") or {}) if isinstance(merged.get("weights"), Mapping) else {}
        base_weights.update(updates["weights"])
        merged["weights"] = base_weights
    thresholds = updates.get("grade_thresholds") or updates.get("thresholds")
    if isinstance(thresholds, Mapping):
        base_thresholds = dict(merged.get("grade_thresholds") or {}) if isinstance(merged.get("grade_thresholds"), Mapping) else {}
        base_thresholds.update(thresholds)
        merged["grade_thresholds"] = base_thresholds
    if updates.get("display_format") is not None:
        merged["display_format"] = updates["display_format"]

    canonical = canonicalize_config(merged)
    _get_tenant_score_config_store().put(tenant_id, canonical)
    return canonical


def clear_exec_score_config(tenant_id: str) -> bool:
    """Remove a tenant's exec-score overrides (revert to defaults)."""
    return _get_tenant_score_config_store().delete(tenant_id)


def exec_score_config_runtime(tenant_id: str) -> dict[str, Any]:
    """Operator-facing config surface: defaults, overrides, and effective config."""
    overrides = get_exec_score_overrides(tenant_id)
    effective = resolve_exec_score_config(tenant_id)
    drivers = [
        {
            "driver": driver,
            "label": DRIVER_LABELS[driver],
            "default_weight": DEFAULT_EXEC_SCORE_WEIGHTS[driver],
            "weight": float(effective.weights.get(driver, DEFAULT_EXEC_SCORE_WEIGHTS[driver])),
            "overridden": bool(overrides.get("weights", {}).get(driver) is not None)
            if isinstance(overrides.get("weights"), dict)
            else False,
        }
        for driver in DRIVER_ORDER
    ]
    return {
        "active_override": bool(overrides),
        "source": effective.source,
        "override_endpoint": "/v1/overview/score-config",
        "display_format": effective.display_format,
        "display_formats": list(DISPLAY_FORMATS),
        "weights": dict(effective.weights),
        "grade_thresholds": dict(effective.grade_thresholds),
        "drivers": drivers,
        "defaults": {
            "weights": dict(DEFAULT_EXEC_SCORE_WEIGHTS),
            "grade_thresholds": dict(DEFAULT_GRADE_THRESHOLDS),
            "display_format": DEFAULT_DISPLAY_FORMAT,
        },
        "overrides": overrides,
        "message": (
            "Exec risk-score model resolves from tenant overrides layered on the documented defaults."
            if overrides
            else (
                "Exec risk-score model resolves from the documented defaults. "
                "Customize weights, grade thresholds, or display format per tenant."
            )
        ),
    }
