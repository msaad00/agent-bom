"""Current-state finding payload overlay + ledger hydration (#3487)."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

_OVERLAY_KEYS = ("origin", "batch_id", "scan_id", "source", "id", "canonical_id")


def resolve_ledger_finding_id(payload: Mapping[str, Any], *, canonical_id: str = "") -> str:
    """Return the ledger ``finding_id`` key for a hub finding payload."""
    explicit = payload.get("id") or payload.get("canonical_id") or canonical_id
    return str(explicit) if explicit else ""


def current_state_overlay(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Persist only filter/sort helper fields in current-state rows."""
    return {key: payload[key] for key in _OVERLAY_KEYS if key in payload and payload[key] is not None}


def is_overlay_only_payload(payload: Mapping[str, Any]) -> bool:
    if not payload:
        return True
    return set(payload.keys()).issubset(set(_OVERLAY_KEYS))


def hydrate_current_payload(
    row: Mapping[str, Any],
    *,
    ledger_payloads: Mapping[str, dict[str, Any]],
) -> dict[str, Any]:
    """Merge a current-state overlay with the canonical ledger payload."""
    overlay = dict(row.get("payload") or {})
    if not is_overlay_only_payload(overlay):
        return overlay
    finding_id = str(row.get("ledger_finding_id") or overlay.get("id") or "")
    if finding_id:
        base = ledger_payloads.get(finding_id)
        if base:
            merged = dict(base)
            merged.update(overlay)
            return merged
    return overlay


def batch_ledger_payloads(
    fetch: Callable[[Sequence[str]], Mapping[str, dict[str, Any]]],
    finding_ids: Iterable[str],
) -> dict[str, dict[str, Any]]:
    """Deduplicate finding ids before a ledger lookup."""
    unique = sorted({fid for fid in finding_ids if fid})
    if not unique:
        return {}
    return dict(fetch(unique))
