"""Canonical config-drift attribute comparison for graph snapshot diffs (#3192)."""

from __future__ import annotations

import json
from typing import Any

_DRIFT_ATTRIBUTE_KEYS = (
    "internet_exposed",
    "encryption_at_rest",
    "encryption_in_transit",
    "iam_policy_arn",
    "iam_role_arn",
)

_SCALAR_DIFF_FIELDS = (
    "entity_type",
    "label",
    "status",
    "severity",
    "severity_id",
    "risk_score",
)


def _normalize_tags(tags: Any) -> list[str]:
    if not tags:
        return []
    if isinstance(tags, str):
        try:
            parsed = json.loads(tags)
        except json.JSONDecodeError:
            return [tags]
        return _normalize_tags(parsed)
    if isinstance(tags, (list, tuple, set)):
        return sorted(str(tag) for tag in tags)
    return [str(tags)]


def _normalize_attributes(raw: Any) -> dict[str, Any]:
    if not raw:
        return {}
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return dict(raw) if isinstance(raw, dict) else {}


def node_diff_metadata(
    *,
    node_id: str,
    entity_type: str,
    label: str,
    status: str,
    severity: str,
    severity_id: int,
    risk_score: float,
    attributes: Any = None,
    compliance_tags: Any = None,
) -> dict[str, Any]:
    """Normalized node metadata used by snapshot diff."""
    return {
        "id": node_id,
        "entity_type": entity_type,
        "label": label,
        "status": status or "",
        "severity": severity or "",
        "severity_id": int(severity_id or 0),
        "risk_score": float(risk_score or 0.0),
        "attributes": _normalize_attributes(attributes),
        "compliance_tags": _normalize_tags(compliance_tags),
    }


def _scalar_projection(meta: dict[str, Any]) -> dict[str, Any]:
    return {field: meta.get(field) for field in _SCALAR_DIFF_FIELDS}


def _drift_value(meta: dict[str, Any], field: str) -> Any:
    if field == "compliance_tags":
        return meta.get("compliance_tags") or []
    return meta.get("attributes", {}).get(field)


def summarize_attribute_delta(field: str, before: Any, after: Any) -> str:
    """Human-readable one-liner for drift legend chips."""
    if field == "internet_exposed":
        if before is False and after is True:
            return "Public exposure opened"
        if before is True and after is False:
            return "Public exposure closed"
        return "Public exposure changed"
    if field == "encryption_at_rest":
        if before is True and after is False:
            return "Encryption at rest disabled"
        if before is False and after is True:
            return "Encryption at rest enabled"
        return "Encryption at rest changed"
    if field == "encryption_in_transit":
        if before is True and after is False:
            return "Encryption in transit disabled"
        if before is False and after is True:
            return "Encryption in transit enabled"
        return "Encryption in transit changed"
    if field.startswith("iam_"):
        return "IAM attachment changed"
    if field == "compliance_tags":
        return "Compliance tags changed"
    return f"{field} changed"


def attribute_deltas(old_meta: dict[str, Any], new_meta: dict[str, Any]) -> list[dict[str, Any]]:
    """Return canonical attribute deltas between two node snapshots."""
    deltas: list[dict[str, Any]] = []
    for field in _DRIFT_ATTRIBUTE_KEYS:
        before = _drift_value(old_meta, field)
        after = _drift_value(new_meta, field)
        if before == after:
            continue
        deltas.append(
            {
                "field": field,
                "before": before,
                "after": after,
                "summary": summarize_attribute_delta(field, before, after),
            }
        )

    old_tags = _drift_value(old_meta, "compliance_tags")
    new_tags = _drift_value(new_meta, "compliance_tags")
    if old_tags != new_tags:
        deltas.append(
            {
                "field": "compliance_tags",
                "before": old_tags,
                "after": new_tags,
                "summary": summarize_attribute_delta("compliance_tags", old_tags, new_tags),
            }
        )
    return deltas


def node_snapshot_changed(old_meta: dict[str, Any], new_meta: dict[str, Any]) -> bool:
    """True when scalar fields or canonical attribute deltas differ."""
    if _scalar_projection(old_meta) != _scalar_projection(new_meta):
        return True
    return bool(attribute_deltas(old_meta, new_meta))
