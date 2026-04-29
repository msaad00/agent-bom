"""Sanitized discovery provenance for canonical assets."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any

from agent_bom.security import sanitize_log_label

DISCOVERY_SOURCE_TYPES = frozenset(
    {
        "direct_cloud_pull",
        "operator_pushed_inventory",
        "skill_invoked_pull",
        "local_discovery",
        "registry_fallback",
        "sbom_ingest",
        "external_scan",
        "filesystem_scan",
        "image_scan",
        "unknown",
    }
)

_STRING_FIELDS = (
    "source",
    "collector",
    "provider",
    "service",
    "resource_type",
    "resource_id",
    "resource_name",
    "location",
    "confidence",
    "version_source",
)
_SENSITIVE_VALUE_RE = re.compile(r"(token|password|secret|api[_-]?key|credential|bearer|jwt)[^\s]*\s*[:=]", re.IGNORECASE)
_URL_USERINFO_RE = re.compile(r"://[^/\s:@]+:[^@/\s]+@")


@dataclass
class DiscoveryProvenance:
    """Low-risk discovery provenance contract shared by Agent/Package assets."""

    source_type: str
    observed_via: list[str] = field(default_factory=list)
    source: str | None = None
    collector: str | None = None
    provider: str | None = None
    service: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    resource_name: str | None = None
    location: str | None = None
    confidence: str | None = None
    resolved_from_registry: bool | None = None
    version_source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return sanitize_discovery_provenance(self) or {}


def sanitize_discovery_provenance(value: Any, defaults: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Return a bounded, JSON-safe provenance payload.

    Explicit values override defaults, but all fields pass through the same
    allowlist and string redaction before leaving the model layer.
    """
    raw: dict[str, Any] = {}
    if defaults:
        raw.update(defaults)
    raw.update(_coerce_mapping(value))
    if not raw:
        return None

    source_type = _sanitize_string(raw.get("source_type") or raw.get("type") or "unknown", max_len=64)
    if source_type not in DISCOVERY_SOURCE_TYPES:
        source_type = "unknown"

    result: dict[str, Any] = {"source_type": source_type}
    observed_via = _sanitize_string_list(raw.get("observed_via") or raw.get("sources") or [])
    if observed_via:
        result["observed_via"] = observed_via

    for field_name in _STRING_FIELDS:
        value = _sanitize_string(raw.get(field_name))
        if value:
            result[field_name] = value

    for field_name in ("resolved_from_registry",):
        if raw.get(field_name) is not None:
            result[field_name] = bool(raw.get(field_name))

    return {key: val for key, val in result.items() if val not in (None, "", [])}


def agent_discovery_provenance(agent: Any) -> dict[str, Any] | None:
    """Build sanitized Agent discovery provenance from explicit or inferred data."""
    metadata = getattr(agent, "metadata", {}) or {}
    if not isinstance(metadata, dict):
        metadata = {}
    explicit = getattr(agent, "discovery_provenance", None) or metadata.get("discovery_provenance")
    source = getattr(agent, "source", None)
    cloud_origin = metadata.get("cloud_origin")
    defaults: dict[str, Any]
    if isinstance(cloud_origin, dict):
        defaults = {
            "source_type": "direct_cloud_pull",
            "observed_via": ["cloud_pull"],
            "source": source,
            "provider": cloud_origin.get("provider"),
            "service": cloud_origin.get("service"),
            "resource_type": cloud_origin.get("resource_type"),
            "resource_id": cloud_origin.get("resource_id"),
            "resource_name": cloud_origin.get("resource_name"),
            "location": cloud_origin.get("location"),
            "confidence": "high",
        }
    else:
        source_text = str(source or "").lower()
        if "skill" in source_text:
            source_type = "skill_invoked_pull"
            observed_via = ["skill_invoked_pull"]
        elif source_text and any(token in source_text for token in ("inventory", "cmdb", "fleet")):
            source_type = "operator_pushed_inventory"
            observed_via = ["operator_inventory"]
        else:
            source_type = "local_discovery"
            observed_via = ["local_discovery"]
        defaults = {
            "source_type": source_type,
            "observed_via": observed_via,
            "source": source,
            "confidence": "medium" if source_type == "local_discovery" else "high",
        }
    return sanitize_discovery_provenance(explicit, defaults=defaults)


def package_discovery_provenance(package: Any, inherited: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Build sanitized Package discovery provenance from explicit/current fields."""
    explicit = getattr(package, "discovery_provenance", None)
    inherited = sanitize_discovery_provenance(inherited) or {}
    defaults: dict[str, Any] = {
        key: inherited[key]
        for key in ("source_type", "observed_via", "source", "provider", "service", "location", "confidence")
        if key in inherited
    }
    version_source = getattr(package, "version_source", None)
    resolved_from_registry = bool(getattr(package, "resolved_from_registry", False))
    if version_source == "registry_fallback":
        defaults.update(
            {
                "source_type": "registry_fallback",
                "observed_via": _merge_observed_via(defaults.get("observed_via"), ["registry_fallback"]),
                "source": "bundled_registry",
                "resolved_from_registry": True,
                "version_source": version_source,
                "confidence": "medium",
            }
        )
    elif resolved_from_registry or version_source:
        defaults.update(
            {
                "resolved_from_registry": resolved_from_registry,
                "version_source": version_source,
            }
        )
    return sanitize_discovery_provenance(explicit, defaults=defaults)


def _coerce_mapping(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, DiscoveryProvenance):
        return asdict(value)
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, dict):
        return dict(value)
    return {}


def _sanitize_string(value: Any, *, max_len: int = 256) -> str:
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return ""
    text = sanitize_log_label(value, max_len=max_len)
    if not text:
        return ""
    if _SENSITIVE_VALUE_RE.search(text) or _URL_USERINFO_RE.search(text):
        return "<redacted>"
    return text


def _sanitize_string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple, set)):
        values = list(value)
    else:
        values = []

    result: list[str] = []
    seen: set[str] = set()
    for item in values:
        safe = _sanitize_string(item, max_len=96)
        if safe and safe not in seen:
            seen.add(safe)
            result.append(safe)
    return result[:10]


def _merge_observed_via(existing: Any, extra: list[str]) -> list[str]:
    return _sanitize_string_list([*_sanitize_string_list(existing), *extra])
