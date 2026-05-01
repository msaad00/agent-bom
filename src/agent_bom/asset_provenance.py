"""Sanitized discovery provenance for canonical assets."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any

from agent_bom.security import sanitize_log_label, sanitize_path_label, sanitize_url

PACKAGE_VERSION_SOURCES = frozenset(
    {
        "runtime_process",
        "image_sbom",
        "installed_package",
        "tool_cache",
        "lockfile",
        "command_pin",
        "registry_latest",
        "unknown",
    }
)
PACKAGE_VERSION_CONFIDENCE = frozenset({"exact", "high", "medium", "low", "unknown"})
_VERSION_SOURCE_ALIASES = {
    "registry_fallback": "registry_latest",
    "registry": "registry_latest",
    "latest": "registry_latest",
    "sbom_ingest": "image_sbom",
    "image_scan": "image_sbom",
    "filesystem_scan": "installed_package",
    "node_modules": "installed_package",
    "installed": "installed_package",
    "cache": "tool_cache",
    "npm_cache": "tool_cache",
    "uv_cache": "tool_cache",
    "manifest": "command_pin",
    "pinned": "command_pin",
    "pin": "command_pin",
}
_VERSION_SOURCE_CONFIDENCE = {
    "runtime_process": "exact",
    "image_sbom": "exact",
    "installed_package": "exact",
    "tool_cache": "high",
    "lockfile": "exact",
    "command_pin": "exact",
    "registry_latest": "low",
    "unknown": "unknown",
}
_VERSION_SOURCE_PRECEDENCE = {
    "runtime_process": 80,
    "image_sbom": 70,
    "installed_package": 60,
    "tool_cache": 50,
    "lockfile": 40,
    "command_pin": 30,
    "registry_latest": 20,
    "unknown": 0,
}

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
_VERSION_PROVENANCE_STRING_FIELDS = (
    "declared_name",
    "declared_version",
    "resolved_version",
    "version_source",
    "confidence",
    "observed_at",
    "version_resolved_at",
    "legacy_version_source",
)
_VERSION_EVIDENCE_STRING_FIELDS = (
    "type",
    "path",
    "source_file",
    "parser",
    "sha256",
    "url",
    "process_id",
    "container_image",
    "sbom_ref",
    "package_path",
)
_VERSION_EVIDENCE_PATH_FIELDS = frozenset({"path", "source_file", "package_path"})
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


def normalize_package_version_source(value: Any, *, resolved_from_registry: bool = False) -> str:
    """Return the canonical package version source enum.

    Legacy parser values are accepted on input so older scanners can keep
    emitting them while downstream surfaces receive the ADR-007 contract.
    """
    raw = _sanitize_string(value, max_len=64).lower().replace("-", "_")
    if not raw:
        return "registry_latest" if resolved_from_registry else "unknown"
    source = _VERSION_SOURCE_ALIASES.get(raw, raw)
    if source == "detected":
        return "registry_latest" if resolved_from_registry else "unknown"
    if source not in PACKAGE_VERSION_SOURCES:
        return "unknown"
    return source


def normalize_package_version_confidence(value: Any, *, version_source: str = "unknown") -> str:
    """Return the canonical confidence enum for a package version source."""
    raw = _sanitize_string(value, max_len=32).lower().replace("-", "_")
    if raw in PACKAGE_VERSION_CONFIDENCE:
        return raw
    return _VERSION_SOURCE_CONFIDENCE.get(version_source, "unknown")


def package_version_provenance(package: Any, inherited: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build structured package version provenance for scanner/API/graph use."""
    explicit_discovery = _coerce_mapping(_field(package, "discovery_provenance"))
    explicit = _coerce_mapping(explicit_discovery.get("version_provenance"))
    inherited = sanitize_discovery_provenance(inherited) or {}

    resolved_from_registry = bool(
        _field(package, "resolved_from_registry", False)
        or explicit.get("resolved_from_registry")
        or explicit_discovery.get("resolved_from_registry")
    )
    legacy_version_source = explicit.get("version_source") or explicit_discovery.get("version_source") or _field(package, "version_source")
    version_source = normalize_package_version_source(
        explicit.get("version_source") or legacy_version_source,
        resolved_from_registry=resolved_from_registry,
    )
    confidence = normalize_package_version_confidence(
        explicit.get("confidence") or _field(package, "version_confidence"),
        version_source=version_source,
    )
    resolved_version = (
        explicit.get("resolved_version") or _field(package, "resolved_version") or _resolved_package_version(_field(package, "version"))
    )
    declared_version = explicit.get("declared_version") or _field(package, "declared_version")
    if not declared_version and _field(package, "floating_reference", False):
        declared_version = _field(package, "registry_version") or _field(package, "version")

    result: dict[str, Any] = {
        "declared_name": explicit.get("declared_name") or _field(package, "name"),
        "declared_version": declared_version,
        "resolved_version": resolved_version,
        "version_source": version_source,
        "confidence": confidence,
        "observed_at": explicit.get("observed_at") or inherited.get("observed_at"),
        "version_resolved_at": explicit.get("version_resolved_at") or _field(package, "version_resolved_at"),
        "resolved_from_registry": resolved_from_registry,
        "source_precedence": _VERSION_SOURCE_PRECEDENCE[version_source],
    }
    canonical_legacy_source = normalize_package_version_source(
        legacy_version_source,
        resolved_from_registry=resolved_from_registry,
    )
    if legacy_version_source and canonical_legacy_source != legacy_version_source:
        result["legacy_version_source"] = str(legacy_version_source)
    if _field(package, "floating_reference", False):
        result["floating_reference"] = True
        if _field(package, "floating_reference_reason"):
            result["floating_reference_reason"] = _field(package, "floating_reference_reason")

    evidence = _sanitize_version_evidence_list(
        explicit.get("evidence") or _field(package, "version_evidence") or _occurrence_version_evidence(package)
    )
    if evidence:
        result["evidence"] = evidence

    conflicts = _sanitize_version_conflicts(explicit.get("version_conflicts") or _field(package, "version_conflicts"))
    if conflicts:
        result["version_conflicts"] = conflicts

    sanitized = _sanitize_version_provenance(result)
    return sanitized or {"version_source": "unknown", "confidence": "unknown", "source_precedence": 0}


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
    provenance = sanitize_discovery_provenance(explicit, defaults=defaults)
    if not provenance:
        provenance = {}
    provenance["version_provenance"] = package_version_provenance(package, inherited=inherited)
    return provenance


def _resolved_package_version(value: Any) -> str | None:
    text = _sanitize_string(value, max_len=128)
    if text and text not in {"latest", "unknown", "*"}:
        return text
    return None


def _sanitize_version_provenance(value: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for field_name in _VERSION_PROVENANCE_STRING_FIELDS:
        field_value = _sanitize_string(value.get(field_name), max_len=256)
        if field_value:
            result[field_name] = field_value

    result["version_source"] = normalize_package_version_source(result.get("version_source") or value.get("version_source"))
    result["confidence"] = normalize_package_version_confidence(result.get("confidence"), version_source=result["version_source"])

    for field_name in ("resolved_from_registry", "floating_reference"):
        if value.get(field_name) is not None:
            result[field_name] = bool(value.get(field_name))

    precedence = value.get("source_precedence")
    if isinstance(precedence, int):
        result["source_precedence"] = precedence
    else:
        result["source_precedence"] = _VERSION_SOURCE_PRECEDENCE[result["version_source"]]

    evidence = _sanitize_version_evidence_list(value.get("evidence"))
    if evidence:
        result["evidence"] = evidence

    conflicts = _sanitize_version_conflicts(value.get("version_conflicts"))
    if conflicts:
        result["version_conflicts"] = conflicts

    return {key: val for key, val in result.items() if val not in (None, "", [])}


def _sanitize_version_evidence_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        values = [value]
    elif isinstance(value, (list, tuple)):
        values = list(value)
    else:
        values = []

    result: list[dict[str, Any]] = []
    for entry in values:
        raw = _coerce_mapping(entry)
        if not raw:
            continue
        item: dict[str, Any] = {}
        for field_name in _VERSION_EVIDENCE_STRING_FIELDS:
            safe = _sanitize_string(raw.get(field_name), max_len=256)
            if safe:
                if field_name in _VERSION_EVIDENCE_PATH_FIELDS:
                    safe = sanitize_path_label(safe)
                elif field_name == "url":
                    safe = sanitize_url(safe) or ""
                    if not safe:
                        continue
                item[field_name] = safe
        line = raw.get("line")
        if isinstance(line, int) and line > 0:
            item["line"] = line
        if item:
            result.append(item)
    return result[:10]


def _sanitize_version_conflicts(value: Any) -> list[dict[str, str]]:
    if isinstance(value, dict):
        values = [value]
    elif isinstance(value, (list, tuple)):
        values = list(value)
    else:
        values = []

    result: list[dict[str, str]] = []
    for entry in values:
        raw = _coerce_mapping(entry)
        source = normalize_package_version_source(raw.get("source") or raw.get("version_source"))
        version = _sanitize_string(raw.get("version"), max_len=128)
        if source != "unknown" and version:
            result.append({"source": source, "version": version})
    return result[:10]


def _occurrence_version_evidence(package: Any) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for occurrence in getattr(package, "occurrences", []) or []:
        raw = _coerce_mapping(occurrence)
        if raw:
            evidence.append(raw)
    return evidence


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


def _field(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


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
