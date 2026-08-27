"""Topology-preserving redaction for linked machine-readable documents."""

from __future__ import annotations

from typing import Any

from agent_bom.output.finding_views import sanitize_output_text, with_output_sanitizer_cache

_DEFINITION_KEYS = frozenset({"@id", "SPDXID", "bom-ref", "id", "ruleId", "spdxId"})


@with_output_sanitizer_cache
def sanitize_linked_document(document: dict[str, Any]) -> dict[str, Any]:
    """Redact a document while keeping distinct IDs and references aligned."""
    raw_ids: list[str] = []

    def collect(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in _DEFINITION_KEYS and isinstance(item, str):
                    raw_ids.append(item)
                collect(item)
        elif isinstance(value, list | tuple):
            for item in value:
                collect(item)

    collect(document)
    id_map: dict[str, str] = {}
    used_ids: set[str] = set()
    for raw_id in raw_ids:
        if raw_id in id_map:
            continue
        candidate = sanitize_output_text(raw_id)
        if candidate in used_ids:
            suffix = 2
            while f"{candidate}#{suffix}" in used_ids:
                suffix += 1
            candidate = f"{candidate}#{suffix}"
        id_map[raw_id] = candidate
        used_ids.add(candidate)

    def sanitize(value: object) -> object:
        if isinstance(value, str):
            # References and definitions must use the same collision-safe
            # projection.  Applying the map here avoids building a fully
            # sanitized document and then walking the whole structure again
            # solely to restore linked identifiers.
            return id_map.get(value, sanitize_output_text(value))
        if isinstance(value, dict):
            return {str(key): sanitize(item) for key, item in value.items()}
        if isinstance(value, list):
            return [sanitize(item) for item in value]
        if isinstance(value, tuple):
            return tuple(sanitize(item) for item in value)
        return value

    sanitized_document = sanitize(document)
    return sanitized_document if isinstance(sanitized_document, dict) else {}
