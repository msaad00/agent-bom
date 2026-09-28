"""Topology-preserving redaction for linked machine-readable documents."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from agent_bom.output.finding_views import sanitize_output_text, with_output_sanitizer_cache

_DEFINITION_KEYS = frozenset({"@id", "SPDXID", "bom-ref", "id", "ruleId", "spdxId"})


def _collect_ids(value: object, raw_ids: list[str]) -> list[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in _DEFINITION_KEYS and isinstance(item, str):
                raw_ids.append(item)
            _collect_ids(item, raw_ids)
    elif isinstance(value, list | tuple):
        for item in value:
            _collect_ids(item, raw_ids)
    return raw_ids


def _projector(trusted_ids: re.Pattern[str] | None) -> Callable[[str], str]:
    if trusted_ids is None:
        return sanitize_output_text

    def project(text: str) -> str:
        return text if trusted_ids.fullmatch(text) is not None else sanitize_output_text(text)

    return project


def _linked_id_map(raw_ids: list[str], project: Callable[[str], str]) -> dict[str, str]:
    id_map: dict[str, str] = {}
    used_ids: set[str] = set()
    for raw_id in raw_ids:
        if raw_id in id_map:
            continue
        candidate = project(raw_id)
        if candidate in used_ids:
            suffix = 2
            while f"{candidate}#{suffix}" in used_ids:
                suffix += 1
            candidate = f"{candidate}#{suffix}"
        id_map[raw_id] = candidate
        used_ids.add(candidate)
    return id_map


@with_output_sanitizer_cache
def sanitize_linked_document(document: dict[str, Any], *, trusted_ids: re.Pattern[str] | None = None) -> dict[str, Any]:
    """Redact a document while keeping distinct IDs and references aligned.

    ``trusted_ids`` lets an exporter exempt identifiers it minted itself from
    per-string redaction. Only strings that *fully* match the pattern skip the
    detectors, so the pattern must admit no caller-supplied text.
    """
    project = _projector(trusted_ids)
    id_map = _linked_id_map(_collect_ids(document, []), project)

    def sanitize(value: object) -> object:
        if isinstance(value, str):
            # References and definitions must use the same collision-safe
            # projection.  Applying the map here avoids building a fully
            # sanitized document and then walking the whole structure again
            # solely to restore linked identifiers.
            return id_map[value] if value in id_map else project(value)
        if isinstance(value, dict):
            return {str(key): sanitize(item) for key, item in value.items()}
        if isinstance(value, list):
            return [sanitize(item) for item in value]
        if isinstance(value, tuple):
            return tuple(sanitize(item) for item in value)
        return value

    sanitized_document = sanitize(document)
    return sanitized_document if isinstance(sanitized_document, dict) else {}
