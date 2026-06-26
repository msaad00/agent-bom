"""Input → scanner-driver router.

A pure resolver: given an input descriptor (type and optional source — path,
image ref, cloud credential, MCP config, ingested SARIF, ...), return the
registered scanner drivers that declare they accept it, by consulting the
``input_types`` metadata in :mod:`agent_bom.scanners.registry`.

Scope of this PR: this module centralizes the input→driver *mapping* conceptually
and is the seam a later PR will route callers through. Selection logic currently
split across the CLI, ``api/pipeline.py``, and ``scanners/__init__.py`` is NOT
changed here — nothing in the scan path imports this module yet.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_bom.scanners.base import ScannerRegistration
from agent_bom.scanners.registry import list_registered_scanners


@dataclass(frozen=True)
class InputDescriptor:
    """A unit of work to route: an input type plus an optional opaque source."""

    input_type: str
    source: str | None = None


def _normalize(input_type: str) -> str:
    return input_type.strip().lower()


def resolve_scanners(input_type: str, *, include_planned: bool = False) -> list[ScannerRegistration]:
    """Return scanner drivers whose ``input_types`` declare ``input_type``.

    Matching is case-insensitive and order-stable (registry sort order, by name).
    Planned (roadmap-slot) drivers are excluded unless ``include_planned`` is set.
    """

    normalized = _normalize(input_type)
    if not normalized:
        return []
    return [
        registration
        for registration in list_registered_scanners(include_planned=include_planned)
        if normalized in {value.lower() for value in registration.input_types}
    ]


def resolve_input(descriptor: InputDescriptor, *, include_planned: bool = False) -> list[ScannerRegistration]:
    """Resolve an :class:`InputDescriptor` to its scanner drivers."""

    return resolve_scanners(descriptor.input_type, include_planned=include_planned)


def known_input_types(*, include_planned: bool = True) -> set[str]:
    """Return the set of input types any registered scanner driver accepts."""

    types: set[str] = set()
    for registration in list_registered_scanners(include_planned=include_planned):
        types.update(value.lower() for value in registration.input_types)
    return types


def can_route(input_type: str, *, include_planned: bool = False) -> bool:
    """Return True when at least one driver handles ``input_type``."""

    return bool(resolve_scanners(input_type, include_planned=include_planned))


def route_table(*, include_planned: bool = True) -> dict[str, list[str]]:
    """Return an ``input_type -> [driver name, ...]`` map for read surfaces."""

    table: dict[str, list[str]] = {}
    for registration in list_registered_scanners(include_planned=include_planned):
        for value in registration.input_types:
            table.setdefault(value.lower(), []).append(registration.name)
    return {key: sorted(set(value)) for key, value in sorted(table.items())}


__all__ = [
    "InputDescriptor",
    "can_route",
    "known_input_types",
    "resolve_input",
    "resolve_scanners",
    "route_table",
]
