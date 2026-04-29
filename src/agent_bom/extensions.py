"""Shared extension registry primitives."""

from __future__ import annotations

import importlib.metadata as metadata
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from agent_bom.security import sanitize_error, sanitize_text

ENTRYPOINTS_ENABLED_ENV = "AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS"


@dataclass(frozen=True)
class ExtensionCapabilities:
    """Declared capabilities and boundaries for an extension."""

    scan_modes: tuple[str, ...] = ("inventory",)
    required_scopes: tuple[str, ...] = ()
    outbound_destinations: tuple[str, ...] = ()
    data_boundary: str = "agentless_read_only"
    writes: bool = False
    network_access: bool = False
    guarantees: tuple[str, ...] = ("read_only",)


@dataclass(frozen=True)
class RegistryEntry:
    """Common registry metadata for provider, connector, and parser extensions."""

    name: str
    module: str
    capabilities: ExtensionCapabilities = field(default_factory=ExtensionCapabilities)
    source: str = "builtin"
    discover_attr: str = "discover"


T = TypeVar("T")


def entrypoint_extensions_enabled() -> bool:
    """Return True when third-party entry-point loading is explicitly enabled."""

    value = os.getenv(ENTRYPOINTS_ENABLED_ENV, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def sanitize_registry_warning(value: object, *, max_len: int = 500) -> str:
    """Sanitize a registry loading diagnostic before it leaves the boundary."""

    return sanitize_text(sanitize_error(str(value)), max_len=max_len)


def _entry_points_for_group(group: str) -> Iterable[Any]:
    entry_points = metadata.entry_points()
    if hasattr(entry_points, "select"):
        return entry_points.select(group=group)
    return entry_points.get(group, ())


def _registration_payload(loaded: Any) -> Any:
    if isinstance(loaded, RegistryEntry):
        return loaded
    if hasattr(loaded, "name") and hasattr(loaded, "module"):
        return loaded
    if callable(loaded):
        return loaded()
    return loaded


def iter_entry_point_registrations(
    *,
    group: str,
    coerce: Callable[[Any, str], T],
    warnings: list[str],
) -> list[T]:
    """Load extension registrations from a Python entry-point group.

    Third-party loading is opt-in via ``AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS``.
    Failures are collected as sanitized warnings so built-ins remain usable.
    """

    if not entrypoint_extensions_enabled():
        return []

    try:
        entry_points = list(_entry_points_for_group(group))
    except Exception as exc:  # noqa: BLE001
        warnings.append(sanitize_registry_warning(f"Could not enumerate entry points for {group}: {exc}"))
        return []

    registrations: list[T] = []
    for entry_point in entry_points:
        entry_point_name = sanitize_text(getattr(entry_point, "name", "unknown"), max_len=120)
        try:
            loaded = entry_point.load()
            payload = _registration_payload(loaded)
            if isinstance(payload, Iterable) and not isinstance(payload, (str, bytes, RegistryEntry)):
                registrations.extend(coerce(item, entry_point_name) for item in payload)
            else:
                registrations.append(coerce(payload, entry_point_name))
        except Exception as exc:  # noqa: BLE001
            warnings.append(sanitize_registry_warning(f"Could not load entry point {entry_point_name} from {group}: {exc}"))
    return registrations
