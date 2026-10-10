"""Scanner importer registry.

Built-in importers (Prowler JSON-OCSF, AWS Security Hub ASFF) are always
available. Third-party packages can add importers through the
``agent_bom.importers`` entry-point group; those load only when
``AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS`` is set, run after every built-in
format, and cannot replace a built-in name. See ``docs/IMPORTERS.md``.
"""

from __future__ import annotations

import re
from typing import Any

from agent_bom.extensions import iter_entry_point_registrations, sanitize_registry_warning
from agent_bom.finding import Finding
from agent_bom.parsers.importers.base import ExternalScanImport, ImporterManifest, ScannerImporter
from agent_bom.parsers.importers.prowler import ProwlerImporter
from agent_bom.parsers.importers.securityhub import SecurityHubImporter

IMPORTERS_ENTRY_POINT_GROUP = "agent_bom.importers"
MAX_IMPORTER_ENTRY_POINTS = 32
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
# Exceptions a third-party ``sniff`` may raise on unexpected shapes. Anything
# else is a programming error in the plugin and propagates.
_SNIFF_ERRORS = (ValueError, TypeError, KeyError, AttributeError, IndexError)

_REGISTRY: dict[str, ScannerImporter] = {}
_WARNINGS: list[str] = []
_LOADED = False


def builtin_importers() -> list[ScannerImporter]:
    """Return the importers that ship with agent-bom."""
    return [ProwlerImporter(), SecurityHubImporter()]


def _coerce_importer(value: Any, entry_point_name: str) -> ScannerImporter:
    if not isinstance(value, ScannerImporter) or not isinstance(value.manifest, ImporterManifest):
        raise ValueError(f"importer {entry_point_name} must expose an ImporterManifest plus sniff() and parse()")
    if not _NAME_RE.match(value.manifest.name):
        raise ValueError(f"importer {entry_point_name} has an invalid manifest name")
    return value


def _ensure_loaded() -> None:
    global _LOADED
    if _LOADED:
        return
    for importer in builtin_importers():
        _REGISTRY[importer.manifest.name] = importer
    for importer in iter_entry_point_registrations(
        group=IMPORTERS_ENTRY_POINT_GROUP,
        coerce=_coerce_importer,
        warnings=_WARNINGS,
        max_entry_points=MAX_IMPORTER_ENTRY_POINTS,
    ):
        if importer.manifest.name in _REGISTRY:
            _WARNINGS.append(sanitize_registry_warning(f"Importer {importer.manifest.name} is already registered; keeping the first"))
            continue
        _REGISTRY[importer.manifest.name] = importer
    _LOADED = True


def list_importers() -> list[ScannerImporter]:
    """Return registered importers in detection order (built-ins first)."""
    _ensure_loaded()
    return list(_REGISTRY.values())


def importer_manifests() -> list[dict[str, Any]]:
    """Return every registered importer's transparency manifest."""
    return [importer.manifest.to_dict() for importer in list_importers()]


def importer_registry_warnings() -> list[str]:
    _ensure_loaded()
    return list(_WARNINGS)


def get_importer(name: str) -> ScannerImporter | None:
    _ensure_loaded()
    return _REGISTRY.get(name)


def detect_importer(data: object) -> ScannerImporter | None:
    """Return the first registered importer whose ``sniff`` claims *data*."""
    for importer in list_importers():
        try:
            if importer.sniff(data):
                return importer
        except _SNIFF_ERRORS as exc:
            _WARNINGS.append(sanitize_registry_warning(f"Importer {importer.manifest.name} sniff failed: {exc}"))
    return None


def import_registered_report(data: object, *, supported_hint: str) -> ExternalScanImport:
    """Parse *data* with the matching registered importer.

    Raises:
        ValueError: when no importer claims the input, or the input is malformed.
    """
    importer = detect_importer(data)
    if importer is None:
        raise ValueError(f"Unrecognized scanner JSON format; expected {supported_hint}")
    imported = importer.parse(data)
    if not isinstance(imported, ExternalScanImport):
        raise ValueError(f"importer {importer.manifest.name} returned an unsupported result")
    imported.findings = [finding for finding in imported.findings if isinstance(finding, Finding)]
    return imported


def _reset_importer_registry_for_tests() -> None:
    global _LOADED
    _REGISTRY.clear()
    _WARNINGS.clear()
    _LOADED = False


__all__ = [
    "IMPORTERS_ENTRY_POINT_GROUP",
    "ExternalScanImport",
    "ImporterManifest",
    "ScannerImporter",
    "builtin_importers",
    "detect_importer",
    "get_importer",
    "import_registered_report",
    "importer_manifests",
    "importer_registry_warnings",
    "list_importers",
]
