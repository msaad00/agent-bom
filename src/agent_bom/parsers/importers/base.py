"""Scanner importer contract: transparency manifest, result type, protocol.

An importer turns one third-party report that is already on disk into the
canonical evidence model: real packages (dependency evidence) and unified
``Finding`` objects. Importers never execute the producing tool, never reach
the network, and never need credentials; the manifest states that contract so
operators can audit each importer before trusting its output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from agent_bom.models import Package

if TYPE_CHECKING:
    from agent_bom.finding import Finding


@dataclass(frozen=True)
class ImporterManifest:
    """Declared behavior of one importer, published with every registration.

    ``credentials_required`` is ``None`` for file-based importers; a non-empty
    tuple names the credential an importer would need. ``network_access`` must
    be ``False`` for built-in importers. ``data_retained`` states which input
    fields survive into findings; ``default_filters`` states which records are
    skipped unless the operator changes the producing tool's own filters.
    """

    name: str
    display_name: str
    tool: str
    formats: tuple[str, ...]
    detection: str
    data_retained: str
    default_filters: str = ""
    credentials_required: tuple[str, ...] | None = None
    network_access: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "tool": self.tool,
            "formats": list(self.formats),
            "detection": self.detection,
            "credentials_required": list(self.credentials_required) if self.credentials_required else None,
            "network_access": self.network_access,
            "data_retained": self.data_retained,
            "default_filters": self.default_filters,
        }


@dataclass
class ExternalScanImport:
    """Everything one external report contributes to a scan.

    ``packages`` carry real package identities (dependency evidence);
    ``findings`` carry code-level results, cloud posture results, and
    dependency results whose package could not be resolved. Neither side
    invents package coordinates.
    """

    format: str
    packages: list[Package] = field(default_factory=list)
    findings: list["Finding"] = field(default_factory=list)
    tool_names: list[str] = field(default_factory=list)
    is_sbom: bool = False
    notices: list[str] = field(default_factory=list)


@runtime_checkable
class ScannerImporter(Protocol):
    """A file-based report importer.

    ``sniff`` must be cheap, side-effect free, and return ``False`` for any
    shape it does not own. ``parse`` raises ``ValueError`` for malformed input
    and treats every field as untrusted.
    """

    manifest: ImporterManifest

    def sniff(self, data: object) -> bool: ...

    def parse(self, data: object) -> ExternalScanImport: ...
