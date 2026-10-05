"""Version eligibility shared by advisory lookup paths."""

from __future__ import annotations

from agent_bom.core.versions.ruby import _gem_canonical_segments
from agent_bom.models import Package


def is_unresolved_version(version: object, ecosystem: str = "") -> bool:
    """Return whether *version* is a floating or missing package coordinate.

    SBOM producers do not agree on sentinel casing (Syft commonly emits
    ``UNKNOWN``). Advisory matching must never treat those sentinels as real
    versions: range parsers can otherwise fail open and attach every advisory
    for the package name.
    """

    if ecosystem.lower() in {"rubygems", "gem"} and _gem_canonical_segments(str(version or "")) is None:
        return True  # An artifact platform suffix is not a Gem::Version.
    return str(version or "").strip().lower() in {"", "*", "latest", "unknown"}


def is_unresolved_package(pkg: Package) -> bool:
    return is_unresolved_version(pkg.version, pkg.ecosystem)
