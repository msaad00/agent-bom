"""Static installed Python runtime and distribution metadata recognition."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from agent_bom.oci_parser import _LayerScan


def _python_metadata_kind(member_name: str) -> str | None:
    if member_name.endswith(".dist-info/METADATA"):
        return "dist-info"
    if member_name.endswith(".egg-info/PKG-INFO") or member_name.endswith(".egg-info/METADATA"):
        return "egg-info"
    return None


def extract_cpython_runtime(scan: _LayerScan, read_member: Callable) -> None:
    """Inventory exact installed CPython header evidence without running binaries."""
    from agent_bom.oci_parser import _append_oci_warning

    for path in sorted(scan.names):
        if not re.fullmatch(r"(?:\./)?usr/local/include/python[0-9]+\.[0-9]+[a-z]*/patchlevel\.h", path) or scan.is_deleted(path):
            continue
        stream = read_member(scan.layer_tf, path)
        if stream is None:
            scan.gap(path)
            continue
        content = stream.read(65_537)
        match = re.search(rb'^\s*#\s*define\s+PY_VERSION\s+"([0-9]+\.[0-9]+\.[0-9]+(?:[a-z]+[0-9]+)?)"', content, re.MULTILINE)
        if len(content) > 65_536 or match is None:
            scan.gap(path)
            continue
        version = match[1].decode("ascii")
        scan.add(path, "cpython", version, "generic", f"pkg:generic/python/cpython@{version}")
        package = scan.packages_by_key[("cpython", "generic")]
        package.is_direct = None
        package.version_source = "installed_package"
        package.version_evidence = [{"type": "installed_metadata", "source_file": path}]
        if scan.warnings is not None and scan.coverage_warnings is not None:
            _append_oci_warning(
                scan.warnings,
                scan.coverage_warnings,
                path=path,
                reason="runtime_advisory_coverage_unknown",
                detail="CPython is inventoried from an installed header; version-verified runtime advisory coverage remains unknown.",
            )
