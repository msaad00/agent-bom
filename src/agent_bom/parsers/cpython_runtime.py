"""Static installed Python runtime and distribution metadata recognition."""

from __future__ import annotations

import hashlib
import re
import tarfile
from typing import TYPE_CHECKING, Callable, Protocol

if TYPE_CHECKING:
    from agent_bom.models import Package


class _LayerIdentity(Protocol):
    @property
    def layer_id(self) -> str: ...


class _LayerScan(Protocol):
    """The slice of ``oci_parser._LayerScan`` the runtime stage uses; avoids an import cycle."""

    layer_tf: tarfile.TarFile
    names: set[str]
    packages_by_key: dict[tuple[str, str], Package]

    @property
    def layer(self) -> _LayerIdentity: ...

    def is_deleted(self, path: str) -> bool: ...

    def gap(self, path: str) -> None: ...

    def add(
        self, path: str, name: str, version: str, ecosystem: str, purl: str | None = None, *, source_package: str | None = None
    ) -> None: ...


def _python_metadata_kind(member_name: str) -> str | None:
    if member_name.endswith(".dist-info/METADATA"):
        return "dist-info"
    if member_name.endswith(".egg-info/PKG-INFO") or member_name.endswith(".egg-info/METADATA"):
        return "egg-info"
    return None


def extract_cpython_runtime(scan: _LayerScan, read_member: Callable) -> None:
    """Inventory exact installed CPython header evidence without running binaries."""
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
        previous = scan.packages_by_key.get(("cpython", "generic"))
        if previous and any(
            item.get("type") == "installed_metadata" and str(item.get("source_file", "")).removeprefix("./") != path.removeprefix("./")
            for item in previous.version_evidence
        ):
            # The package map has one slot per name/ecosystem. Do not present
            # a complete image assessment if it collapses multiple runtimes.
            scan.gap(path)
        scan.add(path, "cpython", version, "generic", f"pkg:generic/python/cpython@{version}")
        package = scan.packages_by_key[("cpython", "generic")]
        package.is_direct = None
        package.version_source = "installed_package"
        package.version_evidence = [{"type": "installed_metadata", "source_file": path}]
        # Header replacement invalidates earlier runtime-specific observations.
        package._cpython_source_hashes = {}  # type: ignore[attr-defined]
    _observe_runtime_source(scan, read_member)


def _observe_runtime_source(scan: _LayerScan, read_member: Callable) -> None:
    """Measure the effective module bytes; never trust imported hash claims."""
    from agent_bom.oci_parser import _layer_whiteouts

    package = scan.packages_by_key.get(("cpython", "generic"))
    if package is None:
        return
    branch = ".".join(package.version.split(".")[:2])
    path = f"usr/local/lib/python{branch}/tarfile.py"
    hashes = getattr(package, "_cpython_source_hashes", {})
    whiteouts = {name.removeprefix("./") for name in _layer_whiteouts(scan.names)}
    members = {member.name.removeprefix("./").rstrip("/"): member for member in scan.layer_tf.getmembers()}
    replaced = [members[path]] if path in members else []
    obscured = any(path.startswith(name + "/") and not member.isdir() for name, member in members.items())
    removed = any(path == name or path.startswith(name.rstrip("/") + "/") for name in whiteouts)
    if not replaced and not removed and not obscured:
        return
    hashes.pop(path, None)
    package.version_evidence = [
        item for item in package.version_evidence if not (item.get("type") == "runtime_source_sha256" and item.get("source_file") == path)
    ]
    # A whiteout removes lower layers only; a same-layer regular replacement
    # supplies the final bytes. Links and unreadable/oversized members invalidate
    # an earlier observation without asserting a new one.
    if replaced and replaced[-1].isfile() and not obscured:
        stream = read_member(scan.layer_tf, replaced[-1].name)
        if stream is not None:
            content = stream.read(1_000_001)
            if len(content) <= 1_000_000:
                digest = hashlib.sha256(content).hexdigest()
                hashes[path] = digest
                package.version_evidence.append(
                    {
                        "type": "runtime_source_sha256",
                        "source_file": path,
                        "sha256": digest,
                        "layer_id": scan.layer.layer_id,
                    }
                )
    package._cpython_source_hashes = hashes  # type: ignore[attr-defined]
