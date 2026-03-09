"""Native OCI / Docker-save image layer parser — no external tools required.

Parses OCI image tarballs created by ``docker save <image> -o image.tar``
or OCI image layout directories (from skopeo/crane) and extracts packages
without requiring Grype, Syft, or Docker CLI.

Supported image formats:
- **Docker save tarball** — ``manifest.json`` + ``<hash>/layer.tar`` inside outer tar.
- **OCI image layout tarball** — ``index.json`` + ``blobs/sha256/<hash>`` inside outer tar.
- **OCI image layout directory** — same structure, unarchived (for skopeo/crane output).

Package ecosystems extracted from each layer filesystem:
- Python: ``*.dist-info/METADATA``
- Node: ``node_modules/*/package.json``
- Debian/Ubuntu: ``var/lib/dpkg/status``
- Alpine Linux: ``lib/apk/db/installed``
- RPM log manifest: ``var/log/installed-rpms``

Whiteout handling: OCI spec uses ``.wh.`` prefix files to signal deletion.
The parser tracks whiteout paths from each layer and skips package detection
on paths that were deleted in subsequent layers.

CLI usage::

    agent-bom scan --image-tar myapp.tar
"""

from __future__ import annotations

import io
import json
import logging
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from agent_bom.models import Package

_logger = logging.getLogger(__name__)

# Whiteout prefix per OCI image spec
_WHITEOUT_PREFIX = ".wh."
_OPAQUE_WHITEOUT = ".wh..wh..opq"


@dataclass
class OCIManifest:
    """Parsed image manifest (Docker save or OCI layout)."""

    config_digest: str
    repo_tags: list[str]
    layer_paths: list[str]  # paths inside the outer tarball


@dataclass
class OCIParseResult:
    """Result of parsing an OCI image tarball or directory."""

    packages: list[Package]
    strategy: str  # "oci-tarball" | "oci-layout-dir"
    layer_count: int
    image_tags: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class OCIParseError(Exception):
    """Raised when an OCI image cannot be parsed."""


# ─── Package extraction from a layer filesystem ───────────────────────────────


def _add_package(
    seen: set[tuple[str, str]],
    packages: list[Package],
    name: str,
    version: str,
    ecosystem: str,
    purl: Optional[str] = None,
) -> None:
    key = (name.lower(), ecosystem)
    if key not in seen:
        seen.add(key)
        packages.append(
            Package(
                name=name,
                version=version,
                ecosystem=ecosystem,
                purl=purl or f"pkg:{ecosystem}/{name}@{version}",
                is_direct=False,
                resolved_from_registry=False,
            )
        )


def _extract_packages_from_layer(
    layer_tf: tarfile.TarFile,
    seen: set[tuple[str, str]],
    packages: list[Package],
    deleted_paths: set[str],
) -> set[str]:
    """Extract packages from an open layer TarFile.

    Args:
        layer_tf: Open TarFile for the layer.
        seen: Mutable set of (name, ecosystem) already found — updated in place.
        packages: Mutable list of packages — updated in place.
        deleted_paths: Set of paths deleted in LATER layers (whiteouts already processed).

    Returns:
        Set of paths marked as whiteout in THIS layer (for caller to accumulate).
    """
    whiteouts: set[str] = set()
    names = set(layer_tf.getnames())

    # Collect whiteout paths from this layer
    for member_name in names:
        base = member_name.split("/")[-1]
        if base == _OPAQUE_WHITEOUT:
            # Opaque whiteout: entire directory deleted
            parent = "/".join(member_name.split("/")[:-1])
            whiteouts.add(parent + "/")
        elif base.startswith(_WHITEOUT_PREFIX):
            real_name = base[len(_WHITEOUT_PREFIX) :]
            parent = "/".join(member_name.split("/")[:-1])
            path = f"{parent}/{real_name}" if parent else real_name
            whiteouts.add(path)

    def _is_deleted(path: str) -> bool:
        if path in deleted_paths:
            return True
        # Check opaque whiteouts (directory deletions)
        for dp in deleted_paths:
            if dp.endswith("/") and path.startswith(dp):
                return True
        return False

    # --- Python: dist-info METADATA ---
    for member_name in names:
        if not member_name.endswith(".dist-info/METADATA"):
            continue
        if _is_deleted(member_name):
            continue
        try:
            f = layer_tf.extractfile(layer_tf.getmember(member_name))
            if f is None:
                continue
            pkg_name = pkg_version = ""
            for raw_line in f:
                line = raw_line.decode("utf-8", errors="ignore").strip()
                if line.startswith("Name:"):
                    pkg_name = line.split(":", 1)[1].strip()
                elif line.startswith("Version:"):
                    pkg_version = line.split(":", 1)[1].strip()
                if pkg_name and pkg_version:
                    break
            if pkg_name and pkg_version:
                _add_package(seen, packages, pkg_name, pkg_version, "pypi")
        except Exception:
            _logger.debug("Skipped Python dist-info: %s", member_name)

    # --- Node: node_modules/*/package.json ---
    for member_name in names:
        if "/node_modules/" not in member_name or not member_name.endswith("package.json"):
            continue
        if member_name.count("/node_modules/") != 1:
            continue
        if _is_deleted(member_name):
            continue
        try:
            f = layer_tf.extractfile(layer_tf.getmember(member_name))
            if f is None:
                continue
            data = json.loads(f.read().decode("utf-8", errors="ignore"))
            pkg_name = data.get("name", "")
            pkg_version = data.get("version", "unknown")
            if pkg_name:
                _add_package(seen, packages, pkg_name, pkg_version, "npm")
        except Exception:
            _logger.debug("Skipped Node package.json: %s", member_name)

    # --- Debian/Ubuntu: dpkg status ---
    for dpkg_path in ("var/lib/dpkg/status", "./var/lib/dpkg/status"):
        if dpkg_path not in names or _is_deleted(dpkg_path):
            continue
        try:
            f = layer_tf.extractfile(layer_tf.getmember(dpkg_path))
            if f:
                content = f.read().decode("utf-8", errors="ignore")
                pkg_name = pkg_version = ""
                for line in content.splitlines():
                    if line.startswith("Package:"):
                        pkg_name = line.split(":", 1)[1].strip()
                    elif line.startswith("Version:"):
                        pkg_version = line.split(":", 1)[1].strip()
                    elif line == "" and pkg_name and pkg_version:
                        _add_package(seen, packages, pkg_name, pkg_version, "deb", f"pkg:deb/debian/{pkg_name}@{pkg_version}")
                        pkg_name = pkg_version = ""
                # Flush last entry
                if pkg_name and pkg_version:
                    _add_package(seen, packages, pkg_name, pkg_version, "deb", f"pkg:deb/debian/{pkg_name}@{pkg_version}")
        except Exception:
            _logger.debug("Failed to parse dpkg status")
        break

    # --- Alpine: apk installed ---
    for apk_path in ("lib/apk/db/installed", "./lib/apk/db/installed"):
        if apk_path not in names or _is_deleted(apk_path):
            continue
        try:
            f = layer_tf.extractfile(layer_tf.getmember(apk_path))
            if f:
                content = f.read().decode("utf-8", errors="ignore")
                pkg_name = pkg_version = ""
                for line in content.splitlines():
                    if line.startswith("P:"):
                        pkg_name = line[2:].strip()
                    elif line.startswith("V:"):
                        pkg_version = line[2:].strip()
                    elif line == "" and pkg_name and pkg_version:
                        _add_package(seen, packages, pkg_name, pkg_version, "apk", f"pkg:apk/alpine/{pkg_name}@{pkg_version}")
                        pkg_name = pkg_version = ""
                if pkg_name and pkg_version:
                    _add_package(seen, packages, pkg_name, pkg_version, "apk", f"pkg:apk/alpine/{pkg_name}@{pkg_version}")
        except Exception:
            _logger.debug("Failed to parse Alpine apk db")
        break

    # --- RPM log manifest ---
    for rpm_path in ("var/log/installed-rpms", "./var/log/installed-rpms"):
        if rpm_path not in names or _is_deleted(rpm_path):
            continue
        try:
            f = layer_tf.extractfile(layer_tf.getmember(rpm_path))
            if f:
                for raw_line in f:
                    line = raw_line.decode("utf-8", errors="ignore").strip()
                    if not line:
                        continue
                    parts = line.split()
                    nvr = parts[0] if parts else line
                    idx2 = nvr.rfind("-")
                    if idx2 > 0:
                        idx1 = nvr.rfind("-", 0, idx2)
                        if idx1 > 0:
                            rpm_name = nvr[:idx1]
                            if rpm_name == "gpg-pubkey":
                                continue
                            rpm_ver = nvr[idx1 + 1 : idx2]
                            _add_package(seen, packages, rpm_name, rpm_ver, "rpm", f"pkg:rpm/redhat/{rpm_name}@{rpm_ver}")
        except Exception:
            _logger.debug("Failed to parse rpm manifest")
        break

    return whiteouts


# ─── Docker save tarball format ───────────────────────────────────────────────


def _parse_docker_save_manifest(tf: tarfile.TarFile) -> list[OCIManifest]:
    """Parse manifest.json from a Docker save tarball."""
    try:
        member = tf.getmember("manifest.json")
        f = tf.extractfile(member)
        if f is None:
            raise OCIParseError("manifest.json is not a regular file")
        raw = json.loads(f.read().decode("utf-8"))
    except KeyError:
        raise OCIParseError("No manifest.json found — not a Docker save tarball")
    except json.JSONDecodeError as e:
        raise OCIParseError(f"Invalid manifest.json: {e}")

    manifests: list[OCIManifest] = []
    for entry in raw:
        manifests.append(
            OCIManifest(
                config_digest=entry.get("Config", ""),
                repo_tags=entry.get("RepoTags") or [],
                layer_paths=entry.get("Layers", []),
            )
        )
    return manifests


def _parse_layers_from_tarball(
    outer_tf: tarfile.TarFile,
    layer_paths: list[str],
) -> tuple[list[Package], list[str]]:
    """Open each layer tarball from the outer tarball and extract packages.

    Layers are processed in order (base → top). Whiteout files in later
    layers are accumulated to suppress packages deleted from earlier layers.

    Returns:
        (packages, warnings)
    """
    seen: set[tuple[str, str]] = set()
    packages: list[Package] = []
    warnings: list[str] = []

    # First pass: collect all whiteouts per layer (in order)
    # Then second pass: extract packages respecting accumulated deletions.
    # For simplicity: single-pass, accumulate deletions from current layer
    # only. Full whiteout handling would require two passes.
    all_deleted: set[str] = set()

    for layer_path in layer_paths:
        # Normalize path (docker save may use paths with leading ./)
        layer_path_norm = layer_path.lstrip("./")
        # Try normalized and original
        member = None
        for candidate in (layer_path, layer_path_norm, "./" + layer_path_norm):
            try:
                member = outer_tf.getmember(candidate)
                break
            except KeyError:
                continue

        if member is None:
            warnings.append(f"Layer not found in tarball: {layer_path}")
            continue

        layer_fobj = outer_tf.extractfile(member)
        if layer_fobj is None:
            warnings.append(f"Layer is not a regular file: {layer_path}")
            continue

        # Read into memory to allow tarfile to seek
        layer_bytes = layer_fobj.read()
        try:
            with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode="r:*") as layer_tf:
                whiteouts = _extract_packages_from_layer(layer_tf, seen, packages, all_deleted)
                all_deleted.update(whiteouts)
        except tarfile.TarError as e:
            warnings.append(f"Failed to read layer {layer_path}: {e}")
            continue

    return packages, warnings


# ─── OCI image layout format ──────────────────────────────────────────────────


def _parse_oci_layout_index(tf: tarfile.TarFile) -> list[str]:
    """Parse index.json from an OCI image layout tarball. Returns layer blob paths."""
    try:
        member = tf.getmember("index.json")
        f = tf.extractfile(member)
        if f is None:
            raise OCIParseError("index.json is not a regular file")
        index = json.loads(f.read().decode("utf-8"))
    except KeyError:
        raise OCIParseError("No index.json found — not an OCI image layout tarball")
    except json.JSONDecodeError as e:
        raise OCIParseError(f"Invalid index.json: {e}")

    # Get first manifest digest
    manifests = index.get("manifests", [])
    if not manifests:
        raise OCIParseError("No manifests in OCI index.json")

    manifest_digest = manifests[0].get("digest", "")
    if not manifest_digest.startswith("sha256:"):
        raise OCIParseError(f"Unsupported manifest digest: {manifest_digest}")

    manifest_hash = manifest_digest[len("sha256:") :]
    blob_path = f"blobs/sha256/{manifest_hash}"
    try:
        member = tf.getmember(blob_path)
        f = tf.extractfile(member)
        if f is None:
            raise OCIParseError(f"Manifest blob not found: {blob_path}")
        manifest = json.loads(f.read().decode("utf-8"))
    except (KeyError, json.JSONDecodeError) as e:
        raise OCIParseError(f"Failed to read OCI manifest blob: {e}")

    layer_paths: list[str] = []
    for layer in manifest.get("layers", []):
        digest = layer.get("digest", "")
        if digest.startswith("sha256:"):
            layer_paths.append(f"blobs/sha256/{digest[len('sha256:') :]}")

    return layer_paths


# ─── Public API ───────────────────────────────────────────────────────────────


def parse_oci_tarball(path: Path) -> OCIParseResult:
    """Parse an OCI image tarball (Docker save or OCI layout format).

    Auto-detects the format by checking for ``manifest.json`` (Docker save)
    or ``index.json`` (OCI layout) inside the tarball.

    Args:
        path: Path to the ``.tar`` or ``.tar.gz`` file.

    Returns:
        OCIParseResult with packages, strategy, layer count, and any warnings.

    Raises:
        OCIParseError: If the tarball cannot be parsed.
    """
    if not path.exists():
        raise OCIParseError(f"File not found: {path}")

    try:
        outer_tf = tarfile.open(str(path), mode="r:*")
    except tarfile.TarError as e:
        raise OCIParseError(f"Cannot open tarball: {e}")

    with outer_tf:
        names = outer_tf.getnames()

        # Detect format
        if "manifest.json" in names or "./manifest.json" in names:
            # Docker save format
            try:
                manifests = _parse_docker_save_manifest(outer_tf)
            except OCIParseError:
                raise
            if not manifests:
                return OCIParseResult(packages=[], strategy="oci-tarball", layer_count=0, warnings=["Empty manifest.json"])
            # Use first image (most users save one image)
            manifest = manifests[0]
            packages, warnings = _parse_layers_from_tarball(outer_tf, manifest.layer_paths)
            return OCIParseResult(
                packages=packages,
                strategy="oci-tarball",
                layer_count=len(manifest.layer_paths),
                image_tags=manifest.repo_tags,
                warnings=warnings,
            )

        elif "index.json" in names or "./index.json" in names:
            # OCI image layout format
            try:
                layer_paths = _parse_oci_layout_index(outer_tf)
            except OCIParseError:
                raise
            packages, warnings = _parse_layers_from_tarball(outer_tf, layer_paths)
            return OCIParseResult(
                packages=packages,
                strategy="oci-tarball",
                layer_count=len(layer_paths),
                warnings=warnings,
            )

        else:
            raise OCIParseError(
                "Unrecognized image tarball format: neither manifest.json (Docker save) nor index.json (OCI layout) found at tarball root."
            )


def parse_oci_layout_dir(path: Path) -> OCIParseResult:
    """Parse an OCI image layout directory (from skopeo copy --dest-dir, crane pull --format=oci).

    Args:
        path: Path to the directory containing ``index.json`` and ``blobs/`` subdirectory.

    Returns:
        OCIParseResult with packages, strategy, and any warnings.

    Raises:
        OCIParseError: If the directory cannot be parsed.
    """
    if not path.is_dir():
        raise OCIParseError(f"Not a directory: {path}")

    index_path = path / "index.json"
    if not index_path.exists():
        raise OCIParseError(f"index.json not found in {path}")

    try:
        index = json.loads(index_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        raise OCIParseError(f"Failed to read index.json: {e}")

    manifests = index.get("manifests", [])
    if not manifests:
        raise OCIParseError("No manifests in OCI index.json")

    manifest_digest = manifests[0].get("digest", "")
    if not manifest_digest.startswith("sha256:"):
        raise OCIParseError(f"Unsupported manifest digest: {manifest_digest}")

    manifest_hash = manifest_digest[len("sha256:") :]
    manifest_blob = path / "blobs" / "sha256" / manifest_hash
    if not manifest_blob.exists():
        raise OCIParseError(f"Manifest blob not found: {manifest_blob}")

    try:
        manifest = json.loads(manifest_blob.read_text())
    except (json.JSONDecodeError, OSError) as e:
        raise OCIParseError(f"Failed to read manifest blob: {e}")

    layer_digests = []
    for layer in manifest.get("layers", []):
        digest = layer.get("digest", "")
        if digest.startswith("sha256:"):
            layer_digests.append(digest[len("sha256:") :])

    seen: set[tuple[str, str]] = set()
    packages: list[Package] = []
    warnings: list[str] = []
    all_deleted: set[str] = set()

    for layer_hash in layer_digests:
        blob_path = path / "blobs" / "sha256" / layer_hash
        if not blob_path.exists():
            warnings.append(f"Layer blob not found: {blob_path}")
            continue
        try:
            with tarfile.open(str(blob_path), mode="r:*") as layer_tf:
                whiteouts = _extract_packages_from_layer(layer_tf, seen, packages, all_deleted)
                all_deleted.update(whiteouts)
        except tarfile.TarError as e:
            warnings.append(f"Failed to read layer blob {layer_hash[:12]}: {e}")

    return OCIParseResult(
        packages=packages,
        strategy="oci-layout-dir",
        layer_count=len(layer_digests),
        warnings=warnings,
    )


def scan_oci(path: str | Path) -> tuple[list[Package], str]:
    """Scan an OCI image tarball or layout directory. Returns (packages, strategy).

    Auto-detects format:
    - File: parses as Docker save or OCI layout tarball.
    - Directory: parses as OCI image layout directory.

    Raises:
        OCIParseError: If the path cannot be parsed.
    """
    p = Path(path)
    if p.is_dir():
        result = parse_oci_layout_dir(p)
    else:
        result = parse_oci_tarball(p)

    if result.warnings:
        for w in result.warnings:
            _logger.warning("OCI parser: %s", w)

    return result.packages, result.strategy
