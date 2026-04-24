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
- RPM: ``var/lib/rpm/rpmdb.sqlite`` (sqlite3) + ``var/log/installed-rpms`` (log manifest)
- Java: ``*.jar``/``*.war``/``*.ear`` → ``META-INF/maven/*/pom.properties`` or ``META-INF/MANIFEST.MF``
- Go binaries: embedded buildinfo (``\xff Go buildinf:`` magic, dep lines)
- Ruby: ``**/specifications/*.gemspec`` (regex name/version extraction)
- .NET: ``**/*.deps.json`` (libraries section, type=package)

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
import os
import posixpath
import re
import sqlite3
import struct
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Optional

from agent_bom.models import Package, PackageOccurrence
from agent_bom.package_utils import parse_debian_source_name

_logger = logging.getLogger(__name__)
_MAX_JSON_MEMBER_BYTES = 100 * 1024 * 1024
_MAX_LAYER_UNCOMPRESSED_BYTES = 5 * 1024 * 1024 * 1024
_MAX_JAR_UNCOMPRESSED_BYTES = 512 * 1024 * 1024


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(1, int(raw))
    except ValueError:
        return default


def _max_json_member_bytes() -> int:
    return _env_int("AGENT_BOM_MAX_MANIFEST_BYTES", _MAX_JSON_MEMBER_BYTES)


def _max_layer_uncompressed_bytes() -> int:
    return _env_int("AGENT_BOM_OCI_MAX_LAYER_UNCOMPRESSED_BYTES", _MAX_LAYER_UNCOMPRESSED_BYTES)


def _max_jar_uncompressed_bytes() -> int:
    return _env_int("AGENT_BOM_OCI_MAX_JAR_UNCOMPRESSED_BYTES", _MAX_JAR_UNCOMPRESSED_BYTES)


# ── Tar member safety ────────────────────────────────────────────────────────
#
# Image tarballs are untrusted input. A malicious tar can carry members whose
# names escape the extraction root, members that are symlinks pointing outside
# the tar, or hardlinks to arbitrary files. `tarfile.TarFile` does not validate
# these by default (Python's `data_filter` arrived in 3.12 but we target 3.11+
# and call `extractfile()` which bypasses it anyway).
#
# The helpers below give us two guarantees the parser relies on:
#   1. `_is_safe_tar_member_name(name)` — the member name, after POSIX
#      normalization, stays inside the tar root. Rejects `../` traversal,
#      absolute paths, and NUL-injected names.
#   2. `_safe_getmember(tf, name)` — resolves a member by name and also
#      requires it to be a regular file. Symlinks and hardlinks never reach
#      `extractfile()`, so the parser cannot be tricked into reading a host
#      file by a crafted tar with `METADATA -> /etc/passwd`.
#
# Both helpers log at debug level when they reject something, so operators
# scanning hostile images can see why certain layers contributed zero
# packages.


def _is_safe_tar_member_name(name: str) -> bool:
    """Return True iff ``name`` is safe to treat as a relative path inside a tar.

    Rejects absolute paths, parent-traversal (``../``), NUL-injected names,
    and any name whose POSIX-normalized form escapes the tar root.
    """
    if not name or "\x00" in name:
        return False
    if name.startswith("/"):
        return False
    # posixpath.normpath collapses "./foo/../bar" → "bar" but preserves a
    # leading ".." if the name escapes. "a/../b" → "b" (safe);
    # "../a" → "../a" (escapes); "a/../../b" → "../b" (escapes).
    normalized = posixpath.normpath(name)
    if normalized.startswith("../") or normalized == "..":
        return False
    if normalized.startswith("/"):
        return False
    # Belt-and-suspenders against split-by-"/" bypasses on odd separators.
    parts = normalized.split("/")
    if any(p == ".." for p in parts):
        return False
    return True


def _safe_tar_names(tf: tarfile.TarFile) -> set[str]:
    """Return member names that are safe regular files inside ``tf``.

    Filters out:
      - names failing ``_is_safe_tar_member_name`` (traversal / absolute / NUL)
      - symlink members (``SYMTYPE``) and hardlink members (``LNKTYPE``)
      - device / fifo members

    Directory members are excluded because this helper exists to feed
    file-reading loops; directories carry no file payload.
    """
    safe: set[str] = set()
    rejected_traversal = 0
    rejected_link = 0
    for member in tf.getmembers():
        name = member.name
        if not _is_safe_tar_member_name(name):
            rejected_traversal += 1
            continue
        if member.issym() or member.islnk():
            # Symlinks / hardlinks inside an image layer are legitimate OS
            # artifacts — but we never follow them for package parsing. We
            # only ingest concrete regular-file payloads.
            rejected_link += 1
            continue
        if not member.isfile():
            # Skip directories, devices, fifos, etc.
            continue
        safe.add(name)
    if rejected_traversal:
        _logger.debug(
            "Rejected %d tar member(s) with unsafe names (traversal / absolute / NUL)",
            rejected_traversal,
        )
    if rejected_link:
        _logger.debug(
            "Skipped %d symlink/hardlink member(s) — package parsing reads concrete files only",
            rejected_link,
        )
    return safe


def _safe_getmember(tf: tarfile.TarFile, name: str) -> tarfile.TarInfo | None:
    """Resolve ``name`` to a tar member only if the name is safe AND the member is a regular file.

    Returns ``None`` (instead of raising ``KeyError``) so callers can treat a
    missing-or-unsafe member the same way they treat a missing-but-legitimate
    member: skip and move on.
    """
    if not _is_safe_tar_member_name(name):
        return None
    try:
        member = tf.getmember(name)
    except KeyError:
        return None
    if member.issym() or member.islnk() or not member.isfile():
        return None
    return member


def _safe_extractfile(tf: tarfile.TarFile, name: str) -> IO[bytes] | None:
    """Open a tar member by name, but only if it is safe (see ``_safe_getmember``).

    Returns ``None`` if the member is missing, a symlink / hardlink, has an
    unsafe name, or can't be opened as a stream. Callers can treat ``None``
    uniformly as "skip this member" without distinguishing the cause.
    """
    member = _safe_getmember(tf, name)
    if member is None:
        return None
    try:
        return tf.extractfile(member)
    except (tarfile.TarError, OSError) as e:
        _logger.debug("Failed to open tar member %s: %s: %s", name, type(e).__name__, e)
        return None


# Whiteout prefix per OCI image spec
_WHITEOUT_PREFIX = ".wh."
_OPAQUE_WHITEOUT = ".wh..wh..opq"

# Java JAR/WAR/EAR file extension pattern
_JAR_EXT_RE = re.compile(r"\.(jar|war|ear)$", re.IGNORECASE)
# Directories likely to contain JARs in container images
_JAR_DIR_HINTS = ("java", "jvm", "/app/", "/opt/", "/srv/", "/usr/local/", "/usr/share/", "/home/")
# Max JAR size to open (skip huge fat JARs > 150 MB — they'd be slow)
_JAR_MAX_BYTES = 150 * 1024 * 1024

# Go binary: embedded build info magic (Go 1.13+)
_GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"
# Directories that commonly contain Go binaries
_GO_BIN_DIR_RE = re.compile(r"^\.?/?(usr/(local/)?s?bin|go/bin|usr/local/go/bin|opt/go/bin)/")
# Max bytes to read from a binary for Go buildinfo scanning (8 MB)
_GO_BIN_MAX_READ = 8 * 1024 * 1024
# Pattern to extract dep lines from Go buildinfo text block
_GO_DEP_LINE_RE = re.compile(rb"dep\t([^\t\n]+)\t(v[^\t\n\s]+)")

# Ruby gemspec: files under .../specifications/*.gemspec
_GEMSPEC_PATH_RE = re.compile(r"specifications/([^/]+)\.gemspec$")
_GEMSPEC_NAME_RE = re.compile(r'\.name\s*=\s*["\']([^"\']+)["\']')
_GEMSPEC_VER_RE = re.compile(r'\.version\s*=\s*(?:Gem::Version\.new\()?["\']([^"\']+)["\']')

# RPM sqlite: database path candidates in a container layer
_RPM_SQLITE_PATHS = ("var/lib/rpm/rpmdb.sqlite", "./var/lib/rpm/rpmdb.sqlite")
# RPM header magic (8 bytes)
_RPM_HDR_MAGIC = b"\x8e\xad\xe8\x01\x00\x00\x00\x00"
_RPMTAG_NAME = 1000
_RPMTAG_VERSION = 1001
_RPMTAG_RELEASE = 1002
_RPMTAG_ARCH = 1022
_RPM_TYPE_STRING = 6


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


@dataclass(frozen=True)
class LayerMetadata:
    """Build and filesystem provenance for a concrete image layer."""

    layer_index: int
    layer_id: str
    layer_path: str
    created_by: Optional[str] = None
    dockerfile_instruction: Optional[str] = None


def _normalize_layer_id(layer_path: str) -> str:
    """Return a stable layer identifier from a tar/layout path."""
    layer_path = layer_path.lstrip("./")
    if layer_path.startswith("blobs/sha256/"):
        return f"sha256:{layer_path.rsplit('/', 1)[-1]}"
    if layer_path.endswith("/layer.tar"):
        return layer_path[: -len("/layer.tar")]
    return layer_path


def _normalize_dockerfile_instruction(created_by: Optional[str]) -> Optional[str]:
    """Convert raw OCI history ``created_by`` text into a Dockerfile-like instruction."""
    if not created_by:
        return None

    raw = created_by.strip()
    for prefix in ("/bin/sh -c #(nop) ", "cmd /S /C #(nop) "):
        if raw.startswith(prefix):
            return raw[len(prefix) :].strip() or raw

    for prefix in ("/bin/sh -c ", "cmd /S /C "):
        if raw.startswith(prefix):
            command = raw[len(prefix) :].strip()
            return f"RUN {command}" if command else "RUN"

    return raw


def _build_layer_metadata(layer_paths: list[str], config: dict | None = None) -> list[LayerMetadata]:
    """Map image layers to normalized build-step metadata."""
    histories = (config or {}).get("history", [])
    metadata: list[LayerMetadata] = []
    history_cursor = 0

    for index, layer_path in enumerate(layer_paths, start=1):
        created_by: str | None = None
        dockerfile_instruction: str | None = None

        while history_cursor < len(histories):
            entry = histories[history_cursor]
            history_cursor += 1
            if entry.get("empty_layer"):
                continue
            created_by = entry.get("created_by")
            dockerfile_instruction = _normalize_dockerfile_instruction(created_by)
            break

        metadata.append(
            LayerMetadata(
                layer_index=index,
                layer_id=_normalize_layer_id(layer_path),
                layer_path=layer_path,
                created_by=created_by,
                dockerfile_instruction=dockerfile_instruction,
            )
        )

    return metadata


def _resolve_tar_member(tf: tarfile.TarFile, member_path: str) -> tarfile.TarInfo | None:
    """Resolve a tar member path with common Docker/OCI prefixes."""
    normalized = member_path.lstrip("./")
    for candidate in (member_path, normalized, f"./{normalized}"):
        try:
            return tf.getmember(candidate)
        except KeyError:
            continue
    return None


def _read_json_member_from_tar(tf: tarfile.TarFile, member_path: str) -> dict | None:
    """Read and decode a JSON file from an outer tarball when present."""
    member = _resolve_tar_member(tf, member_path)
    if member is None:
        return None
    if member.size > _max_json_member_bytes():
        _logger.debug("Skipping oversized JSON member %s", member_path)
        return None
    fileobj = tf.extractfile(member)
    if fileobj is None:
        return None
    try:
        data = fileobj.read(_max_json_member_bytes() + 1)
        if len(data) > _max_json_member_bytes():
            return None
        return json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _read_json_path_limited(path: Path) -> dict | list | None:
    try:
        if path.stat().st_size > _max_json_member_bytes():
            _logger.debug("Skipping oversized JSON file: %s", path)
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _tar_uncompressed_regular_size(tf: tarfile.TarFile) -> int:
    total = 0
    for member in tf.getmembers():
        if member.isfile() and _is_safe_tar_member_name(member.name):
            total += max(0, int(member.size))
            if total > _max_layer_uncompressed_bytes():
                break
    return total


def _zip_uncompressed_size(zf: zipfile.ZipFile) -> int:
    total = 0
    for info in zf.infolist():
        total += max(0, int(info.file_size))
        if total > _max_jar_uncompressed_bytes():
            break
    return total


# ─── RPM header parser ────────────────────────────────────────────────────────


def _parse_rpm_header_blob(blob: bytes) -> Optional[tuple[str, str]]:
    """Parse a minimal RPM header blob and return (name, version) or None.

    RPM header layout (big-endian):
    - 8 bytes magic
    - 4 bytes nindex (number of tag entries)
    - 4 bytes hsize (size of data section)
    - nindex × 16-byte entries: tag(4) type(4) offset(4) count(4)
    - data section (hsize bytes)
    """
    if len(blob) < 16 or blob[:8] != _RPM_HDR_MAGIC:
        return None
    try:
        nindex = struct.unpack_from(">I", blob, 8)[0]
        # hsize = struct.unpack_from(">I", blob, 12)[0]  # unused
        index_start = 16
        data_start = index_start + nindex * 16

        if data_start > len(blob):
            return None

        tags: dict[int, tuple[int, int]] = {}  # tag → (type, offset)
        for i in range(nindex):
            pos = index_start + i * 16
            tag = struct.unpack_from(">I", blob, pos)[0]
            type_ = struct.unpack_from(">I", blob, pos + 4)[0]
            offset = struct.unpack_from(">I", blob, pos + 8)[0]
            tags[tag] = (type_, offset)

        def _read_str(tag_id: int) -> str:
            if tag_id not in tags:
                return ""
            type_, offset = tags[tag_id]
            if type_ != _RPM_TYPE_STRING:
                return ""
            abs_pos = data_start + offset
            end = blob.find(b"\x00", abs_pos)
            if end == -1:
                return ""
            return blob[abs_pos:end].decode("utf-8", errors="ignore")

        name = _read_str(_RPMTAG_NAME)
        version = _read_str(_RPMTAG_VERSION)
        release = _read_str(_RPMTAG_RELEASE)
        if not name or not version:
            return None
        full_version = f"{version}-{release}" if release else version
        return name, full_version
    except (struct.error, OverflowError):
        return None


# ─── Package extraction from a layer filesystem ───────────────────────────────


def _add_package(
    packages_by_key: dict[tuple[str, str], Package],
    packages: list[Package],
    name: str,
    version: str,
    ecosystem: str,
    purl: Optional[str] = None,
    *,
    source_package: str | None = None,
    distro_name: str | None = None,
    distro_version: str | None = None,
    layer: LayerMetadata | None = None,
    package_path: str | None = None,
) -> None:
    key = (name.lower(), ecosystem)
    package = packages_by_key.get(key)
    if package is None:
        package = Package(
            name=name,
            version=version,
            ecosystem=ecosystem,
            purl=purl or f"pkg:{ecosystem}/{name}@{version}",
            is_direct=False,
            resolved_from_registry=False,
            source_package=source_package,
            distro_name=distro_name,
            distro_version=distro_version,
        )
        packages_by_key[key] = package
        packages.append(package)
    else:
        # When a later layer rewrites package metadata (common for lockfiles and
        # package DBs), keep the final image view aligned to the latest version.
        if version and package.version != version:
            package.version = version
            package.purl = purl or f"pkg:{ecosystem}/{name}@{version}"
            package.source_package = source_package
            package.distro_name = distro_name or package.distro_name
            package.distro_version = distro_version or package.distro_version
            package.occurrences.clear()
        elif purl and package.purl != purl:
            package.purl = purl
        if source_package is not None:
            package.source_package = source_package
        if distro_name is not None:
            package.distro_name = distro_name
        if distro_version is not None:
            package.distro_version = distro_version

    if layer is None:
        return

    occurrence = PackageOccurrence(
        layer_index=layer.layer_index,
        layer_id=layer.layer_id,
        layer_path=layer.layer_path,
        package_path=package_path,
        created_by=layer.created_by,
        dockerfile_instruction=layer.dockerfile_instruction,
    )
    occurrence_key = (occurrence.layer_index, occurrence.layer_id, occurrence.package_path or "")
    existing_keys = {(occ.layer_index, occ.layer_id, occ.package_path or "") for occ in package.occurrences}
    if occurrence_key not in existing_keys:
        package.occurrences.append(occurrence)


def _read_os_release_from_layer(layer_tf: tarfile.TarFile, deleted_paths: set[str]) -> tuple[str | None, str | None]:
    """Read distro metadata from ``etc/os-release`` inside a layer."""
    for os_release_path in ("etc/os-release", "./etc/os-release"):
        if os_release_path in deleted_paths:
            continue
        member = _safe_getmember(layer_tf, os_release_path)
        if member is None:
            # Missing, symlinked (refused), or unsafe name. Try next candidate.
            continue
        try:
            f = layer_tf.extractfile(member)
            if f is None:
                continue
            distro_name: str | None = None
            distro_version: str | None = None
            for raw_line in f:
                line = raw_line.decode("utf-8", errors="ignore").strip()
                if line.startswith("ID="):
                    distro_name = line.split("=", 1)[1].strip().strip('"').strip("'").lower() or None
                elif line.startswith("VERSION_ID="):
                    distro_version = line.split("=", 1)[1].strip().strip('"').strip("'") or None
            return distro_name, distro_version
        except (tarfile.TarError, OSError, UnicodeDecodeError) as e:
            _logger.debug("Failed to parse os-release %s: %s: %s", os_release_path, type(e).__name__, e)
    return None, None


def _extract_packages_from_layer(
    layer_tf: tarfile.TarFile,
    packages_by_key: dict[tuple[str, str], Package],
    packages: list[Package],
    deleted_paths: set[str],
    layer: LayerMetadata,
) -> set[str]:
    """Extract packages from an open layer TarFile.

    Args:
        layer_tf: Open TarFile for the layer.
        packages_by_key: Mutable package map keyed by (name, ecosystem).
        packages: Mutable list of packages — updated in place.
        deleted_paths: Set of paths deleted in LATER layers (whiteouts already processed).
        layer: Layer provenance metadata for this concrete tar blob.

    Returns:
        Set of paths marked as whiteout in THIS layer (for caller to accumulate).
    """
    whiteouts: set[str] = set()
    # `_safe_tar_names` filters out path-traversal members (normalized + split-part
    # check, not just substring), absolute paths, NUL-injected names, AND symlink /
    # hardlink members. Prior filter only substring-checked "..".
    names = _safe_tar_names(layer_tf)

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
            f = _safe_extractfile(layer_tf, member_name)
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
                _add_package(packages_by_key, packages, pkg_name, pkg_version, "pypi", layer=layer, package_path=member_name)
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
            f = _safe_extractfile(layer_tf, member_name)
            if f is None:
                continue
            data = json.loads(f.read().decode("utf-8", errors="ignore"))
            pkg_name = data.get("name", "")
            pkg_version = data.get("version", "unknown")
            if pkg_name:
                _add_package(packages_by_key, packages, pkg_name, pkg_version, "npm", layer=layer, package_path=member_name)
        except Exception:
            _logger.debug("Skipped Node package.json: %s", member_name)

    # --- Debian/Ubuntu: dpkg status ---
    for dpkg_path in ("var/lib/dpkg/status", "./var/lib/dpkg/status"):
        if dpkg_path not in names or _is_deleted(dpkg_path):
            continue
        try:
            f = _safe_extractfile(layer_tf, dpkg_path)
            if f:
                content = f.read().decode("utf-8", errors="ignore")
                pkg_name = pkg_version = ""
                source_package: str | None = None
                for line in content.splitlines():
                    if line.startswith("Package:"):
                        pkg_name = line.split(":", 1)[1].strip()
                    elif line.startswith("Version:"):
                        pkg_version = line.split(":", 1)[1].strip()
                    elif line.startswith("Source:"):
                        source_package = parse_debian_source_name(line.split(":", 1)[1].strip())
                    elif line == "" and pkg_name and pkg_version:
                        _add_package(
                            packages_by_key,
                            packages,
                            pkg_name,
                            pkg_version,
                            "deb",
                            f"pkg:deb/debian/{pkg_name}@{pkg_version}",
                            source_package=source_package,
                            layer=layer,
                            package_path=dpkg_path,
                        )
                        pkg_name = pkg_version = ""
                        source_package = None
                # Flush last entry
                if pkg_name and pkg_version:
                    _add_package(
                        packages_by_key,
                        packages,
                        pkg_name,
                        pkg_version,
                        "deb",
                        f"pkg:deb/debian/{pkg_name}@{pkg_version}",
                        source_package=source_package,
                        layer=layer,
                        package_path=dpkg_path,
                    )
        except Exception:
            _logger.debug("Failed to parse dpkg status")
        break

    # --- Alpine: apk installed ---
    for apk_path in ("lib/apk/db/installed", "./lib/apk/db/installed"):
        if apk_path not in names or _is_deleted(apk_path):
            continue
        try:
            f = _safe_extractfile(layer_tf, apk_path)
            if f:
                content = f.read().decode("utf-8", errors="ignore")
                pkg_name = pkg_version = ""
                for line in content.splitlines():
                    if line.startswith("P:"):
                        pkg_name = line[2:].strip()
                    elif line.startswith("V:"):
                        pkg_version = line[2:].strip()
                    elif line == "" and pkg_name and pkg_version:
                        _add_package(
                            packages_by_key,
                            packages,
                            pkg_name,
                            pkg_version,
                            "apk",
                            f"pkg:apk/alpine/{pkg_name}@{pkg_version}",
                            layer=layer,
                            package_path=apk_path,
                        )
                        pkg_name = pkg_version = ""
                if pkg_name and pkg_version:
                    _add_package(
                        packages_by_key,
                        packages,
                        pkg_name,
                        pkg_version,
                        "apk",
                        f"pkg:apk/alpine/{pkg_name}@{pkg_version}",
                        layer=layer,
                        package_path=apk_path,
                    )
        except Exception:
            _logger.debug("Failed to parse Alpine apk db")
        break

    # --- RPM log manifest ---
    for rpm_path in ("var/log/installed-rpms", "./var/log/installed-rpms"):
        if rpm_path not in names or _is_deleted(rpm_path):
            continue
        try:
            f = _safe_extractfile(layer_tf, rpm_path)
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
                            _add_package(
                                packages_by_key,
                                packages,
                                rpm_name,
                                rpm_ver,
                                "rpm",
                                f"pkg:rpm/redhat/{rpm_name}@{rpm_ver}",
                                layer=layer,
                                package_path=rpm_path,
                            )
        except Exception:
            _logger.debug("Failed to parse rpm manifest")
        break

    # --- RPM sqlite database (rpmdb.sqlite) ---
    for sqlite_path in _RPM_SQLITE_PATHS:
        if sqlite_path not in names or _is_deleted(sqlite_path):
            continue
        try:
            f = _safe_extractfile(layer_tf, sqlite_path)
            if f is None:
                continue
            db_bytes = f.read()
            # Write to temp file so sqlite3 can open it
            with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
                tmp.write(db_bytes)
                tmp_path = tmp.name
            try:
                conn = sqlite3.connect(tmp_path)
                try:
                    rows = conn.execute("SELECT blob FROM Packages").fetchall()
                    for (blob,) in rows:
                        if isinstance(blob, bytes):
                            result = _parse_rpm_header_blob(blob)
                            if result:
                                rpm_name, rpm_ver = result
                                if rpm_name != "gpg-pubkey":
                                    _add_package(
                                        packages_by_key,
                                        packages,
                                        rpm_name,
                                        rpm_ver,
                                        "rpm",
                                        f"pkg:rpm/redhat/{rpm_name}@{rpm_ver}",
                                        layer=layer,
                                        package_path=sqlite_path,
                                    )
                except sqlite3.DatabaseError:
                    _logger.debug("Failed to query rpmdb.sqlite")
                finally:
                    conn.close()
            finally:
                import os as _os

                _os.unlink(tmp_path)
        except Exception:
            _logger.debug("Failed to parse rpmdb.sqlite")
        break

    # --- Java: JARs via META-INF/maven/*/pom.properties or MANIFEST.MF ---
    for member_name in names:
        if not _JAR_EXT_RE.search(member_name):
            continue
        if _is_deleted(member_name):
            continue
        # Normalize: tar paths may lack leading '/'; prepend for hint matching
        name_for_hint = "/" + member_name.lower()
        if not any(hint in name_for_hint for hint in _JAR_DIR_HINTS):
            continue
        member = _safe_getmember(layer_tf, member_name)
        if member is None or member.size == 0 or member.size > _JAR_MAX_BYTES:
            continue
        try:
            f = layer_tf.extractfile(member)
            if f is None:
                continue
            jar_bytes = f.read()
            with zipfile.ZipFile(io.BytesIO(jar_bytes)) as zf:
                if _zip_uncompressed_size(zf) > _max_jar_uncompressed_bytes():
                    _logger.debug("Skipping oversized JAR payload: %s", member_name)
                    continue
                jar_names = zf.namelist()
                # Prefer META-INF/maven/*/pom.properties (groupId/artifactId/version)
                pom_props_paths = [n for n in jar_names if re.match(r"META-INF/maven/[^/]+/[^/]+/pom\.properties$", n)]
                found = False
                for prop_path in pom_props_paths:
                    props: dict[str, str] = {}
                    for prop_line in zf.read(prop_path).decode("utf-8", errors="ignore").splitlines():
                        if "=" in prop_line and not prop_line.startswith("#"):
                            k, _, v = prop_line.partition("=")
                            props[k.strip()] = v.strip()
                    artifact_id = props.get("artifactId", "")
                    version = props.get("version", "")
                    group_id = props.get("groupId", "")
                    if artifact_id and version:
                        purl = f"pkg:maven/{group_id}/{artifact_id}@{version}" if group_id else f"pkg:maven/{artifact_id}@{version}"
                        _add_package(packages_by_key, packages, artifact_id, version, "maven", purl, layer=layer, package_path=member_name)
                        found = True
                # Fallback: MANIFEST.MF Implementation-Title/Version or Bundle-*
                if not found and "META-INF/MANIFEST.MF" in jar_names:
                    mf: dict[str, str] = {}
                    for mf_line in zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="ignore").splitlines():
                        if ": " in mf_line:
                            mk, _, mv = mf_line.partition(": ")
                            mf[mk.strip()] = mv.strip()
                    title = mf.get("Implementation-Title") or mf.get("Bundle-Name", "")
                    version = mf.get("Implementation-Version") or mf.get("Bundle-Version", "")
                    if title and version and not title.startswith("$") and not version.startswith("$"):
                        _add_package(packages_by_key, packages, title, version, "maven", layer=layer, package_path=member_name)
        except Exception:
            _logger.debug("Skipped JAR: %s", member_name)

    # --- Go binaries: embedded build info (go version -m equivalent) ---
    for member_name in names:
        if not _GO_BIN_DIR_RE.match(member_name):
            continue
        if _is_deleted(member_name):
            continue
        member = _safe_getmember(layer_tf, member_name)
        if member is None or member.size < 64:
            continue
        try:
            f = layer_tf.extractfile(member)
            if f is None:
                continue
            chunk = f.read(_GO_BIN_MAX_READ)
            if _GO_BUILDINFO_MAGIC not in chunk:
                continue
            # Extract dep lines: dep\t<module>\t<version>
            for m in _GO_DEP_LINE_RE.finditer(chunk):
                mod_path = m.group(1).decode("utf-8", errors="ignore").strip()
                mod_ver = m.group(2).decode("utf-8", errors="ignore").strip()
                if mod_path and mod_ver:
                    _add_package(
                        packages_by_key,
                        packages,
                        mod_path,
                        mod_ver,
                        "golang",
                        f"pkg:golang/{mod_path}@{mod_ver}",
                        layer=layer,
                        package_path=member_name,
                    )
        except Exception:
            _logger.debug("Skipped Go binary: %s", member_name)

    # --- Ruby gems: specifications/*.gemspec ---
    for member_name in names:
        if not _GEMSPEC_PATH_RE.search(member_name):
            continue
        if _is_deleted(member_name):
            continue
        try:
            f = _safe_extractfile(layer_tf, member_name)
            if f is None:
                continue
            content = f.read(32 * 1024).decode("utf-8", errors="ignore")
            name_m = _GEMSPEC_NAME_RE.search(content)
            ver_m = _GEMSPEC_VER_RE.search(content)
            if name_m and ver_m:
                gem_name = name_m.group(1)
                gem_ver = ver_m.group(1)
                _add_package(
                    packages_by_key,
                    packages,
                    gem_name,
                    gem_ver,
                    "gem",
                    f"pkg:gem/{gem_name}@{gem_ver}",
                    layer=layer,
                    package_path=member_name,
                )
        except Exception:
            _logger.debug("Skipped gemspec: %s", member_name)

    # --- .NET: *.deps.json (libraries section, type=package) ---
    for member_name in names:
        if not member_name.endswith(".deps.json"):
            continue
        if _is_deleted(member_name):
            continue
        try:
            f = _safe_extractfile(layer_tf, member_name)
            if f is None:
                continue
            deps = json.loads(f.read().decode("utf-8", errors="ignore"))
            for lib_key, lib_val in deps.get("libraries", {}).items():
                if lib_val.get("type") != "package":
                    continue
                # key format: "PackageName/1.2.3"
                if "/" in lib_key:
                    pkg_name, _, pkg_ver = lib_key.rpartition("/")
                    if pkg_name and pkg_ver:
                        _add_package(
                            packages_by_key,
                            packages,
                            pkg_name,
                            pkg_ver,
                            "nuget",
                            f"pkg:nuget/{pkg_name}@{pkg_ver}",
                            layer=layer,
                            package_path=member_name,
                        )
        except Exception:
            _logger.debug("Skipped deps.json: %s", member_name)

    # --- PHP: composer.lock ---
    for composer_path in (
        "app/composer.lock",
        "var/www/composer.lock",
        "var/www/html/composer.lock",
        "srv/composer.lock",
        "home/composer.lock",
    ):
        # Also check with ./ prefix
        for prefix in ("", "./"):
            path = prefix + composer_path
            if path not in names or _is_deleted(path):
                continue
            try:
                f = _safe_extractfile(layer_tf, path)
                if f is None:
                    continue
                data = json.loads(f.read().decode("utf-8", errors="ignore"))
                for section in ("packages", "packages-dev"):
                    for pkg in data.get(section, []):
                        name = pkg.get("name", "")
                        version = pkg.get("version", "unknown").lstrip("v")
                        if name:
                            _add_package(
                                packages_by_key,
                                packages,
                                name,
                                version,
                                "composer",
                                f"pkg:composer/{name}@{version}",
                                layer=layer,
                                package_path=path,
                            )
            except Exception:
                _logger.debug("Failed to parse composer.lock: %s", path)

    # --- Rust: Cargo.lock ---
    for cargo_path in ("app/Cargo.lock", "usr/src/Cargo.lock", "home/Cargo.lock", "opt/Cargo.lock", "srv/Cargo.lock"):
        for prefix in ("", "./"):
            path = prefix + cargo_path
            if path not in names or _is_deleted(path):
                continue
            try:
                f = _safe_extractfile(layer_tf, path)
                if f is None:
                    continue
                content = f.read().decode("utf-8", errors="ignore")
                # Parse TOML-style [[package]] sections
                import re as _re

                for block in _re.split(r"\[\[package\]\]", content):
                    name_m = _re.search(r'name\s*=\s*"([^"]+)"', block)
                    ver_m = _re.search(r'version\s*=\s*"([^"]+)"', block)
                    if name_m and ver_m:
                        _add_package(
                            packages_by_key,
                            packages,
                            name_m.group(1),
                            ver_m.group(1),
                            "cargo",
                            f"pkg:cargo/{name_m.group(1)}@{ver_m.group(1)}",
                            layer=layer,
                            package_path=path,
                        )
            except Exception:
                _logger.debug("Failed to parse Cargo.lock: %s", path)

    # --- Swift: Package.resolved ---
    for swift_path in ("app/Package.resolved", "Package.resolved", "Sources/Package.resolved"):
        for prefix in ("", "./"):
            path = prefix + swift_path
            if path not in names or _is_deleted(path):
                continue
            try:
                f = _safe_extractfile(layer_tf, path)
                if f is None:
                    continue
                data = json.loads(f.read().decode("utf-8", errors="ignore"))
                pins = data.get("pins", [])
                if not pins and "object" in data:
                    pins = data["object"].get("pins", [])
                for pin in pins:
                    identity = pin.get("identity", "")
                    location = pin.get("location", pin.get("repositoryURL", ""))
                    version = pin.get("state", {}).get("version") or "unknown"
                    name = identity or (location.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git") if location else "")
                    if name:
                        _add_package(
                            packages_by_key,
                            packages,
                            name,
                            version,
                            "swift",
                            f"pkg:swift/{name}@{version}",
                            layer=layer,
                            package_path=path,
                        )
            except Exception:
                _logger.debug("Failed to parse Package.resolved: %s", path)

    return whiteouts


# ─── Docker save tarball format ───────────────────────────────────────────────


def _parse_docker_save_manifest(tf: tarfile.TarFile) -> list[OCIManifest]:
    """Parse manifest.json from a Docker save tarball."""
    try:
        member = tf.getmember("manifest.json")
        if member.size > _max_json_member_bytes():
            raise OCIParseError("manifest.json exceeds parser size limit")
        f = tf.extractfile(member)
        if f is None:
            raise OCIParseError("manifest.json is not a regular file")
        data = f.read(_max_json_member_bytes() + 1)
        if len(data) > _max_json_member_bytes():
            raise OCIParseError("manifest.json exceeds parser size limit")
        raw = json.loads(data.decode("utf-8"))
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
    layer_metadata: list[LayerMetadata] | None = None,
) -> tuple[list[Package], list[str]]:
    """Open each layer tarball from the outer tarball and extract packages.

    Layers are processed in order (base → top). Whiteout files in later
    layers are accumulated to suppress packages deleted from earlier layers.

    Returns:
        (packages, warnings)
    """
    packages_by_key: dict[tuple[str, str], Package] = {}
    packages: list[Package] = []
    warnings: list[str] = []
    detected_distro_name: str | None = None
    detected_distro_version: str | None = None
    layer_metadata = layer_metadata or _build_layer_metadata(layer_paths)

    # First pass: collect all whiteouts per layer (in order)
    # Then second pass: extract packages respecting accumulated deletions.
    # For simplicity: single-pass, accumulate deletions from current layer
    # only. Full whiteout handling would require two passes.
    all_deleted: set[str] = set()

    for layer_path, layer in zip(layer_paths, layer_metadata, strict=False):
        member = _resolve_tar_member(outer_tf, layer_path)

        if member is None:
            warnings.append(f"Layer not found in tarball: {layer_path}")
            continue

        layer_fobj = outer_tf.extractfile(member)
        if layer_fobj is None:
            warnings.append(f"Layer is not a regular file: {layer_path}")
            continue

        # Read into memory to allow tarfile to seek.
        # Cap at 2 GB to prevent OOM on very large image layers (e.g. ML model weights).
        max_layer_bytes = 2 * 1024 * 1024 * 1024  # 2 GB
        layer_bytes = layer_fobj.read(max_layer_bytes + 1)
        if len(layer_bytes) > max_layer_bytes:
            warnings.append(f"Layer {layer_path} exceeds 2 GB — skipped to avoid OOM")
            continue
        try:
            with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode="r:*") as layer_tf:
                uncompressed_bytes = _tar_uncompressed_regular_size(layer_tf)
                if uncompressed_bytes > _max_layer_uncompressed_bytes():
                    warnings.append(f"Layer {layer_path} exceeds uncompressed extraction limit — skipped")
                    continue
                layer_distro_name, layer_distro_version = _read_os_release_from_layer(layer_tf, all_deleted)
                if layer_distro_name:
                    detected_distro_name = layer_distro_name
                if layer_distro_version:
                    detected_distro_version = layer_distro_version
                whiteouts = _extract_packages_from_layer(layer_tf, packages_by_key, packages, all_deleted, layer)
                all_deleted.update(whiteouts)
        except tarfile.TarError as e:
            warnings.append(f"Failed to read layer {layer_path}: {e}")
            continue

    if detected_distro_name or detected_distro_version:
        for pkg in packages:
            if pkg.ecosystem in {"deb", "apk", "rpm"}:
                pkg.distro_name = pkg.distro_name or detected_distro_name
                pkg.distro_version = pkg.distro_version or detected_distro_version

    return packages, warnings


# ─── OCI image layout format ──────────────────────────────────────────────────


def _parse_oci_layout_manifest_from_tar(tf: tarfile.TarFile) -> tuple[dict, list[str], dict | None]:
    """Parse index/manifest/config from an OCI image layout tarball."""
    try:
        member = _resolve_tar_member(tf, "index.json")
        if member is None:
            raise OCIParseError("No index.json found — not an OCI image layout tarball")
        if member.size > _max_json_member_bytes():
            raise OCIParseError("index.json exceeds parser size limit")
        f = tf.extractfile(member)
        if f is None:
            raise OCIParseError("index.json is not a regular file")
        data = f.read(_max_json_member_bytes() + 1)
        if len(data) > _max_json_member_bytes():
            raise OCIParseError("index.json exceeds parser size limit")
        index = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise OCIParseError(f"Invalid index.json: {e}")

    manifests = index.get("manifests", [])
    if not manifests:
        raise OCIParseError("No manifests in OCI index.json")

    manifest_digest = manifests[0].get("digest", "")
    if not manifest_digest.startswith("sha256:"):
        raise OCIParseError(f"Unsupported manifest digest: {manifest_digest}")

    manifest_hash = manifest_digest[len("sha256:") :]
    blob_path = f"blobs/sha256/{manifest_hash}"
    manifest = _read_json_member_from_tar(tf, blob_path)
    if manifest is None:
        raise OCIParseError(f"Failed to read OCI manifest blob: {blob_path}")

    layer_paths = [
        f"blobs/sha256/{digest[len('sha256:') :]}"
        for layer in manifest.get("layers", [])
        if (digest := layer.get("digest", "")).startswith("sha256:")
    ]

    config: dict | None = None
    config_digest = manifest.get("config", {}).get("digest", "")
    if config_digest.startswith("sha256:"):
        config = _read_json_member_from_tar(tf, f"blobs/sha256/{config_digest[len('sha256:') :]}")

    return manifest, layer_paths, config


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
            config = _read_json_member_from_tar(outer_tf, manifest.config_digest)
            layer_metadata = _build_layer_metadata(manifest.layer_paths, config)
            packages, warnings = _parse_layers_from_tarball(outer_tf, manifest.layer_paths, layer_metadata)
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
                _manifest, layer_paths, config = _parse_oci_layout_manifest_from_tar(outer_tf)
            except OCIParseError:
                raise
            layer_metadata = _build_layer_metadata(layer_paths, config)
            packages, warnings = _parse_layers_from_tarball(outer_tf, layer_paths, layer_metadata)
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

    index = _read_json_path_limited(index_path)
    if not isinstance(index, dict):
        raise OCIParseError("Failed to read index.json")

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

    manifest = _read_json_path_limited(manifest_blob)
    if not isinstance(manifest, dict):
        raise OCIParseError("Failed to read manifest blob")

    layer_digests = [
        digest[len("sha256:") :] for layer in manifest.get("layers", []) if (digest := layer.get("digest", "")).startswith("sha256:")
    ]
    layer_paths = [f"blobs/sha256/{layer_hash}" for layer_hash in layer_digests]
    config: dict | None = None
    config_digest = manifest.get("config", {}).get("digest", "")
    if config_digest.startswith("sha256:"):
        config_blob = path / "blobs" / "sha256" / config_digest[len("sha256:") :]
        if config_blob.exists():
            maybe_config = _read_json_path_limited(config_blob)
            config = maybe_config if isinstance(maybe_config, dict) else None
    layer_metadata = _build_layer_metadata(layer_paths, config)

    packages_by_key: dict[tuple[str, str], Package] = {}
    packages: list[Package] = []
    warnings: list[str] = []
    all_deleted: set[str] = set()

    for layer_hash, layer in zip(layer_digests, layer_metadata, strict=False):
        blob_path = path / "blobs" / "sha256" / layer_hash
        if not blob_path.exists():
            warnings.append(f"Layer blob not found: {blob_path}")
            continue
        try:
            with tarfile.open(str(blob_path), mode="r:*") as layer_tf:
                uncompressed_bytes = _tar_uncompressed_regular_size(layer_tf)
                if uncompressed_bytes > _max_layer_uncompressed_bytes():
                    warnings.append(f"Layer {layer_hash[:12]} exceeds uncompressed extraction limit — skipped")
                    continue
                whiteouts = _extract_packages_from_layer(layer_tf, packages_by_key, packages, all_deleted, layer)
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
