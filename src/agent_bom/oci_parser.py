"""Native OCI / Docker-save image layer parser — no external tools required.

Parses OCI image tarballs created by ``docker save <image> -o image.tar``
or OCI image layout directories (from skopeo/crane) and extracts packages
without requiring Grype, Syft, or Docker CLI.

Supported image formats:
- **Docker save tarball** — ``manifest.json`` + ``<hash>/layer.tar`` inside outer tar.
- **OCI image layout tarball** — ``index.json`` + ``blobs/sha256/<hash>`` inside outer tar.
- **OCI image layout directory** — same structure, unarchived (for skopeo/crane output).

Package ecosystems extracted from each layer filesystem:
- Python: ``*.dist-info/METADATA`` (modern wheels) and the legacy
  ``*.egg-info/PKG-INFO`` / ``*.egg-info/METADATA`` (setuptools/pip on older
  base images such as Debian buster ship pip/setuptools/wheel this way)
- Node: ``node_modules/*/package.json``
- Debian/Ubuntu: ``var/lib/dpkg/status``
- Alpine Linux: ``lib/apk/db/installed``
- RPM: modern SQLite plus legacy BerkeleyDB/NDB package databases and ``var/log/installed-rpms``
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
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Optional

from agent_bom.coverage import record_scan_input_warning
from agent_bom.models import Package, PackageOccurrence
from agent_bom.package_utils import parse_debian_source_name
from agent_bom.parsers.cpython_runtime import _python_metadata_kind, extract_cpython_runtime

_logger = logging.getLogger(__name__)
_MAX_JSON_MEMBER_BYTES = 100 * 1024 * 1024
_MAX_LAYER_UNCOMPRESSED_BYTES = 5 * 1024 * 1024 * 1024
_MAX_JAR_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
_MAX_DECOMPRESSION_RATIO = 100


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


def _max_decompression_ratio() -> int:
    return _env_int("AGENT_BOM_OCI_MAX_DECOMPRESSION_RATIO", _MAX_DECOMPRESSION_RATIO)


def _decompression_ratio_exceeded(uncompressed_bytes: int, compressed_bytes: int) -> bool:
    if compressed_bytes <= 0 or uncompressed_bytes <= 0:
        return False
    return uncompressed_bytes > compressed_bytes * _max_decompression_ratio()


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
# Legacy RPM database paths: BerkeleyDB ``Packages`` (RPM < 4.16,
# RHEL/CentOS <= 8 and older UBI images) and NDB ``Packages.db``.
_RPM_BDB_PATHS = ("var/lib/rpm/Packages", "./var/lib/rpm/Packages")
_RPM_NDB_PATHS = ("var/lib/rpm/Packages.db", "./var/lib/rpm/Packages.db")
_RPM_MANIFEST_PATHS = ("var/log/installed-rpms", "./var/log/installed-rpms")
_RPM_MANIFEST_RE = re.compile(r"^(?P<name>.+)-(?P<version>[0-9][^-]*)-(?P<release>\S+)$")
_MAX_LEGACY_RPMDB_BYTES = 512 * 1024 * 1024
# RPM header magic (8 bytes)
_RPM_HDR_MAGIC = b"\x8e\xad\xe8\x01\x00\x00\x00\x00"
_RPMTAG_NAME = 1000
_RPMTAG_VERSION = 1001
_RPMTAG_RELEASE = 1002
_RPMTAG_EPOCH = 1003
_RPMTAG_ARCH = 1022
_RPM_TYPE_INT32 = 4
_RPM_TYPE_STRING = 6


@dataclass
class OCIManifest:
    """Parsed image manifest (Docker save or OCI layout)."""

    config_digest: str
    repo_tags: list[str]
    layer_paths: list[str]  # paths inside the outer tarball


@dataclass(frozen=True)
class OCIInputWarning:
    """One container input that could not be completely inspected."""

    path: str
    reason: str
    detail: str


@dataclass
class OCIParseResult:
    """Result of parsing an OCI image tarball or directory."""

    packages: list[Package]
    strategy: str  # "oci-tarball" | "oci-layout-dir"
    layer_count: int
    image_tags: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    coverage_warnings: list[OCIInputWarning] = field(default_factory=list)


_PACKAGE_METADATA_WARNING_DETAIL = "Container package metadata could not be parsed; image inventory is incomplete."


def is_node_package_manifest_path(member_path: str) -> bool:
    """Return whether a path is an npm package-root manifest.

    Packages may contain subpath ``package.json`` files for export conditions
    (for example ``nanoid/non-secure/package.json``).  Those are not inventory
    candidates and a missing name/version there is not incomplete coverage.
    """
    normalized = member_path.replace("\\", "/")
    marker = "/node_modules/"
    if marker not in normalized or not normalized.endswith("/package.json"):
        return False
    if normalized.count(marker) != 1:
        return False
    relative = normalized.split(marker, 1)[1].split("/")
    if len(relative) == 2:
        return not relative[0].startswith("@") and relative[1] == "package.json"
    return len(relative) == 3 and relative[0].startswith("@") and relative[2] == "package.json"


def _append_oci_warning(
    warnings: list[str],
    coverage_warnings: list[OCIInputWarning],
    *,
    path: str,
    reason: str,
    detail: str,
    message: str | None = None,
) -> None:
    """Preserve the parser diagnostic and its structured coverage consequence."""
    warnings.append(message or f"{path}: {detail}")
    coverage_warnings.append(OCIInputWarning(path=path, reason=reason, detail=detail))


def _mark_package_metadata_gap(
    warnings: list[str] | None,
    coverage_warnings: list[OCIInputWarning] | None,
    member_path: str,
) -> None:
    if warnings is None or coverage_warnings is None:
        return
    _append_oci_warning(
        warnings,
        coverage_warnings,
        path=member_path,
        reason="package_metadata_parse_error",
        detail=_PACKAGE_METADATA_WARNING_DETAIL,
        message=f"Container package metadata could not be parsed: {member_path}",
    )


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


def _zip_compressed_size(zf: zipfile.ZipFile) -> int:
    total = 0
    for info in zf.infolist():
        total += max(0, int(info.compress_size))
    return total


# ─── RPM header parser ────────────────────────────────────────────────────────


def _parse_rpm_header_blob(blob: bytes) -> Optional[tuple[str, str]]:
    """Parse a minimal RPM header blob and return (name, version) or None.

    RPM header layout (big-endian):
    - 8 bytes magic  -- PRESENT on legacy BerkeleyDB/NDB records, ABSENT in the
      ``rpmdb.sqlite`` ``Packages.blob`` column
    - 4 bytes nindex (number of tag entries)
    - 4 bytes hsize (size of data section)
    - nindex × 16-byte entries: tag(4) type(4) offset(4) count(4)
    - data section (hsize bytes)

    Both framings are accepted. Requiring the magic meant every blob from a
    ``rpmdb.sqlite`` returned None, so RHEL 9+, UBI9, Fedora 33+, Amazon Linux
    2023 and Rocky 9 images -- everything on RPM >= 4.16, which is the default
    backend -- reported **zero** OS packages and therefore zero OS CVEs. A
    scanner that finds nothing on the most common enterprise base image is the
    "reports less than it found" failure, and it looks clean.
    """
    if len(blob) < 16:
        return None
    try:
        if blob[:8] == _RPM_HDR_MAGIC:
            nindex = struct.unpack_from(">I", blob, 8)[0]
            index_start = 16
        else:
            # sqlite framing: the record begins at nindex directly.
            nindex = struct.unpack_from(">I", blob, 0)[0]
            index_start = 8
        # A wild nindex means this is not a header at all; bound it before it
        # becomes a multi-gigabyte slice.
        if nindex == 0 or nindex > 100_000:
            return None
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

        def _read_int32(tag_id: int) -> int:
            if tag_id not in tags:
                return 0
            type_, offset = tags[tag_id]
            abs_pos = data_start + offset
            if type_ != _RPM_TYPE_INT32 or abs_pos < data_start or abs_pos + 4 > len(blob):
                return 0
            return struct.unpack_from(">I", blob, abs_pos)[0]

        name = _read_str(_RPMTAG_NAME)
        version = _read_str(_RPMTAG_VERSION)
        release = _read_str(_RPMTAG_RELEASE)
        epoch = _read_int32(_RPMTAG_EPOCH)
        if not name or not version:
            return None
        full_version = f"{version}-{release}" if release else version
        if epoch:
            full_version = f"{epoch}:{full_version}"
        return name, full_version
    except (struct.error, OverflowError):
        return None


def _parse_legacy_rpmdb_bytes(database: bytes) -> list[tuple[str, str]]:
    """Extract embedded RPM header records from BerkeleyDB or NDB payloads.

    Both legacy backends store canonical RPM header blobs as record values. The
    database page/index format is backend-specific, but the value format is not:
    every package header starts with ``_RPM_HDR_MAGIC`` and carries bounded index
    and data lengths. Scanning for those self-describing records avoids a native
    BerkeleyDB dependency while preserving exact RPM name/version/release data.
    """
    packages: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    cursor = 0
    while True:
        start = database.find(_RPM_HDR_MAGIC, cursor)
        if start < 0:
            break
        cursor = start + len(_RPM_HDR_MAGIC)
        if start + 16 > len(database):
            continue
        try:
            nindex, hsize = struct.unpack_from(">II", database, start + 8)
        except struct.error:
            continue
        if nindex > 100_000 or hsize > _MAX_LEGACY_RPMDB_BYTES:
            continue
        record_size = 16 + nindex * 16 + hsize
        end = start + record_size
        if record_size < 16 or end > len(database):
            continue
        parsed = _parse_rpm_header_blob(database[start:end])
        if parsed is None or parsed[0] == "gpg-pubkey" or parsed in seen:
            continue
        seen.add(parsed)
        packages.append(parsed)
        cursor = end
    return packages


def _query_legacy_rpmdb(layer_tf: tarfile.TarFile, database_path: str) -> list[tuple[str, str]]:
    """Read and decode one bounded BerkeleyDB/NDB package database member."""
    member = _safe_getmember(layer_tf, database_path)
    if member is None or not member.isfile() or member.size > _MAX_LEGACY_RPMDB_BYTES:
        raise OCIParseError("Legacy RPM database is missing, invalid, or exceeds the 512 MiB safety limit")
    source = _safe_extractfile(layer_tf, database_path)
    if source is None:
        raise OCIParseError("Legacy RPM database could not be read safely")
    packages = _parse_legacy_rpmdb_bytes(source.read())
    if not packages:
        raise OCIParseError("Legacy RPM database contains no valid package header records")
    return packages


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


def _parse_rfc822_name_version(fileobj: IO[bytes]) -> tuple[str, str]:
    """Extract ``Name``/``Version`` from an RFC822 Python metadata stream.

    Shared by the modern ``*.dist-info/METADATA`` and the legacy
    ``*.egg-info/PKG-INFO`` (or ``*.egg-info/METADATA``) parsers — both use the
    same header format, only the file location differs.
    """
    pkg_name = pkg_version = ""
    for raw_line in fileobj:
        line = raw_line.decode("utf-8", errors="ignore").strip()
        if line.startswith("Name:"):
            pkg_name = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            pkg_version = line.split(":", 1)[1].strip()
        if pkg_name and pkg_version:
            break
    return pkg_name, pkg_version


def _read_os_release_from_layer(layer_tf: tarfile.TarFile, deleted_paths: set[str]) -> tuple[str | None, str | None]:
    """Read distro metadata from ``os-release`` inside a layer.

    Probes both the canonical ``usr/lib/os-release`` location and the historic
    ``etc/os-release`` path. On Debian/Ubuntu ``/etc/os-release`` is a symlink
    to ``/usr/lib/os-release``; the parser refuses to follow symlinks, so the
    real file under ``usr/lib`` must be probed directly or distro detection
    silently fails (which mis-routes OS-package CVE matching to the wrong
    distribution release).
    """
    for os_release_path in (
        "etc/os-release",
        "./etc/os-release",
        "usr/lib/os-release",
        "./usr/lib/os-release",
    ):
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


@dataclass
class _LayerScan:
    """One layer's member names plus the sinks every package stage writes to."""

    layer_tf: tarfile.TarFile
    names: set[str]
    deleted_paths: set[str]
    layer: LayerMetadata
    packages_by_key: dict[tuple[str, str], Package]
    packages: list[Package]
    warnings: list[str] | None
    coverage_warnings: list[OCIInputWarning] | None

    def is_deleted(self, path: str) -> bool:
        if path in self.deleted_paths:
            return True
        # Opaque whiteouts delete whole directories.
        for dp in self.deleted_paths:
            if dp.endswith("/") and path.startswith(dp):
                return True
        return False

    def present(self, path: str) -> bool:
        return path in self.names and not self.is_deleted(path)

    def add(
        self, path: str, name: str, version: str, ecosystem: str, purl: str | None = None, *, source_package: str | None = None
    ) -> None:
        _add_package(
            self.packages_by_key,
            self.packages,
            name,
            version,
            ecosystem,
            purl,
            source_package=source_package,
            layer=self.layer,
            package_path=path,
        )

    def gap(self, path: str) -> None:
        _mark_package_metadata_gap(self.warnings, self.coverage_warnings, path)


def _layer_whiteouts(names: set[str]) -> set[str]:
    whiteouts: set[str] = set()
    for member_name in names:
        base = member_name.split("/")[-1]
        if base == _OPAQUE_WHITEOUT:
            parent = "/".join(member_name.split("/")[:-1])
            whiteouts.add(parent + "/")
        elif base.startswith(_WHITEOUT_PREFIX):
            real_name = base[len(_WHITEOUT_PREFIX) :]
            parent = "/".join(member_name.split("/")[:-1])
            path = f"{parent}/{real_name}" if parent else real_name
            whiteouts.add(path)
    return whiteouts


def _parse_members(scan: _LayerScan, paths: Iterable[str], parse: Callable[[_LayerScan, str], None], failure: str) -> None:
    for path in paths:
        if scan.is_deleted(path):
            continue
        try:
            parse(scan, path)
        except Exception:
            _logger.debug(failure, path)
            scan.gap(path)


def _present_candidates(scan: _LayerScan, bases: tuple[str, ...]) -> Iterator[str]:
    for base in bases:
        for prefix in ("", "./"):
            if prefix + base in scan.names:
                yield prefix + base


def _extract_python_metadata(scan: _LayerScan) -> None:
    extract_cpython_runtime(scan, _safe_extractfile)
    # Older base images (e.g. Debian buster) ship pip/setuptools/wheel as
    # ``*.egg-info/PKG-INFO`` rather than ``*.dist-info/METADATA``; both use the
    # same RFC822 headers and ``_add_package`` dedupes a package found via both.
    for member_name in scan.names:
        metadata_kind = _python_metadata_kind(member_name)
        if metadata_kind is None or scan.is_deleted(member_name):
            continue
        try:
            f = _safe_extractfile(scan.layer_tf, member_name)
            if f is None:
                scan.gap(member_name)
                continue
            pkg_name, pkg_version = _parse_rfc822_name_version(f)
            if pkg_name and pkg_version:
                scan.add(member_name, pkg_name, pkg_version, "pypi")
            else:
                scan.gap(member_name)
        except Exception:
            _logger.debug("Skipped Python %s metadata: %s", metadata_kind, member_name)
            scan.gap(member_name)


def _add_node_manifest(scan: _LayerScan, path: str) -> None:
    f = _safe_extractfile(scan.layer_tf, path)
    if f is None:
        scan.gap(path)
        return
    data = json.loads(f.read().decode("utf-8", errors="ignore"))
    pkg_name = data.get("name", "")
    pkg_version = data.get("version", "unknown")
    if pkg_name:
        scan.add(path, pkg_name, pkg_version, "npm")
    else:
        scan.gap(path)


def _extract_node_manifests(scan: _LayerScan) -> None:
    paths = (name for name in scan.names if is_node_package_manifest_path(name))
    _parse_members(scan, paths, _add_node_manifest, "Skipped Node package.json: %s")


def _add_dpkg_entries(scan: _LayerScan, path: str, content: str) -> bool:
    parsed_package = False
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
            scan.add(path, pkg_name, pkg_version, "deb", f"pkg:deb/debian/{pkg_name}@{pkg_version}", source_package=source_package)
            parsed_package = True
            pkg_name = pkg_version = ""
            source_package = None
    if pkg_name and pkg_version:
        scan.add(path, pkg_name, pkg_version, "deb", f"pkg:deb/debian/{pkg_name}@{pkg_version}", source_package=source_package)
        parsed_package = True
    return parsed_package


def _add_apk_entries(scan: _LayerScan, path: str, content: str) -> bool:
    parsed_package = False
    pkg_name = pkg_version = ""
    source_package: str | None = None
    for line in content.splitlines():
        if line.startswith("P:"):
            pkg_name = line[2:].strip()
        elif line.startswith("V:"):
            pkg_version = line[2:].strip()
        elif line.startswith("o:") or line.startswith("O:"):
            source_package = line[2:].strip() or None
        elif line == "" and pkg_name and pkg_version:
            scan.add(path, pkg_name, pkg_version, "apk", f"pkg:apk/alpine/{pkg_name}@{pkg_version}", source_package=source_package)
            parsed_package = True
            pkg_name = pkg_version = ""
            source_package = None
    if pkg_name and pkg_version:
        scan.add(path, pkg_name, pkg_version, "apk", f"pkg:apk/alpine/{pkg_name}@{pkg_version}", source_package=source_package)
        parsed_package = True
    return parsed_package


def _extract_stanza_database(
    scan: _LayerScan, paths: tuple[str, ...], add_entries: Callable[[_LayerScan, str, str], bool], failure: str
) -> None:
    """Parse the first live copy of a blank-line separated package database."""
    for path in paths:
        if not scan.present(path):
            continue
        try:
            f = _safe_extractfile(scan.layer_tf, path)
            if f:
                content = f.read().decode("utf-8", errors="ignore")
                if not add_entries(scan, path, content) and content.strip():
                    scan.gap(path)
            else:
                scan.gap(path)
        except Exception:
            _logger.debug(failure)
            scan.gap(path)
        break


def _extract_dpkg_status(scan: _LayerScan) -> None:
    _extract_stanza_database(scan, ("var/lib/dpkg/status", "./var/lib/dpkg/status"), _add_dpkg_entries, "Failed to parse dpkg status")


def _extract_apk_installed(scan: _LayerScan) -> None:
    _extract_stanza_database(scan, ("lib/apk/db/installed", "./lib/apk/db/installed"), _add_apk_entries, "Failed to parse Alpine apk db")


def _add_rpm(scan: _LayerScan, path: str, rpm_name: str, rpm_ver: str) -> None:
    scan.add(path, rpm_name, rpm_ver, "rpm", f"pkg:rpm/redhat/{rpm_name}@{rpm_ver}")


def _add_rpm_manifest_lines(scan: _LayerScan, path: str, fileobj: IO[bytes]) -> tuple[bool, bool]:
    had_content = parsed_package = False
    for raw_line in fileobj:
        line = raw_line.decode("utf-8", errors="ignore").strip()
        if not line:
            continue
        had_content = True
        match = _RPM_MANIFEST_RE.match(line.split()[0])
        if match is None:
            continue
        parsed_package = True
        if match.group("name") != "gpg-pubkey":
            _add_rpm(scan, path, match.group("name"), match.group("version"))
    return had_content, parsed_package


def _extract_rpm_manifest(scan: _LayerScan) -> None:
    for rpm_path in _RPM_MANIFEST_PATHS:
        if not scan.present(rpm_path):
            continue
        try:
            f = _safe_extractfile(scan.layer_tf, rpm_path)
            if f:
                had_content, parsed_package = _add_rpm_manifest_lines(scan, rpm_path, f)
                if had_content and not parsed_package:
                    scan.gap(rpm_path)
            else:
                scan.gap(rpm_path)
        except Exception:
            _logger.debug("Failed to parse rpm manifest")
            scan.gap(rpm_path)
        break


def _add_rpm_sqlite_rows(scan: _LayerScan, path: str, db_bytes: bytes) -> None:
    # sqlite3 can only open a database from a real file.
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
        tmp.write(db_bytes)
        tmp_path = tmp.name
    try:
        conn = sqlite3.connect(tmp_path)
        try:
            rows = conn.execute("SELECT blob FROM Packages").fetchall()
            parsed_package = False
            for (blob,) in rows:
                result = _parse_rpm_header_blob(blob) if isinstance(blob, bytes) else None
                if result:
                    parsed_package = True
                    if result[0] != "gpg-pubkey":
                        _add_rpm(scan, path, *result)
            if rows and not parsed_package:
                scan.gap(path)
        finally:
            conn.close()
    finally:
        os.unlink(tmp_path)


def _extract_rpm_sqlite(scan: _LayerScan) -> None:
    for sqlite_path in _RPM_SQLITE_PATHS:
        if not scan.present(sqlite_path):
            continue
        try:
            f = _safe_extractfile(scan.layer_tf, sqlite_path)
            if f is None:
                scan.gap(sqlite_path)
                continue
            _add_rpm_sqlite_rows(scan, sqlite_path, f.read())
        except Exception:
            _logger.debug("Failed to parse rpmdb.sqlite")
            scan.gap(sqlite_path)
        break


def _extract_legacy_rpmdb(scan: _LayerScan) -> None:
    if any(scan.present(p) for p in (*_RPM_SQLITE_PATHS, *_RPM_MANIFEST_PATHS)):
        return
    legacy_rpmdb = next((p for p in (*_RPM_BDB_PATHS, *_RPM_NDB_PATHS) if scan.present(p)), None)
    if legacy_rpmdb:
        for rpm_name, rpm_ver in _query_legacy_rpmdb(scan.layer_tf, legacy_rpmdb):
            _add_rpm(scan, legacy_rpmdb, rpm_name, rpm_ver)


def _sized_jar_member(scan: _LayerScan, member_name: str) -> tarfile.TarInfo | None:
    member = _safe_getmember(scan.layer_tf, member_name)
    if member is None or member.size == 0:
        scan.gap(member_name)
        return None
    if member.size > _JAR_MAX_BYTES:
        if scan.warnings is not None and scan.coverage_warnings is not None:
            _append_oci_warning(
                scan.warnings,
                scan.coverage_warnings,
                path=member_name,
                reason="package_metadata_size_limit",
                detail="Container package metadata exceeds the JAR safety limit; image inventory is incomplete.",
                message=f"JAR exceeds package metadata size limit: {member_name}",
            )
        return None
    return member


def _jar_within_limits(zf: zipfile.ZipFile, member_name: str) -> bool:
    jar_uncompressed_bytes = _zip_uncompressed_size(zf)
    if jar_uncompressed_bytes > _max_jar_uncompressed_bytes():
        _logger.debug("Skipping oversized JAR payload: %s", member_name)
        return False
    if _decompression_ratio_exceeded(jar_uncompressed_bytes, _zip_compressed_size(zf)):
        _logger.debug("Skipping high-ratio compressed JAR payload: %s", member_name)
        return False
    return True


def _read_jar_pairs(zf: zipfile.ZipFile, entry: str, separator: str, skip_comments: bool) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for line in zf.read(entry).decode("utf-8", errors="ignore").splitlines():
        if separator in line and not (skip_comments and line.startswith("#")):
            key, _, value = line.partition(separator)
            pairs[key.strip()] = value.strip()
    return pairs


def _add_jar_pom_properties(scan: _LayerScan, member_name: str, zf: zipfile.ZipFile, jar_names: list[str]) -> bool:
    found = False
    pom_props_paths = [n for n in jar_names if re.match(r"META-INF/maven/[^/]+/[^/]+/pom\.properties$", n)]
    for prop_path in pom_props_paths:
        props = _read_jar_pairs(zf, prop_path, "=", skip_comments=True)
        artifact_id = props.get("artifactId", "")
        version = props.get("version", "")
        group_id = props.get("groupId", "")
        if artifact_id and version:
            purl = f"pkg:maven/{group_id}/{artifact_id}@{version}" if group_id else f"pkg:maven/{artifact_id}@{version}"
            scan.add(member_name, artifact_id, version, "maven", purl)
            found = True
    return found


def _add_jar_manifest(scan: _LayerScan, member_name: str, zf: zipfile.ZipFile) -> None:
    mf = _read_jar_pairs(zf, "META-INF/MANIFEST.MF", ": ", skip_comments=False)
    title = mf.get("Implementation-Title") or mf.get("Bundle-Name", "")
    version = mf.get("Implementation-Version") or mf.get("Bundle-Version", "")
    if title and version and not title.startswith("$") and not version.startswith("$"):
        scan.add(member_name, title, version, "maven")


def _add_jar_packages(scan: _LayerScan, member_name: str, member: tarfile.TarInfo) -> None:
    f = scan.layer_tf.extractfile(member)
    if f is None:
        scan.gap(member_name)
        return
    with zipfile.ZipFile(io.BytesIO(f.read())) as zf:
        if not _jar_within_limits(zf, member_name):
            return
        jar_names = zf.namelist()
        # Prefer pom.properties coordinates; MANIFEST.MF is the fallback.
        found = _add_jar_pom_properties(scan, member_name, zf, jar_names)
        if not found and "META-INF/MANIFEST.MF" in jar_names:
            _add_jar_manifest(scan, member_name, zf)


def _extract_jars(scan: _LayerScan) -> None:
    for member_name in scan.names:
        if not _JAR_EXT_RE.search(member_name) or scan.is_deleted(member_name):
            continue
        # Tar paths may lack a leading '/'; prepend one for hint matching.
        name_for_hint = "/" + member_name.lower()
        if not any(hint in name_for_hint for hint in _JAR_DIR_HINTS):
            continue
        member = _sized_jar_member(scan, member_name)
        if member is None:
            continue
        try:
            _add_jar_packages(scan, member_name, member)
        except Exception:
            _logger.debug("Skipped JAR: %s", member_name)
            scan.gap(member_name)


def _add_go_buildinfo(scan: _LayerScan, member_name: str, member: tarfile.TarInfo) -> None:
    f = scan.layer_tf.extractfile(member)
    if f is None:
        return
    chunk = f.read(_GO_BIN_MAX_READ)
    if _GO_BUILDINFO_MAGIC not in chunk:
        return
    for m in _GO_DEP_LINE_RE.finditer(chunk):
        mod_path = m.group(1).decode("utf-8", errors="ignore").strip()
        mod_ver = m.group(2).decode("utf-8", errors="ignore").strip()
        if mod_path and mod_ver:
            scan.add(member_name, mod_path, mod_ver, "golang", f"pkg:golang/{mod_path}@{mod_ver}")


def _extract_go_binaries(scan: _LayerScan) -> None:
    for member_name in scan.names:
        if not _GO_BIN_DIR_RE.match(member_name) or scan.is_deleted(member_name):
            continue
        member = _safe_getmember(scan.layer_tf, member_name)
        if member is None or member.size < 64:
            continue
        try:
            _add_go_buildinfo(scan, member_name, member)
        except Exception:
            _logger.debug("Skipped Go binary: %s", member_name)


def _add_gemspec(scan: _LayerScan, path: str) -> None:
    f = _safe_extractfile(scan.layer_tf, path)
    if f is None:
        scan.gap(path)
        return
    content = f.read(32 * 1024).decode("utf-8", errors="ignore")
    name_m = _GEMSPEC_NAME_RE.search(content)
    ver_m = _GEMSPEC_VER_RE.search(content)
    if name_m and ver_m:
        scan.add(path, name_m.group(1), ver_m.group(1), "gem", f"pkg:gem/{name_m.group(1)}@{ver_m.group(1)}")
    else:
        scan.gap(path)


def _extract_gemspecs(scan: _LayerScan) -> None:
    paths = (name for name in scan.names if _GEMSPEC_PATH_RE.search(name))
    _parse_members(scan, paths, _add_gemspec, "Skipped gemspec: %s")


def _add_deps_json(scan: _LayerScan, path: str) -> None:
    f = _safe_extractfile(scan.layer_tf, path)
    if f is None:
        scan.gap(path)
        return
    deps = json.loads(f.read().decode("utf-8", errors="ignore"))
    for lib_key, lib_val in deps.get("libraries", {}).items():
        # Library keys are "PackageName/1.2.3"; only type=package entries are NuGet packages.
        if lib_val.get("type") != "package" or "/" not in lib_key:
            continue
        pkg_name, _, pkg_ver = lib_key.rpartition("/")
        if pkg_name and pkg_ver:
            scan.add(path, pkg_name, pkg_ver, "nuget", f"pkg:nuget/{pkg_name}@{pkg_ver}")


def _extract_deps_json(scan: _LayerScan) -> None:
    paths = (name for name in scan.names if name.endswith(".deps.json"))
    _parse_members(scan, paths, _add_deps_json, "Skipped deps.json: %s")


def _add_composer_lock(scan: _LayerScan, path: str) -> None:
    f = _safe_extractfile(scan.layer_tf, path)
    if f is None:
        scan.gap(path)
        return
    data = json.loads(f.read().decode("utf-8", errors="ignore"))
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []):
            name = pkg.get("name", "")
            version = pkg.get("version", "unknown").lstrip("v")
            if name:
                scan.add(path, name, version, "composer", f"pkg:composer/{name}@{version}")


def _extract_composer_locks(scan: _LayerScan) -> None:
    bases = ("app/composer.lock", "var/www/composer.lock", "var/www/html/composer.lock", "srv/composer.lock", "home/composer.lock")
    _parse_members(scan, _present_candidates(scan, bases), _add_composer_lock, "Failed to parse composer.lock: %s")


def _add_cargo_lock(scan: _LayerScan, path: str) -> None:
    f = _safe_extractfile(scan.layer_tf, path)
    if f is None:
        scan.gap(path)
        return
    content = f.read().decode("utf-8", errors="ignore")
    parsed_package = False
    for block in re.split(r"\[\[package\]\]", content):
        name_m = re.search(r'name\s*=\s*"([^"]+)"', block)
        ver_m = re.search(r'version\s*=\s*"([^"]+)"', block)
        if name_m and ver_m:
            scan.add(path, name_m.group(1), ver_m.group(1), "cargo", f"pkg:cargo/{name_m.group(1)}@{ver_m.group(1)}")
            parsed_package = True
    if "[[package]]" in content and not parsed_package:
        scan.gap(path)


def _extract_cargo_locks(scan: _LayerScan) -> None:
    bases = ("app/Cargo.lock", "usr/src/Cargo.lock", "home/Cargo.lock", "opt/Cargo.lock", "srv/Cargo.lock")
    _parse_members(scan, _present_candidates(scan, bases), _add_cargo_lock, "Failed to parse Cargo.lock: %s")


def _add_swift_resolved(scan: _LayerScan, path: str) -> None:
    f = _safe_extractfile(scan.layer_tf, path)
    if f is None:
        scan.gap(path)
        return
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
            scan.add(path, name, version, "swift", f"pkg:swift/{name}@{version}")


def _extract_swift_resolved(scan: _LayerScan) -> None:
    bases = ("app/Package.resolved", "Package.resolved", "Sources/Package.resolved")
    _parse_members(scan, _present_candidates(scan, bases), _add_swift_resolved, "Failed to parse Package.resolved: %s")


_LAYER_PACKAGE_STAGES: tuple[Callable[[_LayerScan], None], ...] = (
    _extract_python_metadata,
    _extract_node_manifests,
    _extract_dpkg_status,
    _extract_apk_installed,
    _extract_rpm_manifest,
    _extract_rpm_sqlite,
    _extract_legacy_rpmdb,
    _extract_jars,
    _extract_go_binaries,
    _extract_gemspecs,
    _extract_deps_json,
    _extract_composer_locks,
    _extract_cargo_locks,
    _extract_swift_resolved,
)


def _extract_packages_from_layer(
    layer_tf: tarfile.TarFile,
    packages_by_key: dict[tuple[str, str], Package],
    packages: list[Package],
    deleted_paths: set[str],
    layer: LayerMetadata,
    warnings: list[str] | None = None,
    coverage_warnings: list[OCIInputWarning] | None = None,
) -> set[str]:
    """Extract packages from an open layer TarFile.

    Args:
        layer_tf: Open TarFile for the layer.
        packages_by_key: Mutable package map keyed by (name, ecosystem).
        packages: Mutable list of packages — updated in place.
        deleted_paths: Set of paths deleted in LATER layers (whiteouts already processed).
        layer: Layer provenance metadata for this concrete tar blob.
        warnings: Optional mutable list for non-fatal parser diagnostics.
        coverage_warnings: Optional structured diagnostics for incomplete inputs.

    Returns:
        Set of paths marked as whiteout in THIS layer (for caller to accumulate).
    """
    # `_safe_tar_names` drops traversal, absolute, NUL-injected and link members.
    names = _safe_tar_names(layer_tf)
    whiteouts = _layer_whiteouts(names)
    scan = _LayerScan(layer_tf, names, deleted_paths, layer, packages_by_key, packages, warnings, coverage_warnings)
    for stage in _LAYER_PACKAGE_STAGES:
        stage(scan)
    return whiteouts


def _occurrence_whiteout_deleted(
    package_path: str | None,
    layer_index: int,
    whiteouts_by_index: dict[int, set[str]],
) -> bool:
    """Return True iff ``package_path`` is removed by a whiteout in a HIGHER layer.

    Per the OCI overlay spec a whiteout deletes paths from layers *below* it
    only. A file re-created in a higher layer therefore survives a lower-layer
    whiteout for the same path. Applying whiteouts as a post-filter scoped to
    strictly-higher layer indices captures both cases: genuine deletion (file in
    a low layer, whiteout above it) and re-add (file in the same or a higher
    layer than the whiteout — kept).
    """
    if not package_path:
        return False
    for whiteout_layer, paths in whiteouts_by_index.items():
        if whiteout_layer <= layer_index:
            continue
        for w in paths:
            if w.endswith("/"):
                if package_path == w[:-1] or package_path.startswith(w):
                    return True
            elif package_path == w or package_path.startswith(w + "/"):
                return True
    return False


def _drop_whiteout_deleted_packages(
    packages: list[Package],
    whiteouts_by_index: dict[int, set[str]],
) -> list[Package]:
    """Drop packages whose every occurrence was deleted by a higher-layer whiteout."""
    if not whiteouts_by_index:
        return packages
    kept: list[Package] = []
    for pkg in packages:
        occurrences = pkg.occurrences
        if not occurrences:
            kept.append(pkg)
            continue
        survivors = [occ for occ in occurrences if not _occurrence_whiteout_deleted(occ.package_path, occ.layer_index, whiteouts_by_index)]
        if survivors:
            pkg.occurrences = survivors
            kept.append(pkg)
    return kept


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
) -> tuple[list[Package], list[str], list[OCIInputWarning]]:
    """Open each layer tarball from the outer tarball and extract packages.

    Layers are processed in order (base → top). Whiteout files in later
    layers are accumulated to suppress packages deleted from earlier layers.

    Returns:
        (packages, warnings, coverage_warnings)
    """
    packages_by_key: dict[tuple[str, str], Package] = {}
    packages: list[Package] = []
    warnings: list[str] = []
    coverage_warnings: list[OCIInputWarning] = []
    detected_distro_name: str | None = None
    detected_distro_version: str | None = None
    layer_metadata = layer_metadata or _build_layer_metadata(layer_paths)

    # Whiteouts are applied as a post-filter (see _drop_whiteout_deleted_packages)
    # scoped to strictly-higher layers, so a file re-created in a higher layer is
    # not wrongly suppressed by a lower-layer whiteout for the same path (the bug
    # that silently dropped pip/setuptools dist-info on Debian-based images).
    whiteouts_by_index: dict[int, set[str]] = {}

    for layer_path, layer in zip(layer_paths, layer_metadata, strict=False):
        member = _resolve_tar_member(outer_tf, layer_path)

        if member is None:
            _append_oci_warning(
                warnings,
                coverage_warnings,
                path=layer_path,
                reason="oci_layer_missing",
                detail="Container layer was not present; image inventory is incomplete.",
                message=f"Layer not found in tarball: {layer_path}",
            )
            continue

        layer_fobj = outer_tf.extractfile(member)
        if layer_fobj is None:
            _append_oci_warning(
                warnings,
                coverage_warnings,
                path=layer_path,
                reason="oci_layer_unreadable",
                detail="Container layer could not be read safely; image inventory is incomplete.",
                message=f"Layer is not a regular file: {layer_path}",
            )
            continue

        # Read into memory to allow tarfile to seek.
        # Cap at 2 GB to prevent OOM on very large image layers (e.g. ML model weights).
        max_layer_bytes = 2 * 1024 * 1024 * 1024  # 2 GB
        layer_bytes = layer_fobj.read(max_layer_bytes + 1)
        if len(layer_bytes) > max_layer_bytes:
            _append_oci_warning(
                warnings,
                coverage_warnings,
                path=layer_path,
                reason="oci_layer_size_limit",
                detail="Container layer exceeds the 2 GiB compressed safety limit; image inventory is incomplete.",
                message=f"Layer {layer_path} exceeds 2 GB — skipped to avoid OOM",
            )
            continue
        try:
            with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode="r:*") as layer_tf:
                uncompressed_bytes = _tar_uncompressed_regular_size(layer_tf)
                if uncompressed_bytes > _max_layer_uncompressed_bytes():
                    _append_oci_warning(
                        warnings,
                        coverage_warnings,
                        path=layer_path,
                        reason="oci_layer_size_limit",
                        detail="Container layer exceeds the uncompressed safety limit; image inventory is incomplete.",
                        message=f"Layer {layer_path} exceeds uncompressed extraction limit — skipped",
                    )
                    continue
                if _decompression_ratio_exceeded(uncompressed_bytes, member.size):
                    _append_oci_warning(
                        warnings,
                        coverage_warnings,
                        path=layer_path,
                        reason="oci_layer_decompression_limit",
                        detail="Container layer exceeds the decompression-ratio safety limit; image inventory is incomplete.",
                        message=f"Layer {layer_path} exceeds decompression ratio limit — skipped",
                    )
                    continue
                layer_distro_name, layer_distro_version = _read_os_release_from_layer(layer_tf, set())
                if layer_distro_name:
                    detected_distro_name = layer_distro_name
                if layer_distro_version:
                    detected_distro_version = layer_distro_version
                whiteouts = _extract_packages_from_layer(
                    layer_tf,
                    packages_by_key,
                    packages,
                    set(),
                    layer,
                    warnings,
                    coverage_warnings,
                )
                if whiteouts:
                    whiteouts_by_index.setdefault(layer.layer_index, set()).update(whiteouts)
        except tarfile.TarError:
            _append_oci_warning(
                warnings,
                coverage_warnings,
                path=layer_path,
                reason="oci_layer_parse_error",
                detail="Container layer archive could not be parsed; image inventory is incomplete.",
                message=f"Failed to read layer {layer_path}",
            )
            continue

    packages = _drop_whiteout_deleted_packages(packages, whiteouts_by_index)

    if detected_distro_name or detected_distro_version:
        for pkg in packages:
            if pkg.ecosystem in {"deb", "apk", "rpm"}:
                pkg.distro_name = pkg.distro_name or detected_distro_name
                pkg.distro_version = pkg.distro_version or detected_distro_version

    return packages, warnings, coverage_warnings


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
                return OCIParseResult(
                    packages=[],
                    strategy="oci-tarball",
                    layer_count=0,
                    warnings=["Empty manifest.json"],
                    coverage_warnings=[
                        OCIInputWarning(
                            path="manifest.json",
                            reason="oci_manifest_empty",
                            detail="Container manifest contains no images; image inventory is incomplete.",
                        )
                    ],
                )
            # Use first image (most users save one image)
            manifest = manifests[0]
            config = _read_json_member_from_tar(outer_tf, manifest.config_digest)
            layer_metadata = _build_layer_metadata(manifest.layer_paths, config)
            packages, warnings, coverage_warnings = _parse_layers_from_tarball(outer_tf, manifest.layer_paths, layer_metadata)
            return OCIParseResult(
                packages=packages,
                strategy="oci-tarball",
                layer_count=len(manifest.layer_paths),
                image_tags=manifest.repo_tags,
                warnings=warnings,
                coverage_warnings=coverage_warnings,
            )

        elif "index.json" in names or "./index.json" in names:
            # OCI image layout format
            try:
                _manifest, layer_paths, config = _parse_oci_layout_manifest_from_tar(outer_tf)
            except OCIParseError:
                raise
            layer_metadata = _build_layer_metadata(layer_paths, config)
            packages, warnings, coverage_warnings = _parse_layers_from_tarball(outer_tf, layer_paths, layer_metadata)
            return OCIParseResult(
                packages=packages,
                strategy="oci-tarball",
                layer_count=len(layer_paths),
                warnings=warnings,
                coverage_warnings=coverage_warnings,
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
    coverage_warnings: list[OCIInputWarning] = []
    detected_distro_name: str | None = None
    detected_distro_version: str | None = None
    whiteouts_by_index: dict[int, set[str]] = {}

    for layer_hash, layer in zip(layer_digests, layer_metadata, strict=False):
        blob_path = path / "blobs" / "sha256" / layer_hash
        if not blob_path.exists():
            layer_path = f"blobs/sha256/{layer_hash}"
            _append_oci_warning(
                warnings,
                coverage_warnings,
                path=layer_path,
                reason="oci_layer_missing",
                detail="Container layer was not present; image inventory is incomplete.",
                message=f"Layer blob not found: {layer_path}",
            )
            continue
        try:
            with tarfile.open(str(blob_path), mode="r:*") as layer_tf:
                uncompressed_bytes = _tar_uncompressed_regular_size(layer_tf)
                if uncompressed_bytes > _max_layer_uncompressed_bytes():
                    layer_path = f"blobs/sha256/{layer_hash}"
                    _append_oci_warning(
                        warnings,
                        coverage_warnings,
                        path=layer_path,
                        reason="oci_layer_size_limit",
                        detail="Container layer exceeds the uncompressed safety limit; image inventory is incomplete.",
                        message=f"Layer {layer_hash[:12]} exceeds uncompressed extraction limit — skipped",
                    )
                    continue
                compressed_bytes = blob_path.stat().st_size
                if _decompression_ratio_exceeded(uncompressed_bytes, compressed_bytes):
                    layer_path = f"blobs/sha256/{layer_hash}"
                    _append_oci_warning(
                        warnings,
                        coverage_warnings,
                        path=layer_path,
                        reason="oci_layer_decompression_limit",
                        detail="Container layer exceeds the decompression-ratio safety limit; image inventory is incomplete.",
                        message=f"Layer {layer_hash[:12]} exceeds decompression ratio limit — skipped",
                    )
                    continue
                layer_distro_name, layer_distro_version = _read_os_release_from_layer(layer_tf, set())
                if layer_distro_name:
                    detected_distro_name = layer_distro_name
                if layer_distro_version:
                    detected_distro_version = layer_distro_version
                whiteouts = _extract_packages_from_layer(
                    layer_tf,
                    packages_by_key,
                    packages,
                    set(),
                    layer,
                    warnings,
                    coverage_warnings,
                )
                if whiteouts:
                    whiteouts_by_index.setdefault(layer.layer_index, set()).update(whiteouts)
        except tarfile.TarError:
            layer_path = f"blobs/sha256/{layer_hash}"
            _append_oci_warning(
                warnings,
                coverage_warnings,
                path=layer_path,
                reason="oci_layer_parse_error",
                detail="Container layer archive could not be parsed; image inventory is incomplete.",
                message=f"Failed to read layer blob {layer_hash[:12]}",
            )

    packages = _drop_whiteout_deleted_packages(packages, whiteouts_by_index)

    if detected_distro_name or detected_distro_version:
        for pkg in packages:
            if pkg.ecosystem in {"deb", "apk", "rpm"}:
                pkg.distro_name = pkg.distro_name or detected_distro_name
                pkg.distro_version = pkg.distro_version or detected_distro_version

    return OCIParseResult(
        packages=packages,
        strategy="oci-layout-dir",
        layer_count=len(layer_digests),
        warnings=warnings,
        coverage_warnings=coverage_warnings,
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

    for warning in result.coverage_warnings:
        record_scan_input_warning(
            scanner="oci",
            path=warning.path,
            reason=warning.reason,
            detail=warning.detail,
        )

    return result.packages, result.strategy
