"""Filesystem and disk snapshot scanning — Syft (primary) + native fallback.

Scans mounted directories and tar archives for packages::

    syft dir:/path/to/mounted/snapshot -o cyclonedx-json   # preferred
    agent-bom scan --filesystem /mnt/vm-snapshot           # auto-selects strategy

When Syft is **not** installed, the native fallback is used instead:

- APT/Debian: ``/var/lib/dpkg/status``
- RPM/RHEL:   ``rpm -qa --qf ...`` (if ``rpm`` binary is on PATH)
- Python:     walks all ``site-packages/`` and ``dist-packages/`` dirs for
              ``.dist-info/METADATA`` files (PEP 566 / importlib.metadata)
- Lock files: runs the full :func:`scan_project_directory` parser suite

This enables agentless VM scanning without requiring Syft — mount a disk
snapshot, point agent-bom at it, and get a full package inventory + CVEs.

Usage from cli.py::

    from agent_bom.filesystem import scan_filesystem, FilesystemScanError
    packages, strategy = scan_filesystem("/mnt/vm-snapshot")
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from pathlib import Path

from agent_bom.models import Package
from agent_bom.sbom import parse_cyclonedx
from agent_bom.security import validate_path

logger = logging.getLogger(__name__)


class FilesystemScanError(Exception):
    """Raised when a filesystem path cannot be scanned."""


# ── Syft-based scanning ───────────────────────────────────────────────────────


def scan_filesystem(path: str, timeout: int = 600) -> tuple[list[Package], str]:
    """Scan a filesystem directory or tar archive for packages.

    Tries Syft first; falls back to native parsers for directories when
    Syft is not installed.

    Args:
        path: Directory path or tar archive path.
        timeout: Subprocess timeout in seconds (default 600 = 10 min).

    Returns:
        ``(packages, strategy)`` where *strategy* is one of:
        ``"syft-dir"``, ``"syft-tar"``, ``"native-dir"``.

    Raises:
        FilesystemScanError: if all strategies fail.
    """
    validated = validate_path(path, must_exist=True)

    if validated.is_dir():
        if shutil.which("syft"):
            return _scan_directory(validated, timeout), "syft-dir"
        # Native fallback — no Syft required
        pkgs = scan_disk_path_native(validated)
        return pkgs, "native-dir"

    if validated.suffix in (".tar", ".gz", ".tgz"):
        if shutil.which("syft"):
            return _scan_archive(validated, timeout), "syft-tar"
        raise FilesystemScanError(
            "syft not found on PATH — required for tar/archive scanning. Install from https://github.com/anchore/syft"
        )

    # Provide helpful guidance for disk image formats
    disk_image_exts = {".qcow2", ".vmdk", ".vhd", ".vhdx", ".raw", ".img"}
    if validated.suffix.lower() in disk_image_exts:
        raise FilesystemScanError(
            f"Cannot scan disk image '{validated.name}' directly. "
            f"Mount it first, then scan the mount point:\n"
            f"  # Linux:  sudo mount -o loop,ro {validated} /mnt/snapshot\n"
            f"  # QCOW2:  sudo qemu-nbd -c /dev/nbd0 {validated} && sudo mount /dev/nbd0p1 /mnt/snapshot\n"
            f"  # Then:   agent-bom scan --filesystem /mnt/snapshot"
        )

    raise FilesystemScanError(f"Unsupported path type: {validated}. Expected a directory or .tar/.tar.gz/.tgz archive.")


def _scan_directory(dir_path: Path, timeout: int = 600) -> list[Package]:
    """Run ``syft dir:/path -o cyclonedx-json`` and parse output."""
    return _run_syft(f"dir:{dir_path}", timeout)


def _scan_archive(tar_path: Path, timeout: int = 600) -> list[Package]:
    """Run ``syft /path/to/archive.tar -o cyclonedx-json``."""
    return _run_syft(str(tar_path), timeout)


def _run_syft(source: str, timeout: int) -> list[Package]:
    """Execute syft and parse CycloneDX output."""
    try:
        result = subprocess.run(
            ["syft", source, "-o", "cyclonedx-json", "--quiet"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise FilesystemScanError(f"syft timed out after {timeout}s scanning {source}") from e

    if result.returncode != 0:
        stderr = result.stderr.strip()[:200] if result.stderr else "unknown error"
        raise FilesystemScanError(f"syft exited {result.returncode}: {stderr}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise FilesystemScanError(f"syft output is not valid JSON: {e}") from e

    return parse_cyclonedx(data)


# ── Native disk snapshot parsers (no external tools required) ─────────────────


def parse_dpkg_status(status_file: Path) -> list[Package]:
    """Parse installed packages from a Debian/Ubuntu ``dpkg/status`` file.

    Works on live systems (``/var/lib/dpkg/status``) and mounted VM disk
    snapshots.  Only packages with ``Status: install ok installed`` are
    included.

    Args:
        status_file: Path to the ``dpkg/status`` file.

    Returns:
        List of :class:`~agent_bom.models.Package` objects with
        ``ecosystem="deb"``.
    """
    if not status_file.exists():
        return []

    packages: list[Package] = []
    current: dict[str, str] = {}

    for raw_line in status_file.read_text(errors="replace").splitlines():
        if raw_line.strip() == "":
            # End of a stanza — commit if it's a fully-installed package
            if current.get("Package") and current.get("Version"):
                status = current.get("Status", "")
                if "install ok installed" in status:
                    name = current["Package"]
                    version = current["Version"]
                    # Strip epoch prefix (e.g. "1:2.3.4" → "2.3.4")
                    version = re.sub(r"^\d+:", "", version)
                    packages.append(
                        Package(
                            name=name,
                            version=version,
                            ecosystem="deb",
                            purl=f"pkg:deb/debian/{name}@{version}",
                            is_direct=True,
                        )
                    )
            current = {}
        elif ":" in raw_line and not raw_line.startswith(" "):
            key, _, value = raw_line.partition(":")
            current[key.strip()] = value.strip()

    return packages


def parse_apk_installed(installed_file: Path) -> list[Package]:
    """Parse installed packages from an Alpine Linux ``lib/apk/db/installed`` file.

    Works on live Alpine systems and mounted VM/container snapshots.

    Args:
        installed_file: Path to the ``lib/apk/db/installed`` file.

    Returns:
        List of :class:`~agent_bom.models.Package` objects with
        ``ecosystem="apk"``.
    """
    if not installed_file.exists():
        return []

    packages: list[Package] = []
    current: dict[str, str] = {}

    for raw_line in installed_file.read_text(errors="replace").splitlines():
        if raw_line.strip() == "":
            if current.get("P") and current.get("V"):
                name = current["P"]
                version = current["V"]
                packages.append(
                    Package(
                        name=name,
                        version=version,
                        ecosystem="apk",
                        purl=f"pkg:apk/alpine/{name}@{version}",
                        is_direct=True,
                    )
                )
            current = {}
        elif len(raw_line) >= 2 and raw_line[1] == ":":
            key = raw_line[0]
            value = raw_line[2:]
            current[key] = value

    # Handle last stanza without trailing blank line
    if current.get("P") and current.get("V"):
        name = current["P"]
        version = current["V"]
        packages.append(
            Package(
                name=name,
                version=version,
                ecosystem="apk",
                purl=f"pkg:apk/alpine/{name}@{version}",
                is_direct=True,
            )
        )

    return packages


def parse_rpm_packages(root: Path) -> list[Package]:
    """Query installed RPM packages from an RPM database.

    For live systems, runs ``rpm -qa`` if the binary is on PATH.
    For mounted snapshots, tries ``rpm --dbpath <root>/var/lib/rpm -qa``.
    Returns empty list if rpm is not available.

    Args:
        root: Filesystem root (``/`` for live, ``/mnt/snapshot`` for VMs).

    Returns:
        List of :class:`~agent_bom.models.Package` objects with
        ``ecosystem="rpm"``.
    """
    if not shutil.which("rpm"):
        return []

    rpm_db = root / "var" / "lib" / "rpm"
    if not rpm_db.exists() and root == Path("/"):
        # Live system, default db path
        rpm_db = None

    cmd = ["rpm"]
    if rpm_db:
        cmd += ["--dbpath", str(rpm_db)]
    cmd += ["-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    if result.returncode != 0:
        return []

    packages: list[Package] = []
    for line in result.stdout.splitlines():
        parts = line.strip().split("\t")
        if len(parts) >= 2:
            name, version = parts[0], parts[1]
            if name and version:
                packages.append(
                    Package(
                        name=name,
                        version=version,
                        ecosystem="rpm",
                        purl=f"pkg:rpm/redhat/{name}@{version}",
                        is_direct=True,
                    )
                )

    return packages


def parse_site_packages(site_packages_dir: Path) -> list[Package]:
    """Parse installed Python packages from a ``site-packages`` or
    ``dist-packages`` directory by reading ``.dist-info/METADATA`` files.

    Works on live systems and mounted disk snapshots.

    Args:
        site_packages_dir: Path to a ``site-packages`` or ``dist-packages``
            directory.

    Returns:
        List of :class:`~agent_bom.models.Package` objects with
        ``ecosystem="pypi"``.
    """
    if not site_packages_dir.exists():
        return []

    packages: list[Package] = []
    seen: set[tuple[str, str]] = set()

    for dist_info in site_packages_dir.glob("*.dist-info"):
        metadata_file = dist_info / "METADATA"
        if not metadata_file.exists():
            continue

        name = ""
        version = ""
        try:
            for line in metadata_file.read_text(errors="replace").splitlines():
                if line.startswith("Name:"):
                    name = line.split(":", 1)[1].strip()
                elif line.startswith("Version:"):
                    version = line.split(":", 1)[1].strip()
                elif line.startswith("") and name and version:
                    # Empty line signals end of headers
                    break
        except OSError:
            continue

        if name and version:
            key = (name.lower(), version)
            if key not in seen:
                seen.add(key)
                packages.append(
                    Package(
                        name=name,
                        version=version,
                        ecosystem="pypi",
                        purl=f"pkg:pypi/{name.lower()}@{version}",
                        is_direct=True,
                    )
                )

    return packages


def scan_disk_path_native(root: Path) -> list[Package]:
    """Scan a directory (VM disk snapshot or live root) natively — no Syft.

    Combines all native parsers:

    - APT/Debian packages from ``var/lib/dpkg/status``
    - RPM packages via ``rpm --dbpath`` (if ``rpm`` binary is on PATH)
    - Python packages from all ``site-packages`` / ``dist-packages`` dirs
    - Lock-file packages via :func:`~agent_bom.parsers.scan_project_directory`

    Args:
        root: Root directory to scan (e.g. ``/mnt/snapshot`` or ``/``).

    Returns:
        Deduplicated list of :class:`~agent_bom.models.Package` objects.
    """
    packages: list[Package] = []

    # APT / Debian
    dpkg_status = root / "var" / "lib" / "dpkg" / "status"
    deb_pkgs = parse_dpkg_status(dpkg_status)
    if deb_pkgs:
        logger.debug("native-dir: found %d deb packages in %s", len(deb_pkgs), dpkg_status)
    packages.extend(deb_pkgs)

    # Alpine Linux (apk)
    apk_installed = root / "lib" / "apk" / "db" / "installed"
    apk_pkgs = parse_apk_installed(apk_installed)
    if apk_pkgs:
        logger.debug("native-dir: found %d apk packages in %s", len(apk_pkgs), apk_installed)
    packages.extend(apk_pkgs)

    # RPM / RHEL / CentOS / Fedora
    rpm_pkgs = parse_rpm_packages(root)
    if rpm_pkgs:
        logger.debug("native-dir: found %d rpm packages via rpm --dbpath", len(rpm_pkgs))
    packages.extend(rpm_pkgs)

    # Node.js global packages
    for node_pattern in (
        "usr/lib/node_modules/*/package.json",
        "usr/local/lib/node_modules/*/package.json",
    ):
        for pkg_json_path in root.glob(node_pattern):
            try:
                pkg_data = json.loads(pkg_json_path.read_text(errors="replace"))
                name = pkg_data.get("name", "")
                version = pkg_data.get("version", "")
                if name and version:
                    packages.append(
                        Package(
                            name=name,
                            version=version,
                            ecosystem="npm",
                            purl=f"pkg:npm/{name}@{version}",
                            is_direct=True,
                        )
                    )
            except (json.JSONDecodeError, OSError):
                continue

    # Python site-packages / dist-packages
    for pattern in (
        "usr/lib/python*/site-packages",
        "usr/lib/python*/dist-packages",
        "usr/local/lib/python*/site-packages",
        "usr/local/lib/python*/dist-packages",
        "opt/conda/lib/python*/site-packages",
    ):
        for sp_dir in root.glob(pattern):
            sp_pkgs = parse_site_packages(sp_dir)
            if sp_pkgs:
                logger.debug("native-dir: found %d Python packages in %s", len(sp_pkgs), sp_dir)
            packages.extend(sp_pkgs)

    # Lock files (requirements.txt, package.json, go.mod, Cargo.toml, etc.)
    from agent_bom.parsers import scan_project_directory

    for dir_pkgs in scan_project_directory(root, max_depth=5).values():
        packages.extend(dir_pkgs)

    # Deduplicate by (name, version, ecosystem)
    seen: set[tuple[str, str, str]] = set()
    unique: list[Package] = []
    for pkg in packages:
        key = (pkg.name, pkg.version, pkg.ecosystem)
        if key not in seen:
            seen.add(key)
            unique.append(pkg)

    return unique


# ── Batch helper ──────────────────────────────────────────────────────────────


def scan_filesystem_batch(paths: list[str], timeout: int = 600) -> list[tuple[str, list[Package], str]]:
    """Scan multiple filesystem paths.

    Returns:
        List of ``(path, packages, strategy)`` tuples.
        Failed paths have strategy ``"error"`` and empty package list.
    """
    results = []
    for p in paths:
        try:
            packages, strategy = scan_filesystem(p, timeout=timeout)
            results.append((p, packages, strategy))
        except FilesystemScanError as e:
            logger.warning("Filesystem scan failed for %s: %s", p, e)
            results.append((p, [], "error"))
    return results
