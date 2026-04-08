"""Live OS package scanners — dpkg (Debian/Ubuntu), rpm (RHEL/Fedora), apk (Alpine)."""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path
from typing import Optional

from agent_bom.filesystem import read_os_release_metadata
from agent_bom.models import Package
from agent_bom.package_utils import parse_debian_source_name

_logger = logging.getLogger(__name__)


def enrich_os_package_context(pkg: Package, root: Path = Path("/")) -> bool:
    """Best-effort enrichment of distro/source context for a single OS package.

    Returns True when the resulting package has enough context to make a
    high-confidence advisory match for its ecosystem.
    """
    distro_name, distro_version = read_os_release_metadata(root)
    pkg.distro_name = pkg.distro_name or distro_name
    pkg.distro_version = pkg.distro_version or distro_version

    if pkg.ecosystem == "deb":
        pkg.source_package = pkg.source_package or _resolve_debian_source_package(pkg.name)
        return bool(pkg.distro_version and pkg.source_package)
    if pkg.ecosystem == "apk":
        return bool(pkg.distro_version)
    if pkg.ecosystem == "rpm":
        return bool(pkg.distro_name or pkg.distro_version)
    return True


def _resolve_debian_source_package(package_name: str) -> Optional[str]:
    """Resolve Debian source package for a binary package name when possible."""
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${source:Package}\\n", package_name],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            source_package = parse_debian_source_name(result.stdout.strip())
            if source_package:
                return source_package
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    try:
        result = subprocess.run(
            ["apt-cache", "show", package_name],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.startswith("Source:"):
                    source_package = parse_debian_source_name(line.split(":", 1)[1].strip())
                    if source_package:
                        return source_package
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return None


def parse_dpkg_packages(root: Path = Path("/")) -> list[Package]:
    """Read installed deb packages from dpkg status database.

    Resolution order:

    1. ``dpkg-query`` command (clean, installed-only output).
    2. Read ``var/lib/dpkg/status`` file directly (works on mounted snapshots).
    3. Read each file in ``var/lib/dpkg/status.d/`` (dpkg status.d layout).

    Args:
        root: Filesystem root to scan (``/`` for live system, or a mount point).

    Returns:
        List of :class:`~agent_bom.models.Package` objects with ``ecosystem="deb"``.
    """
    packages: list[Package] = []

    # Method 1: dpkg-query (live system, installed-only, clean output)
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${source:Package}\n"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.strip().split("\t")
                if len(parts) >= 2 and parts[0] and parts[1]:
                    source_package = parse_debian_source_name(parts[2]) if len(parts) >= 3 else None
                    packages.append(
                        Package(
                            name=parts[0],
                            version=parts[1],
                            ecosystem="deb",
                            purl=f"pkg:deb/debian/{parts[0]}@{parts[1]}",
                            source_package=source_package,
                        )
                    )
            if packages:
                return packages
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Method 2: read status file / status.d directory directly
    status_paths = [
        root / "var/lib/dpkg/status",
        root / "var/lib/dpkg/status.d",
    ]
    for status_path in status_paths:
        if status_path.is_file():
            _parse_dpkg_status_file(status_path, packages)
            break
        elif status_path.is_dir():
            for f in sorted(status_path.iterdir()):
                _parse_dpkg_status_file(f, packages)

    return packages


def _parse_dpkg_status_file(path: Path, packages: list[Package]) -> None:
    """Parse a single dpkg status file, appending results to *packages*.

    Parses the RFC 822-style stanza format used by dpkg.  Only records that
    contain both a ``Package:`` and ``Version:`` field are included — partial
    or broken entries are silently skipped.

    Args:
        path: Path to the dpkg status file (or a file within ``status.d/``).
        packages: List to append discovered :class:`~agent_bom.models.Package`
            objects to (mutated in-place).
    """
    try:
        content = path.read_text(errors="ignore")
    except OSError:
        _logger.debug("Cannot read dpkg status: %s", path)
        return

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
            packages.append(
                Package(
                    name=pkg_name,
                    version=pkg_version,
                    ecosystem="deb",
                    purl=f"pkg:deb/debian/{pkg_name}@{pkg_version}",
                    source_package=source_package,
                )
            )
            pkg_name = pkg_version = ""
            source_package = None

    # Handle last stanza without a trailing blank line
    if pkg_name and pkg_version:
        packages.append(
            Package(
                name=pkg_name,
                version=pkg_version,
                ecosystem="deb",
                purl=f"pkg:deb/debian/{pkg_name}@{pkg_version}",
                source_package=source_package,
            )
        )


def parse_rpm_packages(root: Path = Path("/")) -> list[Package]:
    """Read installed RPM packages via the ``rpm`` command.

    Uses ``rpm -qa`` with the database path derived from *root* to support
    both live systems and mounted filesystem snapshots.  Returns an empty list
    without raising when the ``rpm`` binary is not available.

    Args:
        root: Filesystem root to scan.

    Returns:
        List of :class:`~agent_bom.models.Package` objects with ``ecosystem="rpm"``.
    """
    packages: list[Package] = []
    try:
        result = subprocess.run(
            ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.strip().split("\t")
                if len(parts) >= 2 and parts[0] and parts[1]:
                    packages.append(
                        Package(
                            name=parts[0],
                            version=parts[1],
                            ecosystem="rpm",
                            purl=f"pkg:rpm/redhat/{parts[0]}@{parts[1]}",
                        )
                    )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        _logger.debug("rpm command not available")
    return packages


def parse_apk_packages(root: Path = Path("/")) -> list[Package]:
    """Read installed Alpine packages from the apk database.

    Resolution order:

    1. ``apk list --installed`` command (live system).
    2. Read ``lib/apk/db/installed`` database file directly (snapshots).

    Args:
        root: Filesystem root to scan.

    Returns:
        List of :class:`~agent_bom.models.Package` objects with ``ecosystem="apk"``.
    """
    packages: list[Package] = []

    # Method 1: apk command
    try:
        result = subprocess.run(
            ["apk", "list", "--installed"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            # Line format: "name-version description {origin} (license) [state]"
            for line in result.stdout.splitlines():
                m = re.match(r"^([a-z0-9._+-]+)-(\d[^\s{}]*)\s", line)
                if m:
                    packages.append(
                        Package(
                            name=m.group(1),
                            version=m.group(2),
                            ecosystem="apk",
                            purl=f"pkg:apk/alpine/{m.group(1)}@{m.group(2)}",
                        )
                    )
            if packages:
                return packages
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Method 2: read /lib/apk/db/installed directly
    installed_db = root / "lib/apk/db/installed"
    if installed_db.is_file():
        try:
            content = installed_db.read_text(errors="ignore")
            pkg_name = pkg_version = ""
            for line in content.splitlines():
                if line.startswith("P:"):
                    pkg_name = line[2:].strip()
                elif line.startswith("V:"):
                    pkg_version = line[2:].strip()
                elif line == "" and pkg_name and pkg_version:
                    packages.append(
                        Package(
                            name=pkg_name,
                            version=pkg_version,
                            ecosystem="apk",
                            purl=f"pkg:apk/alpine/{pkg_name}@{pkg_version}",
                        )
                    )
                    pkg_name = pkg_version = ""
            # Handle last stanza without trailing blank line
            if pkg_name and pkg_version:
                packages.append(
                    Package(
                        name=pkg_name,
                        version=pkg_version,
                        ecosystem="apk",
                        purl=f"pkg:apk/alpine/{pkg_name}@{pkg_version}",
                    )
                )
        except OSError:
            _logger.debug("Cannot read apk db: %s", installed_db)

    return packages


def detect_os_type(root: Path = Path("/")) -> str | None:
    """Detect OS type from ``/etc/os-release``.

    Reads the ``ID=`` field from ``<root>/etc/os-release`` and maps it to the
    corresponding package ecosystem identifier.

    Args:
        root: Filesystem root to inspect.

    Returns:
        ``"deb"`` for Debian-family, ``"rpm"`` for RPM-family,
        ``"apk"`` for Alpine, or ``None`` if unrecognised.
    """
    os_release = root / "etc/os-release"
    if not os_release.is_file():
        return None
    try:
        content = os_release.read_text(errors="ignore")
        for line in content.splitlines():
            if line.startswith("ID="):
                os_id = line.split("=", 1)[1].strip().strip('"').lower()
                if os_id in ("debian", "ubuntu", "linuxmint", "pop"):
                    return "deb"
                if os_id in ("fedora", "rhel", "centos", "rocky", "alma", "ol"):
                    return "rpm"
                if os_id == "alpine":
                    return "apk"
    except OSError:
        pass
    return None


def scan_os_packages(root: Path = Path("/")) -> list[Package]:
    """Auto-detect OS type and scan installed system packages.

    Reads ``<root>/etc/os-release`` to identify the package manager, then
    delegates to the appropriate parser.  When the OS type is unrecognised,
    all three parsers are tried in order and the first one that returns results
    is used.

    Args:
        root: Filesystem root to scan (``/`` for a live system, or a mount
            point for a VM/container snapshot).

    Returns:
        Deduplicated list of :class:`~agent_bom.models.Package` objects with
        ``ecosystem`` set to ``"deb"``, ``"rpm"``, or ``"apk"``.
    """
    distro_name, distro_version = read_os_release_metadata(root)

    def _apply_distro(packages: list[Package]) -> list[Package]:
        for pkg in packages:
            if pkg.ecosystem in {"deb", "apk", "rpm"}:
                pkg.distro_name = pkg.distro_name or distro_name
                pkg.distro_version = pkg.distro_version or distro_version
        return packages

    os_type = detect_os_type(root)
    if os_type == "deb":
        return _apply_distro(parse_dpkg_packages(root))
    if os_type == "rpm":
        return _apply_distro(parse_rpm_packages(root))
    if os_type == "apk":
        return _apply_distro(parse_apk_packages(root))

    # Unknown OS — try all parsers and return the first successful result
    for fn in (parse_dpkg_packages, parse_rpm_packages, parse_apk_packages):
        try:
            pkgs = fn(root)
            if pkgs:
                return _apply_distro(pkgs)
        except Exception:  # noqa: BLE001
            continue

    return []
