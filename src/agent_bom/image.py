"""Native Docker image scanning — extract packages from container images.

Primary strategy:

1. **Docker save + native OCI parser**:
   - ``docker inspect`` to confirm the image exists / pull if needed
   - ``docker save`` to a temporary tarball
   - parse layers natively via :mod:`agent_bom.oci_parser`

Fallback strategy:

2. **Docker export + filesystem parser**:
   - ``docker create`` + ``docker export`` to a temporary tarball
   - scan package manager files directly from the container filesystem

The scanner is native-first and must fail loudly if package extraction fails.

Usage from cli.py::

    from agent_bom.image import scan_image, ImageScanError
    packages, strategy = scan_image("myapp:latest")
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Optional

from agent_bom.models import Package, PermissionProfile, Severity, Vulnerability
from agent_bom.sbom import parse_cyclonedx
from agent_bom.security import validate_image_ref

_logger = logging.getLogger(__name__)
_PLATFORM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*){1,2}$")


class ImageScanError(Exception):
    """Raised when an image cannot be scanned."""


# ─── Legacy external-scanner helpers (kept for auth/env compatibility) ──────

_GRYPE_TYPE_MAP: dict[str, str] = {
    "java-archive": "maven",
    "npm": "npm",
    "python": "pypi",
    "go-module": "go",
    "rust-crate": "cargo",
    "gem": "gem",
    "deb": "deb",
    "rpm": "rpm",
    "apk": "apk",
    "dotnet": "nuget",
    "binary": "binary",
}


def _grype_available() -> bool:
    return shutil.which("grype") is not None


def _validate_platform(platform: Optional[str]) -> Optional[str]:
    if platform is None:
        return None
    if not _PLATFORM_RE.match(platform):
        from agent_bom.security import SecurityError

        raise SecurityError(f"Invalid container platform: {platform!r}")
    return platform


def _build_scanner_env(
    registry_user: Optional[str] = None,
    registry_pass: Optional[str] = None,
    user_env_prefix: str = "GRYPE",
) -> dict[str, str] | None:
    """Build subprocess env dict with registry auth credentials.

    Returns None (inherit parent env) when no auth is configured.
    """
    user = registry_user or os.environ.get("AGENT_BOM_REGISTRY_USER")
    passwd = registry_pass or os.environ.get("AGENT_BOM_REGISTRY_PASS")
    if not user or not passwd:
        return None
    env = dict(os.environ)
    env[f"{user_env_prefix}_REGISTRY_AUTH_USERNAME"] = user
    env[f"{user_env_prefix}_REGISTRY_AUTH_PASSWORD"] = passwd
    return env


def _scan_with_grype(
    image_ref: str,
    registry_user: Optional[str] = None,
    registry_pass: Optional[str] = None,
    platform: Optional[str] = None,
) -> list[Package]:
    """Run Grype and return packages with vulnerabilities pre-populated.

    Grype returns packages + CVEs in a single call, covering all ecosystems
    (npm, cargo, go modules, maven, gems, .NET, deb, rpm, apk, Python).
    No secondary OSV query is needed for image packages.
    """
    image_ref = validate_image_ref(image_ref)
    platform = _validate_platform(platform)
    cmd = ["grype", image_ref, "-o", "json", "--quiet"]
    if platform:
        cmd += ["--platform", platform]
    env = _build_scanner_env(registry_user, registry_pass, "GRYPE")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )
    except FileNotFoundError:
        raise ImageScanError("grype not found")
    except subprocess.TimeoutExpired:
        raise ImageScanError(f"grype timed out scanning {image_ref}")

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise ImageScanError(f"grype exited {result.returncode}: {stderr[:200]}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise ImageScanError(f"grype produced invalid JSON: {e}")

    # Build Package objects keyed by (ecosystem, name, version)
    pkg_map: dict[tuple[str, str, str], Package] = {}

    for match in data.get("matches", []):
        artifact = match.get("artifact", {})
        vuln_data = match.get("vulnerability", {})

        raw_type = artifact.get("type", "").lower()
        ecosystem = _GRYPE_TYPE_MAP.get(raw_type, raw_type or "unknown")
        name = artifact.get("name", "")
        version = artifact.get("version", "")
        if not name or not version:
            continue

        key = (ecosystem, name, version)
        if key not in pkg_map:
            pkg_map[key] = Package(name=name, version=version, ecosystem=ecosystem)

        pkg = pkg_map[key]

        # Build Vulnerability from Grype match
        vuln_id = vuln_data.get("id", "")
        if not vuln_id:
            continue

        raw_sev = vuln_data.get("severity", "unknown").upper()
        try:
            severity = Severity[raw_sev]
        except KeyError:
            severity = Severity.NONE

        # Extract CVSS score from Grype's cvss array
        cvss_score: Optional[float] = None
        for cvss in vuln_data.get("cvss", []):
            metrics = cvss.get("metrics", {})
            score = metrics.get("baseScore")
            if score is not None:
                cvss_score = float(score)
                break

        # Fixed version
        fix_info = vuln_data.get("fix", {})
        fixed_versions = fix_info.get("versions", [])
        fixed_version = fixed_versions[0] if fixed_versions else None

        # Avoid duplicating the same CVE on a package
        if not any(v.id == vuln_id for v in pkg.vulnerabilities):
            pkg.vulnerabilities.append(
                Vulnerability(
                    id=vuln_id,
                    summary=vuln_data.get("description", ""),
                    severity=severity,
                    cvss_score=cvss_score,
                    fixed_version=fixed_version,
                )
            )

    return list(pkg_map.values())


# ─── Syft strategy ────────────────────────────────────────────────────────────


def _syft_available() -> bool:
    return shutil.which("syft") is not None


def _scan_with_syft(
    image_ref: str,
    registry_user: Optional[str] = None,
    registry_pass: Optional[str] = None,
    platform: Optional[str] = None,
) -> list[Package]:
    """Run Syft and parse its CycloneDX JSON output."""
    image_ref = validate_image_ref(image_ref)
    platform = _validate_platform(platform)
    cmd = ["syft", image_ref, "-o", "cyclonedx-json", "--quiet"]
    if platform:
        cmd += ["--platform", platform]
    env = _build_scanner_env(registry_user, registry_pass, "SYFT")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )
    except FileNotFoundError:
        raise ImageScanError("syft not found")
    except subprocess.TimeoutExpired:
        raise ImageScanError(f"syft timed out scanning {image_ref}")

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise ImageScanError(f"syft exited {result.returncode}: {stderr[:200]}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise ImageScanError(f"syft produced invalid JSON: {e}")

    return parse_cyclonedx(data)


# ─── Docker CLI fallback ──────────────────────────────────────────────────────


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _docker_inspect(image_ref: str, platform: Optional[str] = None) -> dict:
    """Return docker inspect output for the image (pulls if needed)."""
    image_ref = validate_image_ref(image_ref)
    platform = _validate_platform(platform)
    try:
        result = subprocess.run(
            ["docker", "inspect", "--type", "image", image_ref],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError:
        raise ImageScanError("docker not found")

    if result.returncode != 0:
        # Try pulling first
        pull_cmd = ["docker", "pull"]
        if platform:
            pull_cmd += ["--platform", platform]
        pull_cmd.append(image_ref)
        pull = subprocess.run(
            pull_cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if pull.returncode != 0:
            raise ImageScanError(f"Image not found locally and pull failed: {image_ref}")
        result = subprocess.run(
            ["docker", "inspect", "--type", "image", image_ref],
            capture_output=True,
            text=True,
            timeout=60,
        )

    try:
        return json.loads(result.stdout)[0]
    except (json.JSONDecodeError, IndexError) as e:
        raise ImageScanError(f"docker inspect output parse error: {e}")


def detect_image_privileges(image_ref: str) -> PermissionProfile:
    """Extract privilege info from a Docker image (without running it).

    Uses ``docker inspect --type image`` to check:
    - Config.User: empty/"0"/"root" → runs_as_root
    - Config.ExposedPorts → network_access
    - Config.Volumes → filesystem_write
    """
    try:
        data = _docker_inspect(image_ref)
    except ImageScanError:
        return PermissionProfile()

    config = data.get("Config", {})

    user = config.get("User", "")
    runs_as_root = user in ("", "0", "root")

    exposed_ports = config.get("ExposedPorts") or {}
    network_access = bool(exposed_ports)

    volumes = config.get("Volumes") or {}
    filesystem_write = bool(volumes)

    return PermissionProfile(
        runs_as_root=runs_as_root,
        network_access=network_access,
        filesystem_write=filesystem_write,
    )


def detect_container_privileges(container_id: str) -> PermissionProfile:
    """Extract privilege info from a running or created container.

    Uses ``docker inspect`` on a container to check:
    - Config.User → runs_as_root
    - HostConfig.Privileged → container_privileged
    - HostConfig.CapAdd/CapDrop → capabilities
    - HostConfig.SecurityOpt → security_opt
    - HostConfig.NetworkMode → network_access (host mode)
    """
    try:
        result = subprocess.run(
            ["docker", "inspect", container_id],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return PermissionProfile()

    if result.returncode != 0:
        return PermissionProfile()

    try:
        data = json.loads(result.stdout)[0]
    except (json.JSONDecodeError, IndexError):
        return PermissionProfile()

    config = data.get("Config", {})
    host_config = data.get("HostConfig", {})

    user = config.get("User", "")
    runs_as_root = user in ("", "0", "root")

    container_privileged = host_config.get("Privileged", False)

    cap_add = host_config.get("CapAdd") or []
    cap_drop = host_config.get("CapDrop") or []
    capabilities = [c for c in cap_add if c not in cap_drop]

    security_opt = host_config.get("SecurityOpt") or []

    network_mode = host_config.get("NetworkMode", "")
    network_access = network_mode in ("host", "bridge", "default", "")

    return PermissionProfile(
        runs_as_root=runs_as_root,
        container_privileged=container_privileged,
        capabilities=capabilities,
        security_opt=security_opt,
        network_access=network_access,
    )


def _packages_from_tar(tar_path: Path) -> list[Package]:
    """Extract packages from a container filesystem tar archive.

    Scans for:
    - Python: site-packages RECORD/METADATA files
    - Node: node_modules/*/package.json (name + version)
    - OS packages: /var/lib/dpkg/status (Debian/Ubuntu)
    - OS packages: /var/lib/rpm/Packages (handled via sqlite3 in Python)
    """
    packages: list[Package] = []
    seen: set[tuple[str, str]] = set()

    def _add(name: str, version: str, ecosystem: str, purl: Optional[str] = None) -> None:
        key = (name, ecosystem)
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

    try:
        with tarfile.open(tar_path, "r") as tf:
            names = tf.getnames()

            # --- Python: dist-info METADATA ---
            for member_name in names:
                if member_name.endswith(".dist-info/METADATA"):
                    try:
                        member = tf.getmember(member_name)
                        f = tf.extractfile(member)
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
                            _add(pkg_name, pkg_version, "pypi")
                    except Exception:
                        _logger.debug("Skipped Python package in %s: %s", member_name, Exception)
                        continue

            # --- Node: node_modules/*/package.json ---
            for member_name in names:
                if "/node_modules/" in member_name and member_name.endswith("package.json") and member_name.count("/node_modules/") == 1:
                    try:
                        member = tf.getmember(member_name)
                        f = tf.extractfile(member)
                        if f is None:
                            continue
                        data = json.loads(f.read().decode("utf-8", errors="ignore"))
                        pkg_name = data.get("name", "")
                        pkg_version = data.get("version", "unknown")
                        if pkg_name:
                            _add(pkg_name, pkg_version, "npm")
                    except Exception:
                        _logger.debug("Skipped Node package in %s", member_name)
                        continue

            # --- Debian/Ubuntu: dpkg status ---
            dpkg_status = "var/lib/dpkg/status"
            if dpkg_status in names:
                try:
                    member = tf.getmember(dpkg_status)
                    f = tf.extractfile(member)
                    if f:
                        content = f.read().decode("utf-8", errors="ignore")
                        pkg_name = pkg_version = ""
                        for line in content.splitlines():
                            if line.startswith("Package:"):
                                pkg_name = line.split(":", 1)[1].strip()
                            elif line.startswith("Version:"):
                                pkg_version = line.split(":", 1)[1].strip()
                            elif line == "" and pkg_name and pkg_version:
                                _add(pkg_name, pkg_version, "deb", f"pkg:deb/debian/{pkg_name}@{pkg_version}")
                                pkg_name = pkg_version = ""
                except Exception:
                    _logger.debug("Failed to parse dpkg status from container")

            # --- Alpine: apk installed ---
            apk_installed = "lib/apk/db/installed"
            if apk_installed in names:
                try:
                    member = tf.getmember(apk_installed)
                    f = tf.extractfile(member)
                    if f:
                        content = f.read().decode("utf-8", errors="ignore")
                        pkg_name = pkg_version = ""
                        for line in content.splitlines():
                            if line.startswith("P:"):
                                pkg_name = line[2:].strip()
                            elif line.startswith("V:"):
                                pkg_version = line[2:].strip()
                            elif line == "" and pkg_name and pkg_version:
                                _add(pkg_name, pkg_version, "apk", f"pkg:apk/alpine/{pkg_name}@{pkg_version}")
                                pkg_name = pkg_version = ""
                        # Handle last entry if file doesn't end with blank line
                        if pkg_name and pkg_version:
                            _add(pkg_name, pkg_version, "apk", f"pkg:apk/alpine/{pkg_name}@{pkg_version}")
                except Exception:
                    _logger.debug("Failed to parse Alpine apk db from container")

            # --- RHEL/Fedora: rpm database ---
            # rpm stores a plain text list at /var/lib/rpm/Packages or rpmdb.sqlite
            # Fallback: look for rpm manifest written by some base images
            for rpm_path in ("var/lib/rpm/rpmdb.sqlite", "var/lib/rpm/Packages"):
                if rpm_path in names:
                    # Can't easily parse binary rpm db from tar; skip to
                    # installed-rpms manifest if present
                    break

            rpm_manifest = "var/log/installed-rpms"
            if rpm_manifest in names:
                try:
                    member = tf.getmember(rpm_manifest)
                    f = tf.extractfile(member)
                    if f:
                        for raw_line in f:
                            line = raw_line.decode("utf-8", errors="ignore").strip()
                            if not line:
                                continue
                            # Format: name-version-release.arch (e.g. bash-5.2.26-4.el9.x86_64)
                            # Split from right at the second-to-last hyphen
                            parts = line.split()
                            nvr = parts[0] if parts else line
                            # Find the last two hyphens to split name from version-release
                            idx2 = nvr.rfind("-")
                            if idx2 > 0:
                                idx1 = nvr.rfind("-", 0, idx2)
                                if idx1 > 0:
                                    rpm_name = nvr[:idx1]
                                    if rpm_name == "gpg-pubkey":
                                        continue
                                    rpm_ver = nvr[idx1 + 1 : idx2]
                                    _add(rpm_name, rpm_ver, "rpm", f"pkg:rpm/redhat/{rpm_name}@{rpm_ver}")
                except Exception:
                    _logger.debug("Failed to parse rpm manifest from container")

    except tarfile.TarError as e:
        raise ImageScanError(f"Failed to read container filesystem: {e}")

    return packages


def _scan_with_docker(image_ref: str, platform: Optional[str] = None) -> list[Package]:
    """Scan a Docker image natively and fail if no packages can be extracted."""
    from agent_bom.oci_parser import OCIParseError, scan_oci

    image_ref = validate_image_ref(image_ref)
    platform = _validate_platform(platform)

    # Confirm image exists / pull it
    _docker_inspect(image_ref, platform=platform)

    with tempfile.TemporaryDirectory() as tmpdir:
        oci_tar_path = Path(tmpdir) / "image.tar"
        save = subprocess.run(
            ["docker", "save", "-o", str(oci_tar_path), image_ref],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if save.returncode != 0:
            stderr = (save.stderr or "").strip()
            raise ImageScanError(f"docker save failed: {stderr[:200]}")

        try:
            packages, _strategy = scan_oci(oci_tar_path)
        except OCIParseError as exc:
            _logger.debug("Native OCI parse failed for %s: %s", image_ref, exc)
        else:
            if packages:
                return packages
            _logger.debug("Native OCI parse returned 0 packages for %s; falling back to docker export", image_ref)

    container_id: Optional[str] = None
    try:
        # Create a stopped container
        result = subprocess.run(
            ["docker", "create", image_ref],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise ImageScanError(f"docker create failed: {result.stderr.strip()[:200]}")
        container_id = result.stdout.strip()

        with tempfile.TemporaryDirectory() as tmpdir:
            tar_path = Path(tmpdir) / "fs.tar"

            export = subprocess.run(
                ["docker", "export", "-o", str(tar_path), container_id],
                capture_output=True,
                timeout=300,
            )
            if export.returncode != 0:
                raise ImageScanError("docker export failed")

            packages = _packages_from_tar(tar_path)
            if packages:
                return packages

        raise ImageScanError(
            f"Native image scan extracted 0 packages from {image_ref}. This is likely an extraction or parser failure, not a clean scan."
        )

    finally:
        if container_id:
            try:
                rm_result = subprocess.run(
                    ["docker", "rm", container_id],
                    capture_output=True,
                    timeout=30,
                )
                if rm_result.returncode != 0:
                    import logging as _logging

                    _logging.getLogger(__name__).warning(
                        "docker rm %s failed (exit %d): %s",
                        container_id,
                        rm_result.returncode,
                        rm_result.stderr.strip()[:100],
                    )
            except (subprocess.TimeoutExpired, OSError) as cleanup_err:
                import logging as _logging

                _logging.getLogger(__name__).warning("docker rm %s error: %s", container_id, cleanup_err)


# ─── Public API ───────────────────────────────────────────────────────────────


def detect_multi_arch(image_ref: str) -> list[str]:
    """Detect platforms available in a multi-arch manifest list.

    Uses ``docker manifest inspect`` to list available platforms.
    Returns list of platform strings like ``["linux/amd64", "linux/arm64"]``.
    Returns empty list if not a manifest list or docker is unavailable.
    """
    image_ref = validate_image_ref(image_ref)
    if not _docker_available():
        return []
    try:
        result = subprocess.run(
            ["docker", "manifest", "inspect", image_ref],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    if result.returncode != 0:
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    platforms: list[str] = []
    for manifest in data.get("manifests", []):
        p = manifest.get("platform", {})
        os_name = p.get("os", "")
        arch = p.get("architecture", "")
        if os_name and arch:
            variant = p.get("variant", "")
            platform_str = f"{os_name}/{arch}"
            if variant:
                platform_str += f"/{variant}"
            platforms.append(platform_str)
    return platforms


def scan_image(
    image_ref: str,
    registry_user: Optional[str] = None,
    registry_pass: Optional[str] = None,
    platform: Optional[str] = None,
) -> tuple[list[Package], str]:
    """Scan a Docker image and return (packages, strategy_used).

    Strategy order:
    1. Docker save → native OCI parser
    2. Docker export → native filesystem parser

    Args:
        image_ref: Docker image reference, e.g. ``myapp:latest``,
                   ``ghcr.io/org/image:sha256-abc``, ``nginx:1.25``
        registry_user: Username for private registry authentication.
        registry_pass: Password for private registry authentication.
        platform: Target platform for multi-arch images (e.g. ``linux/amd64``).

    Returns:
        A tuple ``(packages, strategy)`` where strategy is ``"native"``.

    Raises:
        ImageScanError: If Docker is unavailable, the image cannot be found/pulled,
                        or native package extraction fails.
    """
    validate_image_ref(image_ref)
    _validate_platform(platform)

    if not _docker_available():
        raise ImageScanError(
            "Docker is not available. Install Docker to enable native image scanning, "
            "or use 'docker save <image> -o image.tar' and pass the tarball with --image-tar."
        )

    packages = _scan_with_docker(image_ref, platform)
    return packages, "native"


def scan_image_tar(tar_path: str) -> tuple[list[Package], str]:
    """Scan a pre-saved OCI image tarball or layout directory — no Docker/Syft/Grype required.

    Accepts tarballs created by ``docker save``, ``skopeo copy``, or ``crane pull``.

    Args:
        tar_path: Path to the image tarball (``.tar``) or OCI layout directory.

    Returns:
        A tuple ``(packages, strategy)`` where strategy is ``"oci-tarball"``
        or ``"oci-layout-dir"``.

    Raises:
        ImageScanError: If the tarball cannot be parsed.
    """
    from agent_bom.oci_parser import OCIParseError, scan_oci

    path = Path(tar_path)
    if not path.exists():
        raise ImageScanError(f"Image tarball not found: {tar_path}")
    try:
        return scan_oci(path)
    except OCIParseError as e:
        raise ImageScanError(f"OCI parse error: {e}") from e


def image_to_purl(image_ref: str) -> str:
    """Convert a Docker image reference to a Package URL.

    Examples:
      nginx:1.25               → pkg:oci/nginx:1.25
      ghcr.io/org/app:v1.0.0  → pkg:oci/org/app:v1.0.0?repository_url=ghcr.io
    """
    if "://" in image_ref:
        # Strip protocol if someone passes a full URL
        image_ref = image_ref.split("://", 1)[1]

    parts = image_ref.split("/", 1)
    if len(parts) == 2 and ("." in parts[0] or ":" in parts[0]):
        # Has a registry hostname
        registry, rest = parts
        return f"pkg:oci/{rest}?repository_url={registry}"
    else:
        return f"pkg:oci/{image_ref}"
