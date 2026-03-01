"""Filesystem and disk snapshot scanning via Syft.

Scans mounted directories and tar archives for packages::

    syft dir:/path/to/mounted/snapshot -o cyclonedx-json
    syft /path/to/archive.tar -o cyclonedx-json

This enables agentless VM scanning — mount a disk snapshot,
point agent-bom at it, and get a full package inventory + CVEs.
Replaces cloud-native image scanners for on-prem environments.

Usage from cli.py::

    from agent_bom.filesystem import scan_filesystem, FilesystemScanError
    packages, strategy = scan_filesystem("/mnt/vm-snapshot")
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

from agent_bom.models import Package
from agent_bom.sbom import parse_cyclonedx
from agent_bom.security import validate_path

logger = logging.getLogger(__name__)


class FilesystemScanError(Exception):
    """Raised when a filesystem path cannot be scanned."""


def scan_filesystem(path: str, timeout: int = 600) -> tuple[list[Package], str]:
    """Scan a filesystem directory or tar archive for packages.

    Args:
        path: Directory path or tar archive path.
              Directories are scanned as ``syft dir:/path``.
              Tar files are scanned as ``syft /path/to/archive.tar``.
        timeout: Subprocess timeout in seconds (default 600 = 10 min).

    Returns:
        (packages, strategy) where strategy is ``"syft-dir"`` or ``"syft-tar"``.

    Raises:
        FilesystemScanError: if syft is not found or scan fails.
    """
    validated = validate_path(path, must_exist=True)

    if not shutil.which("syft"):
        raise FilesystemScanError("syft not found on PATH. Install from https://github.com/anchore/syft")

    if validated.is_dir():
        return _scan_directory(validated, timeout), "syft-dir"
    elif validated.suffix in (".tar", ".gz", ".tgz"):
        return _scan_archive(validated, timeout), "syft-tar"
    else:
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
