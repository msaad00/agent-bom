"""Package integrity verification — SHA256 checksums and SLSA provenance."""

from __future__ import annotations

import base64
import hashlib
import logging
from importlib.metadata import PackageNotFoundError, distribution
from typing import Optional

import httpx

from agent_bom.http_client import request_with_retry
from agent_bom.models import Package

logger = logging.getLogger(__name__)

# npm registry provides shasum (SHA-1) and integrity (SHA-512 SRI) in dist metadata
# PyPI provides sha256 digests in the JSON API


async def verify_npm_integrity(
    package_name: str,
    version: str,
    client: httpx.AsyncClient,
) -> Optional[dict]:
    """Verify npm package integrity by fetching registry metadata.

    Returns dict with:
        - sha512_sri: Subresource Integrity hash (sha512-...)
        - shasum: SHA-1 hash from npm registry
        - tarball_url: URL to the tarball
        - verified: True if metadata was successfully retrieved
    """
    encoded_name = package_name.replace("/", "%2F")
    response = await request_with_retry(
        client, "GET",
        f"https://registry.npmjs.org/{encoded_name}/{version}",
    )

    if response and response.status_code == 200:
        try:
            data = response.json()
            dist = data.get("dist", {})
            return {
                "sha512_sri": dist.get("integrity"),  # e.g. "sha512-abc123..."
                "shasum": dist.get("shasum"),          # SHA-1 hex
                "tarball_url": dist.get("tarball"),
                "verified": bool(dist.get("integrity") or dist.get("shasum")),
            }
        except (ValueError, KeyError):
            pass

    return None


async def verify_pypi_integrity(
    package_name: str,
    version: str,
    client: httpx.AsyncClient,
) -> Optional[dict]:
    """Verify PyPI package integrity by fetching registry metadata.

    Returns dict with:
        - sha256: SHA-256 hex digest of the wheel/sdist
        - filename: Name of the distribution file
        - requires_python: Python version requirement
        - verified: True if digest was retrieved
    """
    response = await request_with_retry(
        client, "GET",
        f"https://pypi.org/pypi/{package_name}/{version}/json",
    )

    if response and response.status_code == 200:
        try:
            data = response.json()
            urls = data.get("urls", [])

            # Prefer wheel, fall back to sdist
            for url_entry in urls:
                digests = url_entry.get("digests", {})
                sha256 = digests.get("sha256")
                if sha256:
                    return {
                        "sha256": sha256,
                        "filename": url_entry.get("filename"),
                        "requires_python": url_entry.get("requires_python"),
                        "verified": True,
                    }
        except (ValueError, KeyError):
            pass

    return None


async def verify_package_integrity(
    package: Package,
    client: httpx.AsyncClient,
) -> Optional[dict]:
    """Verify a package's integrity against its registry.

    Args:
        package: Package to verify
        client: HTTP client

    Returns:
        Integrity verification result or None if ecosystem not supported
    """
    if package.version in ("latest", "unknown", ""):
        return None

    if package.ecosystem == "npm":
        return await verify_npm_integrity(package.name, package.version, client)
    elif package.ecosystem == "pypi":
        return await verify_pypi_integrity(package.name, package.version, client)

    return None


async def check_npm_provenance(
    package_name: str,
    version: str,
    client: httpx.AsyncClient,
) -> Optional[dict]:
    """Check if an npm package has SLSA build provenance attestation.

    npm packages published with `--provenance` include a Sigstore-signed
    SLSA v1.0 provenance attestation linked from the registry.

    Returns:
        Dict with provenance info or None if not available
    """
    encoded_name = package_name.replace("/", "%2F")

    # npm attestation endpoint (available since npm v9.5.0)
    response = await request_with_retry(
        client, "GET",
        f"https://registry.npmjs.org/-/npm/v1/attestations/{encoded_name}@{version}",
    )

    if response and response.status_code == 200:
        try:
            data = response.json()
            attestations = data.get("attestations", [])
            for att in attestations:
                predicate_type = att.get("predicateType", "")
                if "slsa" in predicate_type.lower() or "provenance" in predicate_type.lower():
                    return {
                        "has_provenance": True,
                        "predicate_type": predicate_type,
                        "attestation_count": len(attestations),
                    }
            # Has attestations but not SLSA provenance specifically
            if attestations:
                return {
                    "has_provenance": False,
                    "attestation_count": len(attestations),
                    "predicate_types": [a.get("predicateType", "") for a in attestations],
                }
        except (ValueError, KeyError):
            pass

    return None


async def check_pypi_provenance(
    package_name: str,
    version: str,
    client: httpx.AsyncClient,
) -> Optional[dict]:
    """Check if a PyPI package has attestation (PEP 740).

    PyPI supports publish attestations via Trusted Publishers.

    Returns:
        Dict with provenance info or None if not available
    """
    # PyPI attestation endpoint (PEP 740)
    response = await request_with_retry(
        client, "GET",
        f"https://pypi.org/integrity/{package_name}/{version}/",
    )

    if response and response.status_code == 200:
        try:
            data = response.json()
            if data.get("attestations"):
                return {
                    "has_provenance": True,
                    "attestation_count": len(data["attestations"]),
                }
        except (ValueError, KeyError):
            pass

    return None


async def check_package_provenance(
    package: Package,
    client: httpx.AsyncClient,
) -> Optional[dict]:
    """Check if a package has SLSA provenance attestation.

    Args:
        package: Package to check
        client: HTTP client

    Returns:
        Provenance info or None
    """
    if package.version in ("latest", "unknown", ""):
        return None

    if package.ecosystem == "npm":
        return await check_npm_provenance(package.name, package.version, client)
    elif package.ecosystem == "pypi":
        return await check_pypi_provenance(package.name, package.version, client)

    return None


def verify_installed_record(package_name: str) -> dict:
    """Verify installed package files against RECORD hashes.

    Re-hashes each installed file on disk and compares against the
    RECORD file written by pip/uv at install time.

    Returns dict with verification results and metadata.
    """
    result: dict = {
        "installed_version": None,
        "total_files": 0,
        "verified_files": 0,
        "failed_files": [],
        "record_available": False,
        "record_intact": False,
        "metadata": {},
    }

    try:
        dist = distribution(package_name)
    except PackageNotFoundError:
        return result

    result["installed_version"] = dist.metadata["Version"]

    # Extract metadata
    meta: dict = {
        "license": dist.metadata.get("License-Expression") or dist.metadata.get("License", ""),
        "author": dist.metadata.get("Author", ""),
    }
    project_urls: dict[str, str] = {}
    for val in dist.metadata.get_all("Project-URL") or []:
        if ", " in val:
            label, url = val.split(", ", 1)
            project_urls[label] = url
    meta["project_urls"] = project_urls
    meta["source_repo"] = (
        project_urls.get("Repository")
        or project_urls.get("Source")
        or project_urls.get("Homepage")
        or ""
    )
    result["metadata"] = meta

    files = dist.files
    if files is None:
        return result

    result["record_available"] = True
    result["total_files"] = len(files)

    for f in files:
        if f.hash is None:
            # RECORD file itself has no hash
            continue
        try:
            full_path = f.locate()
            data = full_path.read_bytes()
            digest = hashlib.sha256(data).digest()
            b64_digest = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
            if b64_digest == f.hash.value:
                result["verified_files"] += 1
            else:
                result["failed_files"].append(str(f))
        except (FileNotFoundError, OSError):
            result["failed_files"].append(str(f))

    result["record_intact"] = len(result["failed_files"]) == 0
    return result


async def fetch_pypi_release_metadata(
    package_name: str,
    version: str,
    client: httpx.AsyncClient,
) -> Optional[dict]:
    """Fetch comprehensive PyPI release metadata for verification display."""
    response = await request_with_retry(
        client, "GET",
        f"https://pypi.org/pypi/{package_name}/{version}/json",
    )

    if response and response.status_code == 200:
        try:
            data = response.json()
            info = data.get("info", {})
            project_urls = info.get("project_urls") or {}
            source_repo = (
                project_urls.get("Repository")
                or project_urls.get("Source")
                or project_urls.get("Homepage")
                or ""
            )

            sha256_digests = []
            for url_entry in data.get("urls", []):
                digests = url_entry.get("digests", {})
                sha256 = digests.get("sha256")
                if sha256:
                    sha256_digests.append({
                        "filename": url_entry.get("filename"),
                        "sha256": sha256,
                        "packagetype": url_entry.get("packagetype"),
                    })

            return {
                "name": info.get("name", package_name),
                "version": info.get("version", version),
                "license": info.get("license", ""),
                "source_repo": source_repo,
                "author": info.get("author", ""),
                "sha256_digests": sha256_digests,
                "requires_python": info.get("requires_python", ""),
                "project_urls": project_urls,
            }
        except (ValueError, KeyError):
            pass

    return None
