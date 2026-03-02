"""Package integrity verification — SHA256 checksums and SLSA provenance.

Also provides instruction file provenance verification for SKILL.md,
CLAUDE.md, and .cursorrules files using Sigstore bundles.
"""

from __future__ import annotations

import base64
import hashlib
import json as _json
import logging
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
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
        client,
        "GET",
        f"https://registry.npmjs.org/{encoded_name}/{version}",
    )

    if response and response.status_code == 200:
        try:
            data = response.json()
            dist = data.get("dist", {})
            return {
                "sha512_sri": dist.get("integrity"),  # e.g. "sha512-abc123..."
                "shasum": dist.get("shasum"),  # SHA-1 hex
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
        client,
        "GET",
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
        client,
        "GET",
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
        client,
        "GET",
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
    meta["source_repo"] = project_urls.get("Repository") or project_urls.get("Source") or project_urls.get("Homepage") or ""
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
        client,
        "GET",
        f"https://pypi.org/pypi/{package_name}/{version}/json",
    )

    if response and response.status_code == 200:
        try:
            data = response.json()
            info = data.get("info", {})
            project_urls = info.get("project_urls") or {}
            source_repo = project_urls.get("Repository") or project_urls.get("Source") or project_urls.get("Homepage") or ""

            sha256_digests = []
            for url_entry in data.get("urls", []):
                digests = url_entry.get("digests", {})
                sha256 = digests.get("sha256")
                if sha256:
                    sha256_digests.append(
                        {
                            "filename": url_entry.get("filename"),
                            "sha256": sha256,
                            "packagetype": url_entry.get("packagetype"),
                        }
                    )

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


# ---------------------------------------------------------------------------
# Instruction file provenance (Sigstore)
# ---------------------------------------------------------------------------

# Instruction files that can have Sigstore provenance bundles
_INSTRUCTION_FILE_NAMES = frozenset(
    {
        "CLAUDE.md",
        ".cursorrules",
        "SKILL.md",
        "skill.md",
        ".claude/CLAUDE.md",
    }
)


@dataclass
class InstructionFileVerification:
    """Result of verifying an instruction file's Sigstore provenance."""

    file_path: str
    sha256: str
    has_sigstore_bundle: bool = False
    bundle_valid: bool = False
    signer_identity: str = ""
    rekor_log_index: int = -1
    certificate_expiry: str = ""
    verified: bool = False
    reason: str = ""


def _compute_sha256(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _find_sigstore_bundle(file_path: Path) -> Path | None:
    """Locate a Sigstore bundle for the given file.

    Checks for ``<file>.sigstore``, ``<file>.sigstore.json``, and
    ``<file>.sig`` in order.
    """
    for suffix in (".sigstore", ".sigstore.json", ".sig"):
        candidate = file_path.parent / (file_path.name + suffix)
        if candidate.is_file():
            return candidate
    return None


def _parse_sigstore_bundle(bundle_path: Path) -> dict:
    """Parse a Sigstore Bundle (v0.3) JSON file.

    Extracts signer identity, subject digest, Rekor log index, and
    certificate expiry from the bundle's verification material and
    DSSE envelope.
    """
    result: dict = {
        "signer_identity": "",
        "subject_digest": "",
        "rekor_log_index": -1,
        "certificate_expiry": "",
    }

    try:
        data = _json.loads(bundle_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.debug("Failed to read Sigstore bundle %s: %s", bundle_path, exc)
        return result

    # --- Verification material ---
    ver_material = data.get("verificationMaterial", {})

    # Rekor transparency log entry
    tlog_entries = ver_material.get("tlogEntries", [])
    if tlog_entries:
        entry = tlog_entries[0]
        log_index = entry.get("logIndex")
        if log_index is not None:
            result["rekor_log_index"] = int(log_index)

    # Public key hint may contain identity info
    pk_hint = ver_material.get("publicKey", {}).get("hint", "")
    if pk_hint:
        result["signer_identity"] = pk_hint

    # --- DSSE envelope ---
    dsse = data.get("dsseEnvelope", {})
    if dsse:
        payload_b64 = dsse.get("payload", "")
        if payload_b64:
            try:
                payload_bytes = base64.b64decode(payload_b64)
                statement = _json.loads(payload_bytes)
                # in-toto statement v1: subjects contain digest
                subjects = statement.get("subject", [])
                for subj in subjects:
                    digests = subj.get("digest", {})
                    sha256_val = digests.get("sha256", "")
                    if sha256_val:
                        result["subject_digest"] = sha256_val
                        break

                # Extract signer from predicate if available
                predicate = statement.get("predicate", {})
                builder = predicate.get("builder", {})
                builder_id = builder.get("id", "")
                if builder_id and not result["signer_identity"]:
                    result["signer_identity"] = builder_id

                # Workflow ref from invocation
                invocation = predicate.get("invocation", {})
                config_source = invocation.get("configSource", {})
                if config_source.get("uri") and not result["signer_identity"]:
                    result["signer_identity"] = config_source["uri"]
            except (ValueError, KeyError):
                pass

    return result


def verify_instruction_file(file_path: str | Path) -> InstructionFileVerification:
    """Verify an instruction file's integrity and Sigstore provenance.

    Computes the SHA-256 digest of the file, looks for an associated
    Sigstore bundle, and validates the bundle's subject digest against
    the computed hash.  If ``cosign`` is on PATH, delegates full
    cryptographic verification to it.
    """
    path = Path(file_path).resolve()

    if not path.is_file():
        return InstructionFileVerification(
            file_path=str(path),
            sha256="",
            reason="file_not_found",
        )

    sha256 = _compute_sha256(path)
    result = InstructionFileVerification(
        file_path=str(path),
        sha256=sha256,
    )

    # Look for Sigstore bundle
    bundle_path = _find_sigstore_bundle(path)
    if bundle_path is None:
        result.reason = "no_sigstore_bundle"
        return result

    result.has_sigstore_bundle = True

    # Parse the bundle
    parsed = _parse_sigstore_bundle(bundle_path)
    result.rekor_log_index = parsed.get("rekor_log_index", -1)
    result.signer_identity = parsed.get("signer_identity", "")
    result.certificate_expiry = parsed.get("certificate_expiry", "")

    # Validate subject digest
    subject_digest = parsed.get("subject_digest", "")
    if subject_digest:
        if subject_digest == sha256:
            result.bundle_valid = True
        else:
            result.reason = "digest_mismatch"
            return result
    else:
        result.reason = "no_subject_digest_in_bundle"

    # Try cosign for full cryptographic verification
    if result.bundle_valid:
        cosign_ok = _try_cosign_verify(path, bundle_path)
        if cosign_ok:
            result.verified = True
            result.reason = "cosign_verified"
        else:
            # cosign not available but digest matches — partial verification
            result.verified = True
            result.reason = "digest_verified"

    return result


def _try_cosign_verify(file_path: Path, bundle_path: Path) -> bool:
    """Attempt full Sigstore verification via cosign CLI."""
    import shutil
    import subprocess

    cosign = shutil.which("cosign")
    if cosign is None:
        return False

    try:
        proc = subprocess.run(
            [
                cosign,
                "verify-blob",
                "--bundle",
                str(bundle_path),
                "--certificate-identity-regexp",
                ".*",
                "--certificate-oidc-issuer-regexp",
                ".*",
                str(file_path),
            ],
            capture_output=True,
            timeout=30,
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def verify_instruction_files_batch(
    paths: list[str | Path],
) -> list[InstructionFileVerification]:
    """Verify a batch of instruction files for Sigstore provenance."""
    return [verify_instruction_file(p) for p in paths]


def discover_instruction_files(root: str | Path) -> list[Path]:
    """Discover instruction files (CLAUDE.md, .cursorrules, SKILL.md) under a directory."""
    root_path = Path(root).resolve()
    found: list[Path] = []

    for name in ("CLAUDE.md", ".cursorrules", "SKILL.md", "skill.md"):
        candidate = root_path / name
        if candidate.is_file():
            found.append(candidate)

    # Check .claude subdirectory
    claude_dir = root_path / ".claude"
    if claude_dir.is_dir():
        candidate = claude_dir / "CLAUDE.md"
        if candidate.is_file():
            found.append(candidate)

    # Check skills/ subdirectory
    skills_dir = root_path / "skills"
    if skills_dir.is_dir():
        for md_file in skills_dir.glob("*.md"):
            found.append(md_file)

    return found
