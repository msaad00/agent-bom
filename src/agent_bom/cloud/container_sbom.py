"""Container image SBOM scanner — Docker Hub / OCI registry metadata without full layer pull.

Fetches registry metadata (manifest, config labels, creation date) for container images
discovered on RunPod, Vast.ai, and Lambda Labs instances. Flags security posture findings:
UNPINNED_TAG, NO_SBOM_ATTESTATION, STALE_IMAGE, MISSING_PROVENANCE.

No full image layer download required — uses Docker Hub registry API v2.

Sources:
  Docker Registry API v2: https://distribution.github.io/distribution/spec/api/
  OCI Image Spec: https://specs.opencontainers.org/image-spec/
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache

logger = logging.getLogger(__name__)

_DOCKERHUB_TOKEN_URL = "https://auth.docker.io/token"
_DOCKERHUB_REGISTRY_URL = "https://registry-1.docker.io/v2"
_API_TIMEOUT = 10

_STALE_IMAGE_DAYS = 180

_MUTABLE_TAGS = frozenset({"latest", "main", "master", "dev", "edge", "nightly", "stable", ""})

_DOCKERHUB_REGISTRIES = frozenset({"docker.io", "registry-1.docker.io"})

# OCI label key substrings that indicate SBOM attestation in image config
_SBOM_LABEL_HINTS = ("sbom", "syft", "bom", "cyclonedx", "spdx")
# OCI label key substrings that indicate provenance attestation
_PROVENANCE_LABEL_HINTS = ("provenance", "buildkit", "org.opencontainers.image", "vcs-ref", "source-url")


@dataclass
class ContainerImageFinding:
    """A security posture finding for a container image."""

    finding_type: str  # UNPINNED_TAG | NO_SBOM_ATTESTATION | STALE_IMAGE | MISSING_PROVENANCE
    severity: str  # "high" | "medium" | "low"
    detail: str

    def to_dict(self) -> dict:
        return {"finding_type": self.finding_type, "severity": self.severity, "detail": self.detail}


@dataclass
class ContainerImageSbom:
    """SBOM-style inventory record for a single container image."""

    image_ref: str
    registry: str
    org: str
    repo: str
    tag: str
    digest: str | None
    size_bytes: int | None
    created_at: str | None  # ISO-8601 or None
    os: str | None
    architecture: str | None
    sbom_attested: bool
    provenance_attested: bool
    findings: list[ContainerImageFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "image_ref": self.image_ref,
            "registry": self.registry,
            "org": self.org,
            "repo": self.repo,
            "tag": self.tag,
            "digest": self.digest,
            "size_bytes": self.size_bytes,
            "created_at": self.created_at,
            "os": self.os,
            "architecture": self.architecture,
            "sbom_attested": self.sbom_attested,
            "provenance_attested": self.provenance_attested,
            "findings": [f.to_dict() for f in self.findings],
            "finding_count": len(self.findings),
        }


def _parse_image_ref(image_ref: str) -> tuple[str, str, str, str]:
    """Parse image_ref into (registry, org, repo, tag).

    Examples::

        "pytorch/pytorch:2.1.0"           → ("docker.io", "pytorch", "pytorch", "2.1.0")
        "ubuntu:22.04"                     → ("docker.io", "library", "ubuntu", "22.04")
        "nvcr.io/nvidia/cuda:12.3"        → ("nvcr.io", "nvidia", "cuda", "12.3")
        "ghcr.io/huggingface/tgi:latest"  → ("ghcr.io", "huggingface", "tgi", "latest")
    """
    tag = "latest"
    last_part = image_ref.rsplit("/", 1)[-1]
    if ":" in last_part:
        image_ref, tag = image_ref.rsplit(":", 1)

    parts = image_ref.split("/")
    if len(parts) >= 3 and ("." in parts[0] or ":" in parts[0]):
        # Custom registry: nvcr.io/nvidia/cuda, ghcr.io/huggingface/tgi
        registry = parts[0]
        org = parts[1]
        repo = "/".join(parts[2:])
    elif len(parts) == 2:
        # Docker Hub user image: pytorch/pytorch
        registry = "docker.io"
        org = parts[0]
        repo = parts[1]
    else:
        # Docker Hub official image: ubuntu
        registry = "docker.io"
        org = "library"
        repo = parts[0]

    return registry, org, repo, tag


def _dockerhub_token(org: str, repo: str) -> str | None:
    """Fetch an anonymous Docker Hub pull token for public images."""
    try:
        import requests
    except ImportError:
        return None
    try:
        resp = requests.get(
            _DOCKERHUB_TOKEN_URL,
            params={"service": "registry.docker.io", "scope": f"repository:{org}/{repo}:pull"},
            timeout=_API_TIMEOUT,
        )
        if resp.status_code == 200:
            return resp.json().get("token")
    except Exception:  # noqa: BLE001
        pass
    return None


def _fetch_manifest(org: str, repo: str, tag: str, token: str) -> dict | None:
    """Fetch the image manifest from Docker Hub registry API v2."""
    try:
        import requests
    except ImportError:
        return None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": ("application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json"),
    }
    try:
        resp = requests.get(
            f"{_DOCKERHUB_REGISTRY_URL}/{org}/{repo}/manifests/{tag}",
            headers=headers,
            timeout=_API_TIMEOUT,
        )
        if resp.status_code == 200:
            return {"manifest": resp.json(), "digest": resp.headers.get("Docker-Content-Digest")}
    except Exception:  # noqa: BLE001
        pass
    return None


def _fetch_config(org: str, repo: str, config_digest: str, token: str) -> dict | None:
    """Fetch the image config blob (contains OS, arch, creation time, labels)."""
    try:
        import requests
    except ImportError:
        return None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.docker.container.image.v1+json",
    }
    try:
        resp = requests.get(
            f"{_DOCKERHUB_REGISTRY_URL}/{org}/{repo}/blobs/{config_digest}",
            headers=headers,
            timeout=_API_TIMEOUT,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:  # noqa: BLE001
        pass
    return None


def _days_since(created_at_str: str | None) -> int | None:
    if not created_at_str:
        return None
    try:
        dt = datetime.fromisoformat(created_at_str.rstrip("Z") + "+00:00")
        return (datetime.now(timezone.utc) - dt).days
    except (ValueError, TypeError):
        return None


def _check_labels(labels: dict[str, str]) -> tuple[bool, bool]:
    """Check OCI labels for SBOM and provenance attestation hints."""
    keys_lower = [k.lower() for k in labels]
    sbom = any(hint in k for k in keys_lower for hint in _SBOM_LABEL_HINTS)
    prov = any(hint in k for k in keys_lower for hint in _PROVENANCE_LABEL_HINTS)
    return sbom, prov


@lru_cache(maxsize=512)
def scan_container_image(image_ref: str) -> ContainerImageSbom:
    """Scan a container image reference for SBOM and provenance posture.

    Queries Docker Hub registry API v2 to fetch manifest and config blob
    without downloading image layers. For non-Docker Hub registries, returns
    a best-effort record with MISSING_PROVENANCE finding.

    Cached per-process by ``image_ref`` so that fleets running the same
    image across many pods (RunPod / Vast.ai discovery) only make one
    Docker Hub round-trip per unique image, avoiding anonymous rate
    limits (100 / 6h) and saving ~3 sequential ``requests.get`` calls per
    duplicate. Cache size is bounded to 512 entries.

    Args:
        image_ref: Image reference string, e.g. ``"pytorch/pytorch:2.1.0"``.

    Returns:
        :class:`ContainerImageSbom` populated with metadata and posture findings.
    """
    registry, org, repo, tag = _parse_image_ref(image_ref)

    findings: list[ContainerImageFinding] = []
    digest = None
    size_bytes = None
    created_at = None
    os_info = None
    arch_info = None
    sbom_attested = False
    provenance_attested = False
    registry_queried = False

    # ── Unpinned tag ──────────────────────────────────────────────────────────
    if tag.lower() in _MUTABLE_TAGS:
        findings.append(
            ContainerImageFinding(
                finding_type="UNPINNED_TAG",
                severity="medium",
                detail=f"Image uses mutable tag '{tag}' — pin to a digest or semantic version for reproducibility",
            )
        )

    # ── Registry metadata query (Docker Hub only) ─────────────────────────────
    if registry in _DOCKERHUB_REGISTRIES or registry == "":
        token = _dockerhub_token(org, repo)
        if token:
            manifest_data = _fetch_manifest(org, repo, tag, token)
            if manifest_data:
                registry_queried = True
                manifest = manifest_data["manifest"]
                digest = manifest_data.get("digest")

                config_digest = (manifest.get("config") or {}).get("digest")
                if config_digest:
                    config = _fetch_config(org, repo, config_digest, token)
                    if config:
                        os_info = config.get("os")
                        arch_info = config.get("architecture")
                        created_at = config.get("created")
                        labels = (config.get("config") or {}).get("Labels") or {}
                        sbom_attested, provenance_attested = _check_labels(labels)

                layers = manifest.get("layers") or []
                if layers:
                    size_bytes = sum(layer.get("size", 0) for layer in layers)
    else:
        findings.append(
            ContainerImageFinding(
                finding_type="MISSING_PROVENANCE",
                severity="low",
                detail=(
                    f"Non-Docker Hub registry '{registry}' — provenance metadata not queried "
                    "(no credentials available for private registry)"
                ),
            )
        )

    # ── Stale image ───────────────────────────────────────────────────────────
    age_days = _days_since(created_at)
    if age_days is not None and age_days > _STALE_IMAGE_DAYS:
        findings.append(
            ContainerImageFinding(
                finding_type="STALE_IMAGE",
                severity="medium",
                detail=f"Image is {age_days} days old (threshold: {_STALE_IMAGE_DAYS}) — may contain unpatched CVEs",
            )
        )

    # ── SBOM / provenance attestation (only when we got registry data) ────────
    if registry_queried:
        if not sbom_attested:
            findings.append(
                ContainerImageFinding(
                    finding_type="NO_SBOM_ATTESTATION",
                    severity="low",
                    detail="No SBOM attestation labels found in image config — add Syft/CycloneDX generation to CI",
                )
            )
        if not provenance_attested:
            findings.append(
                ContainerImageFinding(
                    finding_type="MISSING_PROVENANCE",
                    severity="low",
                    detail="No OCI provenance labels found in image config — add BuildKit provenance attestation to CI",
                )
            )

    logger.debug("container_sbom: %s — %d finding(s)", image_ref, len(findings))

    return ContainerImageSbom(
        image_ref=image_ref,
        registry=registry,
        org=org,
        repo=repo,
        tag=tag,
        digest=digest,
        size_bytes=size_bytes,
        created_at=created_at,
        os=os_info,
        architecture=arch_info,
        sbom_attested=sbom_attested,
        provenance_attested=provenance_attested,
        findings=findings,
    )
