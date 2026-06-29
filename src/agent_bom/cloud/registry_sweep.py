"""Registry-wide container-image sweep — agentless, read-only.

Moves agent-bom from single-image scanning toward *registry coverage*: enumerate
every repository and tag in a cloud container registry (AWS ECR, Azure ACR, or
Google Artifact Registry / GCR), dedupe the work list by image digest, cap the
number of images scanned, and run the existing native
:func:`agent_bom.image.scan_image` on each.

Trust posture — identical to the inventory discoverers:

* **Read-only.** Only registry *read* APIs are called (``DescribeRepositories`` /
  ``DescribeImages`` / ``ListImages`` for ECR, ACR repo+tag listing, GAR
  ``ListRepositories`` / ``ListDockerImages``). No pushes, deletes, or tag
  mutations. ``scan_image`` only ever pulls an image to read its package
  manifests.
* **Graceful degradation.** A registry the role cannot read, or a single image
  that fails to pull, produces an actionable warning and the sweep continues —
  never a silent empty result and never an aborted sweep.
* **Determinism / idempotency.** Images are deduped by digest, the work list is
  sorted deterministically (most-recently-pushed first, then by reference), and
  the same registry state yields the same result set.
* **Cap transparency.** When the discovered image count exceeds
  ``AGENT_BOM_REGISTRY_MAX_IMAGES`` (default 50) the sweep scans the most-recent
  images first and emits a warning naming exactly how many were skipped — no
  silent truncation.

Usage::

    from agent_bom.cloud.registry_sweep import sweep_registry

    report = sweep_registry(provider="ecr", region="us-east-1")
    for image in report["images"]:
        print(image["reference"], image["package_count"])
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from agent_bom.cloud.normalization import sanitize_discovery_warning
from agent_bom.graph.severity import severity_rank

logger = logging.getLogger(__name__)

# Cap on the number of images a single sweep will pull + scan. Operators raise
# this for a full estate sweep; the default keeps an ad-hoc sweep bounded.
MAX_IMAGES_ENV = "AGENT_BOM_REGISTRY_MAX_IMAGES"
DEFAULT_MAX_IMAGES = 50

# Per-repository tag fan-out cap so a single sprawling repo cannot starve the
# rest of the registry before the global digest-dedupe + cap apply.
MAX_TAGS_PER_REPO_ENV = "AGENT_BOM_REGISTRY_MAX_TAGS_PER_REPO"
DEFAULT_MAX_TAGS_PER_REPO = 25

_PROVIDERS = ("ecr", "acr", "gar")

# A pushed-at sentinel for images whose registry exposes no timestamp. Sorting
# newest-first means undated images rank *after* dated ones (older), which keeps
# the cap biased toward images we can prove are recent.
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class RegistryImage:
    """One enumerable image: a ``repo:tag`` reference and its content digest.

    Two tags pointing at the same digest dedupe to a single scan (the first
    reference, deterministically). ``pushed_at`` drives newest-first ordering so
    the cap keeps the freshest images.
    """

    reference: str  # full pullable ref, e.g. "1.dkr.ecr.us-east-1.amazonaws.com/app:v1"
    repository: str  # repository name, e.g. "app"
    digest: str  # content digest, e.g. "sha256:..." (dedupe key; "" when unknown)
    pushed_at: Optional[datetime] = None
    registry: str = ""  # registry host / login server

    def sort_key(self) -> tuple[float, str]:
        """Newest-first, then reference — total order, no ties on equal timestamps."""
        ts = (self.pushed_at or _EPOCH).timestamp()
        return (-ts, self.reference)

    def dedupe_key(self) -> str:
        """Images with the same digest are the same content → scan once.

        Falls back to the full reference when the registry exposes no digest, so
        a digest-less registry still scans each distinct tag exactly once.
        """
        return self.digest or f"ref::{self.reference}"


@dataclass
class SweepResult:
    """Aggregated outcome of a registry sweep — deterministic, JSON-serialisable."""

    provider: str
    status: str = "ok"
    registry: str = ""
    images: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    discovered_count: int = 0  # distinct images found before the cap
    scanned_count: int = 0
    skipped_by_cap: int = 0
    failed_count: int = 0
    max_images: int = DEFAULT_MAX_IMAGES

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "status": self.status,
            "registry": self.registry,
            "discovered_count": self.discovered_count,
            "scanned_count": self.scanned_count,
            "skipped_by_cap": self.skipped_by_cap,
            "failed_count": self.failed_count,
            "max_images": self.max_images,
            "total_packages": sum(int(img.get("package_count", 0)) for img in self.images),
            "total_vulnerable_packages": sum(int(img.get("vulnerable_package_count", 0)) for img in self.images),
            "images": self.images,
            "warnings": self.warnings,
        }


def _max_images() -> int:
    """Resolve the image cap from the environment, clamped to a sane minimum."""
    raw = os.environ.get(MAX_IMAGES_ENV, "").strip()
    if not raw:
        return DEFAULT_MAX_IMAGES
    try:
        value = int(raw)
    except ValueError:
        logger.warning("%s=%r is not an integer; using default %d", MAX_IMAGES_ENV, raw, DEFAULT_MAX_IMAGES)
        return DEFAULT_MAX_IMAGES
    return max(1, value)


def _max_tags_per_repo() -> int:
    raw = os.environ.get(MAX_TAGS_PER_REPO_ENV, "").strip()
    if not raw:
        return DEFAULT_MAX_TAGS_PER_REPO
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_TAGS_PER_REPO
    return max(1, value)


# ───────────────────────── ECR enumeration (AWS) ──────────────────────────


def enumerate_ecr_images(*, region: Optional[str] = None, profile: Optional[str] = None, warnings: list[str]) -> list[RegistryImage]:
    """Enumerate every ECR repository + tagged image in the account (read-only).

    Reuses the boto3 session pattern from :mod:`agent_bom.cloud.aws_inventory`.
    Walks ``describe_repositories`` → ``describe_images`` and emits one
    :class:`RegistryImage` per tag, keyed for dedupe by ``imageDigest``. Missing
    credentials / boto3 / read permission degrade to ``[]`` plus a warning.
    """
    try:
        import boto3
    except ImportError:
        warnings.append("boto3 is required for ECR sweep. Install with: pip install 'agent-bom[aws]'")
        return []

    try:
        session_kwargs: dict[str, Any] = {}
        if profile:
            session_kwargs["profile_name"] = profile
        session = boto3.Session(**session_kwargs)
    except Exception as exc:  # noqa: BLE001 — boto profile/config errors must not crash a sweep
        warnings.append(f"Could not create AWS session for ECR sweep: {sanitize_discovery_warning(exc)}")
        return []

    resolved_region = region or session.region_name or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    try:
        client = session.client("ecr", region_name=resolved_region)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not create ECR client: {sanitize_discovery_warning(exc)}")
        return []

    images: list[RegistryImage] = []
    tag_cap = _max_tags_per_repo()
    try:
        repo_paginator = client.get_paginator("describe_repositories")
        for repo_page in repo_paginator.paginate():
            for repo in repo_page.get("repositories", []):
                repo_name = str(repo.get("repositoryName", "") or "")
                repo_uri = str(repo.get("repositoryUri", "") or "")
                if not repo_name or not repo_uri:
                    continue
                registry_host = repo_uri.split("/", 1)[0]
                images.extend(_enumerate_ecr_repo(client, repo_name, repo_uri, registry_host, tag_cap=tag_cap, warnings=warnings))
    except Exception as exc:  # noqa: BLE001 — list failure must degrade, not abort
        warnings.append(
            "Skipped ECR repositories: role lacks ecr:DescribeRepositories — "
            f"add it to the read-only policy to enumerate the registry. ({sanitize_discovery_warning(exc)})"
        )
    return images


def _enumerate_ecr_repo(
    client: Any, repo_name: str, repo_uri: str, registry_host: str, *, tag_cap: int, warnings: list[str]
) -> list[RegistryImage]:
    """Enumerate the tagged images of one ECR repository (read-only)."""
    out: list[RegistryImage] = []
    seen_digests: set[str] = set()
    try:
        img_paginator = client.get_paginator("describe_images")
        for img_page in img_paginator.paginate(repositoryName=repo_name):
            for detail in img_page.get("imageDetails", []):
                digest = str(detail.get("imageDigest", "") or "")
                pushed = detail.get("imagePushedAt")
                pushed_at = pushed if isinstance(pushed, datetime) else None
                tags = [str(t) for t in (detail.get("imageTags") or []) if t]
                if not tags:
                    # Untagged image — scannable by digest reference.
                    if digest:
                        out.append(
                            RegistryImage(
                                reference=f"{repo_uri}@{digest}",
                                repository=repo_name,
                                digest=digest,
                                pushed_at=pushed_at,
                                registry=registry_host,
                            )
                        )
                    continue
                for tag in sorted(tags):
                    # Within a repo, scan each distinct digest once even if it
                    # carries several tags (the rest dedupe globally anyway).
                    if digest and digest in seen_digests:
                        continue
                    if digest:
                        seen_digests.add(digest)
                    out.append(
                        RegistryImage(
                            reference=f"{repo_uri}:{tag}",
                            repository=repo_name,
                            digest=digest,
                            pushed_at=pushed_at,
                            registry=registry_host,
                        )
                    )
    except Exception as exc:  # noqa: BLE001 — one repo failing must not sink the registry
        warnings.append(f"Could not list images in ECR repository {repo_name}: {sanitize_discovery_warning(exc)}")
        return out
    # Newest-first, then cap this repo's tag fan-out.
    out.sort(key=lambda image: image.sort_key())
    if len(out) > tag_cap:
        out = out[:tag_cap]
    return out


# ───────────────────────── ACR enumeration (Azure) ─────────────────────────


def enumerate_acr_images(*, registry: str, credential: Any = None, warnings: list[str]) -> list[RegistryImage]:
    """Enumerate every repository + tag in an Azure Container Registry (read-only).

    Uses ``azure-containerregistry``'s data-plane ``ContainerRegistryClient``
    with a token credential (``DefaultAzureCredential`` by default — token/cred
    only, never a password). ``registry`` is the ACR login server (e.g.
    ``myacr.azurecr.io``). Missing SDK / credential / read permission degrade to
    ``[]`` plus a warning.
    """
    if not registry:
        warnings.append("ACR sweep requires a registry login server (e.g. myacr.azurecr.io).")
        return []
    endpoint = registry if "://" in registry else f"https://{registry}"
    login_server = endpoint.split("://", 1)[1]

    try:
        from azure.containerregistry import ContainerRegistryClient
    except ImportError:
        warnings.append("azure-containerregistry is required for ACR sweep. Install with: pip install 'agent-bom[azure]'")
        return []

    if credential is None:
        try:
            from azure.identity import DefaultAzureCredential

            credential = DefaultAzureCredential()
        except Exception as exc:  # noqa: BLE001 — credential chain errors must not crash a sweep
            warnings.append(f"Could not resolve Azure credential for ACR sweep: {sanitize_discovery_warning(exc)}")
            return []

    try:
        client = ContainerRegistryClient(endpoint, credential)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not create ACR client for {login_server}: {sanitize_discovery_warning(exc)}")
        return []

    images: list[RegistryImage] = []
    tag_cap = _max_tags_per_repo()
    try:
        repositories = list(client.list_repository_names())
    except Exception as exc:  # noqa: BLE001 — list failure must degrade, not abort
        warnings.append(
            f"Skipped ACR {login_server}: credential lacks AcrPull/repository read — "
            f"grant the read-only role to enumerate the registry. ({sanitize_discovery_warning(exc)})"
        )
        return []

    for repo_name in sorted(str(r) for r in repositories):
        images.extend(_enumerate_acr_repo(client, login_server, repo_name, tag_cap=tag_cap, warnings=warnings))
    return images


def _enumerate_acr_repo(client: Any, login_server: str, repo_name: str, *, tag_cap: int, warnings: list[str]) -> list[RegistryImage]:
    """Enumerate the tagged manifests of one ACR repository (read-only)."""
    out: list[RegistryImage] = []
    try:
        for tag in client.list_tag_properties(repo_name):
            tag_name = str(getattr(tag, "name", "") or "")
            if not tag_name:
                continue
            digest = str(getattr(tag, "digest", "") or "")
            pushed = getattr(tag, "last_updated_on", None) or getattr(tag, "created_on", None)
            pushed_at = pushed if isinstance(pushed, datetime) else None
            out.append(
                RegistryImage(
                    reference=f"{login_server}/{repo_name}:{tag_name}",
                    repository=repo_name,
                    digest=digest,
                    pushed_at=pushed_at,
                    registry=login_server,
                )
            )
    except Exception as exc:  # noqa: BLE001 — one repo failing must not sink the registry
        warnings.append(f"Could not list tags in ACR repository {repo_name}: {sanitize_discovery_warning(exc)}")
        return out
    out.sort(key=lambda image: image.sort_key())
    if len(out) > tag_cap:
        out = out[:tag_cap]
    return out


# ─────────────── GAR / Artifact Registry enumeration (GCP) ───────────────


def enumerate_gar_images(
    *,
    project: Optional[str] = None,
    location: Optional[str] = None,
    credentials: Any = None,
    warnings: list[str],
) -> list[RegistryImage]:
    """Enumerate Docker images across Artifact Registry repositories (read-only).

    Uses ``google-cloud-artifact-registry``'s ``ArtifactRegistryClient`` to list
    Docker images, which already carry the digest + URI + upload timestamp, so a
    single ``list_docker_images`` per repository yields every scannable image.
    Missing SDK / project / read permission degrade to ``[]`` plus a warning.
    """
    resolved_project = project or os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT") or ""
    if not resolved_project:
        warnings.append("GAR sweep requires a GCP project. Pass --project or set GOOGLE_CLOUD_PROJECT.")
        return []

    try:
        from google.cloud import artifactregistry_v1
    except ImportError:
        warnings.append("google-cloud-artifact-registry is required for GAR sweep. Install with: pip install 'agent-bom[gcp]'")
        return []

    try:
        client = artifactregistry_v1.ArtifactRegistryClient(credentials=credentials)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not create Artifact Registry client: {sanitize_discovery_warning(exc)}")
        return []

    # When no location is given, sweep the common multi-regions rather than guess
    # a single one — each is an independent, degradeable discoverer.
    locations = [location] if location else ["us", "europe", "asia"]

    images: list[RegistryImage] = []
    tag_cap = _max_tags_per_repo()
    for loc in locations:
        parent = f"projects/{resolved_project}/locations/{loc}"
        try:
            repos = list(client.list_repositories(parent=parent))
        except Exception as exc:  # noqa: BLE001 — one location failing must not sink the sweep
            warnings.append(
                f"Skipped Artifact Registry in {loc}: lacks artifactregistry.repositories.list — "
                f"grant the read-only role to enumerate the registry. ({sanitize_discovery_warning(exc)})"
            )
            continue
        for repo in repos:
            fmt = str(getattr(repo, "format_", "") or getattr(repo, "format", "") or "").upper()
            if fmt and "DOCKER" not in fmt:
                continue
            repo_full = str(getattr(repo, "name", "") or "")
            if not repo_full:
                continue
            images.extend(_enumerate_gar_repo(client, repo_full, loc, resolved_project, tag_cap=tag_cap, warnings=warnings))
    return images


def _enumerate_gar_repo(
    client: Any, repo_full: str, location: str, project: str, *, tag_cap: int, warnings: list[str]
) -> list[RegistryImage]:
    """Enumerate Docker images of one Artifact Registry repository (read-only)."""
    out: list[RegistryImage] = []
    repo_short = repo_full.rsplit("/", 1)[-1]
    host = f"{location}-docker.pkg.dev"
    try:
        for image in client.list_docker_images(parent=repo_full):
            uri = str(getattr(image, "uri", "") or "")
            if not uri:
                continue
            tags = [str(t) for t in (getattr(image, "tags", None) or []) if t]
            digest = uri.split("@", 1)[1] if "@" in uri else ""
            upload = getattr(image, "upload_time", None)
            pushed_at = _gar_timestamp(upload)
            base = f"{host}/{project}/{repo_short}"
            if tags:
                # One scannable ref per tag (deduped globally by digest).
                for tag in sorted(tags):
                    out.append(
                        RegistryImage(
                            reference=f"{base}/{_gar_image_name(uri, repo_short)}:{tag}",
                            repository=repo_short,
                            digest=digest,
                            pushed_at=pushed_at,
                            registry=host,
                        )
                    )
            elif digest:
                out.append(
                    RegistryImage(
                        reference=uri,
                        repository=repo_short,
                        digest=digest,
                        pushed_at=pushed_at,
                        registry=host,
                    )
                )
    except Exception as exc:  # noqa: BLE001 — one repo failing must not sink the registry
        warnings.append(f"Could not list images in Artifact Registry repository {repo_short}: {sanitize_discovery_warning(exc)}")
        return out
    out.sort(key=lambda image: image.sort_key())
    if len(out) > tag_cap:
        out = out[:tag_cap]
    return out


def _gar_image_name(uri: str, repo_short: str) -> str:
    """Best-effort image-name segment from a GAR image URI.

    A GAR URI looks like ``LOC-docker.pkg.dev/PROJECT/REPO/IMAGE@sha256:...``;
    the image name is the path segment(s) after the repo. Falls back to the repo
    name when the structure is unexpected.
    """
    path = uri.split("@", 1)[0]
    marker = f"/{repo_short}/"
    idx = path.find(marker)
    if idx >= 0:
        tail = path[idx + len(marker) :]
        if tail:
            return tail
    return repo_short


def _gar_timestamp(value: Any) -> Optional[datetime]:
    """Coerce a GAR upload-time protobuf Timestamp / datetime into a datetime."""
    if isinstance(value, datetime):
        return value
    to_dt = getattr(value, "ToDatetime", None)
    if callable(to_dt):
        try:
            dt = to_dt()
            return dt if isinstance(dt, datetime) else None
        except Exception:  # noqa: BLE001
            return None
    return None


# ───────────────────────────── orchestration ──────────────────────────────


def dedupe_and_cap(images: list[RegistryImage], *, max_images: int, warnings: list[str]) -> tuple[list[RegistryImage], int, int]:
    """Dedupe by digest, sort newest-first, and cap — deterministically.

    Returns ``(work_list, discovered_count, skipped_by_cap)``. When the cap drops
    images, a warning naming the count is appended (no silent truncation). The
    work list is fully ordered, so the same registry state always yields the same
    scan set.
    """
    deduped: dict[str, RegistryImage] = {}
    for image in sorted(images, key=lambda im: im.sort_key()):
        # First wins under the deterministic sort: newest pushed_at, then the
        # lexically-smallest reference for that digest.
        deduped.setdefault(image.dedupe_key(), image)

    ordered = sorted(deduped.values(), key=lambda im: im.sort_key())
    discovered = len(ordered)

    if discovered <= max_images:
        return ordered, discovered, 0

    skipped = discovered - max_images
    kept = ordered[:max_images]
    warnings.append(
        f"Image cap reached: scanned the {max_images} most-recent images and skipped {skipped} older image(s). "
        f"Raise {MAX_IMAGES_ENV} to cover the full registry."
    )
    return kept, discovered, skipped


def _summarize_packages(packages: list[Any]) -> tuple[int, int, str]:
    """Return ``(package_count, vulnerable_package_count, max_severity)``.

    ``scan_image`` returns raw packages; vulnerability data is only present when
    a package already carries matches. The sweep reports what it has and lets the
    downstream pipeline do CVE matching — it never fabricates severity.
    """
    pkg_count = len(packages)
    vuln_pkgs = 0
    max_sev = "none"
    best = 0
    for pkg in packages:
        vulns = getattr(pkg, "vulnerabilities", None) or []
        if vulns:
            vuln_pkgs += 1
        sev_obj = getattr(pkg, "max_severity", None)
        sev = sev_obj() if callable(sev_obj) else None
        sev_value = getattr(sev, "value", None) if sev is not None else None
        rank = severity_rank(str(sev_value)) if sev_value else 0
        if rank > best:
            best = rank
            max_sev = str(sev_value).lower()
    return pkg_count, vuln_pkgs, max_sev


def sweep_registry(
    *,
    provider: str,
    region: Optional[str] = None,
    profile: Optional[str] = None,
    registry: Optional[str] = None,
    project: Optional[str] = None,
    location: Optional[str] = None,
    credential: Any = None,
    max_images: Optional[int] = None,
    scan_image_fn: Optional[Callable[[str], tuple[list[Any], str]]] = None,
) -> dict[str, Any]:
    """Enumerate + dedupe + cap + scan every image in a cloud container registry.

    Args:
        provider: ``"ecr"`` (AWS), ``"acr"`` (Azure), or ``"gar"`` (GCP).
        region/profile: AWS selectors (ECR).
        registry: ACR login server, e.g. ``myacr.azurecr.io`` (ACR).
        project/location: GCP selectors (GAR).
        credential: pre-built Azure credential (ACR) or GCP credentials (GAR);
            resolved from the ambient chain when omitted.
        max_images: override the ``AGENT_BOM_REGISTRY_MAX_IMAGES`` cap.
        scan_image_fn: injection seam for tests; defaults to
            :func:`agent_bom.image.scan_image`.

    Returns:
        A deterministic, JSON-serialisable report dict (see :class:`SweepResult`).
        Never raises for registry/access/scan failures — they degrade to
        warnings with actionable guidance.
    """
    prov = (provider or "").strip().lower()
    cap = max_images if max_images is not None else _max_images()
    result = SweepResult(provider=prov, max_images=cap)

    if prov not in _PROVIDERS:
        result.status = "invalid_provider"
        result.warnings.append(f"Unknown registry provider {provider!r}. Use one of: {', '.join(_PROVIDERS)}.")
        return result.to_dict()

    warnings: list[str] = []
    if prov == "ecr":
        discovered = enumerate_ecr_images(region=region, profile=profile, warnings=warnings)
        result.registry = discovered[0].registry if discovered else (region or "")
    elif prov == "acr":
        discovered = enumerate_acr_images(registry=registry or "", credential=credential, warnings=warnings)
        result.registry = registry or ""
    else:  # gar
        discovered = enumerate_gar_images(project=project, location=location, credentials=credential, warnings=warnings)
        result.registry = discovered[0].registry if discovered else (project or "")

    result.warnings.extend(warnings)

    work_list, discovered_count, skipped = dedupe_and_cap(discovered, max_images=cap, warnings=result.warnings)
    result.discovered_count = discovered_count
    result.skipped_by_cap = skipped

    if not work_list:
        if not discovered:
            result.status = "no_images"
        return result.to_dict()

    scan_fn = scan_image_fn or _default_scan_image
    for image in work_list:
        try:
            packages, strategy = scan_fn(image.reference)
        except Exception as exc:  # noqa: BLE001 — one image failing must not abort the sweep
            result.failed_count += 1
            result.warnings.append(f"Image scan failed for {image.reference}: {sanitize_discovery_warning(exc)}")
            continue
        pkg_count, vuln_pkgs, max_sev = _summarize_packages(packages)
        result.scanned_count += 1
        result.images.append(
            {
                "reference": image.reference,
                "repository": image.repository,
                "digest": image.digest,
                "registry": image.registry,
                "pushed_at": image.pushed_at.isoformat() if image.pushed_at else None,
                "strategy": strategy,
                "package_count": pkg_count,
                "vulnerable_package_count": vuln_pkgs,
                "max_severity": max_sev,
            }
        )

    # Deterministic output ordering: by reference (the work list was newest-first
    # for the cap, but the emitted report sorts stably for reproducible diffs).
    result.images.sort(key=lambda img: str(img["reference"]))
    if result.failed_count and not result.scanned_count:
        result.status = "all_failed"
    return result.to_dict()


def _default_scan_image(reference: str) -> tuple[list[Any], str]:
    """Lazy import of the real scanner so test injection stays cheap."""
    from agent_bom.image import scan_image

    return scan_image(reference)
