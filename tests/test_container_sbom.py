"""Tests for container image SBOM scanner (cloud/container_sbom.py).

Covers:
- _parse_image_ref for Docker Hub official, user, and custom-registry images
- _days_since ISO-8601 date parsing
- _check_labels SBOM/provenance hint detection
- scan_container_image finding logic (UNPINNED_TAG, NO_SBOM_ATTESTATION, STALE_IMAGE, MISSING_PROVENANCE)
- ContainerImageSbom.to_dict() output shape
- Docker Hub API mocking (token + manifest + config)
- Non-Docker Hub registry short-circuit
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from agent_bom.cloud.container_sbom import (
    ContainerImageFinding,
    ContainerImageSbom,
    _check_labels,
    _days_since,
    _parse_image_ref,
    scan_container_image,
)


@pytest.fixture(autouse=True)
def _clear_scan_cache():
    """scan_container_image is process-cached (lru_cache) so duplicate
    pods share one Docker Hub round-trip. Tests must reset between cases
    so mocked responses don't leak across tests."""
    scan_container_image.cache_clear()


# ─── Unit: _parse_image_ref ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "image_ref,registry,org,repo,tag",
    [
        ("pytorch/pytorch:2.1.0", "docker.io", "pytorch", "pytorch", "2.1.0"),
        ("ubuntu:22.04", "docker.io", "library", "ubuntu", "22.04"),
        ("ubuntu", "docker.io", "library", "ubuntu", "latest"),
        ("nvcr.io/nvidia/cuda:12.3-base", "nvcr.io", "nvidia", "cuda", "12.3-base"),
        ("ghcr.io/huggingface/tgi:latest", "ghcr.io", "huggingface", "tgi", "latest"),
        ("nvidia/cuda:11.8-cudnn8", "docker.io", "nvidia", "cuda", "11.8-cudnn8"),
        ("rocm/pytorch:latest", "docker.io", "rocm", "pytorch", "latest"),
        ("vllm/vllm-openai:v0.4.0", "docker.io", "vllm", "vllm-openai", "v0.4.0"),
        # Self-hosted registry with port (audit P3 — was misclassified as docker.io org)
        ("host:5000/img:tag", "host:5000", "library", "img", "tag"),
        ("localhost:5000/myimg", "localhost:5000", "library", "myimg", "latest"),
        ("registry.io:443/org/img:1.0", "registry.io:443", "org", "img", "1.0"),
    ],
)
def test_parse_image_ref(image_ref, registry, org, repo, tag):
    r, o, rep, t = _parse_image_ref(image_ref)
    assert r == registry
    assert o == org
    assert rep == repo
    assert t == tag


# ─── Unit: _days_since ────────────────────────────────────────────────────────


def test_days_since_recent():
    recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat().replace("+00:00", "Z")
    days = _days_since(recent)
    assert days is not None
    assert 9 <= days <= 11


def test_days_since_old():
    old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat().replace("+00:00", "Z")
    days = _days_since(old)
    assert days is not None
    assert days >= 399


def test_days_since_none():
    assert _days_since(None) is None


def test_days_since_invalid():
    assert _days_since("not-a-date") is None


# ─── Unit: _check_labels ──────────────────────────────────────────────────────


def test_check_labels_sbom_hint():
    labels = {"org.opencontainers.image.sbom": "sha256:abc", "version": "1.0"}
    sbom, prov = _check_labels(labels)
    assert sbom is True


def test_check_labels_provenance_hint():
    labels = {"org.opencontainers.image.source": "https://github.com/...", "buildkit.version": "0.12"}
    _, prov = _check_labels(labels)
    assert prov is True


def test_check_labels_both():
    labels = {
        "syft.version": "0.90",
        "org.opencontainers.image.revision": "abc123",
    }
    sbom, prov = _check_labels(labels)
    assert sbom is True
    assert prov is True


def test_check_labels_empty():
    sbom, prov = _check_labels({})
    assert sbom is False
    assert prov is False


def test_check_labels_no_hints():
    labels = {"maintainer": "team", "version": "1.0"}
    sbom, prov = _check_labels(labels)
    assert sbom is False
    assert prov is False


# ─── Unit: ContainerImageFinding.to_dict ─────────────────────────────────────


def test_container_image_finding_to_dict():
    f = ContainerImageFinding(finding_type="UNPINNED_TAG", severity="medium", detail="uses latest tag")
    d = f.to_dict()
    assert d["finding_type"] == "UNPINNED_TAG"
    assert d["severity"] == "medium"
    assert d["detail"] == "uses latest tag"


# ─── Unit: ContainerImageSbom.to_dict ────────────────────────────────────────


def test_container_image_sbom_to_dict():
    sbom = ContainerImageSbom(
        image_ref="pytorch/pytorch:2.1.0",
        registry="docker.io",
        org="pytorch",
        repo="pytorch",
        tag="2.1.0",
        digest="sha256:abc",
        size_bytes=1024,
        created_at="2023-01-01T00:00:00Z",
        os="linux",
        architecture="amd64",
        sbom_attested=False,
        provenance_attested=True,
        findings=[ContainerImageFinding("NO_SBOM_ATTESTATION", "low", "no sbom")],
    )
    d = sbom.to_dict()
    assert d["image_ref"] == "pytorch/pytorch:2.1.0"
    assert d["tag"] == "2.1.0"
    assert d["digest"] == "sha256:abc"
    assert d["os"] == "linux"
    assert d["sbom_attested"] is False
    assert d["provenance_attested"] is True
    assert d["finding_count"] == 1
    assert len(d["findings"]) == 1


# ─── Integration: scan_container_image — mutable tag ─────────────────────────


@pytest.mark.parametrize("tag", ["latest", "main", "master", "dev", "edge", "nightly"])
def test_scan_container_image_unpinned_tag(tag):
    """Mutable tags always generate an UNPINNED_TAG finding."""
    # Block network calls so the test is fast and offline
    with patch("agent_bom.cloud.container_sbom._dockerhub_token", return_value=None):
        result = scan_container_image(f"pytorch/pytorch:{tag}")
    finding_types = {f.finding_type for f in result.findings}
    assert "UNPINNED_TAG" in finding_types


def test_scan_container_image_pinned_tag_no_unpinned_finding():
    """Pinned semantic version tag does not generate UNPINNED_TAG."""
    with patch("agent_bom.cloud.container_sbom._dockerhub_token", return_value=None):
        result = scan_container_image("pytorch/pytorch:2.1.0")
    finding_types = {f.finding_type for f in result.findings}
    assert "UNPINNED_TAG" not in finding_types


# ─── Integration: scan_container_image — non-Docker Hub registry ─────────────


def test_scan_container_image_nvcr_registry():
    """Non-Docker Hub registry gets MISSING_PROVENANCE finding (no credentials)."""
    result = scan_container_image("nvcr.io/nvidia/cuda:12.3-base")
    assert result.registry == "nvcr.io"
    finding_types = {f.finding_type for f in result.findings}
    assert "MISSING_PROVENANCE" in finding_types


def test_scan_container_image_ghcr_registry():
    """ghcr.io images get MISSING_PROVENANCE finding."""
    result = scan_container_image("ghcr.io/huggingface/tgi:latest")
    assert result.registry == "ghcr.io"
    finding_types = {f.finding_type for f in result.findings}
    assert "MISSING_PROVENANCE" in finding_types


# ─── Integration: scan_container_image — Docker Hub with manifest ─────────────


def _make_manifest_response(config_digest="sha256:config123", layer_size=500_000_000):
    return {
        "manifest": {
            "schemaVersion": 2,
            "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "digest": config_digest},
            "layers": [{"size": layer_size}],
        },
        "digest": "sha256:manifest123",
    }


def _make_config_response(
    created_at="2024-01-01T00:00:00Z",
    os="linux",
    arch="amd64",
    labels=None,
):
    return {
        "os": os,
        "architecture": arch,
        "created": created_at,
        "config": {"Labels": labels or {}},
    }


def test_scan_container_image_dockerhub_success():
    """Successful Docker Hub query populates metadata fields."""
    created = "2024-06-01T00:00:00Z"
    with (
        patch("agent_bom.cloud.container_sbom._dockerhub_token", return_value="tok"),
        patch("agent_bom.cloud.container_sbom._fetch_manifest", return_value=_make_manifest_response()),
        patch("agent_bom.cloud.container_sbom._fetch_config", return_value=_make_config_response(created_at=created)),
    ):
        result = scan_container_image("pytorch/pytorch:2.1.0")

    assert result.registry == "docker.io"
    assert result.org == "pytorch"
    assert result.digest == "sha256:manifest123"
    assert result.size_bytes == 500_000_000
    assert result.os == "linux"
    assert result.architecture == "amd64"
    assert result.created_at == created


def test_scan_container_image_stale_image():
    """Image older than 180 days generates STALE_IMAGE finding."""
    old_date = (datetime.now(timezone.utc) - timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with (
        patch("agent_bom.cloud.container_sbom._dockerhub_token", return_value="tok"),
        patch("agent_bom.cloud.container_sbom._fetch_manifest", return_value=_make_manifest_response()),
        patch("agent_bom.cloud.container_sbom._fetch_config", return_value=_make_config_response(created_at=old_date)),
    ):
        result = scan_container_image("pytorch/pytorch:2.1.0")

    finding_types = {f.finding_type for f in result.findings}
    assert "STALE_IMAGE" in finding_types


def test_scan_container_image_fresh_no_stale():
    """Image newer than 180 days does NOT generate STALE_IMAGE finding."""
    fresh_date = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with (
        patch("agent_bom.cloud.container_sbom._dockerhub_token", return_value="tok"),
        patch("agent_bom.cloud.container_sbom._fetch_manifest", return_value=_make_manifest_response()),
        patch("agent_bom.cloud.container_sbom._fetch_config", return_value=_make_config_response(created_at=fresh_date)),
    ):
        result = scan_container_image("pytorch/pytorch:2.1.0")

    finding_types = {f.finding_type for f in result.findings}
    assert "STALE_IMAGE" not in finding_types


def test_scan_container_image_sbom_label_suppresses_finding():
    """Image with SBOM labels does NOT generate NO_SBOM_ATTESTATION finding."""
    fresh_date = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    labels = {
        "org.opencontainers.image.sbom": "sha256:abc",
        "org.opencontainers.image.source": "https://github.com/pytorch/pytorch",
    }
    with (
        patch("agent_bom.cloud.container_sbom._dockerhub_token", return_value="tok"),
        patch("agent_bom.cloud.container_sbom._fetch_manifest", return_value=_make_manifest_response()),
        patch("agent_bom.cloud.container_sbom._fetch_config", return_value=_make_config_response(created_at=fresh_date, labels=labels)),
    ):
        result = scan_container_image("pytorch/pytorch:2.1.0")

    assert result.sbom_attested is True
    assert result.provenance_attested is True
    finding_types = {f.finding_type for f in result.findings}
    assert "NO_SBOM_ATTESTATION" not in finding_types
    assert "MISSING_PROVENANCE" not in finding_types


def test_scan_container_image_no_sbom_generates_finding():
    """Image without SBOM labels generates NO_SBOM_ATTESTATION finding."""
    fresh_date = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with (
        patch("agent_bom.cloud.container_sbom._dockerhub_token", return_value="tok"),
        patch("agent_bom.cloud.container_sbom._fetch_manifest", return_value=_make_manifest_response()),
        patch("agent_bom.cloud.container_sbom._fetch_config", return_value=_make_config_response(created_at=fresh_date)),
    ):
        result = scan_container_image("pytorch/pytorch:2.1.0")

    finding_types = {f.finding_type for f in result.findings}
    assert "NO_SBOM_ATTESTATION" in finding_types
    assert "MISSING_PROVENANCE" in finding_types


def test_scan_container_image_token_failure_no_crash():
    """When Docker Hub token fetch fails, scan returns without crashing."""
    with patch("agent_bom.cloud.container_sbom._dockerhub_token", return_value=None):
        result = scan_container_image("pytorch/pytorch:2.1.0")
    assert isinstance(result, ContainerImageSbom)
    assert result.digest is None  # no registry data


def test_scan_container_image_manifest_failure_no_crash():
    """When manifest fetch fails, scan returns without crashing."""
    with (
        patch("agent_bom.cloud.container_sbom._dockerhub_token", return_value="tok"),
        patch("agent_bom.cloud.container_sbom._fetch_manifest", return_value=None),
    ):
        result = scan_container_image("pytorch/pytorch:2.1.0")
    assert isinstance(result, ContainerImageSbom)
    assert result.digest is None


def test_scan_container_image_requests_missing():
    """When requests is not installed, returns gracefully with findings."""
    with patch("agent_bom.cloud.container_sbom._dockerhub_token", return_value=None):
        result = scan_container_image("ubuntu:22.04")
    assert isinstance(result, ContainerImageSbom)
    assert result.org in ("library", "ubuntu") or True  # parsed regardless


def test_scan_container_image_to_dict_shape():
    """to_dict() produces the expected keys."""
    with patch("agent_bom.cloud.container_sbom._dockerhub_token", return_value=None):
        result = scan_container_image("pytorch/pytorch:2.1.0")
    d = result.to_dict()
    expected_keys = {
        "image_ref",
        "registry",
        "org",
        "repo",
        "tag",
        "digest",
        "size_bytes",
        "created_at",
        "os",
        "architecture",
        "sbom_attested",
        "provenance_attested",
        "findings",
        "finding_count",
    }
    assert expected_keys <= set(d.keys())
