"""Tests for registry-wide image sweep (ECR / ACR / GAR).

Registry clients and ``scan_image`` are mocked at the boundary so the tests
exercise enumeration → digest-dedupe → cap → aggregation deterministically,
without network or Docker.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agent_bom.cloud import registry_sweep
from agent_bom.cloud.registry_sweep import (
    DEFAULT_MAX_IMAGES,
    MAX_IMAGES_ENV,
    RegistryImage,
    dedupe_and_cap,
    sweep_registry,
)


def _img(ref: str, digest: str = "", pushed: datetime | None = None, repo: str = "repo") -> RegistryImage:
    return RegistryImage(reference=ref, repository=repo, digest=digest, pushed_at=pushed, registry="reg")


def _fake_scan(packages: int):
    """Return a scan_image-shaped callable yielding *packages* bare package stubs."""

    class _Pkg:
        vulnerabilities: list = []

        def max_severity(self):
            class _Sev:
                value = "none"

            return _Sev()

    def _fn(ref: str):
        return [_Pkg() for _ in range(packages)], "native"

    return _fn


# ───────────────────────────── dedupe + cap ──────────────────────────────


def test_dedupe_by_digest_scans_each_digest_once():
    warnings: list[str] = []
    images = [
        _img("reg/a:v1", digest="sha256:aaa", pushed=datetime(2026, 1, 1, tzinfo=timezone.utc)),
        _img("reg/a:latest", digest="sha256:aaa", pushed=datetime(2026, 1, 1, tzinfo=timezone.utc)),
        _img("reg/b:v1", digest="sha256:bbb", pushed=datetime(2026, 1, 2, tzinfo=timezone.utc)),
    ]
    work, discovered, skipped = dedupe_and_cap(images, max_images=50, warnings=warnings)
    assert discovered == 2  # two distinct digests
    assert skipped == 0
    assert {im.digest for im in work} == {"sha256:aaa", "sha256:bbb"}


def test_dedupe_is_deterministic_first_reference_wins():
    warnings: list[str] = []
    pushed = datetime(2026, 1, 1, tzinfo=timezone.utc)
    images = [
        _img("reg/z:tag", digest="sha256:same", pushed=pushed),
        _img("reg/a:tag", digest="sha256:same", pushed=pushed),
    ]
    work, _, _ = dedupe_and_cap(images, max_images=50, warnings=warnings)
    assert len(work) == 1
    # Same pushed_at → lexically-smallest reference wins, deterministically.
    assert work[0].reference == "reg/a:tag"


def test_digestless_images_dedupe_by_reference():
    warnings: list[str] = []
    images = [_img("reg/a:v1"), _img("reg/a:v1"), _img("reg/a:v2")]
    work, discovered, _ = dedupe_and_cap(images, max_images=50, warnings=warnings)
    assert discovered == 2


def test_cap_keeps_newest_and_warns_with_count():
    warnings: list[str] = []
    images = [_img(f"reg/a:v{i}", digest=f"sha256:{i}", pushed=datetime(2026, 1, i + 1, tzinfo=timezone.utc)) for i in range(5)]
    work, discovered, skipped = dedupe_and_cap(images, max_images=2, warnings=warnings)
    assert discovered == 5
    assert skipped == 3
    assert len(work) == 2
    # Newest first: v4 (Jan 5) and v3 (Jan 4) kept.
    kept_refs = {im.reference for im in work}
    assert kept_refs == {"reg/a:v4", "reg/a:v3"}
    assert any("skipped 3" in w for w in warnings)
    assert any(MAX_IMAGES_ENV in w for w in warnings)


def test_cap_at_boundary_does_not_warn():
    warnings: list[str] = []
    images = [_img(f"reg/a:v{i}", digest=f"sha256:{i}") for i in range(3)]
    work, discovered, skipped = dedupe_and_cap(images, max_images=3, warnings=warnings)
    assert skipped == 0
    assert len(work) == 3
    assert warnings == []


# ───────────────────────── orchestration (sweep) ──────────────────────────


def test_sweep_invalid_provider_degrades():
    report = sweep_registry(provider="dockerhub")
    assert report["status"] == "invalid_provider"
    assert report["scanned_count"] == 0
    assert any("dockerhub" in w for w in report["warnings"])


def test_sweep_scans_each_discovered_image(monkeypatch):
    images = [
        _img("reg/a:v1", digest="sha256:a", pushed=datetime(2026, 1, 1, tzinfo=timezone.utc)),
        _img("reg/b:v1", digest="sha256:b", pushed=datetime(2026, 1, 2, tzinfo=timezone.utc)),
    ]
    monkeypatch.setattr(registry_sweep, "enumerate_ecr_images", lambda **kw: images)
    report = sweep_registry(provider="ecr", scan_image_fn=_fake_scan(3))
    assert report["status"] == "ok"
    assert report["discovered_count"] == 2
    assert report["scanned_count"] == 2
    assert report["total_packages"] == 6
    assert [i["reference"] for i in report["images"]] == ["reg/a:v1", "reg/b:v1"]


def test_sweep_one_failing_image_does_not_abort(monkeypatch):
    images = [
        _img("reg/good:v1", digest="sha256:g"),
        _img("reg/bad:v1", digest="sha256:b"),
    ]
    monkeypatch.setattr(registry_sweep, "enumerate_ecr_images", lambda **kw: images)

    def _scan(ref: str):
        if "bad" in ref:
            raise RuntimeError("manifest unknown")
        return _fake_scan(2)(ref)

    report = sweep_registry(provider="ecr", scan_image_fn=_scan)
    assert report["scanned_count"] == 1
    assert report["failed_count"] == 1
    assert any("reg/bad:v1" in w for w in report["warnings"])
    # The good image still made it into the report.
    assert [i["reference"] for i in report["images"]] == ["reg/good:v1"]


def test_sweep_respects_cap_and_warns(monkeypatch):
    images = [_img(f"reg/a:v{i}", digest=f"sha256:{i}", pushed=datetime(2026, 1, i + 1, tzinfo=timezone.utc)) for i in range(5)]
    monkeypatch.setattr(registry_sweep, "enumerate_ecr_images", lambda **kw: images)
    report = sweep_registry(provider="ecr", max_images=2, scan_image_fn=_fake_scan(1))
    assert report["discovered_count"] == 5
    assert report["scanned_count"] == 2
    assert report["skipped_by_cap"] == 3
    assert any("skipped 3" in w for w in report["warnings"])


def test_sweep_no_access_degrades_with_guidance(monkeypatch):
    def _denied(**kw):
        kw["warnings"].append("Skipped ECR repositories: role lacks ecr:DescribeRepositories — add it to the read-only policy.")
        return []

    monkeypatch.setattr(registry_sweep, "enumerate_ecr_images", _denied)
    report = sweep_registry(provider="ecr", scan_image_fn=_fake_scan(1))
    assert report["status"] == "no_images"
    assert report["scanned_count"] == 0
    assert any("ecr:DescribeRepositories" in w for w in report["warnings"])


def test_sweep_all_images_fail_status(monkeypatch):
    images = [_img("reg/a:v1", digest="sha256:a"), _img("reg/b:v1", digest="sha256:b")]
    monkeypatch.setattr(registry_sweep, "enumerate_ecr_images", lambda **kw: images)

    def _scan(ref: str):
        raise RuntimeError("pull failed")

    report = sweep_registry(provider="ecr", scan_image_fn=_scan)
    assert report["status"] == "all_failed"
    assert report["failed_count"] == 2
    assert report["scanned_count"] == 0


def test_sweep_default_cap_from_env(monkeypatch):
    monkeypatch.delenv(MAX_IMAGES_ENV, raising=False)
    images = [_img("reg/a:v1", digest="sha256:a")]
    monkeypatch.setattr(registry_sweep, "enumerate_ecr_images", lambda **kw: images)
    report = sweep_registry(provider="ecr", scan_image_fn=_fake_scan(1))
    assert report["max_images"] == DEFAULT_MAX_IMAGES


# ─────────────────── per-registry enumeration (mocked SDK) ───────────────────


class _FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return list(self._pages)


class _FakeEcrClient:
    def __init__(self):
        self._repos = [{"repositories": [{"repositoryName": "app", "repositoryUri": "1.dkr.ecr.us-east-1.amazonaws.com/app"}]}]
        self._images = [
            {
                "imageDetails": [
                    {
                        "imageDigest": "sha256:d1",
                        "imageTags": ["v1", "latest"],
                        "imagePushedAt": datetime(2026, 1, 2, tzinfo=timezone.utc),
                    },
                    {
                        "imageDigest": "sha256:d2",
                        "imageTags": ["v2"],
                        "imagePushedAt": datetime(2026, 1, 3, tzinfo=timezone.utc),
                    },
                ]
            }
        ]

    def get_paginator(self, op):
        return _FakePaginator(self._repos if op == "describe_repositories" else self._images)


def test_enumerate_ecr_emits_one_image_per_distinct_digest(monkeypatch):
    fake_session = type("S", (), {"region_name": "us-east-1", "client": lambda self, *a, **k: _FakeEcrClient()})()
    fake_boto3 = type("B", (), {"Session": staticmethod(lambda **kw: fake_session)})()
    monkeypatch.setitem(__import__("sys").modules, "boto3", fake_boto3)

    warnings: list[str] = []
    images = registry_sweep.enumerate_ecr_images(region="us-east-1", warnings=warnings)
    # Two distinct digests in one repo (v1/latest share d1 → one image).
    digests = {im.digest for im in images}
    assert digests == {"sha256:d1", "sha256:d2"}
    assert all(im.registry == "1.dkr.ecr.us-east-1.amazonaws.com" for im in images)


def test_enumerate_ecr_boto3_missing_degrades(monkeypatch):
    monkeypatch.setitem(__import__("sys").modules, "boto3", None)
    # Force ImportError on `import boto3`.
    import builtins

    real_import = builtins.__import__

    def _no_boto3(name, *a, **k):
        if name == "boto3":
            raise ImportError("no boto3")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", _no_boto3)
    warnings: list[str] = []
    images = registry_sweep.enumerate_ecr_images(warnings=warnings)
    assert images == []
    assert any("boto3" in w for w in warnings)


@pytest.mark.parametrize("provider", ["ecr", "acr", "gar"])
def test_sweep_providers_never_raise_without_sdk(provider):
    # No SDK / creds available in the test env → must degrade, not raise.
    report = sweep_registry(provider=provider, registry="x.azurecr.io", project="p")
    assert report["provider"] == provider
    assert isinstance(report["warnings"], list)
    assert report["scanned_count"] == 0
