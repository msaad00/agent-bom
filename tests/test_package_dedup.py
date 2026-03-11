"""Tests for deduplicate_packages() — multi-source asset deduplication."""

from __future__ import annotations

from agent_bom.models import Package
from agent_bom.scanners import deduplicate_packages


def _pkg(name: str, version: str, ecosystem: str = "pypi") -> Package:
    """Helper to create a minimal Package for testing."""
    return Package(name=name, version=version, ecosystem=ecosystem)


def test_dedup_removes_exact_duplicates():
    """Two identical Package objects → only 1 kept."""
    packages = [
        _pkg("torch", "2.3.0"),
        _pkg("torch", "2.3.0"),
    ]
    result = deduplicate_packages(packages)
    assert len(result) == 1
    assert result[0].name == "torch"
    assert result[0].version == "2.3.0"


def test_dedup_keeps_different_versions():
    """torch==2.3.0 and torch==2.4.0 → both kept."""
    packages = [
        _pkg("torch", "2.3.0"),
        _pkg("torch", "2.4.0"),
    ]
    result = deduplicate_packages(packages)
    assert len(result) == 2


def test_dedup_normalizes_hyphen_underscore():
    """'torch-audio' and 'torch_audio' same version → dedup to 1."""
    packages = [
        _pkg("torch-audio", "0.13.0"),
        _pkg("torch_audio", "0.13.0"),
    ]
    result = deduplicate_packages(packages)
    assert len(result) == 1


def test_dedup_normalizes_case():
    """'Torch' and 'torch' same version → dedup to 1."""
    packages = [
        _pkg("Torch", "2.3.0"),
        _pkg("torch", "2.3.0"),
    ]
    result = deduplicate_packages(packages)
    assert len(result) == 1


def test_dedup_different_ecosystems_kept():
    """'requests' in PyPI and 'requests' in npm → both kept."""
    packages = [
        _pkg("requests", "2.31.0", "pypi"),
        _pkg("requests", "2.31.0", "npm"),
    ]
    result = deduplicate_packages(packages)
    assert len(result) == 2


def test_dedup_empty_list():
    """Empty input → empty output."""
    result = deduplicate_packages([])
    assert result == []


def test_dedup_preserves_order():
    """First occurrence is kept; order of unique packages preserved."""
    packages = [
        _pkg("alpha", "1.0.0"),
        _pkg("beta", "2.0.0"),
        _pkg("alpha", "1.0.0"),  # duplicate of first
        _pkg("gamma", "3.0.0"),
        _pkg("beta", "2.0.0"),  # duplicate of second
    ]
    result = deduplicate_packages(packages)
    assert len(result) == 3
    assert [p.name for p in result] == ["alpha", "beta", "gamma"]


def test_dedup_multi_source_same_package():
    """Simulates K8s + cloud + local discovering the same package."""
    # Same package from three different discovery sources
    k8s_pkg = _pkg("numpy", "1.26.0")
    cloud_pkg = _pkg("numpy", "1.26.0")
    local_pkg = _pkg("numpy", "1.26.0")

    result = deduplicate_packages([k8s_pkg, cloud_pkg, local_pkg])
    assert len(result) == 1
    assert result[0] is k8s_pkg  # first occurrence preserved


def test_dedup_normalizes_dot_separator():
    """'my.package' and 'my_package' same version → dedup to 1."""
    packages = [
        _pkg("my.package", "1.0.0"),
        _pkg("my_package", "1.0.0"),
    ]
    result = deduplicate_packages(packages)
    assert len(result) == 1
