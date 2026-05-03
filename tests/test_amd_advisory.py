"""Tests for AMD PSIRT / ROCm advisory enrichment module."""

from __future__ import annotations

import pytest

from agent_bom.cloud.gpu_infra import _driver_lt
from agent_bom.models import Package, Severity
from agent_bom.scanners.amd_advisory import (
    _AMD_PRODUCT_MAP,
    check_amd_advisories,
    get_amd_products_for_package,
)

# ─── get_amd_products_for_package ────────────────────────────────────────────


@pytest.mark.parametrize(
    "pkg_name, expected_products",
    [
        ("rocm", ["rocm"]),
        ("rocm-dev", ["rocm"]),
        ("hip-runtime-amd", ["hip runtime"]),
        ("miopen-hip", ["miopen"]),
        ("rocblas", ["rocblas"]),
        ("rocsolver", ["rocsolver"]),
        ("rccl", ["rccl"]),
        ("rocprim", ["rocprim"]),
        ("rocthrust", ["rocthrust"]),
        ("tensorflow_rocm", ["tensorflow rocm"]),
        ("torch", ["pytorch rocm"]),
        ("numpy", []),
        ("requests", []),
    ],
)
def test_get_amd_products_for_package(pkg_name, expected_products):
    result = get_amd_products_for_package(pkg_name)
    for expected in expected_products:
        assert expected in result, f"{pkg_name!r} should map to {expected!r}, got {result}"
    if not expected_products:
        assert result == [], f"{pkg_name!r} should have no AMD product mapping, got {result}"


def test_product_map_keys_not_empty():
    for product, packages in _AMD_PRODUCT_MAP.items():
        assert isinstance(product, str) and product
        for pkg in packages:
            assert isinstance(pkg, str) and pkg


# ─── check_amd_advisories ────────────────────────────────────────────────────


def _make_pkg(name: str, version: str = "5.0") -> Package:
    return Package(name=name, version=version, ecosystem="pypi")


def test_check_amd_advisories_no_rocm_packages():
    packages = [_make_pkg("requests"), _make_pkg("flask"), _make_pkg("numpy")]
    assert check_amd_advisories(packages, live=False) == 0
    for pkg in packages:
        assert pkg.vulnerabilities == []


def test_check_amd_advisories_rocm_package_gets_vulns():
    pkg = _make_pkg("rocm", version="5.5")
    total = check_amd_advisories([pkg], live=False)
    assert total > 0
    assert len(pkg.vulnerabilities) > 0
    cve_ids = {v.id for v in pkg.vulnerabilities}
    assert "CVE-2023-20598" in cve_ids


def test_check_amd_advisories_hip_runtime_gets_vulns():
    pkg = _make_pkg("hip-runtime-amd", version="5.5")
    total = check_amd_advisories([pkg], live=False)
    assert total > 0
    cve_ids = {v.id for v in pkg.vulnerabilities}
    assert "CVE-2024-21139" in cve_ids


def test_check_amd_advisories_no_duplicate_cves():
    pkg = _make_pkg("rocm", version="5.5")
    check_amd_advisories([pkg], live=False)
    first_count = len(pkg.vulnerabilities)
    check_amd_advisories([pkg], live=False)
    assert len(pkg.vulnerabilities) == first_count


def test_check_amd_advisories_severity_shape():
    pkg = _make_pkg("rocm", version="5.5")
    check_amd_advisories([pkg], live=False)
    for vuln in pkg.vulnerabilities:
        assert vuln.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        assert "amd_psirt" in vuln.advisory_sources
        assert vuln.references


def test_check_amd_advisories_empty_list():
    assert check_amd_advisories([], live=False) == 0


# ─── _driver_lt ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "version, threshold, expected",
    [
        ("525.85", "555.52", True),
        ("555.51", "555.52", True),
        ("555.52", "555.52", False),
        ("560.00", "555.52", False),
        ("600.0", "555.52", False),
        ("520.0.0", "555.52.0", True),
        ("not_a_version", "555.52", False),
        ("555.52.1", "555.52.0", False),
    ],
)
def test_driver_lt(version, threshold, expected):
    assert _driver_lt(version, threshold) == expected
