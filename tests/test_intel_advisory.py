"""Tests for agent_bom.scanners.intel_advisory."""

from __future__ import annotations

from agent_bom.models import Package
from agent_bom.scanners.intel_advisory import (
    check_intel_advisories,
    get_intel_products_for_package,
)


def _make_pkg(name: str, version: str = "1.0") -> Package:
    return Package(name=name, version=version, ecosystem="pypi")


# ─── Product map lookup ───────────────────────────────────────────────────────


def test_openvino_maps_to_intel_gpu():
    products = get_intel_products_for_package("openvino")
    assert "intel gpu" in products


def test_level_zero_maps_to_product():
    products = get_intel_products_for_package("level_zero")
    assert "level zero" in products


def test_unknown_package_returns_empty():
    assert get_intel_products_for_package("boto3") == []


def test_normalise_hyphen_to_underscore():
    products = get_intel_products_for_package("intel-extension-for-pytorch")
    assert "intel gpu" in products


# ─── Advisory matching ────────────────────────────────────────────────────────


def test_check_intel_advisories_no_match():
    pkgs = [_make_pkg("numpy"), _make_pkg("requests")]
    count = check_intel_advisories(pkgs)
    assert count == 0


def test_check_intel_advisories_openvino_gets_cves():
    pkg = _make_pkg("openvino")
    count = check_intel_advisories([pkg])
    assert count > 0
    cve_ids = {v.id for v in pkg.vulnerabilities}
    # openvino maps to "intel gpu" which is covered by multiple CVEs
    assert "CVE-2023-22655" in cve_ids


def test_check_intel_advisories_level_zero_gets_cves():
    pkg = _make_pkg("level_zero")
    count = check_intel_advisories([pkg])
    assert count > 0


def test_check_intel_advisories_no_duplicate():
    pkg = _make_pkg("openvino")
    check_intel_advisories([pkg])
    initial_count = len(pkg.vulnerabilities)
    # Calling again should not add duplicates
    check_intel_advisories([pkg])
    assert len(pkg.vulnerabilities) == initial_count


def test_check_intel_advisories_igc_package():
    pkg = _make_pkg("intel_graphics_compiler")
    count = check_intel_advisories([pkg])
    assert count > 0
    cve_ids = {v.id for v in pkg.vulnerabilities}
    assert "CVE-2023-29494" in cve_ids


def test_check_intel_advisories_advisory_source():
    pkg = _make_pkg("openvino")
    check_intel_advisories([pkg])
    for vuln in pkg.vulnerabilities:
        assert "intel_psirt" in vuln.advisory_sources
