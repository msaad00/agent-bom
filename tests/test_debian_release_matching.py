"""Tests for Debian/distro CVE-matching accuracy.

Covers two accuracy fixes:

1. Release-suffixed DB ecosystems (``debian:10``) must be normalised to a base
   family the version comparator understands, so already-fixed distro CVEs are
   not reported as conservative false positives.
2. Unfixed OS-package advisories (no-dsa / won't-fix / end-of-life open) are
   suppressed by default and surfaced only with the include-unfixed opt-in.
"""

from __future__ import annotations

import sqlite3

import pytest

from agent_bom.db.lookup import _comparator_ecosystem, _version_match_state, lookup_package
from agent_bom.db.schema import init_db
from agent_bom.models import Package, Severity, Vulnerability


@pytest.fixture
def tmp_db(tmp_path) -> sqlite3.Connection:
    db_file = tmp_path / "test_vulns.db"
    conn = init_db(db_file)
    yield conn
    conn.close()


def _insert(conn, vuln_id, ecosystem, pkg, introduced="0", fixed="", last_affected=""):
    conn.execute(
        "INSERT OR REPLACE INTO vulns(id,summary,severity,cvss_score,source) VALUES (?,?,?,?,'osv')",
        (vuln_id, f"Test {vuln_id}", "high", 7.5),
    )
    conn.execute(
        "INSERT OR REPLACE INTO affected(vuln_id,ecosystem,package_name,introduced,fixed,last_affected) VALUES (?,?,?,?,?,?)",
        (vuln_id, ecosystem, pkg, introduced, fixed, last_affected),
    )
    conn.commit()


# ── Ecosystem normalisation ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "stored,expected",
    [
        ("debian:10", "deb"),
        ("debian:12", "deb"),
        ("ubuntu:22.04", "deb"),
        ("alpine:v3.18", "apk"),
        ("linux", "rpm"),
        ("rpm", "rpm"),
        ("PyPI", "pypi"),
    ],
)
def test_comparator_ecosystem_normalises_release_suffix(stored, expected):
    assert _comparator_ecosystem(stored) == expected


def test_version_match_state_release_suffixed_debian_orders_correctly():
    # bash 5.0-4 is newer than the fix 4.3-9.1 → unaffected. The release suffix
    # must not break ordering (previously returned "unknown" → false positive).
    assert _version_match_state("5.0-4", "0", "4.3-9.1", "", "debian:10") == "unaffected"
    assert _version_match_state("4.2", "0", "4.3-9.1", "", "debian:10") == "affected"


def test_already_fixed_debian_cve_not_reported(tmp_db):
    # Installed bash 5.0-4 already includes the fix 4.3-9.1.
    _insert(tmp_db, "DEBIAN-CVE-2014-6271", "debian:10", "bash", introduced="0", fixed="4.3-9.1")
    matches = lookup_package(tmp_db, "debian:10", "bash", "5.0-4")
    assert matches == []


def test_genuinely_vulnerable_debian_cve_reported(tmp_db):
    _insert(tmp_db, "DEBIAN-CVE-2020-0001", "debian:10", "openssl", introduced="0", fixed="1.1.1d-2")
    matches = lookup_package(tmp_db, "debian:10", "openssl", "1.1.1a-1")
    assert [m.id for m in matches] == ["DEBIAN-CVE-2020-0001"]


# ── Unfixed OS-package suppression ───────────────────────────────────────────


def _os_pkg_with_vuln(fixed_version):
    pkg = Package(name="glibc", version="2.28-10", ecosystem="deb")
    pkg.vulnerabilities = [Vulnerability(id="DEBIAN-CVE-2010-4756", summary="x", severity=Severity.MEDIUM, fixed_version=fixed_version)]
    return pkg


def test_unfixed_os_advisory_suppressed_by_default():
    from agent_bom.scanners import _suppress_unfixed_os_advisories, set_include_unfixed

    set_include_unfixed(False)
    try:
        pkg = _os_pkg_with_vuln(fixed_version=None)
        removed = _suppress_unfixed_os_advisories([pkg])
        assert removed == 1
        assert pkg.vulnerabilities == []
    finally:
        set_include_unfixed(False)


def test_unfixed_os_advisory_shown_with_opt_in():
    from agent_bom.scanners import _suppress_unfixed_os_advisories, set_include_unfixed

    set_include_unfixed(True)
    try:
        pkg = _os_pkg_with_vuln(fixed_version=None)
        removed = _suppress_unfixed_os_advisories([pkg])
        assert removed == 0
        assert len(pkg.vulnerabilities) == 1
    finally:
        set_include_unfixed(False)


def test_unfixed_opt_in_via_env(monkeypatch):
    from agent_bom.scanners import _suppress_unfixed_os_advisories, set_include_unfixed

    set_include_unfixed(False)
    monkeypatch.setenv("AGENT_BOM_INCLUDE_UNFIXED", "1")
    try:
        pkg = _os_pkg_with_vuln(fixed_version=None)
        assert _suppress_unfixed_os_advisories([pkg]) == 0
    finally:
        set_include_unfixed(False)


def test_fixed_os_advisory_always_reported():
    from agent_bom.scanners import _suppress_unfixed_os_advisories, set_include_unfixed

    set_include_unfixed(False)
    try:
        pkg = _os_pkg_with_vuln(fixed_version="2.28-10+deb10u2")
        removed = _suppress_unfixed_os_advisories([pkg])
        assert removed == 0
        assert len(pkg.vulnerabilities) == 1
    finally:
        set_include_unfixed(False)


def test_unfixed_app_advisory_not_suppressed():
    # Application-ecosystem (PyPI) unfixed CVEs remain actionable and are kept.
    from agent_bom.scanners import _suppress_unfixed_os_advisories, set_include_unfixed

    set_include_unfixed(False)
    try:
        pkg = Package(name="requests", version="2.0.0", ecosystem="pypi")
        pkg.vulnerabilities = [Vulnerability(id="CVE-2020-0002", summary="x", severity=Severity.HIGH, fixed_version=None)]
        removed = _suppress_unfixed_os_advisories([pkg])
        assert removed == 0
        assert len(pkg.vulnerabilities) == 1
    finally:
        set_include_unfixed(False)
