"""Offline end-to-end scan-accuracy validation (deterministic, CI-safe).

Unlike the canonicalization parity test, this drives the *real* offline scan
path (``_scan_packages_db_conn``) against a seeded local DB and asserts that each
component is matched to the right CVE at the right confidence tier across all
three matchers — OSV/ecosystem version-range, distro advisory, and the new NVD
CPE candidate path. No network: it's the regression net for the matching engine.
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.db.schema import init_db
from agent_bom.models import Package
from agent_bom.scanners import _db_ecosystems_for_package, _scan_packages_db_conn


def _seed(conn) -> None:
    # 1) OSV / ecosystem version-range hit (PyPI requests in [2.0.0, 2.6.0))
    osv_pkg = Package(name="requests", version="2.5.0", ecosystem="pypi")
    osv_eco = _db_ecosystems_for_package(osv_pkg)[0]
    conn.execute(
        "INSERT INTO vulns(id, summary, severity, source) VALUES (?,?,?,?)",
        ("CVE-OSV-0001", "requests SSRF", "high", "osv"),
    )
    conn.execute(
        "INSERT INTO affected(vuln_id, ecosystem, package_name, introduced, fixed) VALUES (?,?,?,?,?)",
        ("CVE-OSV-0001", osv_eco, "requests", "2.0.0", "2.6.0"),
    )

    # 2) Distro advisory hit (apk busybox under the branch key)
    apk_pkg = Package(name="busybox", version="1.35.0-r17", ecosystem="apk", distro_name="alpine", distro_version="3.16.9")
    apk_eco = _db_ecosystems_for_package(apk_pkg)[0]
    conn.execute(
        "INSERT INTO vulns(id, summary, severity, source) VALUES (?,?,?,?)",
        ("CVE-DISTRO-0002", "busybox overflow", "high", "alpine-secdb"),
    )
    conn.execute(
        "INSERT INTO affected(vuln_id, ecosystem, package_name, introduced, fixed) VALUES (?,?,?,?,?)",
        ("CVE-DISTRO-0002", apk_eco, "busybox", "0", "1.35.0-r18"),
    )

    # 3) CPE candidate hit — a non-ecosystem component OSV/distro never cover.
    conn.execute(
        "INSERT INTO vulns(id, summary, severity, source) VALUES (?,?,?,?)",
        ("CVE-CPE-0003", "acmehttpd RCE", "critical", "nvd"),
    )
    conn.execute(
        "INSERT INTO cpe_matches (cve_id, criteria, vendor, product, version, "
        "version_start, version_start_op, version_end, version_end_op) VALUES (?,?,?,?,?,?,?,?,?)",
        ("CVE-CPE-0003", "cpe:2.3:a:acme:acmehttpd:*", "acme", "acmehttpd", None, "1.0.0", "including", "2.0.0", "excluding"),
    )
    conn.commit()


def _vuln_ids(pkg: Package) -> set[str]:
    return {v.id for v in pkg.vulnerabilities}


def test_offline_scan_matches_all_three_tiers(monkeypatch) -> None:
    monkeypatch.setattr("agent_bom.config.ENABLE_CPE_MATCH", True)
    conn = init_db(Path(":memory:"))
    _seed(conn)

    osv_pkg = Package(name="requests", version="2.5.0", ecosystem="pypi")
    apk_pkg = Package(name="busybox", version="1.35.0-r17", ecosystem="apk", distro_name="alpine", distro_version="3.16.9")
    cpe_pkg = Package(name="acmehttpd", version="1.5.0", ecosystem="generic")
    packages = [osv_pkg, apk_pkg, cpe_pkg]

    total = _scan_packages_db_conn(conn, packages, set())

    assert total >= 3
    assert "CVE-OSV-0001" in _vuln_ids(osv_pkg)
    assert "CVE-DISTRO-0002" in _vuln_ids(apk_pkg)
    assert "CVE-CPE-0003" in _vuln_ids(cpe_pkg)

    # The CPE-matched finding must carry the review-grade candidate tier.
    cpe_vuln = next(v for v in cpe_pkg.vulnerabilities if v.id == "CVE-CPE-0003")
    assert cpe_vuln.match_confidence_tier == "nvd_cpe_candidate"


def test_offline_scan_no_false_positive_out_of_range(monkeypatch) -> None:
    monkeypatch.setattr("agent_bom.config.ENABLE_CPE_MATCH", True)
    conn = init_db(Path(":memory:"))
    _seed(conn)

    # requests 3.0.0 is past the fixed 2.6.0; acmehttpd 3.0.0 past the CPE end.
    clean_osv = Package(name="requests", version="3.0.0", ecosystem="pypi")
    clean_cpe = Package(name="acmehttpd", version="3.0.0", ecosystem="generic")
    _scan_packages_db_conn(conn, [clean_osv, clean_cpe], set())

    assert _vuln_ids(clean_osv) == set()
    assert _vuln_ids(clean_cpe) == set()


def test_cpe_off_by_default_no_candidate_noise(monkeypatch) -> None:
    monkeypatch.setattr("agent_bom.config.ENABLE_CPE_MATCH", False)
    conn = init_db(Path(":memory:"))
    _seed(conn)
    cpe_pkg = Package(name="acmehttpd", version="1.5.0", ecosystem="generic")
    _scan_packages_db_conn(conn, [cpe_pkg], set())
    # With the toggle off, no CPE candidate findings leak in.
    assert _vuln_ids(cpe_pkg) == set()
