"""Tests for batch DB lookup (issue #762)."""

from __future__ import annotations

import sqlite3

import pytest

from agent_bom.db.lookup import lookup_package, lookup_packages_batch
from agent_bom.db.schema import init_db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path) -> sqlite3.Connection:
    db_file = tmp_path / "test_vulns.db"
    conn = init_db(db_file)
    yield conn
    conn.close()


def _insert_vuln(conn, vuln_id="CVE-2024-TEST", severity="high", cvss_score=7.5):
    conn.execute(
        "INSERT OR REPLACE INTO vulns(id,summary,severity,cvss_score,source) VALUES (?,?,?,?,'osv')",
        (vuln_id, f"Test vuln {vuln_id}", severity, cvss_score),
    )
    conn.commit()


def _insert_affected(
    conn,
    vuln_id="CVE-2024-TEST",
    ecosystem="pypi",
    pkg="requests",
    introduced="2.0.0",
    fixed="2.1.0",
):
    conn.execute(
        "INSERT OR REPLACE INTO affected(vuln_id,ecosystem,package_name,introduced,fixed,last_affected) VALUES (?,?,?,?,?,'')",
        (vuln_id, ecosystem, pkg, introduced, fixed),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# lookup_packages_batch — basic
# ---------------------------------------------------------------------------


def test_batch_empty_returns_empty(tmp_db):
    result = lookup_packages_batch(tmp_db, [])
    assert result == {}


def test_batch_single_package_matches_individual(tmp_db):
    _insert_vuln(tmp_db)
    _insert_affected(tmp_db)
    individual = lookup_package(tmp_db, "pypi", "requests", "2.0.5")
    batch = lookup_packages_batch(tmp_db, [("pypi", "requests", "2.0.5")])
    assert len(batch[("pypi", "requests", "2.0.5")]) == len(individual)
    assert batch[("pypi", "requests", "2.0.5")][0].id == individual[0].id


def test_batch_multiple_packages(tmp_db):
    _insert_vuln(tmp_db, "CVE-2024-001")
    _insert_affected(tmp_db, vuln_id="CVE-2024-001", ecosystem="pypi", pkg="requests")
    _insert_vuln(tmp_db, "CVE-2024-002", severity="critical", cvss_score=9.5)
    _insert_affected(tmp_db, vuln_id="CVE-2024-002", ecosystem="npm", pkg="express")

    batch = lookup_packages_batch(
        tmp_db,
        [
            ("pypi", "requests", "2.0.5"),
            ("npm", "express", "2.0.5"),
            ("pypi", "nonexistent", "1.0.0"),
        ],
    )
    assert len(batch[("pypi", "requests", "2.0.5")]) == 1
    assert len(batch[("npm", "express", "2.0.5")]) == 1
    assert len(batch[("pypi", "nonexistent", "1.0.0")]) == 0


def test_batch_version_filtering(tmp_db):
    """Batch lookup applies the same version range filtering as individual."""
    _insert_vuln(tmp_db)
    _insert_affected(tmp_db, introduced="2.0.0", fixed="2.1.0")

    batch = lookup_packages_batch(
        tmp_db,
        [
            ("pypi", "requests", "2.0.5"),  # in range
            ("pypi", "requests", "3.0.0"),  # out of range
        ],
    )
    assert len(batch[("pypi", "requests", "2.0.5")]) == 1
    assert len(batch[("pypi", "requests", "3.0.0")]) == 0


def test_batch_kev_and_epss(tmp_db):
    """Batch lookup includes KEV and EPSS data."""
    _insert_vuln(tmp_db)
    _insert_affected(tmp_db)
    tmp_db.execute("INSERT OR REPLACE INTO kev_entries(cve_id, date_added) VALUES ('CVE-2024-TEST', '2024-01-01')")
    tmp_db.execute(
        "INSERT OR REPLACE INTO epss_scores(cve_id, probability, percentile, updated_at) VALUES ('CVE-2024-TEST', 0.95, 99.5, '2024-01-01')"
    )
    tmp_db.commit()

    batch = lookup_packages_batch(tmp_db, [("pypi", "requests", "2.0.5")])
    vuln = batch[("pypi", "requests", "2.0.5")][0]
    assert vuln.is_kev is True
    assert vuln.kev_date_added == "2024-01-01"
    assert vuln.epss_probability == pytest.approx(0.95)
    assert vuln.epss_percentile == pytest.approx(99.5)


def test_batch_alias_cve_enrichment(tmp_db):
    _insert_vuln(tmp_db, vuln_id="GHSA-test-alias", cvss_score=None)
    tmp_db.execute("UPDATE vulns SET aliases='CVE-2024-TESTALIAS' WHERE id='GHSA-test-alias'")
    _insert_affected(tmp_db, vuln_id="GHSA-test-alias")
    tmp_db.execute(
        "INSERT OR REPLACE INTO epss_scores(cve_id, probability, percentile, updated_at) "
        "VALUES ('CVE-2024-TESTALIAS', 0.42, 88.0, '2024-01-01')"
    )
    tmp_db.execute("INSERT OR REPLACE INTO kev_entries(cve_id, date_added) VALUES ('CVE-2024-TESTALIAS', '2024-02-01')")
    tmp_db.commit()

    batch = lookup_packages_batch(tmp_db, [("pypi", "requests", "2.0.5")])
    vuln = batch[("pypi", "requests", "2.0.5")][0]
    assert vuln.epss_probability == pytest.approx(0.42)
    assert vuln.epss_percentile == pytest.approx(88.0)
    assert vuln.is_kev is True
    assert vuln.kev_date_added == "2024-02-01"


def test_batch_ecosystem_case_insensitive(tmp_db):
    """Batch lookup is case-insensitive on ecosystem."""
    _insert_vuln(tmp_db)
    _insert_affected(tmp_db, ecosystem="pypi")

    batch = lookup_packages_batch(tmp_db, [("PyPI", "requests", "2.0.5")])
    assert len(batch[("PyPI", "requests", "2.0.5")]) == 1


# ---------------------------------------------------------------------------
# Chunking — large batches
# ---------------------------------------------------------------------------


def test_batch_chunking_large(tmp_db):
    """Batch lookup correctly handles >400 unique (eco, name) pairs via chunking."""
    # Insert 500 unique packages, each with a vuln
    for i in range(500):
        vuln_id = f"CVE-2024-{i:04d}"
        pkg_name = f"pkg-{i}"
        _insert_vuln(tmp_db, vuln_id=vuln_id, cvss_score=5.0)
        _insert_affected(
            tmp_db,
            vuln_id=vuln_id,
            ecosystem="pypi",
            pkg=pkg_name,
            introduced="1.0.0",
            fixed="2.0.0",
        )

    keys = [("pypi", f"pkg-{i}", "1.5.0") for i in range(500)]
    batch = lookup_packages_batch(tmp_db, keys)

    assert len(batch) == 500
    for key in keys:
        assert len(batch[key]) == 1, f"Missing vuln for {key}"


# ---------------------------------------------------------------------------
# Parity with individual lookup
# ---------------------------------------------------------------------------


def test_batch_parity_with_individual(tmp_db):
    """Batch results are identical to calling lookup_package individually."""
    # Set up diverse data
    for vuln_id, eco, pkg, intro, fix in [
        ("CVE-2024-A", "pypi", "requests", "2.0.0", "2.1.0"),
        ("CVE-2024-B", "pypi", "requests", "1.0.0", "1.5.0"),
        ("CVE-2024-C", "npm", "express", "3.0.0", "3.5.0"),
        ("CVE-2024-D", "npm", "lodash", "4.0.0", ""),
    ]:
        _insert_vuln(tmp_db, vuln_id=vuln_id)
        _insert_affected(tmp_db, vuln_id=vuln_id, ecosystem=eco, pkg=pkg, introduced=intro, fixed=fix)

    test_cases = [
        ("pypi", "requests", "2.0.5"),
        ("pypi", "requests", "1.2.0"),
        ("npm", "express", "3.1.0"),
        ("npm", "lodash", "4.5.0"),
        ("npm", "lodash", "3.9.0"),
    ]

    batch = lookup_packages_batch(tmp_db, test_cases)

    for eco, name, version in test_cases:
        individual = lookup_package(tmp_db, eco, name, version)
        batch_vulns = batch[(eco, name, version)]
        assert len(batch_vulns) == len(individual), f"Mismatch for {eco}:{name}@{version}"
        assert {v.id for v in batch_vulns} == {v.id for v in individual}


# ---------------------------------------------------------------------------
# Regression: unparseable fixed_version must not silently drop CVEs
# ---------------------------------------------------------------------------


def test_unparseable_fixed_version_reports_affected(tmp_db):
    """Regression: when fixed version is a git hash, package is still reported as affected.

    Previously, InvalidVersion caused a silent return False (not affected),
    meaning real CVEs were dropped from scan results.
    """
    _insert_vuln(tmp_db, vuln_id="CVE-2024-HASH")
    # Insert with a git commit hash as the fixed version — non-parseable by packaging.version
    tmp_db.execute(
        "INSERT OR REPLACE INTO affected(vuln_id,ecosystem,package_name,introduced,fixed,last_affected) VALUES (?,?,?,?,?,'')",
        ("CVE-2024-HASH", "pypi", "some-lib", "1.0.0", "abc123def456git"),
    )
    tmp_db.commit()

    # Package is at version 1.5.0 — AFTER "introduced" but fix version is unparseable
    vulns = lookup_package(tmp_db, "pypi", "some-lib", "1.5.0")
    # Must be reported as affected (not silently dropped)
    cve_ids = {v.id for v in vulns}
    assert "CVE-2024-HASH" in cve_ids, (
        "CVE with unparseable fixed version (git hash) was silently dropped; should be conservatively reported as affected"
    )


def test_duplicate_sha_row_does_not_override_semver_unaffected(tmp_db):
    """A duplicate SHA-based row must not resurrect a vuln once a semver row excludes it."""
    _insert_vuln(tmp_db, vuln_id="CVE-2024-DUPE")
    tmp_db.execute(
        "INSERT OR REPLACE INTO affected(vuln_id,ecosystem,package_name,introduced,fixed,last_affected) VALUES (?,?,?,?,?,'')",
        ("CVE-2024-DUPE", "pypi", "requests", "0", "3bd8afbff29e50b38f889b2f688785a669b9aafc"),
    )
    tmp_db.execute(
        "INSERT OR REPLACE INTO affected(vuln_id,ecosystem,package_name,introduced,fixed,last_affected) VALUES (?,?,?,?,?,'')",
        ("CVE-2024-DUPE", "pypi", "requests", "2.1.0", "2.6.0"),
    )
    tmp_db.commit()

    vulns = lookup_package(tmp_db, "pypi", "requests", "2.33.0")
    assert "CVE-2024-DUPE" not in {v.id for v in vulns}

    batch = lookup_packages_batch(tmp_db, [("pypi", "requests", "2.33.0")])
    assert "CVE-2024-DUPE" not in {v.id for v in batch[("pypi", "requests", "2.33.0")]}
