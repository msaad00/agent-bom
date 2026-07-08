"""Regression: git-SHA-bound advisories must not false-positive on offline scans.

OSS-Fuzz / OSV-2022 advisories store git commit SHAs as their ``introduced`` /
``fixed`` bounds. A SHA can never be ordered against a concrete semver, so such a
row must not be reported for a real package version. The offline ``db/lookup``
matcher previously classified these rows as ``unknown`` and then *conservatively
included* them, emitting a false positive on every version (e.g. OSV-2022-1074 /
OSV-2022-715 against ``pillow==11.0.0``).

Mirrors the fixtures in ``test_debian_release_matching.py``.
"""

from __future__ import annotations

import sqlite3

import pytest

from agent_bom.db.lookup import _version_match_state, lookup_package
from agent_bom.db.schema import init_db

_SHA_A = "bb2016794f1f9bf9e4726727080e1beb789823fb"
_SHA_B = "f7363c1091c70356d92e56abfca6b65bef9e7b26"


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


# ── _version_match_state classification ──────────────────────────────────────


def test_sha_bounds_are_uncomparable_not_unknown():
    # Both bounds are git SHAs → cannot order against a semver → uncomparable.
    assert _version_match_state("11.0.0", _SHA_A, _SHA_B, "", "pypi") == "uncomparable"
    assert _version_match_state("99.99.99", _SHA_A, _SHA_B, "", "pypi") == "uncomparable"
    # A single SHA fix bound is equally uncomparable.
    assert _version_match_state("2.0.0", "0", _SHA_B, "", "pypi") == "uncomparable"


def test_semver_bounds_still_classified():
    # In-range semver still affected; past-fix still unaffected.
    assert _version_match_state("0.12.2", "0", "0.12.3", "", "pypi") == "affected"
    assert _version_match_state("0.12.3", "0", "0.12.3", "", "pypi") == "unaffected"


# ── lookup_package end-to-end ────────────────────────────────────────────────


def test_sha_bound_advisory_not_reported_for_semver(tmp_db):
    _insert(tmp_db, "OSV-2022-1074", "pypi", "pillow", introduced=_SHA_A, fixed=_SHA_B)
    _insert(
        tmp_db,
        "OSV-2022-715",
        "pypi",
        "pillow",
        introduced="c58d2817bc891c26e6b8098b8909c0eb2e7ce61b",
        fixed="9887544fafcd13cc8afcfa0c6d0f2e6facc1a8b8",
    )
    assert lookup_package(tmp_db, "pypi", "pillow", "11.0.0") == []
    assert lookup_package(tmp_db, "pypi", "pillow", "99.99.99") == []


def test_semver_advisory_still_reported_and_excluded(tmp_db):
    _insert(tmp_db, "CVE-2018-1000656", "pypi", "flask", introduced="0", fixed="0.12.3")
    # In-range version is affected.
    assert [m.id for m in lookup_package(tmp_db, "pypi", "flask", "0.12.2")] == ["CVE-2018-1000656"]
    # Fixed / past-fix version is excluded.
    assert lookup_package(tmp_db, "pypi", "flask", "0.12.3") == []


def test_mixed_sha_and_semver_rows_resolve_via_comparable_sibling(tmp_db):
    # Same vuln, two affected rows: one SHA-bound (uncomparable), one semver.
    # A comparable "affected" sibling wins → reported for an in-range version.
    _insert(tmp_db, "OSV-2021-1", "pypi", "widget", introduced=_SHA_A, fixed=_SHA_B)
    tmp_db.execute(
        "INSERT INTO affected(vuln_id,ecosystem,package_name,introduced,fixed,last_affected) VALUES (?,?,?,?,?,?)",
        ("OSV-2021-1", "pypi", "widget", "0", "2.0.0", ""),
    )
    tmp_db.commit()
    assert [m.id for m in lookup_package(tmp_db, "pypi", "widget", "1.0.0")] == ["OSV-2021-1"]
    # And a version past the semver sibling's fix is excluded despite the SHA row.
    assert lookup_package(tmp_db, "pypi", "widget", "3.0.0") == []
