"""Tests for the local vulnerability database (issue #606)."""

from __future__ import annotations

import json
import sqlite3
from unittest.mock import patch

import pytest

from agent_bom.db.lookup import VulnDB, _version_affected, lookup_package
from agent_bom.db.schema import DB_PATH, _validated_db_path, db_stats, init_db
from agent_bom.db.sync import (
    _ingest_osv_file,
    _parse_osv_entry,
    _validate_sync_url,
    sync_epss,
    sync_kev,
    sync_osv,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path) -> sqlite3.Connection:
    """In-memory-like DB in a temp file, auto-closed after test."""
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


def _insert_affected(conn, vuln_id="CVE-2024-TEST", ecosystem="pypi", pkg="requests", introduced="2.0.0", fixed="2.1.0"):
    conn.execute(
        "INSERT OR REPLACE INTO affected(vuln_id,ecosystem,package_name,introduced,fixed,last_affected) VALUES (?,?,?,?,?,'')",
        (vuln_id, ecosystem, pkg, introduced, fixed),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# schema / init_db
# ---------------------------------------------------------------------------


def test_init_db_creates_tables(tmp_path):
    db_file = tmp_path / "v.db"
    conn = init_db(db_file)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert "vulns" in tables
    assert "affected" in tables
    assert "epss_scores" in tables
    assert "kev_entries" in tables
    assert "sync_meta" in tables
    assert "schema_version" in tables
    conn.close()


def test_init_db_creates_parent_dirs(tmp_path):
    db_file = tmp_path / "deep" / "nested" / "v.db"
    conn = init_db(db_file)
    assert db_file.exists()
    conn.close()


def test_init_db_idempotent(tmp_path):
    db_file = tmp_path / "v.db"
    conn1 = init_db(db_file)
    conn1.close()
    conn2 = init_db(db_file)  # second open should not error
    conn2.close()


def test_db_stats_empty(tmp_db):
    stats = db_stats(tmp_db)
    assert stats["vuln_count"] == 0
    assert stats["affected_count"] == 0
    assert stats["epss_count"] == 0
    assert stats["kev_count"] == 0


def test_db_stats_after_inserts(tmp_db):
    _insert_vuln(tmp_db)
    _insert_affected(tmp_db)
    stats = db_stats(tmp_db)
    assert stats["vuln_count"] == 1
    assert stats["affected_count"] == 1


def test_db_path_constant():
    assert DB_PATH.suffix == ".db"
    assert "agent-bom" in str(DB_PATH)


# ---------------------------------------------------------------------------
# _version_affected
# ---------------------------------------------------------------------------


def test_version_affected_in_range():
    assert _version_affected("2.0.5", "2.0.0", "2.1.0", None) is True


def test_version_affected_at_intro():
    assert _version_affected("2.0.0", "2.0.0", "2.1.0", None) is True


def test_version_affected_at_fix():
    assert _version_affected("2.1.0", "2.0.0", "2.1.0", None) is False


def test_version_affected_before_intro():
    assert _version_affected("1.9.9", "2.0.0", "2.1.0", None) is False


def test_version_affected_no_fix():
    # No fix means all versions from intro onward are affected
    assert _version_affected("9.0.0", "2.0.0", None, None) is True


def test_version_affected_no_intro_or_fix():
    # Empty intro/fix = all versions affected
    assert _version_affected("1.0.0", None, None, None) is True


def test_version_affected_last_affected():
    assert _version_affected("2.0.5", "2.0.0", None, "2.0.9") is True
    assert _version_affected("2.1.0", "2.0.0", None, "2.0.9") is False


# ---------------------------------------------------------------------------
# lookup_package
# ---------------------------------------------------------------------------


def test_lookup_package_exact_version(tmp_db):
    _insert_vuln(tmp_db)
    _insert_affected(tmp_db)
    results = lookup_package(tmp_db, "pypi", "requests", "2.0.5")
    assert len(results) == 1
    assert results[0].id == "CVE-2024-TEST"


def test_lookup_package_version_outside_range(tmp_db):
    _insert_vuln(tmp_db)
    _insert_affected(tmp_db, introduced="2.0.0", fixed="2.1.0")
    results = lookup_package(tmp_db, "pypi", "requests", "3.0.0")
    assert len(results) == 0


def test_lookup_package_no_version_returns_all(tmp_db):
    _insert_vuln(tmp_db)
    _insert_affected(tmp_db)
    results = lookup_package(tmp_db, "pypi", "requests")
    assert len(results) == 1


def test_lookup_package_ecosystem_case_insensitive(tmp_db):
    _insert_vuln(tmp_db)
    _insert_affected(tmp_db, ecosystem="pypi")
    results = lookup_package(tmp_db, "PyPI", "requests", "2.0.5")
    assert len(results) == 1


def test_lookup_package_name_normalized(tmp_db):
    _insert_vuln(tmp_db)
    # DB has "requests" (normalized), lookup with "Requests" should match
    _insert_affected(tmp_db, pkg="requests")
    results = lookup_package(tmp_db, "pypi", "Requests", "2.0.5")
    assert len(results) == 1


def test_lookup_package_is_kev_false(tmp_db):
    _insert_vuln(tmp_db)
    _insert_affected(tmp_db)
    results = lookup_package(tmp_db, "pypi", "requests", "2.0.5")
    assert results[0].is_kev is False


def test_lookup_package_is_kev_true(tmp_db):
    _insert_vuln(tmp_db)
    _insert_affected(tmp_db)
    tmp_db.execute("INSERT OR REPLACE INTO kev_entries(cve_id, date_added) VALUES ('CVE-2024-TEST', '2024-01-01')")
    tmp_db.commit()
    results = lookup_package(tmp_db, "pypi", "requests", "2.0.5")
    assert results[0].is_kev is True
    assert results[0].kev_date_added == "2024-01-01"


def test_lookup_package_epss_scores(tmp_db):
    _insert_vuln(tmp_db)
    _insert_affected(tmp_db)
    tmp_db.execute(
        "INSERT OR REPLACE INTO epss_scores(cve_id, probability, percentile, updated_at) VALUES ('CVE-2024-TEST', 0.95, 99.5, '2024-01-01')"
    )
    tmp_db.commit()
    results = lookup_package(tmp_db, "pypi", "requests", "2.0.5")
    assert results[0].epss_probability == pytest.approx(0.95)
    assert results[0].epss_percentile == pytest.approx(99.5)


def test_lookup_package_not_found(tmp_db):
    results = lookup_package(tmp_db, "pypi", "nonexistent-package", "1.0.0")
    assert results == []


# ---------------------------------------------------------------------------
# VulnDB context manager
# ---------------------------------------------------------------------------


def test_vulndb_context_manager(tmp_path):
    db_file = tmp_path / "v.db"
    with VulnDB(path=db_file) as db:
        stats = db.stats()
        assert stats["vuln_count"] == 0


def test_vulndb_lookup(tmp_path):
    db_file = tmp_path / "v.db"
    conn = init_db(db_file)
    _insert_vuln(conn)
    _insert_affected(conn)
    conn.close()

    with VulnDB(path=db_file) as db:
        results = db.lookup("pypi", "requests", "2.0.5")
        assert len(results) == 1


def test_vulndb_not_opened_raises():
    db = VulnDB()
    with pytest.raises(RuntimeError, match="not opened"):
        db.lookup("pypi", "requests")


# ---------------------------------------------------------------------------
# OSV ingestion
# ---------------------------------------------------------------------------


def _make_osv_entry(vuln_id="CVE-2024-OSV-TEST", pkg="requests", ecosystem="PyPI") -> dict:
    return {
        "id": vuln_id,
        "summary": "Test advisory",
        "published": "2024-01-01T00:00:00Z",
        "modified": "2024-01-02T00:00:00Z",
        "database_specific": {"cvss_score": 7.5},
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": pkg},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "2.0.0"}, {"fixed": "2.1.0"}],
                    }
                ],
            }
        ],
    }


def test_parse_osv_entry_basic():
    data = _make_osv_entry()
    result = _parse_osv_entry(data)
    assert result is not None
    vuln_row, affected_rows = result
    assert vuln_row["id"] == "CVE-2024-OSV-TEST"
    assert vuln_row["cvss_score"] == pytest.approx(7.5)
    assert vuln_row["severity"] == "high"
    assert len(affected_rows) >= 1
    assert affected_rows[0]["package_name"] == "requests"
    assert affected_rows[0]["introduced"] == "2.0.0"
    assert affected_rows[0]["fixed"] == "2.1.0"


def test_parse_osv_entry_withdrawn_skipped():
    data = _make_osv_entry()
    data["withdrawn"] = "2024-06-01T00:00:00Z"
    assert _parse_osv_entry(data) is None


def test_parse_osv_entry_missing_id_skipped():
    assert _parse_osv_entry({"summary": "no id"}) is None


def test_ingest_osv_file_invalid_json(tmp_db):
    count = _ingest_osv_file(tmp_db, b"not json", "bad.json")
    assert count == 0


def test_ingest_osv_file_valid(tmp_db):
    data = _make_osv_entry()
    content = json.dumps(data).encode()
    count = _ingest_osv_file(tmp_db, content, "CVE-2024-OSV-TEST.json")
    assert count == 1
    row = tmp_db.execute("SELECT id FROM vulns WHERE id = 'CVE-2024-OSV-TEST'").fetchone()
    assert row is not None


# ---------------------------------------------------------------------------
# KEV sync (mocked HTTP)
# ---------------------------------------------------------------------------


def test_sync_kev_mocked(tmp_db):
    kev_data = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-KEV-1", "dateAdded": "2024-01-01", "dueDate": "2024-02-01", "product": "Foo", "vendorProject": "Bar"},
            {"cveID": "CVE-2024-KEV-2", "dateAdded": "2024-01-02", "dueDate": "", "product": "Baz", "vendorProject": "Corp"},
        ]
    }
    kev_bytes = json.dumps(kev_data).encode()

    class _FakeResp:
        def read(self):
            return kev_bytes

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

    with patch("urllib.request.urlopen", return_value=_FakeResp()):
        count = sync_kev(tmp_db, url="https://fake/kev.json")

    assert count == 2
    rows = tmp_db.execute("SELECT cve_id FROM kev_entries ORDER BY cve_id").fetchall()
    assert rows[0][0] == "CVE-2024-KEV-1"
    assert rows[1][0] == "CVE-2024-KEV-2"


# ---------------------------------------------------------------------------
# EPSS sync (mocked HTTP)
# ---------------------------------------------------------------------------


def test_sync_epss_mocked(tmp_db):
    csv_content = b"cve,epss,percentile\nCVE-2024-1,0.95,99.5\nCVE-2024-2,0.10,50.0\n"

    class _FakeResp:
        def read(self):
            return csv_content  # not gzipped — sync_epss handles both

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

    with patch("urllib.request.urlopen", return_value=_FakeResp()):
        count = sync_epss(tmp_db, url="https://fake/epss.csv.gz")

    assert count == 2
    row = tmp_db.execute("SELECT probability FROM epss_scores WHERE cve_id='CVE-2024-1'").fetchone()
    assert row[0] == pytest.approx(0.95)


# ---------------------------------------------------------------------------
# Security hardening — URL validation
# ---------------------------------------------------------------------------


def test_validate_sync_url_accepts_https():
    _validate_sync_url("https://example.com/data.zip")  # must not raise


def test_validate_sync_url_rejects_http():
    with pytest.raises(ValueError, match="https://"):
        _validate_sync_url("http://example.com/data.zip")


def test_validate_sync_url_rejects_file_scheme():
    with pytest.raises(ValueError, match="https://"):
        _validate_sync_url("file:///tmp/osv.zip")


def test_validate_sync_url_rejects_empty():
    with pytest.raises(ValueError, match="https://"):
        _validate_sync_url("")


def test_sync_osv_rejects_http_url(tmp_db):
    with pytest.raises(ValueError, match="https://"):
        sync_osv(tmp_db, url="http://evil.example.com/osv.zip")


def test_sync_epss_rejects_http_url(tmp_db):
    with pytest.raises(ValueError, match="https://"):
        sync_epss(tmp_db, url="http://evil.example.com/epss.csv.gz")


def test_sync_kev_rejects_http_url(tmp_db):
    with pytest.raises(ValueError, match="https://"):
        sync_kev(tmp_db, url="http://evil.example.com/kev.json")


# ---------------------------------------------------------------------------
# Security hardening — DB path validation
# ---------------------------------------------------------------------------


def test_validated_db_path_accepts_home_subpath(tmp_path, monkeypatch):
    """A path under the home directory is accepted."""
    # tmp_path is typically under /tmp which is also allowed
    p = _validated_db_path(str(tmp_path / "vulns.db"))
    assert p == tmp_path / "vulns.db"


def test_validated_db_path_rejects_arbitrary_system_path():
    with pytest.raises(ValueError, match="home directory or /tmp"):
        _validated_db_path("/etc/passwd")


def test_validated_db_path_rejects_traversal(tmp_path):
    with pytest.raises(ValueError):
        _validated_db_path(str(tmp_path / ".." / ".." / "etc" / "passwd"))


# ---------------------------------------------------------------------------
# Security hardening — file permissions (0600)
# ---------------------------------------------------------------------------


def test_init_db_sets_restrictive_permissions(tmp_path):
    import stat as _stat

    db_file = tmp_path / "perms_test.db"
    conn = init_db(db_file)
    conn.close()
    mode = db_file.stat().st_mode
    # Owner read+write must be set; group and other must NOT be set
    assert mode & _stat.S_IRUSR
    assert mode & _stat.S_IWUSR
    assert not (mode & _stat.S_IRGRP)
    assert not (mode & _stat.S_IROTH)


# ---------------------------------------------------------------------------
# Security hardening — integrity check
# ---------------------------------------------------------------------------


def test_init_db_passes_integrity_check(tmp_path, caplog):
    import logging

    db_file = tmp_path / "integrity_test.db"
    with caplog.at_level(logging.WARNING, logger="agent_bom.db.schema"):
        conn = init_db(db_file)
        conn.close()
    # A fresh DB should pass — no integrity warning
    assert "integrity check" not in caplog.text


# ---------------------------------------------------------------------------
# _cvss_to_severity — branches
# ---------------------------------------------------------------------------


def test_cvss_to_severity_none():
    from agent_bom.db.sync import _cvss_to_severity

    assert _cvss_to_severity(None) == "unknown"


def test_cvss_to_severity_critical():
    from agent_bom.db.sync import _cvss_to_severity

    assert _cvss_to_severity(9.5) == "critical"


def test_cvss_to_severity_high():
    from agent_bom.db.sync import _cvss_to_severity

    assert _cvss_to_severity(8.0) == "high"


def test_cvss_to_severity_medium():
    from agent_bom.db.sync import _cvss_to_severity

    assert _cvss_to_severity(5.5) == "medium"


def test_cvss_to_severity_low():
    from agent_bom.db.sync import _cvss_to_severity

    assert _cvss_to_severity(2.5) == "low"


def test_cvss_to_severity_unknown_score():
    from agent_bom.db.sync import _cvss_to_severity

    assert _cvss_to_severity(0.0) == "unknown"


# ---------------------------------------------------------------------------
# _parse_osv_entry — CVSS / database_specific paths
# ---------------------------------------------------------------------------


def test_parse_osv_entry_with_cvss_score_str():
    """database_specific cvss as string is cast to float."""
    data = {
        "id": "CVE-2024-CVSS-STR",
        "summary": "Test with string CVSS",
        "published": "2024-01-01T00:00:00Z",
        "modified": "2024-01-02T00:00:00Z",
        "database_specific": {"cvss": "7.5"},
        "affected": [],
    }
    result = _parse_osv_entry(data)
    assert result is not None
    vuln_row, _ = result
    assert vuln_row["cvss_score"] == 7.5
    assert vuln_row["severity"] == "high"


def test_parse_osv_entry_with_cvss_score_numeric():
    """database_specific cvss as a float."""
    data = {
        "id": "CVE-2024-CVSS-NUM",
        "summary": "Numeric CVSS",
        "published": "2024-01-01T00:00:00Z",
        "modified": "2024-01-02T00:00:00Z",
        "database_specific": {"cvss_score": 9.8},
        "affected": [],
    }
    result = _parse_osv_entry(data)
    assert result is not None
    vuln_row, _ = result
    assert vuln_row["severity"] == "critical"


def test_parse_osv_entry_with_cvss_severity_type():
    """CVSS_V3 severity type sets cvss_vector."""
    data = {
        "id": "CVE-2024-VEC",
        "summary": "CVSS vector test",
        "published": "2024-01-01T00:00:00Z",
        "modified": "2024-01-02T00:00:00Z",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [],
    }
    result = _parse_osv_entry(data)
    assert result is not None
    vuln_row, _ = result
    assert vuln_row["cvss_vector"] is not None


# ---------------------------------------------------------------------------
# sync_db — dispatcher with mocked sources
# ---------------------------------------------------------------------------


def test_sync_db_single_kev_source(tmp_path):
    """sync_db with sources=['kev'] only calls sync_kev."""
    from agent_bom.db.sync import sync_db

    with patch("agent_bom.db.sync.sync_kev", return_value=10) as mock_kev:
        result = sync_db(path=tmp_path / "test.db", sources=["kev"])
    assert result == {"kev": 10}
    mock_kev.assert_called_once()


def test_sync_db_single_epss_source(tmp_path):
    """sync_db with sources=['epss'] only calls sync_epss."""
    from agent_bom.db.sync import sync_db

    with patch("agent_bom.db.sync.sync_epss", return_value=500) as mock_epss:
        result = sync_db(path=tmp_path / "test.db", sources=["epss"])
    assert result == {"epss": 500}
    mock_epss.assert_called_once()


# ---------------------------------------------------------------------------
# db_freshness_days — new function
# ---------------------------------------------------------------------------


def test_db_freshness_days_no_db(tmp_path):
    """Returns None when DB file doesn't exist."""
    from agent_bom.db.schema import db_freshness_days

    assert db_freshness_days(tmp_path / "nonexistent.db") is None


def test_db_freshness_days_never_synced(tmp_path):
    """Returns None when sync_meta is empty (never synced)."""
    from agent_bom.db.schema import db_freshness_days, init_db

    db_file = tmp_path / "fresh.db"
    conn = init_db(db_file)
    conn.close()
    assert db_freshness_days(db_file) is None


def test_db_freshness_days_just_synced(tmp_path):
    """Returns 0 days when synced just now."""
    from datetime import datetime, timezone

    from agent_bom.db.schema import db_freshness_days, init_db

    db_file = tmp_path / "fresh.db"
    conn = init_db(db_file)
    now_iso = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO sync_meta(source, last_synced, record_count) VALUES (?, ?, ?)",
        ("osv", now_iso, 1000),
    )
    conn.commit()
    conn.close()

    age = db_freshness_days(db_file)
    assert age is not None
    assert age == 0


def test_db_freshness_days_old_db(tmp_path):
    """Returns correct age for a stale database."""
    from datetime import datetime, timedelta, timezone

    from agent_bom.db.schema import db_freshness_days, init_db

    db_file = tmp_path / "stale.db"
    conn = init_db(db_file)
    old_iso = (datetime.now(timezone.utc) - timedelta(days=15)).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO sync_meta(source, last_synced, record_count) VALUES (?, ?, ?)",
        ("osv", old_iso, 100),
    )
    conn.commit()
    conn.close()

    age = db_freshness_days(db_file)
    assert age is not None
    assert age >= 14
