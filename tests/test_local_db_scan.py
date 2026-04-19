"""Tests for local SQLite DB integration in the scan pipeline.

Verifies that _scan_packages_local_db() correctly reads from the DB and
that scan_packages() uses it as the primary source before calling OSV.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.models import Package, Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_pkg(name: str = "requests", version: str = "2.28.0", eco: str = "pypi") -> Package:
    return Package(name=name, version=version, ecosystem=eco)


def _make_local_vuln(vuln_id: str = "CVE-2024-1111", severity: str = "high", cvss: float = 7.5):
    lv = MagicMock()
    lv.id = vuln_id
    lv.summary = f"Test vuln {vuln_id}"
    lv.severity = severity
    lv.cvss_score = cvss
    lv.fixed_version = "2.32.0"
    lv.epss_probability = 0.12
    lv.epss_percentile = 0.75
    lv.is_kev = False
    lv.kev_date_added = None
    lv.aliases = []
    lv.references = []
    return lv


# ---------------------------------------------------------------------------
# _local_vuln_to_vulnerability
# ---------------------------------------------------------------------------


def test_local_vuln_to_vulnerability_severity_mapping():
    from agent_bom.scanners import _local_vuln_to_vulnerability

    lv = _make_local_vuln(severity="critical", cvss=9.8)
    v = _local_vuln_to_vulnerability(lv)
    assert v.id == "CVE-2024-1111"
    assert v.severity == Severity.CRITICAL
    assert v.cvss_score == 9.8


def test_local_vuln_to_vulnerability_unknown_severity():
    from agent_bom.scanners import _local_vuln_to_vulnerability

    lv = _make_local_vuln(severity="", cvss=None)
    v = _local_vuln_to_vulnerability(lv)
    assert v.severity == Severity.UNKNOWN  # unknown severity must not silently inflate to MEDIUM


def test_local_vuln_to_vulnerability_kev_flag():
    from agent_bom.scanners import _local_vuln_to_vulnerability

    lv = _make_local_vuln()
    lv.is_kev = True
    lv.kev_date_added = "2024-01-15"
    v = _local_vuln_to_vulnerability(lv)
    assert v.is_kev is True
    assert v.kev_date_added == "2024-01-15"


def test_local_vuln_epss_fields():
    from agent_bom.scanners import _local_vuln_to_vulnerability

    lv = _make_local_vuln()
    lv.epss_probability = 0.42
    lv.epss_percentile = 0.91
    v = _local_vuln_to_vulnerability(lv)
    assert v.epss_score == 0.42
    assert v.epss_percentile == 0.91


# ---------------------------------------------------------------------------
# _scan_packages_local_db — no DB present
# ---------------------------------------------------------------------------


def test_scan_packages_local_db_no_db():
    """When no local DB exists, returns (0, empty set) without crashing."""
    from agent_bom.scanners import _scan_packages_local_db

    with patch("agent_bom.db.schema.db_freshness_days", return_value=None):
        count, covered = _scan_packages_local_db([_make_pkg()])
    assert count == 0
    assert covered == set()


def test_scan_packages_local_db_db_unavailable():
    """DB init failure returns (0, empty set) gracefully."""
    from agent_bom.scanners import _scan_packages_local_db

    with (
        patch("agent_bom.db.schema.db_freshness_days", return_value=1),
        patch("agent_bom.db.schema.init_db", side_effect=RuntimeError("locked")),
        patch("agent_bom.db.schema.open_existing_db_readonly", side_effect=RuntimeError("readonly locked")),
    ):
        count, covered = _scan_packages_local_db([_make_pkg()])
    assert count == 0


def test_scan_packages_local_db_falls_back_to_readonly_open():
    """Read-only fallback still scans when writable init_db fails."""
    from agent_bom.scanners import _scan_packages_local_db

    pkg = _make_pkg()
    lv = _make_local_vuln("CVE-2024-4444", "high", 7.9)
    conn = MagicMock()

    with (
        patch("agent_bom.db.schema.db_freshness_days", return_value=1),
        patch("agent_bom.db.schema.init_db", side_effect=RuntimeError("readonly mount")),
        patch("agent_bom.db.schema.open_existing_db_readonly", return_value=conn),
        patch("agent_bom.db.lookup.package_in_db", return_value=True),
        patch("agent_bom.db.lookup_package", return_value=[lv]),
    ):
        count, covered = _scan_packages_local_db([pkg])

    assert count == 1
    assert len(pkg.vulnerabilities) == 1
    assert covered == {"pypi:requests@2.28.0"}
    conn.close.assert_called_once()


def test_scan_packages_local_db_prefers_readonly_open_for_existing_db(tmp_path):
    """Existing DBs should open read-only on the scan hot path."""
    from agent_bom.scanners import _scan_packages_local_db

    pkg = _make_pkg()
    db_file = tmp_path / "scan.db"
    db_file.write_text("placeholder", encoding="utf-8")
    conn = MagicMock()

    with (
        patch("agent_bom.db.schema.db_freshness_days", return_value=1),
        patch("agent_bom.db.schema.DB_PATH", db_file),
        patch("agent_bom.db.schema.open_existing_db_readonly", return_value=conn) as mock_open_ro,
        patch("agent_bom.db.schema.init_db") as mock_init_db,
        patch("agent_bom.db.lookup.package_in_db", return_value=False),
        patch("agent_bom.db.lookup_package", return_value=[]),
    ):
        count, covered = _scan_packages_local_db([pkg])

    assert count == 0
    assert covered == set()
    mock_open_ro.assert_called_once_with(db_file)
    mock_init_db.assert_not_called()
    conn.close.assert_called_once()


# ---------------------------------------------------------------------------
# _scan_packages_local_db — DB has findings
# ---------------------------------------------------------------------------


def test_scan_packages_local_db_finds_vulns(tmp_path):
    """When DB has a matching vuln, it's added to the package and count incremented."""
    from agent_bom.scanners import _scan_packages_local_db

    pkg = _make_pkg()
    lv = _make_local_vuln("CVE-2024-2222", "high", 7.8)

    with (
        patch("agent_bom.db.schema.db_freshness_days", return_value=1),
        patch("agent_bom.db.schema.DB_PATH", str(tmp_path / "test.db")),
        patch("agent_bom.db.schema.init_db", return_value=MagicMock()),
        patch("agent_bom.db.lookup_package", return_value=[lv]),
    ):
        count, covered = _scan_packages_local_db([pkg])

    assert count == 1
    assert len(pkg.vulnerabilities) == 1
    assert pkg.vulnerabilities[0].id == "CVE-2024-2222"


def test_scan_packages_local_db_no_duplicates(tmp_path):
    """A vuln already on the package is not added twice."""
    from agent_bom.scanners import _local_vuln_to_vulnerability, _scan_packages_local_db

    pkg = _make_pkg()
    lv = _make_local_vuln("CVE-2024-3333")
    pkg.vulnerabilities = [_local_vuln_to_vulnerability(lv)]  # pre-populated

    with (
        patch("agent_bom.db.schema.db_freshness_days", return_value=1),
        patch("agent_bom.db.schema.DB_PATH", str(tmp_path / "test.db")),
        patch("agent_bom.db.schema.init_db", return_value=MagicMock()),
        patch("agent_bom.db.lookup_package", return_value=[lv]),
    ):
        count, _ = _scan_packages_local_db([pkg])

    assert count == 0  # no new vulns added
    assert len(pkg.vulnerabilities) == 1  # no duplicate


# ---------------------------------------------------------------------------
# scan_packages integration — local DB takes priority over OSV
# ---------------------------------------------------------------------------


def test_scan_packages_skips_osv_for_db_covered_packages():
    """Packages covered by local DB should not be sent to OSV."""
    from agent_bom.scanners import scan_packages

    pkg = _make_pkg("requests", "2.28.0")
    db_key = "pypi:requests@2.28.0"

    with (
        patch("agent_bom.scanners._scan_packages_local_db", return_value=(1, {db_key})),
        patch("agent_bom.scanners.query_osv_batch") as mock_osv,
    ):
        asyncio.run(scan_packages([pkg]))

    # OSV should not have been called for the DB-covered package
    if mock_osv.called:
        # If called, the targets list should be empty
        call_args = mock_osv.call_args[0][0]
        assert pkg not in call_args


def test_scan_packages_calls_osv_for_uncovered_packages():
    """Packages NOT covered by local DB should still be sent to OSV."""
    from agent_bom.scanners import scan_packages

    pkg = _make_pkg("some-obscure-package", "1.0.0")

    with (
        patch("agent_bom.scanners._scan_packages_local_db", return_value=(0, set())),
        patch("agent_bom.scanners.query_osv_batch", return_value={}) as mock_osv,
    ):
        asyncio.run(scan_packages([pkg]))

    assert mock_osv.called


def test_scan_packages_offline_requires_local_db(monkeypatch):
    """Offline mode must fail closed when no local DB coverage exists."""
    from agent_bom.scanners import IncompleteScanError, scan_packages

    pkg = _make_pkg("requests", "2.28.0")
    monkeypatch.setattr("agent_bom.scanners.offline_mode", True)

    with patch("agent_bom.scanners._scan_packages_local_db", return_value=(0, set())):
        with pytest.raises(IncompleteScanError, match="populated local vulnerability DB"):
            asyncio.run(scan_packages([pkg]))


def test_scan_packages_offline_partial_db_raises(monkeypatch):
    """Offline mode must fail when any package is missing from the local DB."""
    from agent_bom.scanners import IncompleteScanError, scan_packages

    pkg = _make_pkg("requests", "2.28.0")
    monkeypatch.setattr("agent_bom.scanners.offline_mode", True)

    with patch("agent_bom.scanners._scan_packages_local_db", return_value=(0, {"pypi:other@1.0.0"})):
        with pytest.raises(IncompleteScanError, match="missing from the local vulnerability DB"):
            asyncio.run(scan_packages([pkg]))
