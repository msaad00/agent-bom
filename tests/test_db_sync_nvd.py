"""Tests for NVD CVSS enrichment (sync_nvd)."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from agent_bom.db.schema import init_db
from agent_bom.db.sync import sync_nvd

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_conn() -> sqlite3.Connection:
    return init_db(Path(":memory:"))


def _insert_vuln(
    conn: sqlite3.Connection,
    cve_id: str,
    severity: str = "unknown",
    cvss_score: float | None = None,
) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO vulns
            (id, summary, severity, cvss_score, cvss_vector, fixed_version, published, modified, source)
        VALUES (?, ?, ?, ?, NULL, NULL, '', '', 'osv')
        """,
        (cve_id, f"Test {cve_id}", severity, cvss_score),
    )
    conn.commit()


def _nvd_payload(cve_id: str, score: float = 8.1, severity: str = "HIGH") -> dict:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": score,
                                    "baseSeverity": severity,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                }
                            }
                        ]
                    },
                }
            }
        ]
    }


def _mock_fetch_json_success(score: float = 8.1, severity: str = "HIGH"):
    """Side-effect for fetch_json that returns NVD payloads as parsed dicts."""

    def side_effect(url, *, timeout=30, headers=None):
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        cve_id = qs.get("cveId", ["CVE-UNKNOWN"])[0]
        return _nvd_payload(cve_id, score, severity)

    return side_effect


def _mock_fetch_json_error():
    def side_effect(url, *, timeout=30, headers=None):
        raise ConnectionError("NVD API unavailable")

    return side_effect


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_sync_nvd_enriches_unknown_severity_cves() -> None:
    """CVE with severity='unknown' should be updated with NVD CVSS data."""
    conn = _make_conn()
    _insert_vuln(conn, "CVE-2024-99001", severity="unknown")

    with patch("agent_bom.http_client.fetch_json", side_effect=_mock_fetch_json_success(score=8.1, severity="HIGH")):
        with patch("time.sleep"):  # skip rate-limit sleeps in tests
            count = sync_nvd(conn, url="https://services.nvd.nist.gov/rest/json/cves/2.0", max_entries=10)

    assert count == 1
    row = conn.execute("SELECT * FROM vulns WHERE id = 'CVE-2024-99001'").fetchone()
    assert row["severity"] == "high"
    assert row["cvss_score"] == pytest.approx(8.1)
    assert row["cvss_vector"] is not None


def test_sync_nvd_skips_fresh_cvss_entries() -> None:
    """CVE that already has a CVSS score should not trigger any NVD fetch."""
    conn = _make_conn()
    _insert_vuln(conn, "CVE-2024-99002", severity="medium", cvss_score=6.5)

    with patch("agent_bom.http_client.fetch_json", side_effect=_mock_fetch_json_success()) as mock_fetch:
        with patch("time.sleep"):
            count = sync_nvd(conn, url="https://services.nvd.nist.gov/rest/json/cves/2.0", max_entries=10)

    # CVE-2024-99002 already has a score — should not be touched
    assert count == 0
    mock_fetch.assert_not_called()


def test_sync_nvd_respects_max_entries() -> None:
    """With 10 CVEs in DB but max_entries=3, only 3 should be fetched."""
    conn = _make_conn()
    for i in range(10):
        _insert_vuln(conn, f"CVE-2024-9{i:04d}", severity="unknown")

    call_count = [0]

    def counting_fetch_json(url, *, timeout=30, headers=None):
        call_count[0] += 1
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        cve_id = qs.get("cveId", ["CVE-UNKNOWN"])[0]
        return _nvd_payload(cve_id)

    with patch("agent_bom.http_client.fetch_json", side_effect=counting_fetch_json):
        with patch("time.sleep"):
            count = sync_nvd(
                conn,
                url="https://services.nvd.nist.gov/rest/json/cves/2.0",
                max_entries=3,
            )

    assert count == 3
    assert call_count[0] == 3


def test_sync_nvd_handles_api_error_gracefully() -> None:
    """NVD API returning an error should not crash sync_nvd; it should return 0."""
    conn = _make_conn()
    _insert_vuln(conn, "CVE-2024-99003", severity="unknown")

    with patch("agent_bom.http_client.fetch_json", side_effect=_mock_fetch_json_error()):
        with patch("time.sleep"):
            count = sync_nvd(conn, url="https://services.nvd.nist.gov/rest/json/cves/2.0", max_entries=10)

    assert count == 0
    # Severity should remain unknown — we didn't crash
    row = conn.execute("SELECT severity FROM vulns WHERE id = 'CVE-2024-99003'").fetchone()
    assert row["severity"] == "unknown"
