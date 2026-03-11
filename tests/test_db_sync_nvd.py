"""Tests for NVD CVSS enrichment (sync_nvd)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

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


def _nvd_response(cve_id: str, score: float = 8.1, severity: str = "HIGH") -> bytes:
    payload = {
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
    return json.dumps(payload).encode()


def _mock_urlopen_success(score: float = 8.1, severity: str = "HIGH"):
    def side_effect(req, timeout=30):
        # Extract CVE ID from URL to build response
        url = req.full_url if hasattr(req, "full_url") else str(req)
        # Parse cveId from query string
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        cve_id = qs.get("cveId", ["CVE-UNKNOWN"])[0]
        cm = MagicMock()
        cm.__enter__ = MagicMock(return_value=cm)
        cm.__exit__ = MagicMock(return_value=False)
        cm.read = MagicMock(return_value=_nvd_response(cve_id, score, severity))
        return cm

    return side_effect


def _mock_urlopen_error():
    def side_effect(req, timeout=30):
        raise OSError("NVD API unavailable")

    return side_effect


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_sync_nvd_enriches_unknown_severity_cves() -> None:
    """CVE with severity='unknown' should be updated with NVD CVSS data."""
    conn = _make_conn()
    _insert_vuln(conn, "CVE-2024-99001", severity="unknown")

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen_success(score=8.1, severity="HIGH")):
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

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen_success()) as mock_open:
        with patch("time.sleep"):
            count = sync_nvd(conn, url="https://services.nvd.nist.gov/rest/json/cves/2.0", max_entries=10)

    # CVE-2024-99002 already has a score — should not be touched
    assert count == 0
    mock_open.assert_not_called()


def test_sync_nvd_respects_max_entries() -> None:
    """With 10 CVEs in DB but max_entries=3, only 3 should be fetched."""
    conn = _make_conn()
    for i in range(10):
        _insert_vuln(conn, f"CVE-2024-9{i:04d}", severity="unknown")

    call_count = [0]

    def counting_urlopen(req, timeout=30):
        call_count[0] += 1
        cm = MagicMock()
        cm.__enter__ = MagicMock(return_value=cm)
        cm.__exit__ = MagicMock(return_value=False)
        from urllib.parse import parse_qs, urlparse

        url = req.full_url if hasattr(req, "full_url") else str(req)
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        cve_id = qs.get("cveId", ["CVE-UNKNOWN"])[0]
        cm.read = MagicMock(return_value=_nvd_response(cve_id))
        return cm

    with patch("urllib.request.urlopen", side_effect=counting_urlopen):
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

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen_error()):
        with patch("time.sleep"):
            count = sync_nvd(conn, url="https://services.nvd.nist.gov/rest/json/cves/2.0", max_entries=10)

    assert count == 0
    # Severity should remain unknown — we didn't crash
    row = conn.execute("SELECT severity FROM vulns WHERE id = 'CVE-2024-99003'").fetchone()
    assert row["severity"] == "unknown"
