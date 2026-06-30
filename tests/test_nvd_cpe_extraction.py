"""Tests for NVD CPE applicability extraction + storage (CPE matching foundation)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from agent_bom.db.schema import init_db
from agent_bom.db.sync import _extract_nvd_cpe_matches, sync_nvd_incremental


def _cve_with_cpe() -> dict:
    return {
        "id": "CVE-2026-9999",
        "descriptions": [{"lang": "en", "value": "Example CPE CVE"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "1.0",
                                "versionEndExcluding": "2.0",
                            },
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:acme:gadget:3.1:*:*:*:*:*:*:*",
                            },
                            {
                                # not vulnerable -> must be ignored
                                "vulnerable": False,
                                "criteria": "cpe:2.3:o:acme:os:*:*:*:*:*:*:*:*",
                            },
                        ]
                    }
                ]
            }
        ],
    }


def test_extract_nvd_cpe_matches_filters_and_parses() -> None:
    rows = _extract_nvd_cpe_matches(_cve_with_cpe())
    assert len(rows) == 2  # the non-vulnerable match is dropped
    by_product = {r["product"]: r for r in rows}

    widget = by_product["widget"]
    assert widget["vendor"] == "acme"
    assert widget["version"] is None  # "*" -> range, no exact version
    assert widget["version_start"] == "1.0" and widget["version_start_op"] == "including"
    assert widget["version_end"] == "2.0" and widget["version_end_op"] == "excluding"

    gadget = by_product["gadget"]
    assert gadget["version"] == "3.1"  # exact version pinned in the criteria
    assert gadget["version_start"] is None and gadget["version_end"] is None


def test_sync_persists_cpe_matches() -> None:
    conn = init_db(Path(":memory:"))
    payload = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [{"cve": _cve_with_cpe()}],
    }

    def fake_fetch(url, *, timeout=60, headers=None):
        return payload

    with patch("agent_bom.http_client.fetch_json", side_effect=fake_fetch):
        with patch("time.sleep"):
            sync_nvd_incremental(
                conn,
                nvd_api_key="test-key",
                url="https://services.nvd.nist.gov/rest/json/cves/2.0",
                max_results=10,
            )

    rows = conn.execute(
        "SELECT vendor, product, version, version_start, version_end FROM cpe_matches WHERE cve_id = 'CVE-2026-9999' ORDER BY product"
    ).fetchall()
    assert len(rows) == 2
    assert rows[0]["product"] == "gadget" and rows[0]["version"] == "3.1"
    assert rows[1]["product"] == "widget"
    assert rows[1]["version_start"] == "1.0" and rows[1]["version_end"] == "2.0"
