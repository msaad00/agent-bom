"""Tests for NVD incremental sync."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from agent_bom.db.schema import init_db
from agent_bom.db.sync import sync_nvd_incremental


def _incremental_payload(cve_id: str = "CVE-2026-10001", *, total_results: int = 1) -> dict:
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": total_results,
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": "Example NVD CVE"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 7.5,
                                    "baseSeverity": "HIGH",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                }
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "description": [
                                {"lang": "en", "value": "CWE-79"},
                            ]
                        }
                    ],
                }
            }
        ],
    }


def test_sync_nvd_incremental_upserts_modified_cves() -> None:
    conn = init_db(Path(":memory:"))

    captured: dict = {}

    def fake_fetch(url, *, timeout=60, headers=None):
        captured["url"] = url
        captured["headers"] = headers or {}
        return _incremental_payload()

    with patch("agent_bom.http_client.fetch_json", side_effect=fake_fetch):
        with patch("time.sleep"):
            count = sync_nvd_incremental(
                conn,
                nvd_api_key="test-key",
                url="https://services.nvd.nist.gov/rest/json/cves/2.0",
                max_results=10,
            )

    assert count == 1
    # NVD API 2.0 honors the key only in the apiKey header, never the query string.
    assert captured["headers"].get("apiKey") == "test-key"
    assert "apiKey" not in captured["url"]
    row = conn.execute("SELECT * FROM vulns WHERE id = 'CVE-2026-10001'").fetchone()
    assert row is not None
    assert row["severity"] == "high"
    assert row["cvss_score"] == 7.5
    assert "CWE-79" in (row["cwe_ids"] or "")

    meta = conn.execute("SELECT metadata_json FROM sync_meta WHERE source = 'nvd'").fetchone()
    assert meta is not None
    payload = json.loads(meta[0])
    assert payload["mode"] == "incremental"
    assert payload["api_key_used"] is True


def test_sync_nvd_incremental_keeps_checkpoint_on_failure() -> None:
    conn = init_db(Path(":memory:"))

    def boom(url, *, timeout=60, headers=None):
        raise RuntimeError("nvd unavailable")

    with patch("agent_bom.http_client.fetch_json", side_effect=boom):
        with patch("time.sleep"):
            count = sync_nvd_incremental(
                conn,
                nvd_api_key="test-key",
                url="https://services.nvd.nist.gov/rest/json/cves/2.0",
                max_results=10,
            )

    assert count == 0
    meta = conn.execute("SELECT metadata_json FROM sync_meta WHERE source = 'nvd'").fetchone()
    payload = json.loads(meta[0])
    # On failure the synced-through cursor must NOT jump to now — it stays at the
    # window start so the next run retries the unsynced window (no skipped CVEs).
    assert payload["sync_failed"] is True
    assert payload["last_modified_end"] == payload["last_modified_start"]


def test_sync_nvd_incremental_guards_wrong_shape_payload() -> None:
    """A non-dict JSON payload must not raise AttributeError and abort sync_db.

    Regression: ``data.get("vulnerabilities")`` ran on the raw payload with no
    type guard, so an array/string response crashed the whole sequential sync.
    """
    conn = init_db(Path(":memory:"))

    def wrong_shape(url, *, timeout=60, headers=None):
        return ["unexpected", "array", "payload"]

    with patch("agent_bom.http_client.fetch_json", side_effect=wrong_shape):
        with patch("time.sleep"):
            count = sync_nvd_incremental(
                conn,
                nvd_api_key="test-key",
                url="https://services.nvd.nist.gov/rest/json/cves/2.0",
                max_results=10,
            )

    assert count == 0
    meta = conn.execute("SELECT metadata_json FROM sync_meta WHERE source = 'nvd'").fetchone()
    payload = json.loads(meta[0])
    assert payload["sync_failed"] is True
    assert payload["last_modified_end"] == payload["last_modified_start"]


def test_sync_nvd_incremental_keeps_checkpoint_when_capped() -> None:
    conn = init_db(Path(":memory:"))

    def fake_fetch(url, *, timeout=60, headers=None):
        return _incremental_payload(total_results=10)

    with patch("agent_bom.http_client.fetch_json", side_effect=fake_fetch):
        with patch("time.sleep"):
            count = sync_nvd_incremental(
                conn,
                nvd_api_key="test-key",
                url="https://services.nvd.nist.gov/rest/json/cves/2.0",
                max_results=1,
            )

    assert count == 1
    meta = conn.execute("SELECT metadata_json FROM sync_meta WHERE source = 'nvd'").fetchone()
    payload = json.loads(meta[0])
    assert payload["sync_failed"] is False
    assert payload["sync_truncated"] is True
    assert payload["last_modified_end"] == payload["last_modified_start"]


def _cve_object(cve_id: str) -> dict:
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": f"NVD CVE {cve_id}"}],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        }
                    }
                ]
            },
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
        }
    }


def _paginated_pool_fetch(pool: list[str]):
    """Mock NVD that serves a fixed pool of distinct CVEs paginated by the
    request's startIndex/resultsPerPage — so a capped run fetches a contiguous
    prefix and a later run can reach the unsynced tail."""

    def fetch(url, *, timeout=60, headers=None):
        q = parse_qs(urlparse(url).query)
        start = int(q["startIndex"][0])
        per = int(q["resultsPerPage"][0])
        window = pool[start : start + per]
        return {
            "resultsPerPage": per,
            "startIndex": start,
            "totalResults": len(pool),
            "vulnerabilities": [_cve_object(cid) for cid in window],
        }

    return fetch


def test_sync_nvd_incremental_capped_runs_make_forward_progress() -> None:
    """Regression: a capped window must ingest its unsynced tail across runs.

    The prior behaviour re-saturated the cap on the same head every run (cursor
    pinned, start_index reset to 0, every CVE counted toward the cap), so the
    tail was never reached and was eventually skipped by the lookback clamp.
    """
    conn = init_db(Path(":memory:"))
    pool = [f"CVE-2026-2{n:04d}" for n in range(5)]  # 5 distinct CVEs

    def distinct(n: int) -> int:
        return conn.execute("SELECT COUNT(DISTINCT id) FROM vulns WHERE source='nvd'").fetchone()[0]

    with patch("agent_bom.http_client.fetch_json", side_effect=_paginated_pool_fetch(pool)):
        with patch("time.sleep"):
            kwargs = dict(
                nvd_api_key="test-key",
                url="https://services.nvd.nist.gov/rest/json/cves/2.0",
                max_results=2,
            )
            # Run 1: ingest the first 2, truncated.
            assert sync_nvd_incremental(conn, **kwargs) == 2
            assert distinct(0) == 2
            # Run 2: head (0,1) no longer counts toward the cap -> reach 2,3.
            assert sync_nvd_incremental(conn, **kwargs) == 2
            assert distinct(0) == 4  # forward progress; the bug stayed at 2
            # Run 3: only CVE 4 left -> window drains, cursor advances.
            assert sync_nvd_incremental(conn, **kwargs) == 1
            assert distinct(0) == 5

    meta = conn.execute("SELECT metadata_json FROM sync_meta WHERE source = 'nvd'").fetchone()
    payload = json.loads(meta[0])
    assert payload["sync_truncated"] is False
    # Window fully drained: synced-through cursor advances past the window start.
    assert payload["last_modified_end"] != payload["last_modified_start"]
