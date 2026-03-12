"""Tests for GHSA → local DB ingestion (sync_ghsa)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.db.schema import init_db
from agent_bom.db.sync import sync_ghsa

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_conn() -> sqlite3.Connection:
    """Open an in-memory DB with the full schema applied."""
    return init_db(Path(":memory:"))


def _make_advisory(
    ghsa_id: str = "GHSA-aaaa-bbbb-cccc",
    cve_id: str | None = "CVE-2024-12345",
    pkg_name: str = "torch",
    ecosystem: str = "pip",
    severity: str = "high",
    cvss_score: float | None = 7.5,
    version_range: str = ">= 1.0, < 2.0",
    first_patched: str = "2.0.0",
) -> dict[str, Any]:
    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "summary": f"Test advisory for {pkg_name}",
        "severity": severity,
        "cvss": {"score": cvss_score, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"} if cvss_score else None,
        "published_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-02T00:00:00Z",
        "vulnerabilities": [
            {
                "package": {"ecosystem": ecosystem, "name": pkg_name},
                "vulnerable_version_range": version_range,
                "first_patched_version": first_patched,
            }
        ],
    }


def _mock_urlopen(pages: list[list[dict]]):
    """Return a context-manager mock that yields pages in sequence."""
    call_count = [0]

    def side_effect(req, timeout=30):
        idx = call_count[0]
        call_count[0] += 1
        if idx >= len(pages):
            payload = []
        else:
            payload = pages[idx]
        cm = MagicMock()
        cm.__enter__ = MagicMock(return_value=cm)
        cm.__exit__ = MagicMock(return_value=False)
        cm.read = MagicMock(return_value=json.dumps(payload).encode())
        return cm

    return side_effect


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_sync_ghsa_ingests_ai_package_advisory() -> None:
    """A torch advisory should land in both vulns and affected tables."""
    conn = _make_conn()
    advisory = _make_advisory(pkg_name="torch")

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen([[advisory], []])):
        count = sync_ghsa(conn, url="https://api.github.com/advisories", max_entries=10)

    assert count == 1

    row = conn.execute("SELECT * FROM vulns WHERE id = 'CVE-2024-12345'").fetchone()
    assert row is not None
    assert row["severity"] == "high"
    assert row["source"] == "ghsa"

    aff = conn.execute("SELECT * FROM affected WHERE vuln_id = 'CVE-2024-12345' AND package_name = 'torch'").fetchone()
    assert aff is not None
    assert aff["introduced"] == "1.0"
    # fixed comes from version_range parse ("< 2.0" → "2.0"); first_patched_version only
    # used as fallback when the range string has no upper bound.
    assert aff["fixed"] == "2.0"


def test_sync_ghsa_skips_non_ai_packages() -> None:
    """An advisory for a non-AI package (e.g. ruby gem served via pip name) should be skipped."""
    conn = _make_conn()
    advisory = _make_advisory(ghsa_id="GHSA-xxxx-yyyy-zzzz", cve_id=None, pkg_name="some-random-ruby-library")

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen([[advisory], []])):
        count = sync_ghsa(conn, url="https://api.github.com/advisories", max_entries=10)

    assert count == 0
    row = conn.execute("SELECT * FROM vulns WHERE id = 'GHSA-xxxx-yyyy-zzzz'").fetchone()
    assert row is None


def test_sync_ghsa_deduplicates_by_id() -> None:
    """Calling sync_ghsa twice with identical data should leave exactly one row."""
    conn = _make_conn()
    advisory = _make_advisory(pkg_name="transformers")

    pages = [[advisory], []]

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen(pages)):
        count1 = sync_ghsa(conn, url="https://api.github.com/advisories", max_entries=10)

    # Second sync — reset the side_effect mock
    pages2 = [[advisory], []]
    with patch("urllib.request.urlopen", side_effect=_mock_urlopen(pages2)):
        count2 = sync_ghsa(conn, url="https://api.github.com/advisories", max_entries=10)

    assert count1 == 1
    assert count2 == 1

    total = conn.execute("SELECT COUNT(*) FROM vulns WHERE id = 'CVE-2024-12345'").fetchone()[0]
    assert total == 1


def test_sync_ghsa_url_must_be_https() -> None:
    """Passing an http:// URL should raise ValueError before any network call."""
    conn = _make_conn()
    with pytest.raises(ValueError, match="https://"):
        sync_ghsa(conn, url="http://evil.example.com/advisories")


def test_sync_ghsa_ingests_langflow_advisory() -> None:
    """langflow (active CISA KEV) must be accepted by the AI package filter."""
    conn = _make_conn()
    advisory = _make_advisory(
        ghsa_id="GHSA-lang-flow-0001",
        cve_id="CVE-2025-3248",
        pkg_name="langflow",
    )

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen([[advisory], []])):
        count = sync_ghsa(conn, url="https://api.github.com/advisories", max_entries=10)

    assert count == 1
    row = conn.execute("SELECT * FROM vulns WHERE id = 'CVE-2025-3248'").fetchone()
    assert row is not None
    assert row["source"] == "ghsa"


@pytest.mark.parametrize("pkg_name", ["flowise", "instructor", "dspy", "pydantic-ai", "litellm"])
def test_sync_ghsa_ingests_new_ai_packages(pkg_name: str) -> None:
    """Newly added AI/orchestration packages must pass the filter."""
    conn = _make_conn()
    advisory = _make_advisory(
        ghsa_id=f"GHSA-test-{pkg_name[:4]}-0001",
        cve_id=None,
        pkg_name=pkg_name,
    )

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen([[advisory], []])):
        count = sync_ghsa(conn, url="https://api.github.com/advisories", max_entries=10)

    assert count == 1, f"{pkg_name} was not accepted by AI package filter"


def test_sync_ghsa_handles_missing_cve_id() -> None:
    """An advisory without a CVE ID should be ingested under its GHSA ID."""
    conn = _make_conn()
    advisory = _make_advisory(
        ghsa_id="GHSA-1111-2222-3333",
        cve_id=None,  # No CVE
        pkg_name="langchain",
    )

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen([[advisory], []])):
        count = sync_ghsa(conn, url="https://api.github.com/advisories", max_entries=10)

    assert count == 1
    row = conn.execute("SELECT * FROM vulns WHERE id = 'GHSA-1111-2222-3333'").fetchone()
    assert row is not None
    assert row["source"] == "ghsa"

    aff = conn.execute("SELECT * FROM affected WHERE vuln_id = 'GHSA-1111-2222-3333'").fetchone()
    assert aff is not None
    assert aff["package_name"] == "langchain"
