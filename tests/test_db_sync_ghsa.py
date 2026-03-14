"""Tests for GHSA → local DB ingestion (sync_ghsa)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.db.schema import init_db
from agent_bom.db.sync import GHSA_ECOSYSTEMS, sync_ghsa

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


def _mock_urlopen_by_ecosystem(eco_pages: dict[str, list[list[dict]]]):
    """Return a mock that dispatches pages based on ecosystem= in the URL."""
    eco_counters: dict[str, int] = {}

    def side_effect(req, timeout=30):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        # Extract ecosystem from URL query string
        eco = None
        for param in url.split("?", 1)[-1].split("&"):
            if param.startswith("ecosystem="):
                eco = param.split("=", 1)[1]
                break

        if eco not in eco_counters:
            eco_counters[eco] = 0
        idx = eco_counters[eco]
        eco_counters[eco] += 1

        pages = eco_pages.get(eco, [])
        payload = pages[idx] if idx < len(pages) else []

        cm = MagicMock()
        cm.__enter__ = MagicMock(return_value=cm)
        cm.__exit__ = MagicMock(return_value=False)
        cm.read = MagicMock(return_value=json.dumps(payload).encode())
        return cm

    return side_effect


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_sync_ghsa_ingests_advisory() -> None:
    """A torch advisory should land in both vulns and affected tables."""
    conn = _make_conn()
    advisory = _make_advisory(pkg_name="torch")

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen([[advisory], []])):
        count = sync_ghsa(conn, url="https://api.github.com/advisories", max_entries=10, ecosystems=["pip"])

    assert count == 1

    row = conn.execute("SELECT * FROM vulns WHERE id = 'CVE-2024-12345'").fetchone()
    assert row is not None
    assert row["severity"] == "high"
    assert row["source"] == "ghsa"

    aff = conn.execute("SELECT * FROM affected WHERE vuln_id = 'CVE-2024-12345' AND package_name = 'torch'").fetchone()
    assert aff is not None
    assert aff["introduced"] == "1.0"
    assert aff["fixed"] == "2.0"


def test_sync_ghsa_ingests_non_ai_packages() -> None:
    """Non-AI packages (e.g., 'express', 'django') are now ingested — no package name filter."""
    conn = _make_conn()
    advisory = _make_advisory(
        ghsa_id="GHSA-xxxx-yyyy-zzzz",
        cve_id="CVE-2024-99999",
        pkg_name="django",
        ecosystem="pip",
    )

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen([[advisory], []])):
        count = sync_ghsa(conn, url="https://api.github.com/advisories", max_entries=10, ecosystems=["pip"])

    assert count == 1
    row = conn.execute("SELECT * FROM vulns WHERE id = 'CVE-2024-99999'").fetchone()
    assert row is not None
    assert row["source"] == "ghsa"


def test_sync_ghsa_ingests_npm_advisory() -> None:
    """Advisories from non-pip ecosystems (npm) are ingested."""
    conn = _make_conn()
    advisory = _make_advisory(
        ghsa_id="GHSA-npm1-aaaa-bbbb",
        cve_id="CVE-2024-88888",
        pkg_name="express",
        ecosystem="npm",
    )

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen([[advisory], []])):
        count = sync_ghsa(conn, url="https://api.github.com/advisories", max_entries=10, ecosystems=["npm"])

    assert count == 1
    row = conn.execute("SELECT * FROM vulns WHERE id = 'CVE-2024-88888'").fetchone()
    assert row is not None

    aff = conn.execute("SELECT * FROM affected WHERE vuln_id = 'CVE-2024-88888'").fetchone()
    assert aff is not None
    assert aff["ecosystem"] == "npm"
    assert aff["package_name"] == "express"


def test_sync_ghsa_deduplicates_by_id() -> None:
    """Calling sync_ghsa twice with identical data should leave exactly one row."""
    conn = _make_conn()
    advisory = _make_advisory(pkg_name="transformers")

    pages = [[advisory], []]

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen(pages)):
        count1 = sync_ghsa(conn, url="https://api.github.com/advisories", max_entries=10, ecosystems=["pip"])

    # Second sync — reset the side_effect mock
    pages2 = [[advisory], []]
    with patch("urllib.request.urlopen", side_effect=_mock_urlopen(pages2)):
        count2 = sync_ghsa(conn, url="https://api.github.com/advisories", max_entries=10, ecosystems=["pip"])

    assert count1 == 1
    assert count2 == 1

    total = conn.execute("SELECT COUNT(*) FROM vulns WHERE id = 'CVE-2024-12345'").fetchone()[0]
    assert total == 1


def test_sync_ghsa_url_must_be_https() -> None:
    """Passing an http:// URL should raise ValueError before any network call."""
    conn = _make_conn()
    with pytest.raises(ValueError, match="https://"):
        sync_ghsa(conn, url="http://evil.example.com/advisories")


def test_sync_ghsa_handles_missing_cve_id() -> None:
    """An advisory without a CVE ID should be ingested under its GHSA ID."""
    conn = _make_conn()
    advisory = _make_advisory(
        ghsa_id="GHSA-1111-2222-3333",
        cve_id=None,  # No CVE
        pkg_name="langchain",
    )

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen([[advisory], []])):
        count = sync_ghsa(conn, url="https://api.github.com/advisories", max_entries=10, ecosystems=["pip"])

    assert count == 1
    row = conn.execute("SELECT * FROM vulns WHERE id = 'GHSA-1111-2222-3333'").fetchone()
    assert row is not None
    assert row["source"] == "ghsa"

    aff = conn.execute("SELECT * FROM affected WHERE vuln_id = 'GHSA-1111-2222-3333'").fetchone()
    assert aff is not None
    assert aff["package_name"] == "langchain"


def test_sync_ghsa_multiple_ecosystems() -> None:
    """sync_ghsa iterates over multiple ecosystems and ingests from each."""
    conn = _make_conn()
    pip_advisory = _make_advisory(
        ghsa_id="GHSA-pip1-aaaa-bbbb",
        cve_id="CVE-2024-11111",
        pkg_name="requests",
        ecosystem="pip",
    )
    npm_advisory = _make_advisory(
        ghsa_id="GHSA-npm1-cccc-dddd",
        cve_id="CVE-2024-22222",
        pkg_name="lodash",
        ecosystem="npm",
    )

    eco_pages = {
        "pip": [[pip_advisory], []],
        "npm": [[npm_advisory], []],
    }

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen_by_ecosystem(eco_pages)):
        count = sync_ghsa(
            conn,
            url="https://api.github.com/advisories",
            max_entries=100,
            ecosystems=["pip", "npm"],
        )

    assert count == 2
    assert conn.execute("SELECT COUNT(*) FROM vulns WHERE source = 'ghsa'").fetchone()[0] == 2


def test_sync_ghsa_ecosystem_filtering() -> None:
    """When ecosystems param is set, only those ecosystems are queried."""
    conn = _make_conn()
    advisory = _make_advisory(pkg_name="torch")

    # Only pass pip ecosystem — should only make requests for pip
    with patch("urllib.request.urlopen", side_effect=_mock_urlopen([[advisory], []])) as mock_open:
        sync_ghsa(conn, url="https://api.github.com/advisories", max_entries=10, ecosystems=["pip"])

    # All requests should contain ecosystem=pip
    for call_args in mock_open.call_args_list:
        req = call_args[0][0]
        url = req.full_url if hasattr(req, "full_url") else str(req)
        assert "ecosystem=pip" in url


def test_sync_ghsa_default_ecosystems() -> None:
    """When no ecosystems are specified, all GHSA_ECOSYSTEMS are used."""
    assert len(GHSA_ECOSYSTEMS) == 12
    assert "pip" in GHSA_ECOSYSTEMS
    assert "npm" in GHSA_ECOSYSTEMS
    assert "go" in GHSA_ECOSYSTEMS
    assert "maven" in GHSA_ECOSYSTEMS
    assert "nuget" in GHSA_ECOSYSTEMS
    assert "rubygems" in GHSA_ECOSYSTEMS
    assert "cargo" in GHSA_ECOSYSTEMS
    assert "composer" in GHSA_ECOSYSTEMS
    assert "swift" in GHSA_ECOSYSTEMS
    assert "pub" in GHSA_ECOSYSTEMS
    assert "erlang" in GHSA_ECOSYSTEMS
    assert "actions" in GHSA_ECOSYSTEMS


def test_sync_ghsa_pagination() -> None:
    """sync_ghsa paginates through multiple pages per ecosystem."""
    conn = _make_conn()
    page1 = [_make_advisory(ghsa_id=f"GHSA-p1-{i:04d}-aaaa", cve_id=f"CVE-2024-{1000 + i}", pkg_name="torch") for i in range(3)]
    page2 = [_make_advisory(ghsa_id=f"GHSA-p2-{i:04d}-bbbb", cve_id=f"CVE-2024-{2000 + i}", pkg_name="numpy") for i in range(2)]

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen([page1, page2, []])):
        count = sync_ghsa(conn, url="https://api.github.com/advisories", max_entries=100, ecosystems=["pip"])

    assert count == 5


def test_sync_ghsa_respects_max_entries() -> None:
    """sync_ghsa stops when max_entries is reached."""
    conn = _make_conn()
    advisories = [_make_advisory(ghsa_id=f"GHSA-max-{i:04d}-aaaa", cve_id=f"CVE-2024-{3000 + i}", pkg_name="torch") for i in range(10)]

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen([advisories])):
        count = sync_ghsa(conn, url="https://api.github.com/advisories", max_entries=3, ecosystems=["pip"])

    assert count == 3
