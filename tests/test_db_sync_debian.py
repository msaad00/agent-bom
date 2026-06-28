"""Tests for Debian Security Tracker → local DB ingestion (sync_debian_tracker).

Covers per-release status parsing (resolved / open / undetermined), end-of-life
release coverage via the Extended LTS feed, the no-fix suppression contract, and
the binary→source matcher integration that lets image scans match the
source-package-keyed tracker rows.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from agent_bom.db.lookup import lookup_package
from agent_bom.db.schema import init_db
from agent_bom.db.sync import (
    _DEBIAN_CODENAME_TO_RELEASE,
    _ingest_debian_tracker_payload,
    _parse_debian_tracker_release_entry,
    sync_debian_tracker,
)


def _make_conn() -> sqlite3.Connection:
    return init_db(Path(":memory:"))


# A tiny payload shaped exactly like the tracker JSON: source package -> CVE ->
# {description, releases: {codename: {status, fixed_version, ...}}}.
def _sample_payload() -> dict[str, Any]:
    return {
        "glibc": {
            "CVE-2024-2961": {
                "description": "iconv buffer overflow in the GNU C Library.",
                "releases": {
                    # EOL release with a backported fix (only the ELTS feed has it).
                    "buster": {"status": "resolved", "fixed_version": "2.28-10+deb10u3"},
                    "bookworm": {"status": "resolved", "fixed_version": "2.36-9+deb12u7"},
                },
            },
            "CVE-2010-4756": {
                "description": "glob() resource exhaustion.",
                "releases": {
                    # Open / unimportant => no fix for the release.
                    "buster": {"status": "open", "urgency": "unimportant"},
                },
            },
        },
        "ncurses": {
            "CVE-2023-29491": {
                "description": "ncurses local privilege escalation.",
                "releases": {
                    "buster": {"status": "resolved", "fixed_version": "6.1+20181013-2+deb10u5"},
                    "bullseye": {"status": "undetermined"},
                },
            },
        },
        "neveraffected": {
            "CVE-2020-0001": {
                "description": "not affected here",
                # fixed_version "0" => release was never affected; must be skipped.
                "releases": {"buster": {"status": "resolved", "fixed_version": "0"}},
            },
        },
    }


# ---------------------------------------------------------------------------
# Unit: release-entry parsing
# ---------------------------------------------------------------------------


def test_parse_resolved_returns_backported_fix() -> None:
    assert _parse_debian_tracker_release_entry({"status": "resolved", "fixed_version": "1.2-3+deb10u1"}) == (
        "resolved",
        "1.2-3+deb10u1",
    )


def test_parse_open_is_unfixed() -> None:
    assert _parse_debian_tracker_release_entry({"status": "open", "urgency": "unimportant"}) == ("open", "")


def test_parse_resolved_zero_is_not_affected() -> None:
    assert _parse_debian_tracker_release_entry({"status": "resolved", "fixed_version": "0"}) is None


def test_parse_undetermined_is_skipped() -> None:
    assert _parse_debian_tracker_release_entry({"status": "undetermined"}) is None
    assert _parse_debian_tracker_release_entry({"status": "not-affected"}) is None
    assert _parse_debian_tracker_release_entry("garbage") is None


def test_codename_release_map_covers_10_to_14() -> None:
    assert set(_DEBIAN_CODENAME_TO_RELEASE.values()) == {"10", "11", "12", "13", "14"}
    assert _DEBIAN_CODENAME_TO_RELEASE["buster"] == "10"


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------


def test_ingest_writes_per_release_rows() -> None:
    conn = _make_conn()
    written = _ingest_debian_tracker_payload(conn, _sample_payload(), source="debian-elts-tracker")
    # resolved: glibc/buster, glibc/bookworm, ncurses/buster ; open: glibc(CVE-2010-4756)/buster
    # skipped: undetermined ncurses/bullseye, fixed_version=0 neveraffected/buster
    assert written == 4

    # EOL buster fix is present and carries the backported version.
    row = conn.execute(
        "SELECT fixed FROM affected WHERE ecosystem='debian:10' AND package_name='glibc' AND vuln_id='DEBIAN-CVE-2024-2961'"
    ).fetchone()
    assert row["fixed"] == "2.28-10+deb10u3"

    # Open entry stored with an empty fix (suppressed by default downstream).
    open_row = conn.execute("SELECT fixed FROM affected WHERE ecosystem='debian:10' AND vuln_id='DEBIAN-CVE-2010-4756'").fetchone()
    assert open_row["fixed"] == ""

    # undetermined and fixed_version=0 produce no rows.
    assert conn.execute("SELECT COUNT(*) FROM affected WHERE ecosystem='debian:11'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM affected WHERE package_name='neveraffected'").fetchone()[0] == 0

    # Vuln stub carries the canonical CVE alias for EPSS/KEV/NVD enrichment.
    alias = conn.execute("SELECT aliases FROM vulns WHERE id='DEBIAN-CVE-2024-2961'").fetchone()["aliases"]
    assert alias == "CVE-2024-2961"


def test_ingest_preserves_existing_osv_severity() -> None:
    conn = _make_conn()
    # Simulate OSV having already ingested the advisory with rich severity.
    conn.execute(
        "INSERT INTO vulns (id, summary, severity, cvss_score, source, aliases) VALUES (?,?,?,?,?,?)",
        ("DEBIAN-CVE-2024-2961", "osv summary", "high", 8.1, "osv", "CVE-2024-2961"),
    )
    _ingest_debian_tracker_payload(conn, _sample_payload(), source="debian-tracker")
    row = conn.execute("SELECT severity, cvss_score FROM vulns WHERE id='DEBIAN-CVE-2024-2961'").fetchone()
    assert row["severity"] == "high"
    assert row["cvss_score"] == 8.1


def test_resolved_overrides_sparse_osv_fix() -> None:
    conn = _make_conn()
    # OSV has a wrong/placeholder fix for the same release+source.
    conn.execute("INSERT INTO vulns (id, summary, severity, source) VALUES ('DEBIAN-CVE-2024-2961','s','unknown','osv')")
    conn.execute(
        "INSERT INTO affected (vuln_id, ecosystem, package_name, introduced, fixed, last_affected) "
        "VALUES ('DEBIAN-CVE-2024-2961','debian:10','glibc','0','9.9-wrong','')"
    )
    _ingest_debian_tracker_payload(conn, _sample_payload(), source="debian-elts-tracker")
    row = conn.execute(
        "SELECT fixed FROM affected WHERE ecosystem='debian:10' AND package_name='glibc' AND vuln_id='DEBIAN-CVE-2024-2961'"
    ).fetchone()
    assert row["fixed"] == "2.28-10+deb10u3"


# ---------------------------------------------------------------------------
# sync_debian_tracker wiring (feeds, best-effort ELTS)
# ---------------------------------------------------------------------------


def test_sync_uses_both_feeds(monkeypatch) -> None:
    seen_urls: list[str] = []

    def fake_fetch_bytes(url: str, *, timeout: float = 30, headers: dict | None = None) -> bytes:
        seen_urls.append(url)
        return json.dumps(_sample_payload()).encode("utf-8")

    monkeypatch.setattr("agent_bom.http_client.fetch_bytes", fake_fetch_bytes)
    conn = _make_conn()
    total = sync_debian_tracker(conn)
    assert len(seen_urls) == 2  # supported tracker + ELTS
    assert total == 8  # 4 mappings per feed
    meta = conn.execute("SELECT record_count FROM sync_meta WHERE source='debian'").fetchone()
    assert meta["record_count"] == 8


def test_sync_elts_failure_is_best_effort(monkeypatch) -> None:
    def fake_fetch_bytes(url: str, *, timeout: float = 30, headers: dict | None = None) -> bytes:
        if "freexian" in url:
            raise ConnectionError("ELTS down")
        return json.dumps(_sample_payload()).encode("utf-8")

    monkeypatch.setattr("agent_bom.http_client.fetch_bytes", fake_fetch_bytes)
    conn = _make_conn()
    total = sync_debian_tracker(conn)  # must not raise
    assert total == 4  # only the supported feed ingested


# ---------------------------------------------------------------------------
# Matcher integration: source-keyed rows match a binary package via source_package
# ---------------------------------------------------------------------------


def test_lookup_matches_eol_buster_fix() -> None:
    conn = _make_conn()
    _ingest_debian_tracker_payload(conn, _sample_payload(), source="debian-elts-tracker")
    # Installed buster glibc below the backported fix => vulnerable.
    vulns = lookup_package(conn, "debian:10", "glibc", "2.28-10")
    ids = {v.id for v in vulns}
    assert "DEBIAN-CVE-2024-2961" in ids
    # At/above the fix => not reported.
    fixed = lookup_package(conn, "debian:10", "glibc", "2.28-10+deb10u3")
    assert "DEBIAN-CVE-2024-2961" not in {v.id for v in fixed}
