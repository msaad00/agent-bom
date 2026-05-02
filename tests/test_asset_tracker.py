"""Tests for the persistent asset tracker (first_seen / last_seen / resolved)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from agent_bom.asset_tracker import AssetTracker


@pytest.fixture
def tracker(tmp_path: Path) -> AssetTracker:
    """Create a tracker with a temporary database."""
    return AssetTracker(db_path=tmp_path / "assets.db")


def _report(blast_radius: list[dict]) -> dict:
    """Build a minimal report dict with blast_radius entries."""
    return {"blast_radius": blast_radius}


def _finding(vuln_id: str = "CVE-2024-0001", package: str = "lodash", ecosystem: str = "npm", severity: str = "high") -> dict:
    return {
        "vulnerability_id": vuln_id,
        "package": package,
        "ecosystem": ecosystem,
        "severity": severity,
        "cvss_score": 7.5,
        "epss_score": 0.1,
        "blast_score": 42,
        "affected_agents": ["agent-a"],
    }


# ── Basic recording ─────────────────────────────────────────────────────────


def test_first_scan_records_new_findings(tracker: AssetTracker) -> None:
    report = _report([_finding()])
    diff = tracker.record_scan(report)
    assert diff["summary"]["new_count"] == 1
    assert diff["summary"]["total_open"] == 1
    assert "CVE-2024-0001" in diff["new"]


def test_second_scan_bumps_last_seen(tracker: AssetTracker) -> None:
    report = _report([_finding()])
    tracker.record_scan(report)
    diff2 = tracker.record_scan(report)
    assert diff2["summary"]["unchanged_count"] == 1
    assert diff2["summary"]["new_count"] == 0

    asset = tracker.get_asset("CVE-2024-0001", "lodash", "npm")
    assert asset is not None
    assert asset["scan_count"] == 2


def test_resolved_when_gone(tracker: AssetTracker) -> None:
    tracker.record_scan(_report([_finding()]))
    diff = tracker.record_scan(_report([]))  # finding disappeared
    assert diff["summary"]["resolved_count"] == 1
    assert "CVE-2024-0001" in diff["resolved"]

    asset = tracker.get_asset("CVE-2024-0001", "lodash", "npm")
    assert asset is not None
    assert asset["status"] == "resolved"
    assert asset["resolved_at"] is not None


def test_reopened_when_returns(tracker: AssetTracker) -> None:
    finding = _finding()
    tracker.record_scan(_report([finding]))
    tracker.record_scan(_report([]))  # resolve
    diff = tracker.record_scan(_report([finding]))  # reopen
    assert diff["summary"]["reopened_count"] == 1
    assert "CVE-2024-0001" in diff["reopened"]

    asset = tracker.get_asset("CVE-2024-0001", "lodash", "npm")
    assert asset is not None
    assert asset["status"] == "reopened"
    assert asset["resolved_at"] is None  # cleared on reopen


# ── Multiple findings ───────────────────────────────────────────────────────


def test_multiple_findings(tracker: AssetTracker) -> None:
    findings = [
        _finding("CVE-2024-0001", "lodash", "npm", "critical"),
        _finding("CVE-2024-0002", "express", "npm", "high"),
        _finding("CVE-2024-0003", "django", "pip", "medium"),
    ]
    diff = tracker.record_scan(_report(findings))
    assert diff["summary"]["new_count"] == 3
    assert diff["summary"]["total_open"] == 3


def test_partial_resolution(tracker: AssetTracker) -> None:
    findings = [
        _finding("CVE-2024-0001", "lodash"),
        _finding("CVE-2024-0002", "express"),
    ]
    tracker.record_scan(_report(findings))
    # Resolve only lodash
    diff = tracker.record_scan(_report([_finding("CVE-2024-0002", "express")]))
    assert diff["summary"]["resolved_count"] == 1
    assert diff["summary"]["unchanged_count"] == 1
    assert "CVE-2024-0001" in diff["resolved"]


# ── Query ───────────────────────────────────────────────────────────────────


def test_list_assets_all(tracker: AssetTracker) -> None:
    tracker.record_scan(
        _report(
            [
                _finding("CVE-2024-0001", severity="critical"),
                _finding("CVE-2024-0002", package="express", severity="high"),
            ]
        )
    )
    assets = tracker.list_assets()
    assert len(assets) == 2


def test_list_assets_filter_status(tracker: AssetTracker) -> None:
    tracker.record_scan(_report([_finding()]))
    tracker.record_scan(_report([]))  # resolve

    open_assets = tracker.list_assets(status="open")
    assert len(open_assets) == 0

    resolved = tracker.list_assets(status="resolved")
    assert len(resolved) == 1


def test_list_assets_filter_severity(tracker: AssetTracker) -> None:
    tracker.record_scan(
        _report(
            [
                _finding("CVE-2024-0001", severity="critical"),
                _finding("CVE-2024-0002", package="express", severity="low"),
            ]
        )
    )
    crit = tracker.list_assets(severity="critical")
    assert len(crit) == 1
    assert crit[0]["vuln_id"] == "CVE-2024-0001"


def test_get_asset_not_found(tracker: AssetTracker) -> None:
    assert tracker.get_asset("CVE-9999", "nope") is None


# ── Statistics ──────────────────────────────────────────────────────────────


def test_stats_empty(tracker: AssetTracker) -> None:
    stats = tracker.stats()
    assert stats["total"] == 0


def test_stats_populated(tracker: AssetTracker) -> None:
    tracker.record_scan(
        _report(
            [
                _finding("CVE-2024-0001", severity="critical"),
                _finding("CVE-2024-0002", package="express", severity="high"),
            ]
        )
    )
    stats = tracker.stats()
    assert stats["total"] == 2
    assert stats["open"] == 2
    assert stats["critical_open"] == 1
    assert stats["high_open"] == 1


def test_mttr_none_when_no_resolved(tracker: AssetTracker) -> None:
    tracker.record_scan(_report([_finding()]))
    assert tracker.mttr_days() is None


def test_mttr_calculated(tracker: AssetTracker) -> None:
    tracker.record_scan(_report([_finding()]))
    tracker.record_scan(_report([]))  # resolve immediately
    mttr = tracker.mttr_days()
    # Should be very small (< 1 day) since resolved in same test run
    assert mttr is not None
    assert mttr >= 0


# ── Metadata ────────────────────────────────────────────────────────────────


def test_metadata_stored(tracker: AssetTracker) -> None:
    finding = _finding()
    finding["cvss_score"] = 9.8
    finding["cisa_kev"] = True
    tracker.record_scan(_report([finding]))

    asset = tracker.get_asset("CVE-2024-0001", "lodash", "npm")
    assert asset is not None
    meta = asset["metadata"]
    assert meta["cvss_score"] == 9.8
    assert meta["cisa_kev"] is True


# ── Edge cases ──────────────────────────────────────────────────────────────


def test_empty_report(tracker: AssetTracker) -> None:
    diff = tracker.record_scan(_report([]))
    assert diff["summary"]["new_count"] == 0
    assert diff["summary"]["total_open"] == 0


def test_empty_vuln_id_skipped(tracker: AssetTracker) -> None:
    diff = tracker.record_scan(_report([{"vulnerability_id": "", "package": "x"}]))
    assert diff["summary"]["new_count"] == 0


def test_same_cve_different_packages(tracker: AssetTracker) -> None:
    """Same CVE affecting different packages should be tracked separately."""
    findings = [
        _finding("CVE-2024-0001", "lodash", "npm"),
        _finding("CVE-2024-0001", "underscore", "npm"),
    ]
    diff = tracker.record_scan(_report(findings))
    assert diff["summary"]["new_count"] == 2

    # Resolve one, keep the other
    diff2 = tracker.record_scan(_report([_finding("CVE-2024-0001", "lodash", "npm")]))
    assert diff2["summary"]["resolved_count"] == 1
    assert diff2["summary"]["unchanged_count"] == 1


def test_tenant_scopes_assets_with_shared_database(tmp_path: Path) -> None:
    db_path = tmp_path / "shared-assets.db"
    alpha = AssetTracker(db_path=db_path, tenant_id="tenant-alpha")
    beta = AssetTracker(db_path=db_path, tenant_id="tenant-beta")
    try:
        alpha.record_scan(_report([_finding("CVE-2024-0001", "lodash", "npm")]))
        beta.record_scan(_report([_finding("CVE-2024-0002", "requests", "pip")]))

        assert [asset["vuln_id"] for asset in alpha.list_assets()] == ["CVE-2024-0001"]
        assert [asset["vuln_id"] for asset in beta.list_assets()] == ["CVE-2024-0002"]
        assert alpha.get_asset("CVE-2024-0002", "requests", "pip") is None
    finally:
        alpha.close()
        beta.close()


def test_legacy_asset_database_migrates_to_tenant_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy-assets.db"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE assets (
                vuln_id TEXT NOT NULL,
                package TEXT NOT NULL,
                ecosystem TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                resolved_at TEXT,
                scan_count INTEGER NOT NULL DEFAULT 1,
                metadata TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY (vuln_id, package, ecosystem)
            )
            """
        )
        conn.execute(
            """
            INSERT INTO assets (
                vuln_id, package, ecosystem, severity, status,
                first_seen, last_seen, resolved_at, scan_count, metadata
            )
            VALUES (
                'CVE-2024-0001', 'lodash', 'npm', 'high', 'open',
                '2024-01-01T00:00:00+00:00', '2024-01-01T00:00:00+00:00',
                NULL, 1, '{}'
            )
            """
        )
        conn.commit()
    finally:
        conn.close()

    tracker = AssetTracker(db_path=db_path, tenant_id="default")
    try:
        asset = tracker.get_asset("CVE-2024-0001", "lodash", "npm")
        assert asset is not None
        assert asset["tenant_id"] == "default"
        tracker.record_scan(_report([_finding("CVE-2024-0002", "express", "npm")]))
    finally:
        tracker.close()

    conn = sqlite3.connect(db_path)
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(assets)")}
        indexes = {row[1] for row in conn.execute("PRAGMA index_list(assets)")}
    finally:
        conn.close()

    assert "tenant_id" in columns
    assert "idx_assets_tenant_status" in indexes


def test_asset_tracker_context_manager_closes_connection(tmp_path: Path) -> None:
    db_path = tmp_path / "assets.db"

    with AssetTracker(db_path=db_path) as tracker:
        tracker.record_scan(_report([_finding("CVE-2024-0001", "lodash", "npm")]))

    with pytest.raises(sqlite3.ProgrammingError):
        tracker.stats()


def test_asset_tracker_enables_wal_for_file_database(tmp_path: Path) -> None:
    db_path = tmp_path / "assets.db"

    with AssetTracker(db_path=db_path) as tracker:
        mode = tracker._conn.execute("PRAGMA journal_mode").fetchone()[0]  # noqa: SLF001

    assert mode.lower() == "wal"
