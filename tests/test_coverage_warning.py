"""Tests for end-of-life / incomplete OS-release vulnerability coverage warnings."""

from __future__ import annotations

import asyncio

import pytest

from agent_bom.coverage import detect_release_coverage_gaps
from agent_bom.db.schema import init_db
from agent_bom.models import Package


def _seed_db(conn, *, family_releases, family_rows_each=20, release_rows=None):
    """Seed the affected table.

    Args:
        conn: open DB connection.
        family_releases: list of release ecosystem keys to populate broadly
            (e.g. ["debian:11", "debian:12", "debian:13"]).
        family_rows_each: advisory rows to insert per family release.
        release_rows: optional dict {release_key: row_count} for sparse releases.
    """
    n = 0
    for release in family_releases:
        for i in range(family_rows_each):
            vid = f"CVE-{release.replace(':', '-')}-{i}"
            conn.execute(
                "INSERT INTO vulns(id, summary, severity, source) VALUES (?, ?, ?, ?)",
                (vid, "seeded", "high", "osv"),
            )
            conn.execute(
                "INSERT INTO affected(vuln_id, ecosystem, package_name, introduced, fixed, last_affected) VALUES (?, ?, ?, ?, ?, ?)",
                (vid, release, f"pkg{i}", "0", "99", None),
            )
            n += 1
    for release, count in (release_rows or {}).items():
        for i in range(count):
            vid = f"CVE-sparse-{release.replace(':', '-')}-{i}"
            conn.execute(
                "INSERT INTO vulns(id, summary, severity, source) VALUES (?, ?, ?, ?)",
                (vid, "seeded", "high", "osv"),
            )
            conn.execute(
                "INSERT INTO affected(vuln_id, ecosystem, package_name, introduced, fixed, last_affected) VALUES (?, ?, ?, ?, ?, ?)",
                (vid, release, f"sparse{i}", "0", "99", None),
            )
    conn.commit()


def _deb_packages(distro_version, count=8):
    return [
        Package(
            name=f"libfoo{i}",
            version="1.0",
            ecosystem="deb",
            distro_name="debian",
            distro_version=distro_version,
        )
        for i in range(count)
    ]


def test_uncovered_release_emits_warning(tmp_path):
    """A release with packages present but zero advisory rows (while the family
    is broadly covered) is flagged as an incomplete-coverage gap."""
    conn = init_db(tmp_path / "vulns.db")
    # Family carried at 11/12/13, but buster (10) dropped — zero rows.
    _seed_db(conn, family_releases=["debian:11", "debian:12", "debian:13"])

    warnings = detect_release_coverage_gaps(_deb_packages("10"), conn=conn)
    conn.close()

    assert len(warnings) == 1
    w = warnings[0]
    assert w["ecosystem"] == "debian"
    assert w["release"] == "debian:10"
    assert w["reason"] == "release_advisories_absent"
    assert w["advisory_rows"] == 0
    assert w["package_count"] == 8
    assert "end-of-life" in w["detail"].lower()
    assert "under-report" in w["detail"].lower()


def test_covered_release_no_warning(tmp_path):
    """A release the data source carries produces no spurious warning."""
    conn = init_db(tmp_path / "vulns.db")
    _seed_db(conn, family_releases=["debian:11", "debian:12", "debian:13"])

    warnings = detect_release_coverage_gaps(_deb_packages("12"), conn=conn)
    conn.close()

    assert warnings == []


def test_empty_db_no_false_positive(tmp_path):
    """When the family is not carried at all (empty/absent DB, e.g. default online
    scans), no per-release gap is reported — the remote source covers it."""
    conn = init_db(tmp_path / "vulns.db")  # no rows

    warnings = detect_release_coverage_gaps(_deb_packages("10"), conn=conn)
    conn.close()

    assert warnings == []


def test_below_package_threshold_no_warning(tmp_path):
    """A stray package of an uncovered release does not trip the gap detector."""
    conn = init_db(tmp_path / "vulns.db")
    _seed_db(conn, family_releases=["debian:11", "debian:12", "debian:13"])

    warnings = detect_release_coverage_gaps(_deb_packages("10", count=2), conn=conn)
    conn.close()

    assert warnings == []


def test_alpine_release_gap(tmp_path):
    """Detection is data-source-agnostic across distro families (Alpine)."""
    conn = init_db(tmp_path / "vulns.db")
    _seed_db(conn, family_releases=["alpine:v3.19", "alpine:v3.20", "alpine:v3.21"])

    pkgs = [Package(name=f"musl{i}", version="1.0", ecosystem="apk", distro_name="alpine", distro_version="3.9") for i in range(8)]
    warnings = detect_release_coverage_gaps(pkgs, conn=conn)
    conn.close()

    assert len(warnings) == 1
    assert warnings[0]["release"] == "alpine:v3.9"


def test_scan_packages_records_coverage_warning(tmp_path, monkeypatch):
    """Integration: an offline scan of an uncovered release populates the
    structured coverage_warnings state and a scan-warning string."""
    from agent_bom.scanners import (
        ScanOptions,
        consume_coverage_warnings,
        consume_scan_warnings,
        scan_packages,
    )

    db_path = tmp_path / "vulns.db"
    conn = init_db(db_path)
    _seed_db(conn, family_releases=["debian:11", "debian:12", "debian:13"])
    conn.close()

    monkeypatch.setattr("agent_bom.db.schema.DB_PATH", db_path)
    monkeypatch.setattr("agent_bom.db.schema.db_freshness_days", lambda path=None: 0)

    pkgs = _deb_packages("10")
    asyncio.run(scan_packages(pkgs, options=ScanOptions(offline=True)))

    coverage = consume_coverage_warnings()
    scan_warnings = consume_scan_warnings()

    assert any(w["release"] == "debian:10" for w in coverage)
    assert any("debian:10" in s for s in scan_warnings)


def test_scan_packages_covered_release_no_warning(tmp_path, monkeypatch):
    """Integration: an offline scan of a covered release yields no coverage warning."""
    from agent_bom.scanners import ScanOptions, consume_coverage_warnings, scan_packages

    db_path = tmp_path / "vulns.db"
    conn = init_db(db_path)
    _seed_db(conn, family_releases=["debian:11", "debian:12", "debian:13"])
    conn.close()

    monkeypatch.setattr("agent_bom.db.schema.DB_PATH", db_path)
    monkeypatch.setattr("agent_bom.db.schema.db_freshness_days", lambda path=None: 0)

    pkgs = _deb_packages("12")
    asyncio.run(scan_packages(pkgs, options=ScanOptions(offline=True)))

    assert consume_coverage_warnings() == []


def test_json_and_console_surface_coverage_warnings():
    """The warning reaches the JSON report summary and the console summary panel."""
    from rich.console import Console

    from agent_bom.models import AIBOMReport
    from agent_bom.output.console_render import print_summary
    from agent_bom.output.json_fmt import to_json

    warning = {
        "ecosystem": "debian",
        "release": "debian:10",
        "reason": "release_advisories_absent",
        "detail": "Vulnerability coverage for debian:10 is incomplete.",
        "package_count": 8,
        "advisory_rows": 0,
    }
    report = AIBOMReport(coverage_warnings=[warning])

    payload = to_json(report)
    assert payload["coverage_warnings"] == [warning]
    assert payload["summary"]["coverage_warnings"] == [warning]

    console = Console(record=True, width=120)
    monkey_console = console
    import agent_bom.output.console_render as cr

    original = cr._console
    cr._console = lambda: monkey_console  # type: ignore[assignment]
    try:
        print_summary(report)
    finally:
        cr._console = original
    text = console.export_text()
    assert "Incomplete vulnerability coverage" in text
    assert "debian:10" in text


def test_osv_fallback_db_keys_for_sparse_release(tmp_path):
    from agent_bom.coverage import osv_fallback_db_keys, package_db_key

    conn = init_db(tmp_path / "vulns.db")
    _seed_db(conn, family_releases=["debian:11", "debian:12", "debian:13"])
    packages = _deb_packages("10")
    gaps = detect_release_coverage_gaps(packages, conn=conn)
    conn.close()

    keys = osv_fallback_db_keys(packages, gaps=gaps)
    assert keys == {package_db_key(pkg) for pkg in packages}


def test_malformed_package_json_records_coverage_warning(tmp_path):
    from agent_bom.parsers.node_parsers import parse_npm_packages
    from agent_bom.scanners.state import consume_coverage_warnings

    consume_coverage_warnings()  # clear any prior state
    (tmp_path / "package.json").write_text('{ "dependencies": { "express": "^4"  BROKEN', encoding="utf-8")

    pkgs = parse_npm_packages(tmp_path)
    warnings = consume_coverage_warnings()

    assert pkgs == []  # nothing parsed — but the gap must be surfaced
    assert any(w.get("reason") == "manifest_parse_error" and w.get("ecosystem") == "npm" for w in warnings)


def test_malformed_pom_xml_records_coverage_warning(tmp_path):
    from agent_bom.parsers.compiled_parsers import parse_maven_packages
    from agent_bom.scanners.state import consume_coverage_warnings

    consume_coverage_warnings()
    (tmp_path / "pom.xml").write_text("<project><dependencies><dependency><groupId>g</groupId><artifactId>a", encoding="utf-8")

    pkgs = parse_maven_packages(tmp_path)
    warnings = consume_coverage_warnings()

    assert pkgs == []
    assert any(w.get("reason") == "manifest_parse_error" and w.get("ecosystem") == "maven" for w in warnings)


def test_valid_package_json_records_no_manifest_warning(tmp_path):
    from agent_bom.parsers.node_parsers import parse_npm_packages
    from agent_bom.scanners.state import consume_coverage_warnings

    consume_coverage_warnings()
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "4.18.2"}}', encoding="utf-8")

    parse_npm_packages(tmp_path)
    warnings = consume_coverage_warnings()

    assert not any(w.get("reason") == "manifest_parse_error" for w in warnings)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
