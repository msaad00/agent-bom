"""Distro advisories (DLA/DSA/USN/ALSA/RHSA...) inherit severity from upstream CVEs.

OSV publishes a distro fix advisory such as ``DLA-4306-1`` with no severity of
its own, only ``upstream`` links to the CVEs it fixes. Left ``unknown`` it
trips the fail-closed CI gate even though every upstream CVE is scored. The
severity is the maximum of the upstream CVEs' scores, taken from data the scan
already holds (other advisories in the scan, then the local DB) — never a new
network request. Unresolvable advisories stay ``unknown`` and keep failing
closed.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from agent_bom.finding import blast_radius_to_finding
from agent_bom.models import BlastRadius, Package, Severity, Vulnerability
from agent_bom.scanners.upstream_severity import resolve_upstream_advisory_severity


def _dla(advisory_id: str = "DLA-4306-1", upstream: list[str] | None = None) -> Vulnerability:
    return Vulnerability(
        id=advisory_id,
        summary="pam security update",
        severity=Severity.UNKNOWN,
        fixed_version="1.4.0-9+deb11u2",
        upstream_ids=upstream
        if upstream is not None
        else ["CVE-2024-22365", "CVE-2025-6020", "DEBIAN-CVE-2024-22365", "DEBIAN-CVE-2025-6020"],
        advisory_sources=["osv"],
    )


def _pkg(name: str, *vulns: Vulnerability) -> Package:
    return Package(name=name, version="1.4.0-9+deb11u1", ecosystem="deb", vulnerabilities=list(vulns))


def _write_db(path: Path, rows: list[tuple[str, str, float | None, str | None]], epss=(), kev=()) -> Path:
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE vulns (id TEXT PRIMARY KEY, summary TEXT, severity TEXT, cvss_score REAL, cvss_vector TEXT, source TEXT);"
        "CREATE TABLE epss_scores (cve_id TEXT PRIMARY KEY, probability REAL, percentile REAL, updated_at TEXT);"
        "CREATE TABLE kev_entries (cve_id TEXT PRIMARY KEY, date_added TEXT, due_date TEXT, product TEXT, vendor_project TEXT);"
    )
    conn.executemany("INSERT INTO vulns VALUES (?, '', ?, ?, ?, 'osv')", rows)
    conn.executemany("INSERT INTO epss_scores VALUES (?, ?, ?, '2026-01-01')", list(epss))
    conn.executemany("INSERT INTO kev_entries VALUES (?, ?, ?, '', '')", list(kev))
    conn.commit()
    conn.close()
    return path


def test_severity_is_max_of_upstream_cves_held_by_the_scan(tmp_path: Path) -> None:
    dla = _dla()
    medium = Vulnerability(id="CVE-2024-22365", summary="", severity=Severity.MEDIUM, cvss_score=5.5)
    high = Vulnerability(
        id="CVE-2025-6020",
        summary="",
        severity=Severity.HIGH,
        cvss_score=7.8,
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    )
    packages = [_pkg("libpam-modules", dla), _pkg("pam-other", medium, high)]

    resolved = resolve_upstream_advisory_severity(packages, db_path=tmp_path / "absent.db")

    assert resolved == 1
    assert dla.severity == Severity.HIGH
    assert dla.cvss_score == 7.8
    assert dla.cvss_vector == "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    assert dla.attack_vector is not None
    assert dla.severity_source == "upstream_cve:CVE-2025-6020"
    assert dla.compliance_tags, "re-tagged with the resolved severity"


def test_severity_falls_back_to_local_db_without_network(tmp_path: Path) -> None:
    db = _write_db(
        tmp_path / "vulns.db",
        [
            ("CVE-2024-22365", "medium", 5.5, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"),
            ("CVE-2025-6020", "high", 7.8, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
        ],
        epss=[("CVE-2024-22365", 0.02, 55.0), ("CVE-2025-6020", 0.01, 40.0)],
        kev=[("CVE-2025-6020", "2026-01-02", "2026-01-23")],
    )
    dla = _dla()

    assert resolve_upstream_advisory_severity([_pkg("libpam-modules", dla)], db_path=db) == 1

    assert dla.severity == Severity.HIGH
    assert dla.cvss_score == 7.8
    # EPSS/KEV attach through the upstream CVEs, with attribution.
    assert dla.epss_score == 0.02 and dla.epss_cve_id == "CVE-2024-22365"
    assert dla.is_kev and dla.kev_cve_id == "CVE-2025-6020" and dla.kev_due_date == "2026-01-23"


def test_label_only_upstream_uses_label_severity(tmp_path: Path) -> None:
    db = _write_db(tmp_path / "vulns.db", [("CVE-2024-1111", "critical", None, None)])
    dla = _dla("DSA-5000-1", ["CVE-2024-1111"])

    resolve_upstream_advisory_severity([_pkg("openssl", dla)], db_path=db)

    assert dla.severity == Severity.CRITICAL
    assert dla.cvss_score is None


@pytest.mark.parametrize("advisory_id", ["USN-7000-1", "ALSA-2025:1234", "RHSA-2025:0001", "DSA-5800-1"])
def test_every_distro_advisory_family_shares_the_path(tmp_path: Path, advisory_id: str) -> None:
    db = _write_db(tmp_path / "vulns.db", [("CVE-2024-2222", "low", 3.1, None)])
    advisory = _dla(advisory_id, ["CVE-2024-2222"])

    resolve_upstream_advisory_severity([_pkg("pkg", advisory)], db_path=db)

    assert advisory.severity == Severity.LOW


def test_unresolvable_advisory_stays_unknown_and_fails_closed(tmp_path: Path) -> None:
    db = _write_db(tmp_path / "vulns.db", [("CVE-2024-22365", "unknown", None, None)])
    dla = _dla(upstream=["CVE-2024-22365", "CVE-2099-0001"])
    no_upstream = _dla("DLA-1-1", [])

    assert resolve_upstream_advisory_severity([_pkg("libpam-modules", dla, no_upstream)], db_path=db) == 0

    assert dla.severity == Severity.UNKNOWN
    assert no_upstream.severity == Severity.UNKNOWN


def test_known_severity_is_never_overridden(tmp_path: Path) -> None:
    db = _write_db(tmp_path / "vulns.db", [("CVE-2025-6020", "critical", 9.8, None)])
    scored = Vulnerability(id="DLA-9-1", summary="", severity=Severity.LOW, cvss_score=3.0, upstream_ids=["CVE-2025-6020"])

    resolve_upstream_advisory_severity([_pkg("x", scored)], db_path=db)

    assert scored.severity == Severity.LOW and scored.cvss_score == 3.0


def test_distro_advisory_id_is_not_projected_as_a_cve_id() -> None:
    dla = _dla()
    dla.severity = Severity.HIGH
    pkg = _pkg("libpam-modules", dla)
    finding = blast_radius_to_finding(
        BlastRadius(vulnerability=dla, package=pkg, affected_servers=[], affected_agents=[], exposed_credentials=[], exposed_tools=[])
    )

    payload = finding.to_dict()

    assert payload["cve_ids"] == []
    assert "DLA-4306-1" in payload["advisory_ids"]
    assert payload["vulnerability_id"] == "DLA-4306-1"


def test_cve_finding_keeps_its_cve_id() -> None:
    cve = Vulnerability(id="CVE-2025-6020", summary="", severity=Severity.HIGH)
    finding = blast_radius_to_finding(
        BlastRadius(
            vulnerability=cve,
            package=_pkg("libpam-modules", cve),
            affected_servers=[],
            affected_agents=[],
            exposed_credentials=[],
            exposed_tools=[],
        )
    )

    assert finding.to_dict()["cve_ids"] == ["CVE-2025-6020"]
