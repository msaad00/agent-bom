"""OS/distro vulnerability coverage breadth.

Verifies that installed OS packages from the mainstream RPM/apk distros resolve
to the correct OSV advisory ecosystem key, match a known-vulnerable version with
the right per-distro version semantics (rpm EVR / apk), do NOT match a patched
version, and that the coverage surface honestly reports the active distros.

All ecosystem keys and version formats below were checked against the real OSV
bulk-export data (per-ecosystem ``all.zip``) on 2026-07-16.
"""

from __future__ import annotations

import sqlite3

import pytest

from agent_bom.db.lookup import _comparator_ecosystem, lookup_package
from agent_bom.db.schema import init_db
from agent_bom.models import Package
from agent_bom.os_advisory import (
    apk_advisory_ecosystems,
    covered_distro_labels,
    normalize_redhat_ecosystem,
    rpm_advisory_ecosystems,
)

# ── pure resolver: rpm distros ───────────────────────────────────────────────


@pytest.mark.parametrize(
    "name,version,expected_db",
    [
        ("rocky", "8.9", ["Rocky Linux:8"]),
        ("rocky", "9.3", ["Rocky Linux:9"]),
        ("almalinux", "8.9", ["AlmaLinux:8"]),
        ("alma", "9", ["AlmaLinux:9"]),
        ("rhel", "8.9", ["Red Hat:enterprise_linux:8"]),
        ("centos", "9", ["Red Hat:enterprise_linux:9"]),
        ("redhat", "10.0", ["Red Hat:enterprise_linux:10"]),
    ],
)
def test_rpm_resolver_local_db_keys(name, version, expected_db):
    assert rpm_advisory_ecosystems(name, version, for_local_db=True) == expected_db


def test_rpm_resolver_online_rhel_uses_base_ecosystem():
    # The live OSV API rejects the module-qualified RHEL key; it accepts bare
    # "Red Hat" and version-filters via the .elN release tag.
    assert rpm_advisory_ecosystems("rhel", "8.9", for_local_db=False) == ["Red Hat"]
    # Rocky/Alma keys are identical online and offline (API accepts them as-is).
    assert rpm_advisory_ecosystems("rocky", "8.9", for_local_db=False) == ["Rocky Linux:8"]


def test_rpm_resolver_opensuse_leap_includes_nonfree():
    assert rpm_advisory_ecosystems("opensuse-leap", "15.5", for_local_db=True) == [
        "openSUSE:Leap 15.5",
        "openSUSE:Leap 15.5 NonFree",
    ]


def test_rpm_resolver_unknown_distro_returns_empty():
    # Amazon Linux / Oracle Linux are NOT in the OSV export — do not guess a key.
    assert rpm_advisory_ecosystems("amzn", "2023", for_local_db=True) == []
    assert rpm_advisory_ecosystems("ol", "8.9", for_local_db=True) == []
    assert rpm_advisory_ecosystems("rocky", "", for_local_db=True) == []


# ── pure resolver: apk distros ───────────────────────────────────────────────


def test_apk_resolver_wolfi_and_chainguard():
    assert apk_advisory_ecosystems("wolfi") == ["Wolfi"]
    assert apk_advisory_ecosystems("chainguard") == ["Chainguard"]
    assert apk_advisory_ecosystems("alpine") == []  # handled by existing branch


# ── Red Hat ingest normalisation ─────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Red Hat:enterprise_linux:8::baseos", "Red Hat:enterprise_linux:8"),
        ("Red Hat:enterprise_linux:9::appstream", "Red Hat:enterprise_linux:9"),
        ("Red Hat:enterprise_linux:10.0", "Red Hat:enterprise_linux:10"),
        ("Red Hat:enterprise_linux:7::server", "Red Hat:enterprise_linux:7"),
        # Non enterprise_linux products are left untouched.
        ("Red Hat:openshift:4.14::el8", "Red Hat:openshift:4.14::el8"),
        ("Red Hat:enterprise_linux_ai:1.5::el9", "Red Hat:enterprise_linux_ai:1.5::el9"),
        ("Rocky Linux:8", "Rocky Linux:8"),
    ],
)
def test_normalize_redhat_ecosystem(raw, expected):
    assert normalize_redhat_ecosystem(raw) == expected


# ── comparator family wiring ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "stored,expected",
    [
        ("red hat:enterprise_linux:8", "rpm"),
        ("rocky linux:8", "rpm"),
        ("almalinux:9", "rpm"),
        ("opensuse:leap 15.5", "rpm"),
        ("wolfi", "apk"),
        ("chainguard", "apk"),
    ],
)
def test_new_distros_map_to_correct_comparator(stored, expected):
    assert _comparator_ecosystem(stored) == expected


# ── coverage surface ─────────────────────────────────────────────────────────


def test_covered_distro_labels_reports_active_distros():
    present = {
        "alpine:v3.18",
        "debian:12",
        "ubuntu:22.04",
        "red hat:enterprise_linux:9",
        "rocky linux:8",
        "almalinux:9",
        "wolfi",
        "chainguard",
        "openSUSE:Leap 15.5",
        "pypi",  # non-OS ecosystem must not appear as a distro label
    }
    labels = covered_distro_labels(present)
    assert labels == [
        "Alpine",
        "Debian",
        "Ubuntu",
        "RHEL",
        "Rocky Linux",
        "AlmaLinux",
        "openSUSE",
        "Wolfi",
        "Chainguard",
    ]


def test_covered_distro_labels_empty_when_no_os_data():
    assert covered_distro_labels({"pypi", "npm", "maven"}) == []


# ── end-to-end DB matching with real ecosystem keys + version formats ─────────


@pytest.fixture
def tmp_db(tmp_path) -> sqlite3.Connection:
    conn = init_db(tmp_path / "os_distro.db")
    yield conn
    conn.close()


def _insert(conn, vuln_id, ecosystem, pkg, fixed):
    conn.execute(
        "INSERT OR REPLACE INTO vulns(id,summary,severity,cvss_score,source) VALUES (?,?,?,?,'osv')",
        (vuln_id, f"Test {vuln_id}", "high", 7.5),
    )
    conn.execute(
        "INSERT OR REPLACE INTO affected(vuln_id,ecosystem,package_name,introduced,fixed,last_affected) VALUES (?,?,?,'0',?,'')",
        (vuln_id, ecosystem, pkg, fixed),
    )
    conn.commit()


@pytest.mark.parametrize(
    "os_id,os_ver,ecosystem,pkg,fixed,vuln_ver,patched_ver",
    [
        # RHEL: rpm EVR, installed version carries no epoch, OSV fix carries 0:.
        (
            "rhel",
            "8.9",
            "red hat:enterprise_linux:8",
            "python-markupsafe",
            "0:0.23-19.el8",
            "0.23-18.el8",
            "0.23-19.el8",
        ),
        # Rocky: major-only ecosystem, epoch-1 fix.
        (
            "rocky",
            "8.9",
            "rocky linux:8",
            "oci-systemd-hook",
            "1:0.1.15-2.git2d0b8a3.module+el8.4.0",
            "0:0.1.15-1.el8",
            "1:0.1.15-2.git2d0b8a3.module+el8.4.0",
        ),
        # AlmaLinux.
        (
            "almalinux",
            "9.3",
            "almalinux:9",
            "expat",
            "0:2.5.0-2.el9_3",
            "0:2.5.0-1.el9",
            "0:2.5.0-2.el9_3",
        ),
        # Wolfi: apk version semantics (-rN revision).
        ("wolfi", "", "wolfi", "glibc", "2.38-r5", "2.38-r3", "2.38-r5"),
    ],
)
def test_distro_package_matches_vulnerable_not_patched(tmp_db, os_id, os_ver, ecosystem, pkg, fixed, vuln_ver, patched_ver):
    _insert(tmp_db, "TEST-2024-0001", ecosystem, pkg, fixed)

    is_rpm = ecosystem.split(":", 1)[0] not in ("wolfi", "chainguard")
    resolved = rpm_advisory_ecosystems(os_id, os_ver, for_local_db=True) if is_rpm else apk_advisory_ecosystems(os_id)
    assert resolved, "resolver must produce an ecosystem key for a supported distro"
    db_eco = resolved[0].lower()
    assert db_eco == ecosystem  # resolver key must equal the stored DB key

    vulnerable = lookup_package(tmp_db, db_eco, pkg, vuln_ver)
    assert [m.id for m in vulnerable] == ["TEST-2024-0001"]
    assert vulnerable[0].fixed_version == fixed

    patched = lookup_package(tmp_db, db_eco, pkg, patched_ver)
    assert patched == []


# ── scanner ecosystem resolver integration ───────────────────────────────────


def test_scanner_db_ecosystems_for_rpm_and_apk_packages():
    from agent_bom.scanners import _db_ecosystems_for_package, _osv_ecosystems_for_package

    rhel_pkg = Package(name="bash", version="4.4.19-8.el8", ecosystem="rpm")
    rhel_pkg.distro_name = "rhel"
    rhel_pkg.distro_version = "8.9"
    assert _db_ecosystems_for_package(rhel_pkg) == ["red hat:enterprise_linux:8"]
    assert _osv_ecosystems_for_package(rhel_pkg) == ["Red Hat"]

    wolfi_pkg = Package(name="glibc", version="2.38-r5", ecosystem="apk")
    wolfi_pkg.distro_name = "wolfi"
    assert _db_ecosystems_for_package(wolfi_pkg) == ["wolfi"]


# ── OSV ingest normalises Red Hat repo-qualified ecosystems ──────────────────


def test_osv_ingest_collapses_redhat_repo_ecosystems(tmp_db):
    """A real Red Hat advisory keyed by two repo streams collapses to one per-major
    key on ingest, so a scanned RHEL host matches it exactly (shape from
    RHSA/RHBA OSV export, 2026-07-16)."""
    import json

    from agent_bom.db.sync import _ingest_osv_file

    advisory = {
        "id": "RHBA-2019:1992",
        "modified": "2024-01-01T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "Red Hat:enterprise_linux:8::appstream", "name": "cloud-init"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0:18.5-1.el8.4"}]}],
            },
            {
                "package": {"ecosystem": "Red Hat:enterprise_linux:8::baseos", "name": "cloud-init"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0:18.5-1.el8.4"}]}],
            },
        ],
    }
    _ingest_osv_file(tmp_db, json.dumps(advisory).encode(), "RHBA-2019:1992.json")
    tmp_db.commit()

    stored = {r[0] for r in tmp_db.execute("SELECT DISTINCT ecosystem FROM affected").fetchall()}
    assert stored == {"red hat:enterprise_linux:8"}

    # And a RHEL 8 host with an older cloud-init matches; the patched one does not.
    resolved = rpm_advisory_ecosystems("rhel", "8.9", for_local_db=True)[0].lower()
    assert [m.id for m in lookup_package(tmp_db, resolved, "cloud-init", "18.4-1.el8")] == ["RHBA-2019:1992"]
    assert lookup_package(tmp_db, resolved, "cloud-init", "18.5-1.el8.4") == []


def test_covered_os_distros_reads_from_db(tmp_db):
    from agent_bom.coverage import covered_os_distros

    assert covered_os_distros(tmp_db) == []
    _insert(tmp_db, "V1", "red hat:enterprise_linux:9", "bash", "0:5.1-1.el9")
    _insert(tmp_db, "V2", "wolfi", "glibc", "2.38-r5")
    _insert(tmp_db, "V3", "debian:12", "openssl", "3.0.0-1")
    _insert(tmp_db, "V4", "pypi", "requests", "2.0.0")  # non-OS: excluded
    assert covered_os_distros(tmp_db) == ["Debian", "RHEL", "Wolfi"]


# ── live-system OS type detection recognises the new distros directly ─────────


@pytest.mark.parametrize(
    "os_id,expected",
    [
        ("rocky", "rpm"),
        ("almalinux", "rpm"),
        ("opensuse-leap", "rpm"),
        ("sles", "rpm"),
        ("wolfi", "apk"),
        ("chainguard", "apk"),
    ],
)
def test_detect_os_type_new_distros(tmp_path, os_id, expected):
    from agent_bom.parsers.os_parsers import detect_os_type

    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "os-release").write_text(f'ID={os_id}\nVERSION_ID="1.0"\n')
    assert detect_os_type(tmp_path) == expected


# ── full scanner DB path (freshness gate + resolver + lookup + attach) ────────


def test_scanner_local_db_path_attaches_distro_vulns(tmp_path, monkeypatch):
    """Drive the real ``_scan_packages_local_db`` entry (not just ``lookup_package``)
    so the freshness gate, resolver, and vuln-attach are all exercised for the new
    RPM/apk distros."""
    from datetime import datetime, timezone

    import agent_bom.db.schema as schema
    import agent_bom.scanners as sc

    db = tmp_path / "scan.db"
    conn = schema.init_db(db)
    _insert(conn, "RLSA-1", "rocky linux:8", "python-markupsafe", "0:0.23-19.el8")
    _insert(conn, "RHSA-1", "red hat:enterprise_linux:9", "bash", "0:5.1.8-6.el9")
    _insert(conn, "CGA-1", "wolfi", "glibc", "2.38-r5")
    conn.execute(
        "INSERT OR REPLACE INTO sync_meta(source,last_synced,record_count) VALUES('osv',?,3)",
        (datetime.now(timezone.utc).isoformat(),),
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(schema, "DB_PATH", db)

    def _pkg(name, ver, eco, distro, distro_ver=""):
        p = Package(name=name, version=ver, ecosystem=eco)
        p.distro_name = distro
        p.distro_version = distro_ver
        return p

    vulnerable = [
        _pkg("python-markupsafe", "0.23-18.el8", "rpm", "rocky", "8.9"),
        _pkg("bash", "5.1.8-5.el9", "rpm", "rhel", "9.3"),
        _pkg("glibc", "2.38-r3", "apk", "wolfi"),
    ]
    matched, _ = sc._scan_packages_local_db(vulnerable)
    assert matched == 3
    assert [v.id for p in vulnerable for v in p.vulnerabilities] == ["RLSA-1", "RHSA-1", "CGA-1"]

    patched = [
        _pkg("python-markupsafe", "0.23-19.el8", "rpm", "rocky", "8.9"),
        _pkg("glibc", "2.38-r5", "apk", "wolfi"),
    ]
    assert sc._scan_packages_local_db(patched)[0] == 0
    assert all(not p.vulnerabilities for p in patched)
