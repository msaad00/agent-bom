"""Regressions for Alpine apk advisory release keying.

Alpine security advisories are published and stored per *minor branch*
(``alpine:v3.16``), never per point release. The scanner historically built the
apk lookup key from the full ``VERSION_ID`` (``3.16.9`` -> ``Alpine:v3.16.9``),
which matched zero advisory rows and silently reported 0 CVEs on every Alpine
image. These tests lock the truncation to ``v{major}.{minor}`` in both the
scanner ecosystem mapping and the coverage release key, and prove a 3-part
``VERSION_ID`` resolves advisories stored under the branch key.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.coverage import _release_key
from agent_bom.db.lookup import lookup_packages_batch
from agent_bom.db.schema import init_db
from agent_bom.models import Package
from agent_bom.package_utils import alpine_release_branch
from agent_bom.scanners import _db_ecosystems_for_package, _osv_ecosystems_for_package, _scan_packages_db_conn


@pytest.mark.parametrize(
    "version_id, expected",
    [
        ("3.16.9", "v3.16"),
        ("v3.16.9", "v3.16"),
        ("3.20.10", "v3.20"),
        ("3.16", "v3.16"),
        ("v3.16", "v3.16"),
        ("3.21.0", "v3.21"),
        # Non major.minor / odd inputs keep prior v-prefix behaviour.
        ("edge", "vedge"),
        ("3", "v3"),
        ("", ""),
    ],
)
def test_alpine_release_branch_normalization(version_id: str, expected: str):
    assert alpine_release_branch(version_id) == expected


def _apk_pkg(version_id: str) -> Package:
    return Package(
        name="busybox",
        version="1.35.0-r17",
        ecosystem="apk",
        distro_name="alpine",
        distro_version=version_id,
    )


@pytest.mark.parametrize(
    "version_id, expected_osv",
    [
        ("3.16.9", "Alpine:v3.16"),
        ("3.20.10", "Alpine:v3.20"),
        ("3.16", "Alpine:v3.16"),
        ("v3.16.9", "Alpine:v3.16"),
    ],
)
def test_osv_ecosystems_truncate_apk_to_branch(version_id: str, expected_osv: str):
    assert _osv_ecosystems_for_package(_apk_pkg(version_id)) == [expected_osv]
    assert _db_ecosystems_for_package(_apk_pkg(version_id)) == [expected_osv.lower()]


@pytest.mark.parametrize(
    "version_id, expected_key",
    [
        ("3.16.9", "alpine:v3.16"),
        ("3.20.10", "alpine:v3.20"),
        ("3.16", "alpine:v3.16"),
    ],
)
def test_coverage_release_key_truncates_apk(version_id: str, expected_key: str):
    assert _release_key(_apk_pkg(version_id)) == ("alpine", expected_key)


def test_debian_and_ubuntu_keys_unchanged():
    """The apk fix must not perturb Debian/Ubuntu release keying."""
    deb = Package(
        name="bash",
        version="5.1-2",
        ecosystem="deb",
        distro_name="debian",
        distro_version="12.5",
    )
    ubuntu = Package(
        name="bash",
        version="5.1-6ubuntu1",
        ecosystem="deb",
        distro_name="ubuntu",
        distro_version="22.04",
    )
    assert _osv_ecosystems_for_package(deb) == ["Debian:12"]
    assert _release_key(deb) == ("debian", "debian:12")
    assert _osv_ecosystems_for_package(ubuntu) == ["Ubuntu:22.04:LTS", "Ubuntu:22.04"]
    assert _release_key(ubuntu) == ("ubuntu", "ubuntu:22.04")


def test_three_part_version_resolves_branch_advisory():
    """A 3-part Alpine VERSION_ID must match advisories stored under the branch key.

    Mirrors the real DB layout: advisories are ingested as ``alpine:v3.16`` but
    the scanned image reports ``VERSION_ID=3.16.9``. The lookup key built from
    the package must collapse to ``alpine:v3.16`` so the row is found.
    """
    conn = init_db(Path(":memory:"))
    try:
        conn.execute(
            "INSERT INTO vulns(id, summary, severity, source) VALUES (?, ?, ?, ?)",
            ("CVE-2023-42366", "busybox issue", "high", "alpine-secdb"),
        )
        conn.execute(
            "INSERT INTO affected(vuln_id, ecosystem, package_name, introduced, fixed) VALUES (?, ?, ?, ?, ?)",
            ("CVE-2023-42366", "alpine:v3.16", "busybox", "0", "1.35.0-r18"),
        )
        conn.commit()

        pkg = _apk_pkg("3.16.9")
        (db_eco,) = _db_ecosystems_for_package(pkg)
        assert db_eco == "alpine:v3.16"

        results = lookup_packages_batch(conn, [(db_eco, "busybox", "1.35.0-r17")])
        vulns = results[(db_eco, "busybox", "1.35.0-r17")]
        assert [v.id for v in vulns] == ["CVE-2023-42366"]

        # And the older, buggy full-VERSION_ID key resolves nothing.
        empty = lookup_packages_batch(conn, [("alpine:v3.16.9", "busybox", "1.35.0-r17")])
        assert empty[("alpine:v3.16.9", "busybox", "1.35.0-r17")] == []
    finally:
        conn.close()


def test_alpine_subpackage_matches_source_package_advisory_individual_path():
    """Alpine secdb advisories are keyed by origin/source package.

    Installed apk packages such as ``musl-utils`` and ``ssl_client`` are
    subpackages. Their advisories live under ``musl`` and ``busybox`` in secdb,
    so source-package candidates must be used for exact local DB lookup.
    """
    conn = init_db(Path(":memory:"))
    try:
        conn.execute(
            "INSERT INTO vulns(id, summary, severity, source) VALUES (?, ?, ?, ?)",
            ("CVE-2025-26519", "musl issue", "high", "alpine-secdb"),
        )
        conn.execute(
            "INSERT INTO affected(vuln_id, ecosystem, package_name, introduced, fixed) VALUES (?, ?, ?, ?, ?)",
            ("CVE-2025-26519", "alpine:v3.16", "musl", "0", "1.2.3-r4"),
        )
        conn.commit()

        pkg = Package(
            name="musl-utils",
            version="1.2.3-r3",
            ecosystem="apk",
            source_package="musl",
            distro_name="alpine",
            distro_version="3.16.9",
        )
        covered: set[str] = set()

        assert _scan_packages_db_conn(conn, [pkg], covered) == 1
        assert [v.id for v in pkg.vulnerabilities] == ["CVE-2025-26519"]
        assert "apk:musl-utils@1.2.3-r3" in covered
    finally:
        conn.close()


def test_alpine_subpackage_matches_source_package_advisory_batch_path():
    """Batch local DB lookup must use the same source-package candidates."""
    conn = init_db(Path(":memory:"))
    try:
        conn.execute(
            "INSERT INTO vulns(id, summary, severity, source) VALUES (?, ?, ?, ?)",
            ("CVE-2023-42366", "busybox issue", "medium", "alpine-secdb"),
        )
        conn.execute(
            "INSERT INTO affected(vuln_id, ecosystem, package_name, introduced, fixed) VALUES (?, ?, ?, ?, ?)",
            ("CVE-2023-42366", "alpine:v3.16", "busybox", "0", "1.35.0-r18"),
        )
        conn.commit()

        packages = [
            Package(
                name="ssl_client",
                version="1.35.0-r17",
                ecosystem="apk",
                source_package="busybox",
                distro_name="alpine",
                distro_version="3.16.9",
            )
        ]
        packages.extend(
            Package(
                name=f"filler-{idx}",
                version="1.0.0-r0",
                ecosystem="apk",
                distro_name="alpine",
                distro_version="3.16.9",
            )
            for idx in range(55)
        )
        covered: set[str] = set()

        assert _scan_packages_db_conn(conn, packages, covered) == 1
        assert [v.id for v in packages[0].vulnerabilities] == ["CVE-2023-42366"]
        assert "apk:ssl_client@1.35.0-r17" in covered
    finally:
        conn.close()
