"""`agent-bom fs` must read the rpmdb schema RHEL actually ships.

`filesystem._parse_rpm_sqlite` queried::

    SELECT name, version, release, epoch, arch FROM Packages

Those columns do not exist. The real RHEL 9+ `rpmdb.sqlite` schema is
`Packages(hnum INTEGER PRIMARY KEY, blob BLOB)`, where `blob` is a binary RPM
header that has to be decoded. The query raised, the `except` swallowed it to
`logger.debug`, and the function returned `[]`. `parse_rpm_packages` then fell
through to the `rpm` binary — absent on any non-RPM scanner host — and also
returned `[]`.

Net effect: **every RHEL / UBI / Fedora / Amazon Linux filesystem and VM
snapshot scanned clean, exit 0, with no warning.**

This is a regression of the defect #4684 fixed in `oci_parser.py`: the same
judgement implemented twice, and the two disagreed on the identical bytes —
`oci_parser` decoded `bash 5.1.8-9.el9` from the same fixture that
`filesystem` read as empty.

Nine tests in `tests/test_filesystem.py` passed throughout, because they
*fabricated* the schema they tested against:

    CREATE TABLE Packages (name TEXT, version TEXT, release TEXT, epoch INTEGER, arch TEXT)

So the tests certified an invented format. These use the real fixture the OCI
path already ships, `tests/fixtures/rpmdb_sqlite_min.sqlite`, so a parser that
cannot read a genuine rpmdb fails here.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "rpmdb_sqlite_min.sqlite"


@pytest.fixture
def rhel_root(tmp_path: Path) -> Path:
    """A minimal RHEL 9 rootfs shaped the way a real snapshot is."""
    root = tmp_path / "rhel9root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "os-release").write_text('NAME="Red Hat Enterprise Linux"\nID="rhel"\nVERSION_ID="9.3"\n')
    rpm_dir = root / "var" / "lib" / "rpm"
    rpm_dir.mkdir(parents=True)
    shutil.copy(FIXTURE, rpm_dir / "rpmdb.sqlite")
    return root


def test_the_real_rpmdb_schema_yields_packages() -> None:
    """The defect, at its source."""
    from agent_bom.filesystem import _parse_rpm_sqlite

    packages = _parse_rpm_sqlite(FIXTURE)
    assert packages, "no packages read from a genuine rpmdb.sqlite — the false-clean defect"
    names = {p.name for p in packages}
    assert "bash" in names, sorted(names)
    assert "openssl-libs" in names, sorted(names)


def test_it_agrees_with_the_oci_parser_on_the_same_bytes() -> None:
    """Two implementations of one judgement must not disagree.

    `oci_parser` already decoded this fixture correctly; the whole defect was
    that the filesystem path did not.
    """
    import sqlite3

    from agent_bom.filesystem import _parse_rpm_sqlite
    from agent_bom.oci_parser import _parse_rpm_header_blob

    conn = sqlite3.connect(f"file:{FIXTURE}?mode=ro", uri=True)
    try:
        blobs = [row[0] for row in conn.execute("SELECT blob FROM Packages")]
    finally:
        conn.close()

    expected = {r for r in (_parse_rpm_header_blob(b) for b in blobs if isinstance(b, bytes)) if r}
    expected = {(name, ver) for name, ver in expected if name != "gpg-pubkey"}
    actual = {(p.name, p.version) for p in _parse_rpm_sqlite(FIXTURE)}
    assert actual == expected, f"filesystem and oci_parser disagree: {actual ^ expected}"


def test_versions_are_real_rpm_versions() -> None:
    from agent_bom.filesystem import _parse_rpm_sqlite

    by_name = {p.name: p.version for p in _parse_rpm_sqlite(FIXTURE)}
    assert by_name.get("bash") == "5.1.8-9.el9", by_name
    assert by_name.get("openssl-libs") == "3.0.7-27.el9", by_name


def test_every_package_is_tagged_rpm() -> None:
    from agent_bom.filesystem import _parse_rpm_sqlite

    assert {p.ecosystem for p in _parse_rpm_sqlite(FIXTURE)} == {"rpm"}


def test_the_signing_key_pseudo_package_is_excluded() -> None:
    """`gpg-pubkey` is a key in the rpmdb, not software; the OCI path drops it."""
    from agent_bom.filesystem import _parse_rpm_sqlite

    assert "gpg-pubkey" not in {p.name for p in _parse_rpm_sqlite(FIXTURE)}


def test_a_missing_database_is_still_empty_not_an_error(tmp_path: Path) -> None:
    from agent_bom.filesystem import _parse_rpm_sqlite

    assert _parse_rpm_sqlite(tmp_path / "absent.sqlite") == []


def test_a_corrupt_database_does_not_raise(tmp_path: Path) -> None:
    from agent_bom.filesystem import _parse_rpm_sqlite

    junk = tmp_path / "rpmdb.sqlite"
    junk.write_bytes(b"this is not a sqlite database")
    assert _parse_rpm_sqlite(junk) == []


def test_scanning_a_rhel_rootfs_finds_its_packages(rhel_root: Path) -> None:
    """End to end: the path a `agent-bom fs` run actually takes."""
    from agent_bom.filesystem import parse_rpm_packages

    packages = parse_rpm_packages(rhel_root)
    assert packages, "a RHEL rootfs scanned clean — this is the false clean"
    assert "openssl-libs" in {p.name for p in packages}


def test_an_rpm_distro_is_covered_by_the_release_gap_detector() -> None:
    """The safety net that could never fire.

    `coverage._release_key` handled only `deb` and `apk`, returning None for
    `rpm`, so `detect_release_coverage_gaps` could not report a missing RPM
    feed even when one was missing. A silent parser failure had no backstop.
    """
    from agent_bom.coverage import _release_key
    from agent_bom.models import Package

    pkg = Package(name="openssl-libs", version="3.0.7-27.el9", ecosystem="rpm")
    pkg.distro_name = "rhel"
    pkg.distro_version = "9.3"
    key = _release_key(pkg)
    assert key is not None, "an RPM distro yields no release key, so a missing feed cannot be reported"
    family, db_key = key
    # The advisory DB stores these as `red hat:enterprise_linux:9` (35,458 rows).
    assert db_key == "red hat:enterprise_linux:9", key
