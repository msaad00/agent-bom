"""RPM 4.16+ stores its database as ``rpmdb.sqlite``; we must be able to read it.

That backend is the default on RHEL 9+, UBI9, Fedora 33+, Amazon Linux 2023 and
Rocky 9 — i.e. most enterprise base images. Two independent defects meant every
one of them reported **zero** OS packages, and therefore zero OS CVEs:

1. ``_parse_rpm_header_blob`` required the 8-byte header magic. Legacy
   BerkeleyDB/NDB records carry it; the sqlite ``Packages.blob`` column does
   not — it starts at ``nindex`` directly. Every sqlite blob returned None.
2. ``parse_rpm_packages`` shelled out to the ``rpm`` binary with no file
   fallback, so a host without ``rpm`` (every macOS workstation, most
   Debian/Alpine CI runners) read nothing from a mounted snapshot — while the
   dpkg and apk parsers both fall back to reading their database files.

A scanner that returns nothing on RHEL looks clean. These tests use a synthetic
two-package database so they need no container and no network.
"""

from __future__ import annotations

import sqlite3
import struct
from pathlib import Path

import pytest

from agent_bom.oci_parser import _RPM_HDR_MAGIC, _parse_rpm_header_blob
from agent_bom.parsers.os_parsers import parse_rpm_packages

FIXTURE = Path(__file__).parent / "fixtures" / "rpmdb_sqlite_min.sqlite"

_TAG_NAME, _TAG_VERSION, _TAG_RELEASE, _TAG_EPOCH = 1000, 1001, 1002, 1003
_TYPE_INT32 = 4
_TYPE_STRING = 6


def _rpm_header(
    name: str,
    version: str,
    release: str,
    *,
    with_magic: bool,
    epoch: int | None = None,
) -> bytes:
    """Build one RPM header record in either framing."""
    entries = [(_TAG_NAME, name), (_TAG_VERSION, version), (_TAG_RELEASE, release)]
    data = b""
    index = b""
    for tag, value in entries:
        index += struct.pack(">IIII", tag, _TYPE_STRING, len(data), 1)
        data += value.encode() + b"\x00"
    if epoch is not None:
        index += struct.pack(">IIII", _TAG_EPOCH, _TYPE_INT32, len(data), 1)
        data += struct.pack(">I", epoch)
        entries.append((_TAG_EPOCH, str(epoch)))
    body = struct.pack(">II", len(entries), len(data)) + index + data
    return (_RPM_HDR_MAGIC + body) if with_magic else body


def test_header_blob_parses_in_both_framings() -> None:
    """The sqlite column has no lead magic; legacy records do. Both are valid."""
    sqlite_framed = _rpm_header("bash", "5.1.8", "9.el9", with_magic=False)
    legacy_framed = _rpm_header("bash", "5.1.8", "9.el9", with_magic=True)

    assert _parse_rpm_header_blob(sqlite_framed) == ("bash", "5.1.8-9.el9"), (
        "rpmdb.sqlite blobs carry no header magic — requiring it returned None for every "
        "package on RHEL 9+, UBI9, Fedora 33+, Amazon Linux 2023 and Rocky 9"
    )
    assert _parse_rpm_header_blob(legacy_framed) == ("bash", "5.1.8-9.el9")


def test_header_blob_preserves_nonzero_rpm_epoch() -> None:
    """RPM epoch is part of EVR identity and must survive snapshot parsing."""
    blob = _rpm_header("openssl-libs", "3.5.5", "6.el9_8", with_magic=False, epoch=1)

    assert _parse_rpm_header_blob(blob) == ("openssl-libs", "1:3.5.5-6.el9_8")


def test_header_blob_rejects_garbage_without_scanning_gigabytes() -> None:
    """Tolerating a missing magic must not turn any blob into a header."""
    assert _parse_rpm_header_blob(b"") is None
    assert _parse_rpm_header_blob(b"\x00" * 8) is None
    # A huge leading word would previously be read as an index count.
    assert _parse_rpm_header_blob(struct.pack(">II", 0xFFFFFFFF, 4) + b"\x00" * 8) is None


@pytest.mark.skipif(not FIXTURE.is_file(), reason="rpmdb fixture not present")
def test_rpm_packages_are_read_from_the_database_file(tmp_path: Path) -> None:
    """A mounted snapshot must be readable with no ``rpm`` binary on the host.

    Asserted through ``parse_rpm_packages`` with a non-``/`` root, which is the
    path an image or disk scan takes. dpkg and apk already did this; rpm did not.
    """
    db_dir = tmp_path / "var" / "lib" / "rpm"
    db_dir.mkdir(parents=True)
    (db_dir / "rpmdb.sqlite").write_bytes(FIXTURE.read_bytes())

    packages = parse_rpm_packages(tmp_path)
    found = {(p.name, p.version) for p in packages}

    assert found == {("bash", "5.1.8-9.el9"), ("openssl-libs", "3.0.7-27.el9")}, found
    assert all(p.ecosystem == "rpm" for p in packages)
    assert all(p.purl and p.purl.startswith("pkg:rpm/") for p in packages)


def test_missing_database_is_an_empty_result_not_an_error(tmp_path: Path) -> None:
    """No rpm database means no rpm packages — not a crash."""
    assert parse_rpm_packages(tmp_path) == []


def test_unreadable_database_does_not_masquerade_as_a_clean_scan(tmp_path: Path, caplog) -> None:
    """A database that exists but cannot be read must be reported, not swallowed.

    Returning a silent empty list here is the exact failure this module exists
    to end: it is indistinguishable from an image with no packages.
    """
    db_dir = tmp_path / "var" / "lib" / "rpm"
    db_dir.mkdir(parents=True)
    (db_dir / "rpmdb.sqlite").write_bytes(b"this is not a sqlite database")

    with caplog.at_level("WARNING"):
        packages = parse_rpm_packages(tmp_path)

    assert packages == []
    assert any("could not be read" in r.message or "could not be read" in r.getMessage() for r in caplog.records), (
        "an unreadable rpm database was swallowed silently"
    )


def test_fixture_is_a_real_sqlite_rpmdb() -> None:
    """Guard the fixture itself, so a corrupted one fails loudly here."""
    if not FIXTURE.is_file():
        pytest.skip("fixture not present")
    conn = sqlite3.connect(f"file:{FIXTURE}?immutable=1", uri=True)
    try:
        rows = conn.execute("SELECT blob FROM Packages").fetchall()
    finally:
        conn.close()
    assert len(rows) == 2
    parsed = [_parse_rpm_header_blob(bytes(b)) for (b,) in rows]
    assert all(parsed), parsed
