"""Tests for OS package parsers (dpkg/rpm/apk)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from agent_bom.parsers.os_parsers import (
    _parse_dpkg_status_file,
    detect_os_type,
    parse_apk_packages,
    parse_dpkg_packages,
    parse_rpm_packages,
    scan_os_packages,
)

# ─── Test fixtures ─────────────────────────────────────────────────────────────

DPKG_STATUS = """\
Package: libc6
Version: 2.35-0ubuntu3
Status: install ok installed
Architecture: amd64
Source: glibc

Package: libssl3
Version: 3.0.2-0ubuntu1.12
Status: install ok installed
Architecture: amd64
Source: openssl

"""

# dpkg status with an incomplete stanza (no Version) — must be skipped
DPKG_STATUS_PARTIAL = """\
Package: broken-pkg
Status: install ok installed

Package: libgcc-s1
Version: 12.3.0-1ubuntu1
Status: install ok installed

"""

APK_DB = """\
P:musl
V:1.2.4-r2
T:the musl c library

P:busybox
V:1.36.1-r19
T:size optimized toolbox of many common UNIX utilities

"""

# APK db that does NOT end with a blank line (last stanza test)
APK_DB_NO_TRAILING = """\
P:openssl
V:3.1.4-r5
T:Toolkit for TLS/SSL"""


# ─── _parse_dpkg_status_file ───────────────────────────────────────────────────


def test_parse_dpkg_status_file(tmp_path: Path) -> None:
    f = tmp_path / "status"
    f.write_text(DPKG_STATUS)
    packages: list = []
    _parse_dpkg_status_file(f, packages)
    assert len(packages) == 2
    assert packages[0].name == "libc6"
    assert packages[0].version == "2.35-0ubuntu3"
    assert packages[0].ecosystem == "deb"
    assert packages[1].name == "libssl3"


def test_parse_dpkg_status_file_skips_incomplete_stanza(tmp_path: Path) -> None:
    f = tmp_path / "status"
    f.write_text(DPKG_STATUS_PARTIAL)
    packages: list = []
    _parse_dpkg_status_file(f, packages)
    # "broken-pkg" has no Version → skipped; "libgcc-s1" → included
    assert len(packages) == 1
    assert packages[0].name == "libgcc-s1"


def test_parse_dpkg_status_file_missing(tmp_path: Path) -> None:
    packages: list = []
    _parse_dpkg_status_file(tmp_path / "nonexistent", packages)
    assert packages == []


def test_parse_dpkg_status_file_purl_format(tmp_path: Path) -> None:
    f = tmp_path / "status"
    f.write_text(DPKG_STATUS)
    packages: list = []
    _parse_dpkg_status_file(f, packages)
    assert packages[0].purl == "pkg:deb/debian/libc6@2.35-0ubuntu3"


def test_parse_dpkg_status_file_source_package(tmp_path: Path) -> None:
    f = tmp_path / "status"
    f.write_text(DPKG_STATUS)
    packages: list = []
    _parse_dpkg_status_file(f, packages)
    assert packages[0].source_package == "glibc"
    assert packages[1].source_package == "openssl"


# ─── detect_os_type ────────────────────────────────────────────────────────────


def test_detect_os_type_debian(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text('ID=debian\nNAME="Debian GNU/Linux"\n')
    assert detect_os_type(tmp_path) == "deb"


def test_detect_os_type_ubuntu(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text('ID=ubuntu\nNAME="Ubuntu"\n')
    assert detect_os_type(tmp_path) == "deb"


def test_detect_os_type_alpine(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text("ID=alpine\n")
    assert detect_os_type(tmp_path) == "apk"


def test_detect_os_type_rhel(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text('ID=rhel\nNAME="Red Hat Enterprise Linux"\n')
    assert detect_os_type(tmp_path) == "rpm"


def test_detect_os_type_centos(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text("ID=centos\n")
    assert detect_os_type(tmp_path) == "rpm"


def test_detect_os_type_fedora(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text("ID=fedora\n")
    assert detect_os_type(tmp_path) == "rpm"


def test_detect_os_type_unknown(tmp_path: Path) -> None:
    # No etc/os-release
    assert detect_os_type(tmp_path) is None


def test_detect_os_type_unrecognised_id(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text("ID=gentoo\n")
    assert detect_os_type(tmp_path) is None


# ─── parse_dpkg_packages ──────────────────────────────────────────────────────


def test_parse_dpkg_packages_uses_dpkg_query(tmp_path: Path) -> None:
    """When dpkg-query succeeds, packages are returned from its output."""
    mock_stdout = "libc6\t2.35-0ubuntu3\tamd64\nlibssl3\t3.0.2-0ubuntu1.12\tamd64\n"
    mock_result = type("R", (), {"returncode": 0, "stdout": mock_stdout})()
    with patch("subprocess.run", return_value=mock_result):
        packages = parse_dpkg_packages(tmp_path)
    assert len(packages) == 2
    assert packages[0].name == "libc6"
    assert packages[0].ecosystem == "deb"


def test_parse_dpkg_packages_fallback_to_status_file(tmp_path: Path) -> None:
    """Falls back to reading status file when dpkg-query is unavailable."""
    (tmp_path / "var/lib/dpkg").mkdir(parents=True)
    (tmp_path / "var/lib/dpkg/status").write_text(DPKG_STATUS)
    with patch("subprocess.run", side_effect=FileNotFoundError):
        packages = parse_dpkg_packages(tmp_path)
    assert len(packages) == 2
    assert packages[0].name == "libc6"


def test_parse_dpkg_packages_fallback_status_d(tmp_path: Path) -> None:
    """Falls back to reading status.d directory when status file absent."""
    status_d = tmp_path / "var/lib/dpkg/status.d"
    status_d.mkdir(parents=True)
    (status_d / "libc6").write_text("Package: libc6\nVersion: 2.35-0ubuntu3\n\n")
    with patch("subprocess.run", side_effect=FileNotFoundError):
        packages = parse_dpkg_packages(tmp_path)
    assert len(packages) == 1
    assert packages[0].name == "libc6"


def test_parse_dpkg_packages_dpkg_query_timeout_fallback(tmp_path: Path) -> None:
    """Timeout on dpkg-query falls back to status file."""
    import subprocess as _sp

    (tmp_path / "var/lib/dpkg").mkdir(parents=True)
    (tmp_path / "var/lib/dpkg/status").write_text(DPKG_STATUS)
    with patch("subprocess.run", side_effect=_sp.TimeoutExpired("dpkg-query", 10)):
        packages = parse_dpkg_packages(tmp_path)
    assert len(packages) == 2


def test_parse_dpkg_packages_purl_format(tmp_path: Path) -> None:
    (tmp_path / "var/lib/dpkg").mkdir(parents=True)
    (tmp_path / "var/lib/dpkg/status").write_text(DPKG_STATUS)
    with patch("subprocess.run", side_effect=FileNotFoundError):
        packages = parse_dpkg_packages(tmp_path)
    assert packages[0].purl.startswith("pkg:deb/debian/libc6@")


def test_parse_dpkg_packages_empty_root(tmp_path: Path) -> None:
    """Returns empty list when no dpkg database present and command unavailable."""
    with patch("subprocess.run", side_effect=FileNotFoundError):
        packages = parse_dpkg_packages(tmp_path)
    assert packages == []


# ─── parse_rpm_packages ───────────────────────────────────────────────────────


def test_parse_rpm_packages_success(tmp_path: Path) -> None:
    """Parses rpm -qa output correctly."""
    mock_stdout = "bash\t5.2.15-3.fc39\tx86_64\nglibc\t2.38-16.fc39\tx86_64\n"
    mock_result = type("R", (), {"returncode": 0, "stdout": mock_stdout})()
    with patch("subprocess.run", return_value=mock_result):
        packages = parse_rpm_packages(tmp_path)
    assert len(packages) == 2
    assert packages[0].name == "bash"
    assert packages[0].version == "5.2.15-3.fc39"
    assert packages[0].ecosystem == "rpm"


def test_parse_rpm_packages_not_available(tmp_path: Path) -> None:
    """Returns empty list when rpm binary is not installed."""
    with patch("subprocess.run", side_effect=FileNotFoundError):
        packages = parse_rpm_packages(tmp_path)
    assert packages == []


def test_parse_rpm_packages_timeout(tmp_path: Path) -> None:
    """Returns empty list on timeout."""
    import subprocess as _sp

    with patch("subprocess.run", side_effect=_sp.TimeoutExpired("rpm", 15)):
        packages = parse_rpm_packages(tmp_path)
    assert packages == []


def test_parse_rpm_packages_purl_format(tmp_path: Path) -> None:
    mock_stdout = "bash\t5.2.15-3.fc39\tx86_64\n"
    mock_result = type("R", (), {"returncode": 0, "stdout": mock_stdout})()
    with patch("subprocess.run", return_value=mock_result):
        packages = parse_rpm_packages(tmp_path)
    assert packages[0].purl == "pkg:rpm/redhat/bash@5.2.15-3.fc39"


# ─── parse_apk_packages ───────────────────────────────────────────────────────


def test_parse_apk_packages_uses_command(tmp_path: Path) -> None:
    """When apk list --installed succeeds, packages are returned."""
    mock_stdout = "musl-1.2.4-r2 {musl} (MIT) [installed]\nbusybox-1.36.1-r19 {busybox} (GPL-2.0-only) [installed]\n"
    mock_result = type("R", (), {"returncode": 0, "stdout": mock_stdout})()
    with patch("subprocess.run", return_value=mock_result):
        packages = parse_apk_packages(tmp_path)
    assert len(packages) == 2
    assert packages[0].name == "musl"
    assert packages[0].version == "1.2.4-r2"
    assert packages[0].ecosystem == "apk"


def test_parse_apk_packages_from_db(tmp_path: Path) -> None:
    """Reads from lib/apk/db/installed when apk command unavailable."""
    (tmp_path / "lib/apk/db").mkdir(parents=True)
    (tmp_path / "lib/apk/db/installed").write_text(APK_DB)
    with patch("subprocess.run", side_effect=FileNotFoundError):
        packages = parse_apk_packages(tmp_path)
    assert len(packages) == 2
    assert packages[0].name == "musl"
    assert packages[0].version == "1.2.4-r2"
    assert packages[1].name == "busybox"


def test_parse_apk_packages_from_db_no_trailing_blank(tmp_path: Path) -> None:
    """Handles last apk stanza without trailing blank line."""
    (tmp_path / "lib/apk/db").mkdir(parents=True)
    (tmp_path / "lib/apk/db/installed").write_text(APK_DB_NO_TRAILING)
    with patch("subprocess.run", side_effect=FileNotFoundError):
        packages = parse_apk_packages(tmp_path)
    assert len(packages) == 1
    assert packages[0].name == "openssl"


def test_parse_apk_packages_empty(tmp_path: Path) -> None:
    """Returns empty list when apk not available and no db file."""
    with patch("subprocess.run", side_effect=FileNotFoundError):
        packages = parse_apk_packages(tmp_path)
    assert packages == []


def test_parse_apk_packages_purl_format(tmp_path: Path) -> None:
    (tmp_path / "lib/apk/db").mkdir(parents=True)
    (tmp_path / "lib/apk/db/installed").write_text(APK_DB)
    with patch("subprocess.run", side_effect=FileNotFoundError):
        packages = parse_apk_packages(tmp_path)
    assert packages[0].purl == "pkg:apk/alpine/musl@1.2.4-r2"


# ─── scan_os_packages ─────────────────────────────────────────────────────────


def test_scan_os_packages_debian(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text("ID=debian\n")
    (tmp_path / "var/lib/dpkg").mkdir(parents=True)
    (tmp_path / "var/lib/dpkg/status").write_text(DPKG_STATUS)
    with patch("subprocess.run", side_effect=FileNotFoundError):
        packages = scan_os_packages(tmp_path)
    assert len(packages) == 2
    assert all(p.ecosystem == "deb" for p in packages)


def test_scan_os_packages_alpine(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text("ID=alpine\n")
    (tmp_path / "lib/apk/db").mkdir(parents=True)
    (tmp_path / "lib/apk/db/installed").write_text(APK_DB)
    with patch("subprocess.run", side_effect=FileNotFoundError):
        packages = scan_os_packages(tmp_path)
    assert len(packages) == 2
    assert all(p.ecosystem == "apk" for p in packages)


def test_scan_os_packages_unknown_os_no_data(tmp_path: Path) -> None:
    """Returns empty list for unknown OS with no package databases."""
    with patch("subprocess.run", side_effect=FileNotFoundError):
        packages = scan_os_packages(tmp_path)
    assert packages == []


def test_scan_os_packages_unknown_os_tries_all(tmp_path: Path) -> None:
    """For unknown OS, tries all parsers and returns first success (deb)."""
    # No os-release, but dpkg status file present
    (tmp_path / "var/lib/dpkg").mkdir(parents=True)
    (tmp_path / "var/lib/dpkg/status").write_text(DPKG_STATUS)
    with patch("subprocess.run", side_effect=FileNotFoundError):
        packages = scan_os_packages(tmp_path)
    assert len(packages) == 2
    assert packages[0].ecosystem == "deb"


def test_scan_os_packages_ubuntu(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text("ID=ubuntu\n")
    (tmp_path / "var/lib/dpkg").mkdir(parents=True)
    (tmp_path / "var/lib/dpkg/status").write_text(DPKG_STATUS)
    with patch("subprocess.run", side_effect=FileNotFoundError):
        packages = scan_os_packages(tmp_path)
    assert len(packages) == 2
