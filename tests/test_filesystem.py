"""Tests for filesystem/disk snapshot scanning via Syft."""

import json
import sqlite3
import subprocess

import pytest

from agent_bom.filesystem import (
    FilesystemScanError,
    _parse_rpm_sqlite,
    _run_syft,
    parse_rpm_packages,
    scan_filesystem,
    scan_filesystem_batch,
)

# ─── Mock CycloneDX output from Syft ─────────────────────────────────────────

_MOCK_CDX = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
            {"type": "library", "name": "flask", "version": "3.0.0", "purl": "pkg:pypi/flask@3.0.0"},
            {"type": "library", "name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2"},
        ],
    }
)


# ─── scan_filesystem — directory ──────────────────────────────────────────────


def test_scan_directory(monkeypatch, tmp_path):
    """Syft directory scan returns parsed packages."""

    def _fake_run(cmd, **kwargs):
        assert "dir:" in cmd[1]
        return subprocess.CompletedProcess(cmd, 0, stdout=_MOCK_CDX, stderr="")

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/syft" if name == "syft" else None)
    monkeypatch.setattr("agent_bom.filesystem.subprocess.run", _fake_run)

    packages, strategy = scan_filesystem(str(tmp_path))
    assert strategy == "syft-dir"
    assert len(packages) == 3
    assert packages[0].name == "requests"
    assert packages[0].version == "2.31.0"
    assert packages[0].ecosystem == "pypi"


def test_scan_directory_with_packages(monkeypatch, tmp_path):
    """Verify package details from Syft CycloneDX output."""

    def _fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=_MOCK_CDX, stderr="")

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/syft")
    monkeypatch.setattr("agent_bom.filesystem.subprocess.run", _fake_run)

    packages, _ = scan_filesystem(str(tmp_path))
    ecosystems = {p.ecosystem for p in packages}
    assert "pypi" in ecosystems
    assert "npm" in ecosystems


# ─── scan_filesystem — tar archive ────────────────────────────────────────────


def test_scan_tar_archive(monkeypatch, tmp_path):
    """Syft tar archive scan works."""
    tar_file = tmp_path / "snapshot.tar"
    tar_file.touch()

    def _fake_run(cmd, **kwargs):
        assert "snapshot.tar" in cmd[1]
        return subprocess.CompletedProcess(cmd, 0, stdout=_MOCK_CDX, stderr="")

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/syft")
    monkeypatch.setattr("agent_bom.filesystem.subprocess.run", _fake_run)

    packages, strategy = scan_filesystem(str(tar_file))
    assert strategy == "syft-tar"
    assert len(packages) == 3


def test_scan_tgz_archive(monkeypatch, tmp_path):
    """Supports .tgz extension."""
    tgz_file = tmp_path / "snapshot.tgz"
    tgz_file.touch()

    def _fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=_MOCK_CDX, stderr="")

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/syft")
    monkeypatch.setattr("agent_bom.filesystem.subprocess.run", _fake_run)

    packages, strategy = scan_filesystem(str(tgz_file))
    assert strategy == "syft-tar"


def test_scan_tar_gz_archive(monkeypatch, tmp_path):
    """Supports .tar.gz via .gz suffix."""
    gz_file = tmp_path / "snapshot.gz"
    gz_file.touch()

    def _fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=_MOCK_CDX, stderr="")

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/syft")
    monkeypatch.setattr("agent_bom.filesystem.subprocess.run", _fake_run)

    packages, strategy = scan_filesystem(str(gz_file))
    assert strategy == "syft-tar"


# ─── Error cases ──────────────────────────────────────────────────────────────


def test_syft_not_found_uses_native_fallback(monkeypatch, tmp_path):
    """Missing syft binary falls back to native scanning for directories."""
    monkeypatch.setattr("shutil.which", lambda name: None)
    # Empty directory → native scan returns empty list (no error)
    pkgs, strategy = scan_filesystem(str(tmp_path))
    assert strategy == "native-dir"
    assert isinstance(pkgs, list)


def test_syft_not_found_tar_raises(monkeypatch, tmp_path):
    """Missing syft binary raises FilesystemScanError for tar archives."""
    monkeypatch.setattr("shutil.which", lambda name: None)
    tar = tmp_path / "archive.tar"
    tar.write_bytes(b"fake")
    with pytest.raises(FilesystemScanError, match="syft not found"):
        scan_filesystem(str(tar))


def test_syft_nonzero_exit(monkeypatch, tmp_path):
    """Non-zero exit code raises FilesystemScanError."""

    def _fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="permission denied")

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/syft")
    monkeypatch.setattr("agent_bom.filesystem.subprocess.run", _fake_run)

    with pytest.raises(FilesystemScanError, match="syft exited 1"):
        scan_filesystem(str(tmp_path))


def test_syft_timeout(monkeypatch, tmp_path):
    """Subprocess timeout raises FilesystemScanError."""

    def _fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 600))

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/syft")
    monkeypatch.setattr("agent_bom.filesystem.subprocess.run", _fake_run)

    with pytest.raises(FilesystemScanError, match="timed out"):
        scan_filesystem(str(tmp_path), timeout=10)


def test_syft_invalid_json(monkeypatch, tmp_path):
    """Invalid JSON output raises FilesystemScanError."""

    def _fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="not json {{{", stderr="")

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/syft")
    monkeypatch.setattr("agent_bom.filesystem.subprocess.run", _fake_run)

    with pytest.raises(FilesystemScanError, match="not valid JSON"):
        scan_filesystem(str(tmp_path))


def test_unsupported_file_type(monkeypatch, tmp_path):
    """Unsupported file extension raises FilesystemScanError."""
    txt_file = tmp_path / "data.txt"
    txt_file.touch()

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/syft")

    with pytest.raises(FilesystemScanError, match="Unsupported path type"):
        scan_filesystem(str(txt_file))


def test_nonexistent_path():
    """Non-existent path raises SecurityError from validate_path."""
    with pytest.raises(Exception):  # SecurityError from validate_path
        scan_filesystem("/nonexistent/path/to/nowhere")


# ─── scan_filesystem_batch ────────────────────────────────────────────────────


def test_batch_scan_success(monkeypatch, tmp_path):
    """Batch scan processes multiple directories."""
    dir1 = tmp_path / "snap1"
    dir1.mkdir()
    dir2 = tmp_path / "snap2"
    dir2.mkdir()

    def _fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=_MOCK_CDX, stderr="")

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/syft")
    monkeypatch.setattr("agent_bom.filesystem.subprocess.run", _fake_run)

    results = scan_filesystem_batch([str(dir1), str(dir2)])
    assert len(results) == 2
    assert results[0][2] == "syft-dir"
    assert results[1][2] == "syft-dir"
    assert len(results[0][1]) == 3
    assert len(results[1][1]) == 3


def test_batch_scan_partial_failure(monkeypatch, tmp_path):
    """Batch scan handles partial failures gracefully."""
    good_dir = tmp_path / "good"
    good_dir.mkdir()

    call_count = 0

    def _fake_run(cmd, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return subprocess.CompletedProcess(cmd, 0, stdout=_MOCK_CDX, stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="error")

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/syft")
    monkeypatch.setattr("agent_bom.filesystem.subprocess.run", _fake_run)

    # Second path will fail (same dir triggers syft again)
    results = scan_filesystem_batch([str(good_dir), str(good_dir)])
    assert results[0][2] == "syft-dir"
    assert results[0][1]  # Has packages
    assert results[1][2] == "error"
    assert results[1][1] == []


def test_batch_scan_empty_list():
    """Empty batch returns empty results."""
    results = scan_filesystem_batch([])
    assert results == []


# ─── _run_syft internals ─────────────────────────────────────────────────────


def test_run_syft_empty_output(monkeypatch):
    """Empty but valid JSON from syft returns no packages."""

    def _fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout='{"components": []}', stderr="")

    monkeypatch.setattr("agent_bom.filesystem.subprocess.run", _fake_run)

    packages = _run_syft("dir:/tmp/test", timeout=60)
    assert packages == []


def test_run_syft_captures_stderr(monkeypatch):
    """Error message includes truncated stderr."""

    def _fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="a" * 300)

    monkeypatch.setattr("agent_bom.filesystem.subprocess.run", _fake_run)

    with pytest.raises(FilesystemScanError, match="syft exited 2"):
        _run_syft("dir:/tmp/test", timeout=60)


# ─── RPM SQLite parser ────────────────────────────────────────────────────────


def _make_rpm_sqlite(db_path, rows):
    """Helper: create a minimal SQLite RPM DB with given rows."""
    con = sqlite3.connect(str(db_path))
    con.execute("CREATE TABLE Packages (name TEXT, version TEXT, release TEXT, epoch INTEGER, arch TEXT)")
    con.executemany("INSERT INTO Packages VALUES (?,?,?,?,?)", rows)
    con.commit()
    con.close()


def test_parse_rpm_sqlite_db(tmp_path):
    """_parse_rpm_sqlite reads Packages table and returns Package objects."""
    db = tmp_path / "rpmdb.sqlite"
    _make_rpm_sqlite(db, [("bash", "5.1.8", "6.el9", 0, "x86_64")])

    pkgs = _parse_rpm_sqlite(db)
    assert len(pkgs) == 1
    assert pkgs[0].name == "bash"
    assert pkgs[0].ecosystem == "rpm"
    assert "5.1.8" in pkgs[0].version


def test_parse_rpm_sqlite_epoch_in_version(tmp_path):
    """Packages with non-zero epoch include it in the version string."""
    db = tmp_path / "rpmdb.sqlite"
    _make_rpm_sqlite(db, [("openssl", "1.1.1", "34.el9_0", 1, "x86_64")])

    pkgs = _parse_rpm_sqlite(db)
    assert len(pkgs) == 1
    assert pkgs[0].version.startswith("1:")


def test_rpm_purl_with_epoch(tmp_path):
    """PURL includes epoch when non-zero."""
    db = tmp_path / "rpmdb.sqlite"
    _make_rpm_sqlite(db, [("curl", "7.76.1", "14.el9_0.2", 1, "x86_64")])

    pkgs = _parse_rpm_sqlite(db)
    assert len(pkgs) == 1
    assert "1:7.76.1-14.el9_0.2" in pkgs[0].purl


def test_rpm_purl_without_epoch(tmp_path):
    """PURL omits epoch when epoch is 0."""
    db = tmp_path / "rpmdb.sqlite"
    _make_rpm_sqlite(db, [("gzip", "1.10", "1.el9", 0, "x86_64")])

    pkgs = _parse_rpm_sqlite(db)
    assert len(pkgs) == 1
    assert "pkg:rpm/rhel/gzip@1.10-1.el9" in pkgs[0].purl


def test_parse_rpm_sqlite_missing_file(tmp_path):
    """Returns empty list when the database file does not exist."""
    pkgs = _parse_rpm_sqlite(tmp_path / "nonexistent.sqlite")
    assert pkgs == []


def test_parse_rpm_sqlite_multiple_packages(tmp_path):
    """All rows in the Packages table are returned."""
    db = tmp_path / "rpmdb.sqlite"
    _make_rpm_sqlite(
        db,
        [
            ("bash", "5.1.8", "6.el9", 0, "x86_64"),
            ("coreutils", "8.32", "34.el9", 0, "x86_64"),
            ("systemd", "250", "12.el9_1.3", 0, "x86_64"),
        ],
    )

    pkgs = _parse_rpm_sqlite(db)
    assert len(pkgs) == 3
    names = {p.name for p in pkgs}
    assert names == {"bash", "coreutils", "systemd"}


def test_parse_rpm_packages_no_binary(monkeypatch, tmp_path):
    """When rpm binary is absent and no SQLite DB, returns empty list gracefully."""
    monkeypatch.setattr("shutil.which", lambda name: None)

    pkgs = parse_rpm_packages(tmp_path)
    assert pkgs == []


def test_parse_rpm_packages_uses_sqlite_when_present(tmp_path):
    """parse_rpm_packages prefers SQLite DB over rpm binary."""
    rpm_dir = tmp_path / "var" / "lib" / "rpm"
    rpm_dir.mkdir(parents=True)
    db = rpm_dir / "rpmdb.sqlite"
    _make_rpm_sqlite(db, [("bash", "5.1.8", "6.el9", 0, "x86_64")])

    pkgs = parse_rpm_packages(tmp_path)
    assert len(pkgs) == 1
    assert pkgs[0].name == "bash"


def test_parse_rpm_sqlite_arch_in_purl(tmp_path):
    """Architecture is included as a query parameter in the PURL."""
    db = tmp_path / "rpmdb.sqlite"
    _make_rpm_sqlite(db, [("kernel", "5.14.0", "70.13.1.el9_0", 0, "x86_64")])

    pkgs = _parse_rpm_sqlite(db)
    assert len(pkgs) == 1
    assert "arch=x86_64" in pkgs[0].purl
