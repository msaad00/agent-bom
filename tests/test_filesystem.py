"""Tests for filesystem/disk snapshot scanning via Syft."""

import json
import shutil
import subprocess
from pathlib import Path

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


def test_scan_directory(tmp_path):
    """Native directory scan returns empty for empty dir."""
    packages, strategy = scan_filesystem(str(tmp_path))
    assert strategy == "native-dir"
    assert len(packages) == 0


def test_scan_directory_with_packages(tmp_path):
    """Native directory scan discovers packages from lockfiles."""
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask==3.0.0\n")

    packages, strategy = scan_filesystem(str(tmp_path))
    assert strategy == "native-dir"
    names = {p.name for p in packages}
    assert "requests" in names or "flask" in names


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
    """Non-zero exit code raises FilesystemScanError for tar archives."""
    tar_file = tmp_path / "test.tar"
    tar_file.touch()

    def _fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="permission denied")

    # Mock OCI parser to return empty result (so Syft fallback is tried)
    import agent_bom.oci_parser as _oci_mod

    _orig_parse = _oci_mod.parse_oci_tarball
    monkeypatch.setattr(
        _oci_mod,
        "parse_oci_tarball",
        lambda p: type("R", (), {"packages": []})(),
    )
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/syft")
    monkeypatch.setattr("agent_bom.filesystem.subprocess.run", _fake_run)

    with pytest.raises(FilesystemScanError, match="syft exited 1"):
        scan_filesystem(str(tar_file))


def test_syft_timeout(monkeypatch, tmp_path):
    """Subprocess timeout raises FilesystemScanError for tar archives."""
    tar_file = tmp_path / "test.tar"
    tar_file.touch()

    import agent_bom.oci_parser as _oci_mod

    monkeypatch.setattr(
        _oci_mod,
        "parse_oci_tarball",
        lambda p: type("R", (), {"packages": []})(),
    )

    def _fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 600))

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/syft")
    monkeypatch.setattr("agent_bom.filesystem.subprocess.run", _fake_run)

    with pytest.raises(FilesystemScanError, match="timed out"):
        scan_filesystem(str(tar_file), timeout=10)


def test_syft_invalid_json(monkeypatch, tmp_path):
    """Invalid JSON output raises FilesystemScanError for tar archives."""
    tar_file = tmp_path / "test.tar"
    tar_file.touch()

    import agent_bom.oci_parser as _oci_mod

    monkeypatch.setattr(
        _oci_mod,
        "parse_oci_tarball",
        lambda p: type("R", (), {"packages": []})(),
    )

    def _fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="not json {{{", stderr="")

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/syft")
    monkeypatch.setattr("agent_bom.filesystem.subprocess.run", _fake_run)

    with pytest.raises(FilesystemScanError, match="not valid JSON"):
        scan_filesystem(str(tar_file))


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


def test_batch_scan_success(tmp_path):
    """Batch scan processes multiple directories using native scanner."""
    dir1 = tmp_path / "snap1"
    dir1.mkdir()
    dir2 = tmp_path / "snap2"
    dir2.mkdir()
    # Add lockfiles so native scanner finds packages
    (dir1 / "requirements.txt").write_text("requests==2.31.0\n")
    (dir2 / "requirements.txt").write_text("flask==3.0.0\n")

    results = scan_filesystem_batch([str(dir1), str(dir2)])
    assert len(results) == 2
    assert results[0][2] == "native-dir"
    assert results[1][2] == "native-dir"


def test_batch_scan_partial_failure(tmp_path):
    """Batch scan handles empty directories gracefully."""
    good_dir = tmp_path / "good"
    good_dir.mkdir()
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    (good_dir / "requirements.txt").write_text("requests==2.31.0\n")

    results = scan_filesystem_batch([str(good_dir), str(empty_dir)])
    assert results[0][2] == "native-dir"
    assert results[1][2] == "native-dir"
    assert results[1][1] == []  # Empty dir = no packages


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


REAL_RPMDB = Path(__file__).parent / "fixtures" / "rpmdb_sqlite_min.sqlite"


def _make_rpm_sqlite(db_path, _rows=None):
    """Place a REAL rpmdb.sqlite at ``db_path``.

    This used to fabricate the schema::

        CREATE TABLE Packages (name TEXT, version TEXT, release TEXT, epoch INTEGER, arch TEXT)

    Those columns exist in no rpmdb. RHEL 9+ ships
    ``Packages(hnum INTEGER PRIMARY KEY, blob BLOB)``, one binary RPM header per
    row. So every test below validated the parser against an invented format,
    and all of them stayed green while `agent-bom fs` returned zero packages for
    every RHEL / UBI / Fedora / Amazon Linux filesystem.

    The fixture is the one the OCI path already scans, so both code paths are
    now tested against the same real bytes.
    """
    shutil.copy(REAL_RPMDB, db_path)


def test_parse_rpm_sqlite_db(tmp_path):
    """_parse_rpm_sqlite reads the real Packages table and returns Packages."""
    db = tmp_path / "rpmdb.sqlite"
    _make_rpm_sqlite(db)

    pkgs = _parse_rpm_sqlite(db)
    assert pkgs, "a genuine rpmdb.sqlite produced no packages"
    by_name = {p.name: p for p in pkgs}
    assert "bash" in by_name
    assert by_name["bash"].ecosystem == "rpm"
    assert "5.1.8" in by_name["bash"].version


def test_parse_rpm_sqlite_version_includes_release(tmp_path):
    """The RPM version carries its release suffix, as the advisory feeds key on."""
    db = tmp_path / "rpmdb.sqlite"
    _make_rpm_sqlite(db)

    by_name = {p.name: p.version for p in _parse_rpm_sqlite(db)}
    assert by_name["bash"] == "5.1.8-9.el9", by_name
    assert by_name["openssl-libs"] == "3.0.7-27.el9", by_name


def test_rpm_purl_is_well_formed(tmp_path):
    db = tmp_path / "rpmdb.sqlite"
    _make_rpm_sqlite(db)

    by_name = {p.name: p.purl for p in _parse_rpm_sqlite(db)}
    assert by_name["bash"] == "pkg:rpm/rhel/bash@5.1.8-9.el9", by_name


def test_parse_rpm_sqlite_missing_file(tmp_path):
    """Returns empty list when the database file does not exist."""
    pkgs = _parse_rpm_sqlite(tmp_path / "nonexistent.sqlite")
    assert pkgs == []


def test_parse_rpm_sqlite_multiple_packages(tmp_path):
    """Every header row in the database is returned."""
    db = tmp_path / "rpmdb.sqlite"
    _make_rpm_sqlite(db)

    names = {p.name for p in _parse_rpm_sqlite(db)}
    assert {"bash", "openssl-libs"} <= names, sorted(names)


def test_parse_rpm_packages_no_binary(monkeypatch, tmp_path):
    """When rpm binary is absent and no SQLite DB, returns empty list gracefully."""
    monkeypatch.setattr("shutil.which", lambda name: None)

    pkgs = parse_rpm_packages(tmp_path)
    assert pkgs == []


def test_parse_rpm_packages_uses_sqlite_when_present(tmp_path):
    """parse_rpm_packages prefers SQLite DB over rpm binary."""
    rpm_dir = tmp_path / "var" / "lib" / "rpm"
    rpm_dir.mkdir(parents=True)
    _make_rpm_sqlite(rpm_dir / "rpmdb.sqlite")

    pkgs = parse_rpm_packages(tmp_path)
    assert "bash" in {p.name for p in pkgs}


# ─── discover_filesystem_mcps ─────────────────────────────────────────────────


def test_discover_filesystem_mcps_finds_claude(tmp_path):
    """Discover MCP configs inside a mounted filesystem."""
    from agent_bom.discovery import discover_filesystem_mcps

    # Create a fake home with Claude Desktop config
    home = tmp_path / "home" / "user"
    config_dir = home / ".config" / "Claude"
    config_dir.mkdir(parents=True)
    config_file = config_dir / "claude_desktop_config.json"
    config_file.write_text('{"mcpServers":{"myserver":{"command":"npx","args":["@myorg/mcp-server"]}}}')

    agents = discover_filesystem_mcps(tmp_path)
    assert len(agents) >= 1
    assert any("claude" in a.name.lower() for a in agents)
    assert agents[0].mcp_servers  # Has at least one server


def test_discover_filesystem_mcps_empty_dir(tmp_path):
    """No MCP configs in empty dir returns empty list."""
    from agent_bom.discovery import discover_filesystem_mcps

    agents = discover_filesystem_mcps(tmp_path)
    assert agents == []


def test_discover_filesystem_mcps_blocks_symlink_escape(tmp_path):
    """Symlinks escaping root are rejected."""
    from agent_bom.discovery import discover_filesystem_mcps

    home = tmp_path / "home" / "user" / ".config" / "Claude"
    home.mkdir(parents=True)
    # Create a symlink that points outside the root
    link = home / "claude_desktop_config.json"
    link.symlink_to("/etc/passwd")

    agents = discover_filesystem_mcps(tmp_path)
    # Should not parse /etc/passwd
    assert agents == []
