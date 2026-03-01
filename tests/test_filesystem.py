"""Tests for filesystem/disk snapshot scanning via Syft."""

import json
import subprocess

import pytest

from agent_bom.filesystem import (
    FilesystemScanError,
    _run_syft,
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


def test_syft_not_found(monkeypatch, tmp_path):
    """Missing syft binary raises FilesystemScanError."""
    monkeypatch.setattr("shutil.which", lambda name: None)

    with pytest.raises(FilesystemScanError, match="syft not found"):
        scan_filesystem(str(tmp_path))


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
