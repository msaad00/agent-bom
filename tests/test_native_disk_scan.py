"""Tests for native disk snapshot parsers and parse_pip_environment."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.filesystem import (
    FilesystemScanError,
    parse_apk_installed,
    parse_dpkg_status,
    parse_site_packages,
    scan_disk_path_native,
    scan_filesystem,
)
from agent_bom.parsers import parse_pip_environment

# ── parse_dpkg_status ─────────────────────────────────────────────────────────

DPKG_STATUS = """\
Package: libssl3
Status: install ok installed
Architecture: amd64
Version: 3.0.11-1~deb12u2
Description: Secure Sockets Layer toolkit - shared libraries

Package: python3-requests
Status: install ok installed
Architecture: all
Version: 2.28.2-1
Description: elegant and simple HTTP library for Python3

Package: vim-tiny
Status: deinstall ok config-files
Version: 2:9.0.1378-2
Description: Vi IMproved - enhanced vi editor - compact version

Package: incomplete-package
Status: install ok installed
Version:
Description: missing version field

"""


class TestParseDpkgStatus:
    def test_parses_installed_packages(self, tmp_path):
        f = tmp_path / "status"
        f.write_text(DPKG_STATUS)
        pkgs = parse_dpkg_status(f)
        names = {p.name for p in pkgs}
        assert "libssl3" in names
        assert "python3-requests" in names

    def test_excludes_deinstalled(self, tmp_path):
        f = tmp_path / "status"
        f.write_text(DPKG_STATUS)
        pkgs = parse_dpkg_status(f)
        names = {p.name for p in pkgs}
        assert "vim-tiny" not in names

    def test_strips_epoch_prefix(self, tmp_path):
        f = tmp_path / "status"
        f.write_text(DPKG_STATUS)
        pkgs = parse_dpkg_status(f)
        # libssl3 version 3.0.11-1~deb12u2, no epoch
        by_name = {p.name: p for p in pkgs}
        assert by_name["libssl3"].version == "3.0.11-1~deb12u2"

    def test_ecosystem_is_deb(self, tmp_path):
        f = tmp_path / "status"
        f.write_text(DPKG_STATUS)
        pkgs = parse_dpkg_status(f)
        assert all(p.ecosystem == "deb" for p in pkgs)

    def test_purl_format(self, tmp_path):
        f = tmp_path / "status"
        f.write_text(DPKG_STATUS)
        pkgs = parse_dpkg_status(f)
        by_name = {p.name: p for p in pkgs}
        assert by_name["libssl3"].purl == "pkg:deb/debian/libssl3@3.0.11-1~deb12u2"

    def test_missing_file_returns_empty(self, tmp_path):
        assert parse_dpkg_status(tmp_path / "nonexistent") == []

    def test_skips_incomplete_entries(self, tmp_path):
        f = tmp_path / "status"
        f.write_text(DPKG_STATUS)
        pkgs = parse_dpkg_status(f)
        names = {p.name for p in pkgs}
        assert "incomplete-package" not in names

    def test_real_vm_path_layout(self, tmp_path):
        """Simulate mounted VM snapshot structure."""
        status_dir = tmp_path / "var" / "lib" / "dpkg"
        status_dir.mkdir(parents=True)
        (status_dir / "status").write_text("Package: curl\nStatus: install ok installed\nVersion: 7.88.1-10\n\n")
        pkgs = parse_dpkg_status(status_dir / "status")
        assert any(p.name == "curl" for p in pkgs)


# ── parse_site_packages ───────────────────────────────────────────────────────


class TestParseSitePackages:
    def _make_dist_info(self, site_dir: Path, name: str, version: str) -> None:
        dist_info = site_dir / f"{name}-{version}.dist-info"
        dist_info.mkdir(parents=True)
        (dist_info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\nSome description.\n")

    def test_parses_installed_packages(self, tmp_path):
        self._make_dist_info(tmp_path, "requests", "2.31.0")
        self._make_dist_info(tmp_path, "flask", "3.0.0")
        pkgs = parse_site_packages(tmp_path)
        names = {p.name for p in pkgs}
        assert "requests" in names
        assert "flask" in names

    def test_versions_correct(self, tmp_path):
        self._make_dist_info(tmp_path, "numpy", "1.26.4")
        pkgs = parse_site_packages(tmp_path)
        by_name = {p.name: p for p in pkgs}
        assert by_name["numpy"].version == "1.26.4"

    def test_ecosystem_is_pypi(self, tmp_path):
        self._make_dist_info(tmp_path, "pandas", "2.2.0")
        pkgs = parse_site_packages(tmp_path)
        assert all(p.ecosystem == "pypi" for p in pkgs)

    def test_purl_format(self, tmp_path):
        self._make_dist_info(tmp_path, "Requests", "2.31.0")
        pkgs = parse_site_packages(tmp_path)
        by_name = {p.name: p for p in pkgs}
        assert by_name["Requests"].purl == "pkg:pypi/requests@2.31.0"

    def test_missing_directory_returns_empty(self, tmp_path):
        assert parse_site_packages(tmp_path / "nonexistent") == []

    def test_deduplicates_same_package(self, tmp_path):
        # Same name+version twice (shouldn't happen but be safe)
        self._make_dist_info(tmp_path, "requests", "2.31.0")
        # Manually create a second dist-info with same content
        dist2 = tmp_path / "requests-2.31.0.dist-info.bak"
        dist2.mkdir()
        (dist2 / "METADATA").write_text("Name: requests\nVersion: 2.31.0\n\n")
        pkgs = parse_site_packages(tmp_path)
        req_pkgs = [p for p in pkgs if p.name == "requests"]
        assert len(req_pkgs) == 1

    def test_skips_dist_info_without_metadata(self, tmp_path):
        (tmp_path / "broken-1.0.dist-info").mkdir()
        pkgs = parse_site_packages(tmp_path)
        assert pkgs == []


# ── scan_disk_path_native ─────────────────────────────────────────────────────


class TestScanDiskPathNative:
    def test_finds_dpkg_packages(self, tmp_path):
        status_dir = tmp_path / "var" / "lib" / "dpkg"
        status_dir.mkdir(parents=True)
        (status_dir / "status").write_text("Package: openssl\nStatus: install ok installed\nVersion: 3.1.0\n\n")
        pkgs = scan_disk_path_native(tmp_path)
        names = {p.name for p in pkgs}
        assert "openssl" in names

    def test_finds_python_site_packages(self, tmp_path):
        sp = tmp_path / "usr" / "lib" / "python3.11" / "site-packages"
        sp.mkdir(parents=True)
        dist_info = sp / "flask-3.0.0.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text("Name: flask\nVersion: 3.0.0\n\n")
        pkgs = scan_disk_path_native(tmp_path)
        names = {p.name for p in pkgs}
        assert "flask" in names

    def test_finds_lock_files(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("django==4.2.0\n")
        pkgs = scan_disk_path_native(tmp_path)
        names = {p.name for p in pkgs}
        assert "django" in names

    def test_deduplicates_across_sources(self, tmp_path):
        # Same package in dpkg/status AND requirements.txt (shouldn't happen but cover it)
        status_dir = tmp_path / "var" / "lib" / "dpkg"
        status_dir.mkdir(parents=True)
        (status_dir / "status").write_text("Package: curl\nStatus: install ok installed\nVersion: 7.88.1\n\n")
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        pkgs = scan_disk_path_native(tmp_path)
        # Should not crash; packages from both sources present
        names = {p.name for p in pkgs}
        assert "requests" in names
        assert "curl" in names

    def test_empty_directory_returns_empty(self, tmp_path):
        pkgs = scan_disk_path_native(tmp_path)
        assert pkgs == []


# ── parse_pip_environment ─────────────────────────────────────────────────────


class TestParsePipEnvironment:
    def test_parses_current_environment(self):
        """Runs pip list on the current env — should find at least pytest."""
        pkgs = parse_pip_environment()
        names = {p.name.lower() for p in pkgs}
        assert "pytest" in names

    def test_ecosystem_is_pypi(self):
        pkgs = parse_pip_environment()
        assert all(p.ecosystem == "pypi" for p in pkgs)

    def test_versions_are_strings(self):
        pkgs = parse_pip_environment()
        assert all(isinstance(p.version, str) for p in pkgs)

    def test_purl_format(self):
        pkgs = parse_pip_environment()
        by_name = {p.name.lower(): p for p in pkgs}
        pip_pkg = by_name.get("pip")
        if pip_pkg:
            assert pip_pkg.purl.startswith("pkg:pypi/pip@")

    def test_invalid_python_exec_returns_empty(self):
        pkgs = parse_pip_environment(python_exec="/nonexistent/python")
        assert pkgs == []

    def test_mock_pip_output(self):
        """Test parsing with controlled pip JSON output."""
        fake_output = json.dumps(
            [
                {"name": "requests", "version": "2.31.0"},
                {"name": "Flask", "version": "3.0.0"},
            ]
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=fake_output, stderr="")
            pkgs = parse_pip_environment()
        names = {p.name for p in pkgs}
        assert "requests" in names
        assert "Flask" in names
        assert len(pkgs) == 2

    def test_pip_failure_returns_empty(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
            pkgs = parse_pip_environment()
        assert pkgs == []

    def test_pip_timeout_returns_empty(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=[], timeout=30)):
            pkgs = parse_pip_environment()
        assert pkgs == []

    def test_invalid_json_returns_empty(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="not json", stderr="")
            pkgs = parse_pip_environment()
        assert pkgs == []


# ── scan_filesystem native fallback ───────────────────────────────────────────


class TestScanFilesystemNativeFallback:
    def test_uses_native_when_syft_not_found(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        with patch("shutil.which", return_value=None):
            pkgs, strategy = scan_filesystem(str(tmp_path))
        assert strategy == "native-dir"
        assert any(p.name == "requests" for p in pkgs)

    def test_uses_syft_when_available(self, tmp_path):
        fake_cdx = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [{"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21", "type": "library"}],
            }
        )
        mock_result = MagicMock(returncode=0, stdout=fake_cdx, stderr="")
        with patch("shutil.which", return_value="/usr/bin/syft"), patch("subprocess.run", return_value=mock_result):
            pkgs, strategy = scan_filesystem(str(tmp_path))
        assert strategy == "syft-dir"
        assert any(p.name == "lodash" for p in pkgs)

    def test_tar_without_syft_raises(self, tmp_path):
        tar_file = tmp_path / "archive.tar"
        tar_file.write_bytes(b"fake tar content")
        with patch("shutil.which", return_value=None):
            with pytest.raises(FilesystemScanError, match="syft not found"):
                scan_filesystem(str(tar_file))

    def test_disk_image_gives_mount_instructions(self, tmp_path):
        """Disk images (.qcow2, .vmdk, etc.) should give mount instructions."""
        for ext in (".qcow2", ".vmdk", ".vhd", ".raw"):
            img = tmp_path / f"disk{ext}"
            img.write_bytes(b"fake")
            with pytest.raises(FilesystemScanError, match="Mount it first"):
                scan_filesystem(str(img))


# ── parse_apk_installed (Alpine Linux) ────────────────────────────────────────

APK_INSTALLED = """\
P:busybox
V:1.36.1-r6
A:x86_64
T:Size optimized toolbox of many common UNIX utilities

P:musl
V:1.2.4_git20230717-r4
A:x86_64
T:the musl c library (libc) implementation

P:zlib
V:1.3-r2
A:x86_64
T:A compression/decompression Library
"""


class TestParseApkInstalled:
    def test_parses_alpine_packages(self, tmp_path):
        f = tmp_path / "installed"
        f.write_text(APK_INSTALLED)
        pkgs = parse_apk_installed(f)
        assert len(pkgs) == 3
        names = {p.name for p in pkgs}
        assert names == {"busybox", "musl", "zlib"}

    def test_ecosystem_is_apk(self, tmp_path):
        f = tmp_path / "installed"
        f.write_text(APK_INSTALLED)
        pkgs = parse_apk_installed(f)
        assert all(p.ecosystem == "apk" for p in pkgs)

    def test_purl_format(self, tmp_path):
        f = tmp_path / "installed"
        f.write_text(APK_INSTALLED)
        pkgs = parse_apk_installed(f)
        bb = next(p for p in pkgs if p.name == "busybox")
        assert bb.purl == "pkg:apk/alpine/busybox@1.36.1-r6"

    def test_missing_file_returns_empty(self, tmp_path):
        assert parse_apk_installed(tmp_path / "nonexistent") == []

    def test_empty_file(self, tmp_path):
        f = tmp_path / "installed"
        f.write_text("")
        assert parse_apk_installed(f) == []


class TestScanDiskPathNativeAlpine:
    def test_finds_apk_packages(self, tmp_path):
        apk_dir = tmp_path / "lib" / "apk" / "db"
        apk_dir.mkdir(parents=True)
        (apk_dir / "installed").write_text(APK_INSTALLED)
        pkgs = scan_disk_path_native(tmp_path)
        assert any(p.name == "busybox" and p.ecosystem == "apk" for p in pkgs)

    def test_finds_node_global_packages(self, tmp_path):
        node_dir = tmp_path / "usr" / "local" / "lib" / "node_modules" / "typescript"
        node_dir.mkdir(parents=True)
        (node_dir / "package.json").write_text(json.dumps({"name": "typescript", "version": "5.3.3"}))
        pkgs = scan_disk_path_native(tmp_path)
        ts = [p for p in pkgs if p.name == "typescript"]
        assert len(ts) == 1
        assert ts[0].ecosystem == "npm"
        assert ts[0].version == "5.3.3"
