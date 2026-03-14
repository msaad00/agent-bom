"""Tests for OS-level package vulnerability scanning (deb/rpm/apk → OSV)."""

from __future__ import annotations

import pytest

from agent_bom.filesystem import detect_linux_distro
from agent_bom.models import Package
from agent_bom.scanners import ECOSYSTEM_MAP

# ── ECOSYSTEM_MAP coverage ───────────────────────────────────────────────────


class TestEcosystemMap:
    """Verify OS ecosystems are mapped to correct OSV identifiers."""

    def test_deb_maps_to_debian(self):
        assert ECOSYSTEM_MAP["deb"] == "Debian"

    def test_apk_maps_to_alpine(self):
        assert ECOSYSTEM_MAP["apk"] == "Alpine"

    def test_rpm_maps_to_linux(self):
        assert ECOSYSTEM_MAP["rpm"] == "Linux"

    def test_existing_ecosystems_unchanged(self):
        """Ensure adding OS ecosystems didn't break existing mappings."""
        assert ECOSYSTEM_MAP["npm"] == "npm"
        assert ECOSYSTEM_MAP["pypi"] == "PyPI"
        assert ECOSYSTEM_MAP["go"] == "Go"
        assert ECOSYSTEM_MAP["cargo"] == "crates.io"
        assert ECOSYSTEM_MAP["maven"] == "Maven"
        assert ECOSYSTEM_MAP["nuget"] == "NuGet"
        assert ECOSYSTEM_MAP["rubygems"] == "RubyGems"
        assert ECOSYSTEM_MAP["conda"] == "PyPI"


# ── detect_linux_distro ──────────────────────────────────────────────────────


class TestDetectLinuxDistro:
    """Test distro detection from /etc/os-release."""

    def test_debian(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "os-release").write_text('ID=debian\nVERSION_ID="12"\n')
        assert detect_linux_distro(tmp_path) == "debian"

    def test_ubuntu(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "os-release").write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
        assert detect_linux_distro(tmp_path) == "ubuntu"

    def test_alpine(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "os-release").write_text("ID=alpine\nVERSION_ID=3.19\n")
        assert detect_linux_distro(tmp_path) == "alpine"

    def test_rhel(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "os-release").write_text('ID="rhel"\nVERSION_ID="9.3"\n')
        assert detect_linux_distro(tmp_path) == "rhel"

    def test_rocky(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "os-release").write_text('ID="rocky"\nVERSION_ID="9.3"\n')
        assert detect_linux_distro(tmp_path) == "rocky"

    def test_almalinux(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "os-release").write_text('ID="almalinux"\nVERSION_ID="9.3"\n')
        assert detect_linux_distro(tmp_path) == "almalinux"

    def test_missing_os_release(self, tmp_path):
        """Falls back to 'linux' when /etc/os-release does not exist."""
        assert detect_linux_distro(tmp_path) == "linux"

    def test_empty_os_release(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "os-release").write_text("")
        assert detect_linux_distro(tmp_path) == "linux"

    def test_missing_id_field(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "os-release").write_text('VERSION_ID="12"\nPRETTY_NAME="Some Linux"\n')
        assert detect_linux_distro(tmp_path) == "linux"

    def test_single_quoted_id(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "os-release").write_text("ID='fedora'\n")
        assert detect_linux_distro(tmp_path) == "fedora"

    def test_unquoted_id(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "os-release").write_text("ID=centos\n")
        assert detect_linux_distro(tmp_path) == "centos"


# ── OS packages are not silently skipped by scanner ──────────────────────────


class TestOSPackagesNotSkipped:
    """Verify that packages with deb/rpm/apk ecosystems pass the ecosystem
    filter in the scanner (the core bug this feature fixes)."""

    def test_deb_package_has_osv_ecosystem(self):
        pkg = Package(name="libc6", version="2.36-9", ecosystem="deb")
        eco_key = pkg.ecosystem.lower()
        osv_eco = ECOSYSTEM_MAP.get(eco_key)
        assert osv_eco is not None, "deb packages should not be skipped by scanner"
        assert osv_eco == "Debian"

    def test_apk_package_has_osv_ecosystem(self):
        pkg = Package(name="musl", version="1.2.4-r2", ecosystem="apk")
        eco_key = pkg.ecosystem.lower()
        osv_eco = ECOSYSTEM_MAP.get(eco_key)
        assert osv_eco is not None, "apk packages should not be skipped by scanner"
        assert osv_eco == "Alpine"

    def test_rpm_package_has_osv_ecosystem(self):
        pkg = Package(name="openssl-libs", version="3.0.7-24.el9", ecosystem="rpm")
        eco_key = pkg.ecosystem.lower()
        osv_eco = ECOSYSTEM_MAP.get(eco_key)
        assert osv_eco is not None, "rpm packages should not be skipped by scanner"
        assert osv_eco == "Linux"


# ── Unknown ecosystem warning (no silent failures) ──────────────────────────


class TestUnknownEcosystemWarning:
    """Packages with ecosystems not in ECOSYSTEM_MAP must produce a warning."""

    def test_unknown_ecosystem_logs_warning(self, caplog):
        """Scanner must warn when it skips a package due to unmapped ecosystem."""
        import asyncio
        import logging

        from agent_bom.scanners import scan_packages

        pkg = Package(name="somelib", version="1.0.0", ecosystem="pacman")
        with caplog.at_level(logging.WARNING, logger="agent_bom.scanners"):
            asyncio.run(scan_packages([pkg]))

        assert any("unknown ecosystem" in r.message.lower() for r in caplog.records), (
            "Expected a warning about unknown ecosystem 'pacman', got: " + "; ".join(r.message for r in caplog.records)
        )


# ── CLI flag existence ───────────────────────────────────────────────────────


class TestOSPackagesFlag:
    """Verify --os-packages flag is wired into the CLI."""

    def test_flag_in_scan_params(self):
        """The scan command should accept os_packages parameter."""
        from agent_bom.cli.scan import scan

        # Click commands expose params as a list of Parameter objects
        param_names = [p.name for p in scan.params]
        assert "os_packages" in param_names, "--os-packages flag not found in scan command"

    def test_flag_is_boolean(self):
        """The flag should be a boolean (is_flag=True)."""
        from agent_bom.cli.scan import scan

        for p in scan.params:
            if p.name == "os_packages":
                assert p.is_flag is True
                assert p.default is False
                break
        else:
            pytest.fail("os_packages parameter not found")
