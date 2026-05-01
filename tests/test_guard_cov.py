"""Tests for guard module — coverage expansion for async and sync functions."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, patch

import pytest

from agent_bom.guard import (
    _check_package,
    _find_real_tool,
    guard_install,
    run_guarded_install,
)


class TestGuardInstall:
    @pytest.mark.asyncio
    async def test_unknown_tool(self):
        result = await guard_install("ruby", ["install", "rails"])
        assert result.install_allowed is True

    @pytest.mark.asyncio
    async def test_no_packages_found(self):
        result = await guard_install("pip", ["list"])
        assert result.install_allowed is True
        assert result.packages_checked == 0

    @pytest.mark.asyncio
    async def test_pip_with_clean_packages(self):
        async def mock_check(name, eco, **_kwargs):
            return {"name": name, "ecosystem": eco, "vulns": [], "blocked": False}

        with patch("agent_bom.guard._check_package", side_effect=mock_check):
            result = await guard_install("pip", ["install", "requests", "flask"])
            assert result.packages_checked == 2
            assert result.packages_clean == 2
            assert result.install_allowed is True

    @pytest.mark.asyncio
    async def test_npm_with_blocked_packages(self):
        async def mock_check(name, eco, **_kwargs):
            return {
                "name": name,
                "ecosystem": eco,
                "vulns": [{"id": "CVE-2024-001", "severity": "critical"}],
                "blocked": True,
                "vuln_count": 1,
            }

        with patch("agent_bom.guard._check_package", side_effect=mock_check):
            result = await guard_install("npm", ["install", "lodash"])
            assert result.packages_blocked == 1
            assert result.install_allowed is False

    @pytest.mark.asyncio
    async def test_allow_risky_overrides_block(self):
        async def mock_check(name, eco, **_kwargs):
            return {"name": name, "ecosystem": eco, "vulns": [{"id": "CVE-2024-001"}], "blocked": True, "vuln_count": 1}

        with patch("agent_bom.guard._check_package", side_effect=mock_check):
            result = await guard_install("pip", ["install", "badpkg"], allow_risky=True)
            assert result.packages_blocked == 1
            assert result.install_allowed is True

    @pytest.mark.asyncio
    async def test_allow_risky_does_not_override_scan_failure(self):
        async def mock_check(name, eco, **_kwargs):
            return {
                "name": name,
                "ecosystem": eco,
                "error": "lookup_names",
                "vulns": [],
                "blocked": True,
                "scan_failed": True,
                "vuln_count": 0,
            }

        with patch("agent_bom.guard._check_package", side_effect=mock_check):
            result = await guard_install("pip", ["install", "badpkg"], allow_risky=True)

        assert result.packages_blocked == 1
        assert result.install_allowed is False

    @pytest.mark.asyncio
    async def test_npx_tool(self):
        async def mock_check(name, eco, **_kwargs):
            return {"name": name, "ecosystem": eco, "vulns": [], "blocked": False}

        with patch("agent_bom.guard._check_package", side_effect=mock_check):
            result = await guard_install("npx", ["install", "express"])
            assert result.packages_checked == 1

    @pytest.mark.asyncio
    async def test_pip_scanner_error_fails_closed(self):
        async def mock_check(name, eco, **_kwargs):
            return {
                "name": name,
                "ecosystem": eco,
                "error": "Package object missing lookup_names",
                "vulns": [],
                "blocked": True,
                "scan_failed": True,
                "vuln_count": 0,
            }

        with patch("agent_bom.guard._check_package", side_effect=mock_check):
            result = await guard_install("pip", ["install", "requests"])

        assert result.packages_checked == 1
        assert result.packages_blocked == 1
        assert result.packages_clean == 0
        assert result.clean == []
        assert result.blocked[0]["scan_failed"] is True
        assert result.install_allowed is False

    @pytest.mark.asyncio
    async def test_npm_scanner_error_fails_closed(self):
        async def mock_check(name, eco, **_kwargs):
            return {
                "name": name,
                "ecosystem": eco,
                "error": "Package object missing license",
                "vulns": [],
                "blocked": True,
                "scan_failed": True,
                "vuln_count": 0,
            }

        with patch("agent_bom.guard._check_package", side_effect=mock_check):
            result = await guard_install("npm", ["install", "express"])

        assert result.packages_checked == 1
        assert result.packages_blocked == 1
        assert result.packages_clean == 0
        assert result.clean == []
        assert result.blocked[0]["scan_failed"] is True
        assert result.install_allowed is False


class TestCheckPackage:
    @pytest.mark.asyncio
    async def test_constructs_scanner_package_model(self):
        captured = {}

        async def mock_scan(packages, **_kwargs):
            captured["package"] = packages[0]
            return 0

        with patch("agent_bom.scanners.scan_packages", new=AsyncMock(side_effect=mock_scan)):
            result = await _check_package("requests", "pypi")

        pkg = captured["package"]
        assert pkg.name == "requests"
        assert pkg.version == "latest"
        assert pkg.ecosystem == "pypi"
        assert pkg.lookup_names == ["requests"]
        assert hasattr(pkg, "license")
        assert result["blocked"] is False

    @pytest.mark.asyncio
    async def test_scan_exception_blocks_package(self):
        with patch("agent_bom.scanners.scan_packages", new=AsyncMock(side_effect=AttributeError("lookup_names"))):
            result = await _check_package("express", "npm")

        assert result["blocked"] is True
        assert result["scan_failed"] is True
        assert result["error"] == "lookup_names"


class TestFindRealTool:
    def test_finds_real_binary(self):
        with patch("shutil.which", return_value="/usr/bin/pip"):
            with patch("os.path.realpath", return_value="/usr/bin/pip"):
                result = _find_real_tool("pip")
                assert result == "/usr/bin/pip"

    def test_rejects_agent_bom_binary(self):
        with patch("shutil.which", return_value="/usr/local/bin/agent-bom"):
            with patch("os.path.realpath", return_value="/usr/local/bin/agent-bom"):
                result = _find_real_tool("pip")
                assert result is None or "agent-bom" not in (result or "")

    def test_fallback_common_paths(self):
        with patch("shutil.which", return_value=None):
            with patch("os.path.isfile", return_value=False):
                result = _find_real_tool("pip")
                assert result is None

    def test_no_tool_found(self):
        with patch("shutil.which", return_value=None):
            with patch("os.path.isfile", return_value=False):
                result = _find_real_tool("nonexistent")
                assert result is None


class TestRunGuardedInstall:
    def test_blocked_install(self):
        from agent_bom.guard import GuardResult

        mock_result = GuardResult(
            packages_checked=1,
            packages_blocked=1,
            install_allowed=False,
            blocked=[{"name": "badpkg", "vulns": [{"id": "CVE-2024-1"}], "vuln_count": 1}],
        )
        with patch("agent_bom.guard.guard_install_sync", return_value=mock_result):
            exit_code = run_guarded_install("pip", ["install", "badpkg"])
            assert exit_code == 1

    def test_allowed_install_no_tool_found(self):
        from agent_bom.guard import GuardResult

        mock_result = GuardResult(packages_checked=1, packages_clean=1, install_allowed=True, clean=["goodpkg"])
        with (
            patch("agent_bom.guard.guard_install_sync", return_value=mock_result),
            patch("agent_bom.guard._find_real_tool", return_value=None),
        ):
            exit_code = run_guarded_install("pip", ["install", "goodpkg"])
            assert exit_code == 1

    def test_allowed_risky_install(self):
        from agent_bom.guard import GuardResult

        mock_result = GuardResult(
            packages_checked=1,
            packages_blocked=1,
            install_allowed=True,
            blocked=[{"name": "risky", "vuln_count": 1}],
            clean=[],
        )
        with (
            patch("agent_bom.guard.guard_install_sync", return_value=mock_result),
            patch("agent_bom.guard._find_real_tool", return_value=None),
        ):
            exit_code = run_guarded_install("pip", ["install", "risky"], allow_risky=True)
            assert exit_code == 1

    def test_allowed_install_logs_sanitized_command(self, caplog):
        from agent_bom.guard import GuardResult

        mock_result = GuardResult(packages_checked=1, packages_clean=1, install_allowed=True, clean=["goodpkg"])
        secret_url = "https://user:token@example.com/simple"

        with (
            patch("agent_bom.guard.guard_install_sync", return_value=mock_result),
            patch("agent_bom.guard._find_real_tool", return_value="/usr/bin/pip"),
            patch("agent_bom.guard.subprocess.call", return_value=0),
            caplog.at_level(logging.INFO, logger="agent_bom.guard"),
        ):
            exit_code = run_guarded_install("pip", ["install", "goodpkg", "--extra-index-url", secret_url])

        assert exit_code == 0
        assert secret_url not in caplog.text
        assert "Executing:" not in caplog.text
        assert "Executing guarded pip install for 1 package(s)" in caplog.text
