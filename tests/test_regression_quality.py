"""Regression tests for quality issues found by Codex audits.

These tests prevent regressions on fixes that were verified at runtime.
"""

from __future__ import annotations

import re


class TestFixVersionFiltering:
    """Ensure git SHAs and commit hashes never appear as fix recommendations."""

    def test_vulnerability_model_filters_40char_sha(self):
        from agent_bom.models import Severity, Vulnerability

        v = Vulnerability(
            id="CVE-2024-99999",
            summary="Test",
            severity=Severity.HIGH,
            fixed_version="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        )
        assert v.fixed_version is None, "40-char SHA should be filtered"

    def test_vulnerability_model_filters_short_sha(self):
        from agent_bom.models import Severity, Vulnerability

        v = Vulnerability(
            id="CVE-2024-99999",
            summary="Test",
            severity=Severity.HIGH,
            fixed_version="a1b2c3d",
        )
        assert v.fixed_version is None, "7-char hex-only string should be filtered"

    def test_vulnerability_model_keeps_semver(self):
        from agent_bom.models import Severity, Vulnerability

        v = Vulnerability(
            id="CVE-2024-99999",
            summary="Test",
            severity=Severity.HIGH,
            fixed_version="2.32.4",
        )
        assert v.fixed_version == "2.32.4"

    def test_vulnerability_model_keeps_v_prefixed(self):
        from agent_bom.models import Severity, Vulnerability

        v = Vulnerability(
            id="CVE-2024-99999",
            summary="Test",
            severity=Severity.HIGH,
            fixed_version="v1.2.3",
        )
        assert v.fixed_version == "v1.2.3"

    def test_vulnerability_model_filters_no_digits(self):
        from agent_bom.models import Severity, Vulnerability

        v = Vulnerability(
            id="CVE-2024-99999",
            summary="Test",
            severity=Severity.HIGH,
            fixed_version="main",
        )
        assert v.fixed_version is None, "'main' has no digits"

    def test_vulnerability_model_keeps_none(self):
        from agent_bom.models import Severity, Vulnerability

        v = Vulnerability(
            id="CVE-2024-99999",
            summary="Test",
            severity=Severity.HIGH,
            fixed_version=None,
        )
        assert v.fixed_version is None

    def test_parse_fixed_version_filters_sha(self):
        from agent_bom.scanners import _is_valid_fix_version

        assert _is_valid_fix_version("2.32.4") is True
        assert _is_valid_fix_version("v1.0.0") is True
        assert _is_valid_fix_version("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2") is False
        assert _is_valid_fix_version("a1b2c3d") is False
        assert _is_valid_fix_version("") is False
        assert _is_valid_fix_version("main") is False


class TestInventoryIsolation:
    """Ensure --inventory does not auto-detect CWD lockfiles or IaC."""

    def test_inventory_guard_in_discovery(self):
        """The auto-detection guards must include 'and not inventory'."""
        from pathlib import Path

        discovery_path = Path("src/agent_bom/cli/agents/_discovery.py")
        content = discovery_path.read_text()

        # Both auto-detection blocks must check for inventory
        lockfile_guard = re.search(r"if not filesystem_paths.*and not inventory", content)
        iac_guard = re.search(r"if not iac_paths.*and not inventory", content)

        assert lockfile_guard, "Lockfile auto-detection must check 'and not inventory'"
        assert iac_guard, "IaC auto-detection must check 'and not inventory'"


class TestCountConsistency:
    """Ensure counts in docs match source of truth in code."""

    def test_mcp_tool_count_matches_pyproject(self):
        """MCP tool count in pyproject.toml must match actual @mcp.tool decorators."""
        from pathlib import Path

        mcp_server = Path("src/agent_bom/mcp_server.py").read_text()
        actual_tools = mcp_server.count("@mcp.tool")

        pyproject = Path("pyproject.toml").read_text()
        # Extract "33 MCP tools" or similar from description
        match = re.search(r"(\d+) MCP tools", pyproject)
        if match:
            claimed = int(match.group(1))
            assert claimed == actual_tools, f"pyproject.toml claims {claimed} MCP tools but code has {actual_tools}"

    def test_detector_count_in_readme(self):
        """Detector count in README must match actual detector classes."""
        from pathlib import Path

        detectors = Path("src/agent_bom/runtime/detectors.py").read_text()
        actual = len(
            re.findall(
                r"^class \w+(?:Detector|Analyzer|Inspector|Correlator|Tracker)\b",
                detectors,
                re.MULTILINE,
            )
        )

        readme = Path("README.md").read_text()
        match = re.search(r"(\d+) behavioral detectors", readme)
        if match:
            claimed = int(match.group(1))
            assert claimed == actual, f"README claims {claimed} detectors but code has {actual}"
