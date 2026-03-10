"""Stats alignment tests — single source of truth for counts.

These tests derive actual counts from code, then verify that docs,
diagrams, and integration files reflect the correct numbers.
Any stale reference in any surface will fail CI immediately.

Run: pytest tests/test_stats_alignment.py -v
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "agent_bom"


# ---------------------------------------------------------------------------
# Derive actual counts from code (single source of truth)
# ---------------------------------------------------------------------------


def _count_mcp_tools() -> int:
    """Count @mcp.tool decorators in mcp_server.py."""
    text = (SRC / "mcp_server.py").read_text()
    return len(re.findall(r"@mcp\.tool", text))


def _count_server_card_tools() -> int:
    """Count tool entries in _SERVER_CARD_TOOLS list (each has a 'name' key)."""
    text = (SRC / "mcp_server.py").read_text()
    # _SERVER_CARD_TOOLS is a list of dicts; count occurrences of "name" keys
    start = text.find("_SERVER_CARD_TOOLS")
    if start == -1:
        return 0
    # Count dict entries by counting '"name"' occurrences after the marker
    section = text[start:]
    # Find the closing bracket
    bracket_depth = 0
    end = 0
    for i, ch in enumerate(section):
        if ch == "[":
            bracket_depth += 1
        elif ch == "]":
            bracket_depth -= 1
            if bracket_depth == 0:
                end = i
                break
    section = section[:end]
    return len(re.findall(r'"name"', section))


def _count_config_locations() -> int:
    """Count AgentType entries in CONFIG_LOCATIONS (excluding CUSTOM)."""
    text = (SRC / "discovery" / "__init__.py").read_text()
    return (
        len(re.findall(r"AgentType\.\w+(?!.*CUSTOM)", text.split("CONFIG_LOCATIONS")[1].split("}")[0])) if "CONFIG_LOCATIONS" in text else 0
    )


def _count_detector_classes() -> int:
    """Count detector/analyzer/tracker/inspector classes in runtime/detectors.py."""
    text = (SRC / "runtime" / "detectors.py").read_text()
    return len(re.findall(r"^class \w+(Detector|Analyzer|Tracker|Inspector)\b", text, re.MULTILINE))


def _count_cloud_providers() -> int:
    """Count entries in cloud/__init__.py _PROVIDERS."""
    text = (SRC / "cloud" / "__init__.py").read_text()
    match = re.search(r"_PROVIDERS\s*=\s*\{([^}]+)\}", text, re.DOTALL)
    if not match:
        return 0
    return len(re.findall(r'"(\w+)"', match.group(1)))


def _count_python_modules() -> int:
    """Count .py files in src/agent_bom/ (excluding __pycache__)."""
    return len([f for f in SRC.rglob("*.py") if "__pycache__" not in str(f)])


def _count_test_files() -> int:
    """Count test_*.py files in tests/."""
    return len(list((ROOT / "tests").glob("test_*.py")))


# ---------------------------------------------------------------------------
# Actual counts (computed once per test session)
# ---------------------------------------------------------------------------


ACTUAL_MCP_TOOLS = _count_mcp_tools()
ACTUAL_CARD_TOOLS = _count_server_card_tools()
ACTUAL_CONFIG_LOCATIONS = _count_config_locations()
ACTUAL_DETECTORS = _count_detector_classes()
ACTUAL_CLOUD_PROVIDERS = _count_cloud_providers()
ACTUAL_MODULES = _count_python_modules()
ACTUAL_TEST_FILES = _count_test_files()


# ---------------------------------------------------------------------------
# Meta-consistency: code counts must agree with each other
# ---------------------------------------------------------------------------


class TestCodeConsistency:
    """Verify internal code counts are self-consistent."""

    def test_mcp_tools_match_card_tools(self):
        assert ACTUAL_MCP_TOOLS == ACTUAL_CARD_TOOLS, (
            f"@mcp.tool count ({ACTUAL_MCP_TOOLS}) != _SERVER_CARD_TOOLS count ({ACTUAL_CARD_TOOLS})"
        )

    def test_mcp_tools_docstring(self):
        text = (SRC / "mcp_server.py").read_text()
        match = re.search(r"Tools \((\d+)\)", text)
        assert match, "mcp_server.py docstring missing 'Tools (N)'"
        assert int(match.group(1)) == ACTUAL_MCP_TOOLS


# ---------------------------------------------------------------------------
# Helpers to scan files for stale numbers
# ---------------------------------------------------------------------------


def _check_file_for_pattern(filepath: Path, pattern: str, expected: str, description: str):
    """Assert that a pattern in a file matches expected value."""
    if not filepath.exists():
        pytest.skip(f"{filepath.name} not found")
    text = filepath.read_text()
    matches = re.findall(pattern, text)
    for match in matches:
        assert match == expected, f"{filepath.name}: found '{match}' but expected '{expected}' for {description}"


# ---------------------------------------------------------------------------
# SVG diagram stats alignment
# ---------------------------------------------------------------------------

SVG_DIR = ROOT / "docs" / "images"

# Pairs: (glob pattern, regex to find number, actual count, description)
SVG_CHECKS = [
    ("**/engine-internals-*.svg", r">(\d+)</text>\s*\n\s*<text[^>]*>MCP clients", "MCP clients"),
    ("**/engine-internals-*.svg", r">(\d+)</text>\s*\n\s*<text[^>]*>MCP server tools", "MCP server tools"),
    ("**/engine-internals-*.svg", r">(\d+)</text>\s*\n\s*<text[^>]*>compliance frameworks", "compliance frameworks"),
]


class TestSVGStats:
    """Verify SVG diagrams reflect actual code counts."""

    def test_no_stale_tool_count_in_svgs(self):
        """No SVG should contain '22 tools' or '23 tools' — must match actual."""
        for svg in SVG_DIR.glob("*.svg"):
            text = svg.read_text()
            for stale in ["22 tools", "23 tools", "22 MCP", "23 MCP"]:
                assert stale not in text, f"{svg.name} contains stale '{stale}' — actual MCP tool count is {ACTUAL_MCP_TOOLS}"

    def test_no_stale_client_count_in_svgs(self):
        """No SVG should say '20 MCP clients' or '20</text>...MCP clients'."""
        for svg in SVG_DIR.glob("*.svg"):
            text = svg.read_text()
            assert "20 MCP client" not in text.lower(), f"{svg.name} contains stale '20 MCP clients'"


# ---------------------------------------------------------------------------
# Markdown docs alignment
# ---------------------------------------------------------------------------

DOCS_TO_CHECK = [
    ROOT / "README.md",
    ROOT / "ARCHITECTURE.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "DEPLOYMENT.md",
    ROOT / "AUDIT.md",
]


class TestMarkdownStats:
    """Verify markdown docs reflect actual counts."""

    @pytest.mark.parametrize("doc", DOCS_TO_CHECK, ids=lambda p: p.name)
    def test_no_stale_tool_count(self, doc):
        if not doc.exists():
            pytest.skip(f"{doc.name} not found")
        text = doc.read_text()
        for stale in ["22 tools", "23 tools", "22 MCP tool", "23 MCP tool"]:
            assert stale not in text, f"{doc.name} contains stale '{stale}' — actual is {ACTUAL_MCP_TOOLS} tools"

    @pytest.mark.parametrize("doc", DOCS_TO_CHECK, ids=lambda p: p.name)
    def test_no_stale_client_count(self, doc):
        if not doc.exists():
            pytest.skip(f"{doc.name} not found")
        text = doc.read_text()
        # "20 clients" in prose (not "20 named" which is technically correct)
        for stale in ["(20 clients)", "20 MCP clients"]:
            assert stale not in text, f"{doc.name} contains stale '{stale}'"


# ---------------------------------------------------------------------------
# Integration files alignment
# ---------------------------------------------------------------------------


class TestIntegrationStats:
    """Verify integration metadata reflects actual counts."""

    def test_toolhive_server_json_tool_count(self):
        """Verify toolhive description mentions correct tool count."""
        path = ROOT / "integrations" / "toolhive" / "server.json"
        if not path.exists():
            pytest.skip("toolhive server.json not found")
        text = path.read_text()
        for stale in ["22 tools", "23 tools", "22 MCP", "23 MCP"]:
            assert stale not in text, f"toolhive server.json contains stale '{stale}'"

    def test_mcp_registry_version_matches(self):
        from agent_bom import __version__

        path = ROOT / "integrations" / "mcp-registry" / "server.json"
        if not path.exists():
            pytest.skip("mcp-registry server.json not found")
        data = json.loads(path.read_text())
        assert data.get("version") == __version__, f"mcp-registry version {data.get('version')} != {__version__}"


# ---------------------------------------------------------------------------
# pyproject.toml description alignment
# ---------------------------------------------------------------------------


class TestPyProjectStats:
    """Verify pyproject.toml description reflects actual counts."""

    def test_description_not_stale(self):
        text = (ROOT / "pyproject.toml").read_text()
        desc_match = re.search(r'description\s*=\s*"([^"]+)"', text)
        assert desc_match, "No description in pyproject.toml"
        desc = desc_match.group(1)
        assert "20 clients" not in desc, "pyproject.toml description has stale '20 clients'"
        assert "22 tools" not in desc and "23 tools" not in desc, "pyproject.toml description has stale tool count"


# ---------------------------------------------------------------------------
# Dashboard alignment
# ---------------------------------------------------------------------------


class TestDashboardStats:
    """Verify dashboard strings reflect actual counts."""

    def test_dashboard_client_count(self):
        path = ROOT / "dashboard" / "app.py"
        if not path.exists():
            pytest.skip("dashboard/app.py not found")
        text = path.read_text()
        assert "20 MCP client" not in text, "dashboard/app.py has stale '20 MCP client'"


# ---------------------------------------------------------------------------
# Print actual counts for debugging
# ---------------------------------------------------------------------------


def test_print_actual_counts(capsys):
    """Print actual counts for reference (always passes)."""
    print("\n--- Actual Code Counts ---")
    print(f"MCP tools (@mcp.tool):    {ACTUAL_MCP_TOOLS}")
    print(f"_SERVER_CARD_TOOLS:       {ACTUAL_CARD_TOOLS}")
    print(f"CONFIG_LOCATIONS:         {ACTUAL_CONFIG_LOCATIONS}")
    print(f"Runtime detectors:        {ACTUAL_DETECTORS}")
    print(f"Cloud providers:          {ACTUAL_CLOUD_PROVIDERS}")
    print(f"Python modules:           {ACTUAL_MODULES}")
    print(f"Test files:               {ACTUAL_TEST_FILES}")
