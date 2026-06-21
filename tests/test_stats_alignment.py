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
    """Count @mcp.tool decorators across MCP server registration modules."""
    total = 0
    for path in sorted(SRC.glob("mcp_server*.py")):
        text = path.read_text()
        total += len(re.findall(r"@mcp\.tool", text))
    return total


def _count_server_card_tools() -> int:
    """Count tool entries in _SERVER_CARD_TOOLS list (each has a 'name' key)."""
    for path in (SRC / "mcp_server_metadata.py", SRC / "mcp_server.py"):
        if not path.exists():
            continue
        text = path.read_text()
        # _SERVER_CARD_TOOLS is a list of dicts; count occurrences of "name" keys
        start = text.find("_SERVER_CARD_TOOLS")
        if start == -1:
            continue
        section = text[start:]
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
    return 0


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


def _count_mcp_registry_servers() -> int:
    """Count bundled MCP registry server records."""
    data = json.loads((SRC / "mcp_registry.json").read_text())
    return int(data.get("_total_servers") or len(data.get("servers", [])))


def _graph_taxonomy_counts() -> tuple[int, int]:
    """Count canonical graph entities and relationships from code."""
    from agent_bom.graph import EntityType, RelationshipType

    return len(EntityType), len(RelationshipType)


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
ACTUAL_MCP_REGISTRY_SERVERS = _count_mcp_registry_servers()
ACTUAL_GRAPH_ENTITY_TYPES, ACTUAL_GRAPH_RELATIONSHIP_TYPES = _graph_taxonomy_counts()


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
            for stale in ["22 tools", "23 tools", "30 tools", "31 tools", "22 MCP tools", "23 MCP tools", "30 MCP tools", "31 MCP tools"]:
                assert stale not in text, f"{svg.name} contains stale '{stale}' — actual MCP tool count is {ACTUAL_MCP_TOOLS}"

    def test_no_stale_client_count_in_svgs(self):
        """No SVG should contain stale MCP client counts."""
        for svg in SVG_DIR.glob("*.svg"):
            text = svg.read_text().lower()
            for stale in ["20 mcp client", "20 clients", "21 clients", "21 mcp client"]:
                assert stale not in text, f"{svg.name} contains stale '{stale}' — actual is {ACTUAL_CONFIG_LOCATIONS}"


# ---------------------------------------------------------------------------
# Markdown docs alignment
# ---------------------------------------------------------------------------

DOCS_TO_CHECK = [
    ROOT / "README.md",
    ROOT / "docs" / "ARCHITECTURE.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "docs" / "DEPLOYMENT.md",
    ROOT / "docs" / "archive" / "AUDIT.md",
]


class TestMarkdownStats:
    """Verify markdown docs reflect actual counts."""

    @pytest.mark.parametrize("doc", DOCS_TO_CHECK, ids=lambda p: p.name)
    def test_no_stale_tool_count(self, doc):
        if not doc.exists():
            pytest.skip(f"{doc.name} not found")
        text = doc.read_text()
        for stale in ["22 tools", "23 tools", "30 tools", "31 tools", "22 MCP tool", "23 MCP tool", "30 MCP tool", "31 MCP tool"]:
            assert stale not in text, f"{doc.name} contains stale '{stale}' — actual is {ACTUAL_MCP_TOOLS} tools"

    @pytest.mark.parametrize("doc", DOCS_TO_CHECK, ids=lambda p: p.name)
    def test_no_stale_client_count(self, doc):
        if not doc.exists():
            pytest.skip(f"{doc.name} not found")
        text = doc.read_text()
        # "20 clients" in prose (not "20 named" which is technically correct)
        for stale in ["(20 clients)", "20 MCP clients", "(21 clients)", "21 MCP clients"]:
            assert stale not in text, f"{doc.name} contains stale '{stale}' — actual is {ACTUAL_CONFIG_LOCATIONS}"

    def test_data_model_atlas_covers_runtime_intel_manifest_schemas(self):
        text = (ROOT / "docs" / "DATA_MODEL.md").read_text()
        required = {
            "agent-bom.manifest/v1",
            "agentic_identity_graph.v1",
            "runtime.production_index.v1",
            "runtime.blueprints.v1",
            "runtime.blueprint_drift.v1",
            "intel.sources.v1",
            "intel.lookup.v1",
            "intel.match.v1",
            "inventory_snapshot.packages",
            "visibility.risk_signals",
        }
        missing = sorted(item for item in required if item not in text)
        assert not missing, f"DATA_MODEL.md missing schema contracts: {missing}"

    def test_data_model_graph_taxonomy_counts_match_code(self):
        text = (ROOT / "docs" / "DATA_MODEL.md").read_text()
        entity_match = re.search(r"### Entity types \((\d+)\)", text)
        relationship_match = re.search(r"### Relationship types \((\d+)\)", text)
        assert entity_match, "DATA_MODEL.md missing graph entity type count"
        assert relationship_match, "DATA_MODEL.md missing graph relationship type count"
        assert int(entity_match.group(1)) == ACTUAL_GRAPH_ENTITY_TYPES
        assert int(relationship_match.group(1)) == ACTUAL_GRAPH_RELATIONSHIP_TYPES

    def test_data_model_graph_taxonomy_lists_every_code_value(self):
        from agent_bom.graph import EntityType, RelationshipType

        text = (ROOT / "docs" / "DATA_MODEL.md").read_text()
        missing_entities = sorted(entity.name for entity in EntityType if f"`{entity.name}`" not in text)
        missing_relationships = sorted(relationship.name for relationship in RelationshipType if f"`{relationship.name}`" not in text)
        assert not missing_entities, f"DATA_MODEL.md missing graph entities: {missing_entities}"
        assert not missing_relationships, f"DATA_MODEL.md missing graph relationships: {missing_relationships}"

    def test_site_index_registry_count_matches_bundled_registry(self):
        text = (ROOT / "site-docs" / "index.md").read_text()
        assert f"{ACTUAL_MCP_REGISTRY_SERVERS} MCP server security metadata entries" in text


# ---------------------------------------------------------------------------
# Integration files alignment
# ---------------------------------------------------------------------------


class TestIntegrationStats:
    """Verify integration metadata reflects actual counts."""

    def test_docker_mcp_tools_json_matches_tool_count(self):
        path = ROOT / "integrations" / "docker-mcp-registry" / "tools.json"
        if not path.exists():
            pytest.skip("Docker MCP tools.json not found")
        data = json.loads(path.read_text())
        assert len(data) == ACTUAL_MCP_TOOLS

    def test_docker_mcp_submission_tool_count_matches_code(self):
        path = ROOT / "integrations" / "docker-mcp-registry" / "SUBMISSION.md"
        if not path.exists():
            pytest.skip("Docker MCP submission docs not found")
        text = path.read_text()
        assert f"all {ACTUAL_MCP_TOOLS} MCP tools" in text
        assert "all 41 MCP tools" not in text

    def test_docker_mcp_readme_client_count_matches_code(self):
        from agent_bom.discovery.coverage import supported_clients

        path = ROOT / "integrations" / "docker-mcp-registry" / "readme.md"
        if not path.exists():
            pytest.skip("Docker MCP readme not found")
        text = path.read_text()
        assert f"{len(supported_clients())} first-class MCP client types" in text
        assert "30 MCP client types" not in text

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
        for _stale in ["22 tools", "23 tools", "30 tools", "31 tools"]:
            assert _stale not in desc, f"pyproject.toml description has stale '{_stale}'"


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


# ---------------------------------------------------------------------------
# Live tool-count + registry-header freshness lock (CI gate)
#
# The advertised MCP tool count drifted repeatedly across the CLI help,
# Dockerfile, docstring, server card, and docker tools.json because nothing
# tied them to the LIVE registered tool count. The registry ``_total_servers``
# header likewise undercounted the bundled ``servers`` map. These tests derive
# the truth from the running server / the registry file and assert every
# advertised surface matches, so a future capability wave can never silently
# leave a stale number behind.
# ---------------------------------------------------------------------------


def _live_mcp_tool_count() -> int:
    """Number of tools the MCP server actually registers at runtime."""
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    return len(server._tool_manager._tools)


LIVE_MCP_TOOLS = _live_mcp_tool_count()


class TestToolCountFreshness:
    """Tie every advertised MCP tool count to the LIVE registered count."""

    def test_live_count_matches_decorator_count(self):
        # The @mcp.tool decorator scan and the live registration must agree.
        assert LIVE_MCP_TOOLS == ACTUAL_MCP_TOOLS, f"live tool count ({LIVE_MCP_TOOLS}) != @mcp.tool decorator count ({ACTUAL_MCP_TOOLS})"

    def test_live_count_matches_server_card(self):
        assert LIVE_MCP_TOOLS == ACTUAL_CARD_TOOLS, f"live tool count ({LIVE_MCP_TOOLS}) != _SERVER_CARD_TOOLS count ({ACTUAL_CARD_TOOLS})"

    def test_mcp_server_docstring_count_matches_live(self):
        text = (SRC / "mcp_server.py").read_text()
        match = re.search(r"^Tools \((\d+)\):", text, re.MULTILINE)
        assert match, "mcp_server.py module docstring missing 'Tools (N):'"
        assert int(match.group(1)) == LIVE_MCP_TOOLS, f"mcp_server.py docstring advertises {match.group(1)} tools, live is {LIVE_MCP_TOOLS}"

    def test_cli_help_count_matches_live(self):
        text = (SRC / "cli" / "_server.py").read_text()
        match = re.search(r"Exposes (\d+) security tools via MCP protocol", text)
        assert match, "cli/_server.py missing 'Exposes N security tools via MCP protocol'"
        assert int(match.group(1)) == LIVE_MCP_TOOLS, f"cli/_server.py advertises {match.group(1)} tools, live is {LIVE_MCP_TOOLS}"

    def test_dockerfile_sse_count_matches_live(self):
        path = ROOT / "deploy" / "docker" / "Dockerfile.sse"
        if not path.exists():
            pytest.skip("Dockerfile.sse not found")
        text = path.read_text()
        match = re.search(r"(\d+) MCP tools", text)
        assert match, "Dockerfile.sse missing 'N MCP tools'"
        assert int(match.group(1)) == LIVE_MCP_TOOLS, f"Dockerfile.sse advertises {match.group(1)} MCP tools, live is {LIVE_MCP_TOOLS}"

    def test_docker_mcp_tools_json_count_matches_live(self):
        path = ROOT / "integrations" / "docker-mcp-registry" / "tools.json"
        if not path.exists():
            pytest.skip("Docker MCP tools.json not found")
        data = json.loads(path.read_text())
        assert len(data) == LIVE_MCP_TOOLS, f"docker tools.json lists {len(data)} tools, live is {LIVE_MCP_TOOLS}"

    def test_hardening_strict_args_surface_matches_live(self):
        from agent_bom.mcp_hardening import strict_args_tool_count

        assert strict_args_tool_count() == LIVE_MCP_TOOLS, (
            f"mcp_hardening strict-args surface counts {strict_args_tool_count()}, live is {LIVE_MCP_TOOLS}"
        )


class TestRegistryHeaderFreshness:
    """Tie the registry ``_total_servers`` header to the bundled servers map."""

    def test_total_servers_header_matches_bundled_map(self):
        data = json.loads((SRC / "mcp_registry.json").read_text())
        servers = data.get("servers", {})
        actual = len(servers)
        header = data.get("_total_servers")
        assert header == actual, f"mcp_registry.json _total_servers={header} but bundled servers map has {actual} entries"


def test_print_actual_counts(capsys):
    """Print actual counts for reference (always passes)."""
    print("\n--- Actual Code Counts ---")
    print(f"MCP tools (@mcp.tool):    {ACTUAL_MCP_TOOLS}")
    print(f"MCP tools (live):         {LIVE_MCP_TOOLS}")
    print(f"_SERVER_CARD_TOOLS:       {ACTUAL_CARD_TOOLS}")
    print(f"CONFIG_LOCATIONS:         {ACTUAL_CONFIG_LOCATIONS}")
    print(f"Runtime detectors:        {ACTUAL_DETECTORS}")
    print(f"Cloud providers:          {ACTUAL_CLOUD_PROVIDERS}")
    print(f"Python modules:           {ACTUAL_MODULES}")
    print(f"Test files:               {ACTUAL_TEST_FILES}")
    print(f"MCP registry servers:     {ACTUAL_MCP_REGISTRY_SERVERS}")
