"""Tests for fleet_scan — batch registry lookup + risk scoring."""

from __future__ import annotations

import json

from agent_bom.fleet_scan import (
    FleetScanResult,
    ServerResult,
    _compute_verdict,
    _match_server,
    fleet_scan,
)

# ── Sample registry fixture ─────────────────────────────────────────────

SAMPLE_REGISTRY = {
    "filesystem": {
        "package": "@modelcontextprotocol/server-filesystem",
        "name": "Filesystem",
        "ecosystem": "npm",
        "category": "filesystem",
        "risk_level": "high",
        "risk_justification": "write_file grants full filesystem write access.",
        "verified": True,
        "license": "MIT",
        "tools": ["read_file", "write_file", "list_directory"],
        "credential_env_vars": [],
        "command_patterns": ["server-filesystem"],
        "latest_version": "2026.1.14",
        "source_url": "https://github.com/modelcontextprotocol/servers",
        "known_cves": [],
    },
    "brave-search": {
        "package": "@anthropic-ai/mcp-server-brave-search",
        "name": "Brave Search",
        "ecosystem": "npm",
        "category": "search",
        "risk_level": "low",
        "risk_justification": "Read-only web search.",
        "verified": True,
        "license": "MIT",
        "tools": ["brave_web_search", "brave_local_search"],
        "credential_env_vars": ["BRAVE_API_KEY"],
        "command_patterns": ["brave-search"],
        "latest_version": "0.6.2",
        "source_url": "https://github.com/anthropic-ai/mcp-servers",
        "known_cves": [],
    },
    "postgres": {
        "package": "@modelcontextprotocol/server-postgres",
        "name": "PostgreSQL",
        "ecosystem": "npm",
        "category": "database",
        "risk_level": "medium",
        "risk_justification": "SQL queries on connected database.",
        "verified": True,
        "license": "MIT",
        "tools": ["query"],
        "credential_env_vars": ["POSTGRES_URL"],
        "command_patterns": ["server-postgres"],
        "latest_version": "0.6.2",
        "source_url": "https://github.com/modelcontextprotocol/servers",
        "known_cves": ["CVE-2026-99999"],
    },
}


# ── _match_server ────────────────────────────────────────────────────────


class TestMatchServer:
    def test_exact_key_match(self):
        result = _match_server("filesystem", SAMPLE_REGISTRY)
        assert result is not None
        assert result[0] == "filesystem"

    def test_package_name_match(self):
        result = _match_server("@modelcontextprotocol/server-filesystem", SAMPLE_REGISTRY)
        assert result is not None
        assert result[0] == "filesystem"

    def test_display_name_match(self):
        result = _match_server("Brave Search", SAMPLE_REGISTRY)
        assert result is not None
        assert result[0] == "brave-search"

    def test_command_pattern_match(self):
        result = _match_server("server-postgres", SAMPLE_REGISTRY)
        assert result is not None
        assert result[0] == "postgres"

    def test_substring_match(self):
        result = _match_server("brave", SAMPLE_REGISTRY)
        assert result is not None
        assert result[0] == "brave-search"

    def test_no_match(self):
        result = _match_server("nonexistent-server", SAMPLE_REGISTRY)
        assert result is None

    def test_case_insensitive(self):
        result = _match_server("FILESYSTEM", SAMPLE_REGISTRY)
        assert result is not None
        assert result[0] == "filesystem"

    def test_empty_name(self):
        result = _match_server("", SAMPLE_REGISTRY)
        assert result is None

    def test_whitespace_name(self):
        result = _match_server("   ", SAMPLE_REGISTRY)
        assert result is None


# ── _compute_verdict ─────────────────────────────────────────────────────


class TestComputeVerdict:
    def test_unmatched(self):
        assert _compute_verdict(False, "", []) == "unknown-unvetted"

    def test_high_risk(self):
        assert _compute_verdict(True, "high", []) == "known-high-risk"

    def test_medium_risk(self):
        assert _compute_verdict(True, "medium", []) == "known-medium"

    def test_low_risk(self):
        assert _compute_verdict(True, "low", []) == "known-low"

    def test_with_cves(self):
        verdict = _compute_verdict(True, "medium", ["CVE-2024-1234"])
        assert "cves" in verdict

    def test_high_with_cves(self):
        verdict = _compute_verdict(True, "high", ["CVE-2024-1234"])
        assert verdict == "known-high-risk-with-cves"


# ── fleet_scan ───────────────────────────────────────────────────────────


class TestFleetScan:
    def test_basic_scan(self):
        result = fleet_scan(
            ["filesystem", "brave-search", "nonexistent"],
            registry=SAMPLE_REGISTRY,
        )
        assert result.total == 3
        assert result.matched == 2
        assert result.unmatched == 1
        assert result.high_risk == 1
        assert result.low_risk == 1

    def test_all_matched(self):
        result = fleet_scan(
            ["filesystem", "brave-search", "postgres"],
            registry=SAMPLE_REGISTRY,
        )
        assert result.matched == 3
        assert result.unmatched == 0

    def test_all_unmatched(self):
        result = fleet_scan(["foo", "bar", "baz"], registry=SAMPLE_REGISTRY)
        assert result.matched == 0
        assert result.unmatched == 3

    def test_deduplication(self):
        result = fleet_scan(
            ["filesystem", "FILESYSTEM", "Filesystem"],
            registry=SAMPLE_REGISTRY,
        )
        assert result.total == 1
        assert result.matched == 1

    def test_empty_input(self):
        result = fleet_scan([], registry=SAMPLE_REGISTRY)
        assert result.total == 0
        assert len(result.servers) == 0

    def test_whitespace_handling(self):
        result = fleet_scan(
            ["  filesystem  ", "  ", "brave-search"],
            registry=SAMPLE_REGISTRY,
        )
        assert result.matched == 2

    def test_cve_counting(self):
        result = fleet_scan(["postgres"], registry=SAMPLE_REGISTRY)
        assert result.with_cves == 1
        assert result.servers[0].known_cves == ["CVE-2026-99999"]
        assert "cves" in result.servers[0].verdict

    def test_server_result_fields(self):
        result = fleet_scan(["filesystem"], registry=SAMPLE_REGISTRY)
        srv = result.servers[0]
        assert srv.registry_match is True
        assert srv.registry_id == "filesystem"
        assert srv.display_name == "Filesystem"
        assert srv.package == "@modelcontextprotocol/server-filesystem"
        assert srv.ecosystem == "npm"
        assert srv.category == "filesystem"
        assert srv.risk_category == "high"
        assert srv.verified is True
        assert "write_file" in srv.tools
        assert srv.verdict == "known-high-risk"

    def test_unmatched_result_fields(self):
        result = fleet_scan(["unknown-server"], registry=SAMPLE_REGISTRY)
        srv = result.servers[0]
        assert srv.registry_match is False
        assert srv.verdict == "unknown-unvetted"
        assert srv.tools == []
        assert srv.risk_category == ""

    def test_to_dict(self):
        result = fleet_scan(["filesystem"], registry=SAMPLE_REGISTRY)
        d = result.to_dict()
        assert "summary" in d
        assert "servers" in d
        assert d["summary"]["total"] == 1
        assert d["summary"]["matched"] == 1

    def test_to_json(self):
        result = fleet_scan(["filesystem"], registry=SAMPLE_REGISTRY)
        j = result.to_json()
        parsed = json.loads(j)
        assert parsed["summary"]["total"] == 1

    def test_loads_real_registry(self):
        """Verify fleet_scan works with the actual bundled registry."""
        result = fleet_scan(["filesystem", "brave-search"])
        # These should be in the real registry
        assert result.matched >= 2

    def test_npm_scoped_package(self):
        result = fleet_scan(
            ["@modelcontextprotocol/server-filesystem"],
            registry=SAMPLE_REGISTRY,
        )
        assert result.matched == 1
        assert result.servers[0].registry_id == "filesystem"


# ── ServerResult ─────────────────────────────────────────────────────────


class TestServerResult:
    def test_to_dict(self):
        sr = ServerResult(server_name="test", registry_match=False, verdict="unknown-unvetted")
        d = sr.to_dict()
        assert d["server_name"] == "test"
        assert d["registry_match"] is False

    def test_default_fields(self):
        sr = ServerResult(server_name="test")
        assert sr.tools == []
        assert sr.credential_env_vars == []
        assert sr.known_cves == []


# ── FleetScanResult ──────────────────────────────────────────────────────


class TestFleetScanResult:
    def test_empty_result(self):
        r = FleetScanResult()
        d = r.to_dict()
        assert d["summary"]["total"] == 0
        assert d["servers"] == []

    def test_json_roundtrip(self):
        r = FleetScanResult(total=1, matched=1, high_risk=1)
        r.servers.append(ServerResult(server_name="test", verdict="known-high-risk"))
        j = r.to_json()
        parsed = json.loads(j)
        assert parsed["summary"]["high_risk"] == 1


# ── Meta test: tool count ────────────────────────────────────────────────


def test_server_card_tools_count_matches_mcp_tools():
    """Ensure _SERVER_CARD_TOOLS stays in sync with actual @mcp.tool count."""
    # Count @mcp.tool decorators in the source
    import inspect
    import re

    from agent_bom import mcp_server
    from agent_bom.mcp_server import _SERVER_CARD_TOOLS

    source = inspect.getsource(mcp_server)
    tool_count = len(re.findall(r"@mcp\.tool\(", source))
    card_count = len(_SERVER_CARD_TOOLS)
    assert card_count == tool_count, f"_SERVER_CARD_TOOLS has {card_count} entries but found {tool_count} @mcp.tool decorators"
