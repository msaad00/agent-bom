"""Tests for transitive dependency graph export (#292).

Tests cover:
- load_graph_from_scan() parses agents/servers/packages/CVEs
- Transitive packages (is_direct=False, dependency_depth>0) are included
- Packages with no vulns get 'pkg' kind; with vulns get 'pkg_vuln'
- Servers with has_credentials=True get 'server_cred' kind
- to_dot() produces valid DOT syntax
- to_mermaid() produces valid Mermaid syntax
- to_json() produces serialisable dict with nodes/edges/stats
- load_graph_from_scan() raises ValueError for non-agent-bom JSON
- Empty agents list produces empty graph
- graph CLI command: json/dot/mermaid --output to file
- graph CLI command: bad file raises SystemExit
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.output.graph_export import (
    DepGraph,
    load_graph_from_scan,
    to_cypher,
    to_dot,
    to_graphml,
    to_json,
    to_mermaid,
)

# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_scan_json(agents: list[dict] | None = None) -> dict:
    return {
        "document_type": "AI-BOM",
        "spec_version": "1.0",
        "ai_bom_version": "0.62.0",
        "generated_at": "2026-03-08T00:00:00",
        "summary": {
            "total_agents": len(agents or []),
            "total_mcp_servers": 0,
            "total_packages": 0,
            "total_vulnerabilities": 0,
            "critical_findings": 0,
        },
        "agents": agents or [],
    }


def _pkg(name: str, version: str = "1.0.0", eco: str = "npm", vulns: list | None = None, is_direct: bool = True, depth: int = 0) -> dict:
    return {
        "name": name,
        "version": version,
        "ecosystem": eco,
        "purl": f"pkg:{eco}/{name}@{version}",
        "is_direct": is_direct,
        "dependency_depth": depth,
        "parent_package": None,
        "vulnerabilities": vulns or [],
    }


def _vuln(vid: str = "CVE-2024-0001", severity: str = "high") -> dict:
    return {"id": vid, "severity": severity, "summary": "A test vulnerability.", "cvss_score": 7.5}


def _server(
    name: str,
    pkgs: list | None = None,
    has_creds: bool = False,
    tools: list[dict] | None = None,
    credential_env_vars: list[str] | None = None,
) -> dict:
    return {
        "name": name,
        "command": "npx",
        "args": [],
        "transport": "stdio",
        "url": "",
        "has_credentials": has_creds,
        "tools": tools or [],
        "credential_env_vars": credential_env_vars or [],
        "packages": pkgs or [],
    }


def _agent(name: str, servers: list | None = None, source: str = "local") -> dict:
    return {
        "name": name,
        "type": "custom",
        "config_path": "/tmp/mcp.json",
        "source": source,
        "status": "active",
        "mcp_servers": servers or [],
    }


def _cloud_agent(name: str = "bedrock-agent") -> dict:
    agent = _agent(name, [], source="aws")
    agent.update(
        {
            "discovered_at": "2026-04-28T10:00:00Z",
            "last_seen": "2026-04-28T11:00:00Z",
            "metadata": {
                "cloud_origin": {
                    "provider": "aws",
                    "service": "bedrock",
                    "resource_type": "agent",
                    "resource_id": "agent-123",
                    "location": "us-east-1",
                    "scope": {"account_id": "123456789012"},
                },
                "cloud_state": {"lifecycle_state": "ready", "raw_state": "PREPARED"},
            },
        }
    )
    return agent


def _write_scan(data: dict) -> str:
    f = tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False)
    json.dump(data, f)
    f.close()
    return f.name


# ── load_graph_from_scan ───────────────────────────────────────────────────────


def test_empty_agents_produces_empty_graph():
    path = _write_scan(_make_scan_json([]))
    try:
        g = load_graph_from_scan(path)
        assert g.node_count() == 0
        assert g.edge_count() == 0
    finally:
        os.unlink(path)


def test_loads_agent_server_package_nodes():
    data = _make_scan_json([_agent("myagent", [_server("myserver", [_pkg("requests", "2.31.0", "pypi")])])])
    path = _write_scan(data)
    try:
        g = load_graph_from_scan(path)
        kinds = {n.kind for n in g.nodes}
        assert "provider" in kinds
        assert "agent" in kinds
        assert "server" in kinds
        assert "pkg" in kinds
    finally:
        os.unlink(path)


def test_credential_to_tool_reaches_edges_export_with_evidence():
    server = _server(
        "github",
        tools=[{"name": "create_issue"}, {"name": "delete_repo"}],
        credential_env_vars=["GITHUB_TOKEN"],
    )
    data = _make_scan_json([_agent("a", [server])])
    path = _write_scan(data)
    try:
        graph = load_graph_from_scan(path)
        payload = to_json(graph)
        edge = next(edge for edge in payload["edges"] if edge["kind"] == "reaches_tool" and edge["target"].endswith("/delete_repo"))

        assert edge["source"] == "cred:GITHUB_TOKEN"
        assert edge["evidence"]["mapping_method"] == "server_scope_conservative"
        assert edge["evidence"]["confidence"] == "medium"
        assert "|reaches_tool|" in to_mermaid(graph)
        assert "REACHES_TOOL" in to_cypher(graph)
        assert "reaches_tool" in to_graphml(graph)
    finally:
        os.unlink(path)


def test_vulnerable_package_gets_pkg_vuln_kind():
    pkg = _pkg("lodash", "4.17.20", "npm", vulns=[_vuln("CVE-2021-23337")])
    data = _make_scan_json([_agent("a", [_server("s", [pkg])])])
    path = _write_scan(data)
    try:
        g = load_graph_from_scan(path)
        kinds = {n.kind for n in g.nodes}
        assert "pkg_vuln" in kinds
        assert "cve" in kinds
    finally:
        os.unlink(path)


def test_transitive_package_gets_pkg_transitive_kind():
    pkg = _pkg("semver", "7.5.4", "npm", is_direct=False, depth=2)
    data = _make_scan_json([_agent("a", [_server("s", [pkg])])])
    path = _write_scan(data)
    try:
        g = load_graph_from_scan(path)
        trans_nodes = [n for n in g.nodes if n.kind == "pkg_transitive"]
        assert len(trans_nodes) == 1
        assert "depth 2" in trans_nodes[0].label
    finally:
        os.unlink(path)


def test_credential_server_gets_server_cred_kind():
    srv = _server("cred-server", has_creds=True)
    data = _make_scan_json([_agent("a", [srv])])
    path = _write_scan(data)
    try:
        g = load_graph_from_scan(path)
        kinds = {n.kind for n in g.nodes}
        assert "server_cred" in kinds
    finally:
        os.unlink(path)


def test_edges_connect_hierarchy():
    pkg = _pkg("axios", "1.0.0", "npm")
    data = _make_scan_json([_agent("a", [_server("s", [pkg])])])
    path = _write_scan(data)
    try:
        g = load_graph_from_scan(path)
        edge_kinds = {e.kind for e in g.edges}
        assert "hosts" in edge_kinds
        assert "uses" in edge_kinds
        assert "depends_on" in edge_kinds
    finally:
        os.unlink(path)


def test_cve_edge_affects():
    pkg = _pkg("pkg", vulns=[_vuln("CVE-2024-9999", "critical")])
    data = _make_scan_json([_agent("a", [_server("s", [pkg])])])
    path = _write_scan(data)
    try:
        g = load_graph_from_scan(path)
        affects_edges = [e for e in g.edges if e.kind == "affects"]
        assert len(affects_edges) == 1
        cve_nodes = [n for n in g.nodes if n.kind == "cve"]
        assert cve_nodes[0].severity == "critical"
    finally:
        os.unlink(path)


def test_multiple_agents_multiple_providers():
    a1 = _agent("agent1", source="aws")
    a2 = _agent("agent2", source="azure")
    data = _make_scan_json([a1, a2])
    path = _write_scan(data)
    try:
        g = load_graph_from_scan(path)
        provider_nodes = [n for n in g.nodes if n.kind == "provider"]
        assert len(provider_nodes) == 2
        labels = {n.label for n in provider_nodes}
        assert "aws" in labels
        assert "azure" in labels
    finally:
        os.unlink(path)


def test_raises_value_error_for_invalid_json():
    path = _write_scan({"not": "an-agent-bom-report"})
    try:
        with pytest.raises(ValueError, match="AI-BOM"):
            load_graph_from_scan(path)
    finally:
        os.unlink(path)


def test_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_graph_from_scan("/nonexistent/path/report.json")


# ── to_dot ────────────────────────────────────────────────────────────────────


def test_to_dot_basic_structure():
    pkg = _pkg("react", "18.0.0", "npm")
    data = _make_scan_json([_agent("a", [_server("s", [pkg])])])
    path = _write_scan(data)
    try:
        g = load_graph_from_scan(path)
        dot = to_dot(g)
        assert "digraph dependency_graph" in dot
        assert "rankdir=LR" in dot
        assert "->" in dot
    finally:
        os.unlink(path)


def test_to_dot_contains_all_node_labels():
    pkg = _pkg("express", "4.18.0", "npm", vulns=[_vuln("CVE-2024-1234")])
    data = _make_scan_json([_agent("myagent", [_server("mysrv", [pkg])])])
    path = _write_scan(data)
    try:
        g = load_graph_from_scan(path)
        dot = to_dot(g)
        assert "myagent" in dot
        assert "mysrv" in dot
        assert "express" in dot
        assert "CVE-2024-1234" in dot
    finally:
        os.unlink(path)


def test_to_dot_empty_graph():
    g = DepGraph()
    dot = to_dot(g)
    assert "digraph dependency_graph" in dot
    assert "->" not in dot


# ── to_mermaid ────────────────────────────────────────────────────────────────


def test_to_mermaid_basic_structure():
    pkg = _pkg("vue", "3.0.0", "npm")
    data = _make_scan_json([_agent("a", [_server("s", [pkg])])])
    path = _write_scan(data)
    try:
        g = load_graph_from_scan(path)
        mmd = to_mermaid(g)
        assert "flowchart LR" in mmd
        assert "classDef" in mmd
        assert "-->" in mmd
    finally:
        os.unlink(path)


def test_to_mermaid_uses_short_ids_and_descriptive_labels():
    pkg = _pkg("@scope/very-long-package", "1.2.3", "npm", vulns=[_vuln("CVE-2026-9999")])
    data = _make_scan_json([_agent("claude desktop", [_server("filesystem server", [pkg])])])
    path = _write_scan(data)
    try:
        g = load_graph_from_scan(path)
        mmd = to_mermaid(g)
        assert "n1" in mmd
        assert "agent_claude_desktop" not in mmd
        assert "server_claude_desktop_filesystem_server" not in mmd
        assert "claude desktop" in mmd
        assert "filesystem server" in mmd
        assert "@scope/very-long-package@1.2.3" in mmd
        assert "CVE-2026-9999" in mmd
    finally:
        os.unlink(path)


def test_to_mermaid_empty_graph():
    g = DepGraph()
    mmd = to_mermaid(g)
    assert "flowchart LR" in mmd
    assert "-->" not in mmd


# ── to_json ──────────────────────────────────────────────────────────────────


def test_to_json_structure():
    pkg = _pkg("numpy", "1.24.0", "pypi")
    data = _make_scan_json([_agent("a", [_server("s", [pkg])])])
    path = _write_scan(data)
    try:
        g = load_graph_from_scan(path)
        result = to_json(g)
        assert "nodes" in result
        assert "edges" in result
        assert "stats" in result
        assert result["stats"]["node_count"] == g.node_count()
        assert result["stats"]["edge_count"] == g.edge_count()
        # Should be JSON-serialisable
        json.dumps(result)
    finally:
        os.unlink(path)


def test_to_json_node_has_required_fields():
    pkg = _pkg("flask", "3.0.0", "pypi")
    data = _make_scan_json([_agent("a", [_server("s", [pkg])])])
    path = _write_scan(data)
    try:
        g = load_graph_from_scan(path)
        result = to_json(g)
        for node in result["nodes"]:
            assert "id" in node
            assert "label" in node
            assert "kind" in node
    finally:
        os.unlink(path)


def test_to_json_preserves_cloud_context_attributes():
    data = _make_scan_json([_cloud_agent()])
    path = _write_scan(data)
    try:
        graph = load_graph_from_scan(path)
        result = to_json(graph)
        agent_node = next(node for node in result["nodes"] if node["id"] == "agent:bedrock-agent")
        attrs = agent_node["attributes"]
        assert attrs["cloud_origin"]["provider"] == "aws"
        assert attrs["cloud_origin"]["service"] == "bedrock"
        assert attrs["cloud_origin"]["scope"]["account_id"] == "123456789012"
        assert attrs["cloud_state"]["lifecycle_state"] == "ready"
        assert attrs["discovered_at"] == "2026-04-28T10:00:00Z"
        assert attrs["last_seen"] == "2026-04-28T11:00:00Z"
    finally:
        os.unlink(path)


# ── CLI graph command ─────────────────────────────────────────────────────────


def test_cli_graph_json_to_stdout():
    from agent_bom.cli import main

    pkg = _pkg("boto3", "1.28.0", "pypi")
    data = _make_scan_json([_agent("cli-agent", [_server("s", [pkg])])])
    path = _write_scan(data)
    try:
        runner = CliRunner()
        result = runner.invoke(main, ["graph", path, "--format", "json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "nodes" in parsed
        assert "edges" in parsed
    finally:
        os.unlink(path)


def test_cli_graph_dot_to_file():
    from agent_bom.cli import main

    pkg = _pkg("django", "4.2.0", "pypi")
    data = _make_scan_json([_agent("a", [_server("s", [pkg])])])
    path = _write_scan(data)
    with tempfile.NamedTemporaryFile(suffix=".dot", delete=False) as out:
        out_path = out.name

    try:
        runner = CliRunner()
        result = runner.invoke(main, ["graph", path, "--format", "dot", "--output", out_path])
        assert result.exit_code == 0
        dot_content = Path(out_path).read_text()
        assert "digraph dependency_graph" in dot_content
    finally:
        os.unlink(path)
        os.unlink(out_path)


def test_cli_graph_mermaid_to_stdout():
    from agent_bom.cli import main

    data = _make_scan_json([_agent("a", [])])
    path = _write_scan(data)
    try:
        runner = CliRunner()
        result = runner.invoke(main, ["graph", path, "--format", "mermaid"])
        assert result.exit_code == 0
        assert "flowchart LR" in result.output
    finally:
        os.unlink(path)


def test_cli_graph_invalid_file_exits_nonzero():
    from agent_bom.cli import main

    path = _write_scan({"invalid": True})
    try:
        runner = CliRunner()
        result = runner.invoke(main, ["graph", path])
        assert result.exit_code != 0
    finally:
        os.unlink(path)


# ── to_graphml ─────────────────────────────────────────────────────────────


def test_to_graphml_basic_structure():
    pkg = _pkg("fastapi", "0.100.0", "pypi")
    data = _make_scan_json([_agent("a", [_server("s", [pkg])])])
    path = _write_scan(data)
    try:
        g = load_graph_from_scan(path)
        gml = to_graphml(g)
        assert '<?xml version="1.0"' in gml
        assert "<graphml" in gml
        assert 'id="aibom"' in gml
        assert "<node" in gml
        assert "<edge" in gml
        assert 'key="kind"' in gml
    finally:
        os.unlink(path)


def test_to_graphml_aibom_attributes():
    pkg = _pkg("lodash", "4.17.20", "npm", vulns=[_vuln("CVE-2021-23337")])
    srv = _server("cred-srv", [pkg], has_creds=True)
    data = _make_scan_json([_agent("a", [srv])])
    path = _write_scan(data)
    try:
        g = load_graph_from_scan(path)
        gml = to_graphml(g)
        assert "has_credentials" in gml
        assert "is_vulnerable" in gml
        assert "severity" in gml
    finally:
        os.unlink(path)


def test_to_graphml_empty_graph():
    g = DepGraph()
    gml = to_graphml(g)
    assert "<graphml" in gml
    assert "<node" not in gml


# ── to_cypher ──────────────────────────────────────────────────────────────


def test_to_cypher_basic_structure():
    pkg = _pkg("express", "4.18.0", "npm")
    data = _make_scan_json([_agent("a", [_server("s", [pkg])])])
    path = _write_scan(data)
    try:
        g = load_graph_from_scan(path)
        cypher = to_cypher(g)
        assert "CREATE CONSTRAINT" in cypher
        assert "MERGE" in cypher
        assert ":AIAgent" in cypher or ":Provider" in cypher
        assert "USES_SERVER" in cypher or "HOSTS" in cypher
    finally:
        os.unlink(path)


def test_to_cypher_aibom_labels():
    pkg = _pkg("react", "18.0.0", "npm", vulns=[_vuln("CVE-2024-1234")])
    data = _make_scan_json([_agent("myagent", [_server("mysrv", [pkg])])])
    path = _write_scan(data)
    try:
        g = load_graph_from_scan(path)
        cypher = to_cypher(g)
        assert ":AIAgent" in cypher
        assert ":MCPServer" in cypher
        assert ":Package" in cypher
        assert ":Vulnerability" in cypher
        assert "DEPENDS_ON" in cypher
        assert "AFFECTS" in cypher
    finally:
        os.unlink(path)


def test_to_cypher_empty_graph():
    g = DepGraph()
    cypher = to_cypher(g)
    assert "CREATE CONSTRAINT" in cypher
    assert "Total: 0 nodes" in cypher


# ── CLI graphml / cypher ──────────────────────────────────────────────────


def test_cli_graph_graphml_to_stdout():
    from agent_bom.cli import main

    data = _make_scan_json([_agent("a", [_server("s", [_pkg("pkg", "1.0.0")])])])
    path = _write_scan(data)
    try:
        runner = CliRunner()
        result = runner.invoke(main, ["graph", path, "--format", "graphml"])
        assert result.exit_code == 0
        assert "<graphml" in result.output
    finally:
        os.unlink(path)


def test_cli_graph_cypher_to_file():
    from agent_bom.cli import main

    data = _make_scan_json([_agent("a", [_server("s", [_pkg("pkg", "1.0.0")])])])
    path = _write_scan(data)
    with tempfile.NamedTemporaryFile(suffix=".cypher", delete=False) as out:
        out_path = out.name
    try:
        runner = CliRunner()
        result = runner.invoke(main, ["graph", path, "--format", "cypher", "--output", out_path])
        assert result.exit_code == 0
        content = Path(out_path).read_text()
        assert "MERGE" in content
    finally:
        os.unlink(path)
        os.unlink(out_path)
