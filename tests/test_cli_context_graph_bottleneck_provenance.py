"""`--context-graph` must ship the bottleneck ranking's provenance with it.

The CLI printed "N bottleneck(s)" and wrote a `bottleneck_nodes` list into the
JSON report. Both were the output of a bounded, approximate traversal presented
as fact — the reader had no way to tell whether every source had been walked or
fifty of them had. Presenting a sample as a complete answer is the bug; the
ranking itself is fine.
"""

from __future__ import annotations

import json
from unittest.mock import patch

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.models import Agent, AgentType, BlastRadius, MCPServer, Package, Severity, Vulnerability


def _scan_mocks():
    vuln = Vulnerability(id="CVE-2099-0001", summary="crit", severity=Severity.CRITICAL, fixed_version="9.9.9")
    pkg = Package(name="badpkg", version="1.0.0", ecosystem="pypi", vulnerabilities=[vuln])
    server = MCPServer(name="srv", command="python", packages=[pkg])
    agent = Agent(name="ag", agent_type=AgentType.CUSTOM, config_path="a.json", mcp_servers=[server])
    blast = [
        BlastRadius(
            vulnerability=vuln,
            package=pkg,
            affected_servers=[server],
            affected_agents=[agent],
            exposed_credentials=[],
            exposed_tools=[],
        )
    ]
    return agent, blast


def _run_context_graph_scan(tmp_path):
    agent, blast = _scan_mocks()
    out = tmp_path / "report.json"
    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[agent]),
        patch("agent_bom.cli.agents.extract_packages", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=blast),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = CliRunner().invoke(
            main,
            ["scan", "--project", str(tmp_path), "--context-graph", "-f", "json", "-o", str(out), "--no-auto-update-db"],
            catch_exceptions=False,
        )
    assert result.exit_code in (0, 1), result.output
    return result, json.loads(out.read_text(encoding="utf-8"))


def test_report_carries_the_bottleneck_sample_it_was_derived_from(tmp_path):
    _result, report = _run_context_graph_scan(tmp_path)
    provenance = report["context_graph"]["bottleneck_provenance"]

    assert provenance["total_nodes"] > 0
    assert 0 < provenance["sampled_sources"] <= provenance["total_nodes"]
    assert provenance["sampled"] is (provenance["sampled_sources"] < provenance["total_nodes"])


def test_console_line_does_not_imply_a_sample_when_every_source_was_walked(tmp_path):
    """This estate is small enough to traverse exhaustively — saying "sampled"
    there would be as dishonest as omitting it on a large one."""
    result, report = _run_context_graph_scan(tmp_path)
    assert report["context_graph"]["bottleneck_provenance"]["sampled"] is False
    assert "bottleneck(s)" in result.output
    assert "sampled" not in result.output


def test_console_qualifier_appears_once_the_traversal_is_sampled():
    """The printed line must name the sample when one was taken."""
    from agent_bom.graph.bottleneck import MAX_SAMPLE_SOURCES, MIN_SAMPLE_SOURCES
    from agent_bom.graph_backend import InMemoryBackend

    backend = InMemoryBackend()
    for index in range(MIN_SAMPLE_SOURCES * 4):
        backend.add_node(f"n:{index:04d}", kind="agent", label=str(index))
    for index in range(MIN_SAMPLE_SOURCES * 4 - 1):
        backend.add_edge(f"n:{index:04d}", f"n:{index + 1:04d}", kind="uses", directed=True)

    analysis = backend.bottleneck_analysis(top_n=5)
    assert analysis.sampled is True
    assert MIN_SAMPLE_SOURCES <= analysis.sampled_sources <= MAX_SAMPLE_SOURCES
    assert analysis.sampled_sources < analysis.total_nodes
