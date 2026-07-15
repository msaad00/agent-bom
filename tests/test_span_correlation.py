"""Per-span trace -> attack-path correlation (#3898).

A traced tool-call span must resolve to the *exact* reachable CVE + exposed
credential + non-human identity + blast radius — i.e. "span abc123 = the exact
call that hit the CVE", not just an aggregate "run_shell called N times".
"""

from __future__ import annotations

from agent_bom.models import (
    Agent,
    AgentType,
    BlastRadius,
    MCPServer,
    MCPTool,
    Package,
    Severity,
    Vulnerability,
)
from agent_bom.otel_ingest import ToolCallTrace, parse_otel_traces
from agent_bom.runtime_correlation import correlate_spans_to_attack_paths


def _blast_radius(
    *,
    cve: str = "CVE-2025-1234",
    tool: str = "run_shell",
    server: str = "shell-mcp",
    pkg: str = "requests",
    creds: list[str] | None = None,
    is_kev: bool = True,
) -> BlastRadius:
    vuln = Vulnerability(
        id=cve,
        summary="RCE",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        epss_score=0.7,
        is_kev=is_kev,
    )
    br = BlastRadius(
        vulnerability=vuln,
        package=Package(name=pkg, version="2.0.0", ecosystem="pypi"),
        affected_servers=[MCPServer(name=server)],
        affected_agents=[Agent(name="ci-agent", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp")],
        exposed_credentials=creds or ["AWS_SECRET_ACCESS_KEY"],
        exposed_tools=[MCPTool(name=tool, description="d")],
    )
    br.calculate_risk_score()
    return br


NHI_MAP = {
    "aws_secret_access_key": [{"node_id": "nhi:1", "name": "ci-bot", "risk_score": 88, "risk_band": "critical"}],
}


def test_span_resolves_to_exact_cve_cred_nhi_and_blast() -> None:
    vulnerable = _blast_radius()
    unrelated = _blast_radius(cve="CVE-0000-0000", tool="read_file", server="fs-mcp", pkg="left-pad", creds=[])

    trace = ToolCallTrace(trace_id="t1", span_id="abc123", tool_name="run_shell", server_name="shell-mcp")

    paths = correlate_spans_to_attack_paths([trace], [vulnerable, unrelated], nhi_by_credential=NHI_MAP)

    assert len(paths) == 1, "span should resolve to exactly the CVE it hit, not every finding"
    path = paths[0]
    assert path.span_id == "abc123"  # the exact traced call, not an aggregate
    assert path.match_basis == "tool"
    assert path.vulnerability_id == "CVE-2025-1234"
    assert path.is_kev is True
    assert "AWS_SECRET_ACCESS_KEY" in path.exposed_credentials
    assert [n["name"] for n in path.exposed_nhi] == ["ci-bot"]
    assert path.affected_servers == ["shell-mcp"]
    assert path.affected_agents == ["ci-agent"]
    assert path.blast_radius_score > 0


def test_per_span_identity_not_aggregate() -> None:
    """Two calls of the same tool resolve as two distinct spans, not one row."""
    vulnerable = _blast_radius()
    traces = [
        ToolCallTrace(trace_id="t1", span_id="span-A", tool_name="run_shell", server_name="shell-mcp"),
        ToolCallTrace(trace_id="t1", span_id="span-B", tool_name="run_shell", server_name="shell-mcp"),
    ]
    paths = correlate_spans_to_attack_paths(traces, [vulnerable], nhi_by_credential=NHI_MAP)
    assert {p.span_id for p in paths} == {"span-A", "span-B"}
    assert all(p.vulnerability_id == "CVE-2025-1234" for p in paths)


def test_unmatched_span_yields_no_attack_path() -> None:
    vulnerable = _blast_radius()
    trace = ToolCallTrace(trace_id="t1", span_id="x", tool_name="totally_unrelated", server_name="other")
    assert correlate_spans_to_attack_paths([trace], [vulnerable]) == []


def test_server_and_package_match_bases() -> None:
    br = _blast_radius(tool="run_shell", server="shell-mcp", pkg="requests")
    # server-only match (tool name not in exposed_tools)
    server_span = ToolCallTrace(trace_id="t", span_id="s1", tool_name="unknown_tool", server_name="shell-mcp")
    # package match via explicit package attribute
    pkg_span = ToolCallTrace(trace_id="t", span_id="s2", tool_name="x", package_name="requests")
    paths = correlate_spans_to_attack_paths([server_span, pkg_span], [br])
    bases = {p.span_id: p.match_basis for p in paths}
    assert bases["s1"] == "server"
    assert bases["s2"] == "package"


def test_correlation_over_parsed_otlp_trace() -> None:
    """End-to-end: parse an OTLP trace, then resolve its span to the attack path."""
    otlp = {
        "spans": [
            {
                "traceId": "trace-9",
                "spanId": "deadbeef",
                "name": "adk.tool.run_shell",
                "attributes": [{"key": "mcp.server", "value": {"stringValue": "shell-mcp"}}],
            }
        ]
    }
    traces = parse_otel_traces(otlp)
    assert traces and traces[0].span_id == "deadbeef"
    paths = correlate_spans_to_attack_paths(traces, [_blast_radius()], nhi_by_credential=NHI_MAP)
    assert len(paths) == 1
    assert paths[0].span_id == "deadbeef"
    assert paths[0].vulnerability_id == "CVE-2025-1234"
    assert paths[0].exposed_nhi[0]["name"] == "ci-bot"
