"""Tests for agentic search content risk detection."""

from agent_bom.enforcement import check_agentic_search_risk
from agent_bom.models import MCPServer, MCPTool, Package, Severity, Vulnerability


def _server(*, tools=None, has_cves=False, has_creds=False) -> MCPServer:
    pkgs = []
    if has_cves:
        pkg = Package(name="vuln-pkg", version="1.0", ecosystem="npm")
        pkg.vulnerabilities = [Vulnerability(id="CVE-2025-1", summary="x", severity=Severity.HIGH)]
        pkgs = [pkg]
    env = {"API_KEY": "***"} if has_creds else {}
    return MCPServer(name="srv", tools=tools or [], packages=pkgs, env=env)


def test_no_search_tools():
    srv = _server(tools=[MCPTool(name="read_file", description="read")])
    assert check_agentic_search_risk(srv) == []


def test_search_tool_with_creds_is_high():
    srv = _server(
        tools=[MCPTool(name="web_search", description="search the web")],
        has_creds=True,
    )
    findings = check_agentic_search_risk(srv)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "exfiltration" in findings[0].reason


def test_search_tool_with_cves_is_medium():
    srv = _server(
        tools=[MCPTool(name="tavily_search", description="search with Tavily")],
        has_cves=True,
    )
    findings = check_agentic_search_risk(srv)
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_search_tool_clean_server_no_findings():
    srv = _server(tools=[MCPTool(name="web_search", description="search")])
    assert check_agentic_search_risk(srv) == []


def test_multiple_search_tools():
    srv = _server(
        tools=[
            MCPTool(name="web_search", description="search"),
            MCPTool(name="browse", description="browse web"),
        ],
        has_creds=True,
    )
    findings = check_agentic_search_risk(srv)
    assert len(findings) == 2
