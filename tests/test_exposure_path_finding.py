"""ExposurePath parity tests for unified Finding migration (#2918)."""

from __future__ import annotations

from agent_bom.finding import blast_radius_to_finding
from agent_bom.models import Agent, AgentStatus, AgentType, BlastRadius, MCPServer, MCPTool, Package, Severity, TransportType, Vulnerability
from agent_bom.output.exposure_path import exposure_path_for_blast_radius, exposure_path_for_finding


def _pkg(name: str = "lodash", version: str = "4.17.20", ecosystem: str = "npm") -> Package:
    return Package(name=name, version=version, ecosystem=ecosystem)


def _vuln(vuln_id: str = "CVE-2024-0001") -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        summary="Test vulnerability",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        fixed_version="4.17.21",
    )


def _server(name: str = "prod-mcp", tools: list[MCPTool] | None = None) -> MCPServer:
    return MCPServer(name=name, command="npx srv", transport=TransportType.STDIO, tools=tools or [])


def _agent(name: str = "prod-agent", servers: list[MCPServer] | None = None) -> Agent:
    return Agent(
        name=name,
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/test.json",
        mcp_servers=servers or [],
        status=AgentStatus.CONFIGURED,
    )


def _blast_radius() -> BlastRadius:
    tool = MCPTool(name="deploy", description="Deploy workloads")
    server = _server(tools=[tool])
    agent = _agent(servers=[server])
    br = BlastRadius(
        package=_pkg(),
        vulnerability=_vuln(),
        affected_agents=[agent],
        affected_servers=[server],
        exposed_credentials=["AWS_SECRET_ACCESS_KEY"],
        exposed_tools=[tool],
    )
    br.risk_score = 9.4
    br.attack_vector_summary = "Agent reaches vulnerable MCP package."
    return br


def test_exposure_path_for_finding_matches_blast_radius_projection() -> None:
    br = _blast_radius()
    legacy = exposure_path_for_blast_radius(br, rank=1)
    finding = blast_radius_to_finding(br)
    projected = exposure_path_for_finding(finding, rank=1, provenance_source="blast_radius_output")

    assert projected["label"] == legacy["label"]
    assert projected["summary"] == legacy["summary"]
    assert projected["riskScore"] == legacy["riskScore"]
    assert projected["affectedAgents"] == legacy["affectedAgents"]
    assert projected["affectedServers"] == legacy["affectedServers"]
    assert projected["reachableTools"] == legacy["reachableTools"]
    assert projected["exposedCredentials"] == legacy["exposedCredentials"]
    assert projected["relationships"] == legacy["relationships"]
    assert projected["provenance"] == legacy["provenance"]


def test_exposure_path_for_blast_radius_keeps_legacy_id_prefix() -> None:
    br = _blast_radius()
    path = exposure_path_for_blast_radius(br, rank=2)
    assert path["id"].startswith("blast:")
    assert path["rank"] == 2


def test_json_and_sarif_exposure_paths_use_finding_native_projection() -> None:
    from agent_bom.output.json_fmt import to_json
    from agent_bom.output.sarif import to_sarif

    tool = MCPTool(name="deploy", description="Deploy workloads")
    server = _server(tools=[tool])
    agent = _agent(servers=[server])
    br = _blast_radius()
    br.affected_servers = [server]
    br.exposed_tools = [tool]
    br.exposed_credentials = ["AWS_SECRET_ACCESS_KEY"]
    br.risk_score = 9.4

    from agent_bom.models import AIBOMReport

    report = AIBOMReport(
        agents=[agent],
        blast_radii=[br],
        tool_version="0.91.0",
    )

    json_path = to_json(report)["exposure_paths"]["paths"][0]
    sarif_path = to_sarif(report)["runs"][0]["results"][0]["properties"]["exposure_path"]

    assert json_path["id"].startswith("blast:")
    assert sarif_path["id"].startswith("finding:")
    assert json_path["label"] == sarif_path["label"] == "lodash@4.17.20 -> CVE-2024-0001"
    assert json_path["affectedAgents"] == sarif_path["affectedAgents"] == ["prod-agent"]
    assert json_path["reachableTools"] == sarif_path["reachableTools"] == ["deploy"]
