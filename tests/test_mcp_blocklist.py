from agent_bom.mcp_blocklist import blocklist_findings_for_agents, match_mcp_server
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
from agent_bom.output import to_json


def _agent_with_server(server: MCPServer) -> Agent:
    return Agent(
        name="test-agent",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/claude.json",
        mcp_servers=[server],
    )


def test_exact_blocklist_match_is_critical_and_blocks_server() -> None:
    blocklist = {
        "entries": [
            {
                "id": "confirmed-bad-server",
                "title": "Confirmed malicious MCP server",
                "description": "Confirmed malicious behavior.",
                "names": ["evil-mcp"],
            }
        ]
    }
    server = MCPServer(name="evil-mcp", command="npx", args=["evil-mcp"])
    agent = _agent_with_server(server)

    findings = blocklist_findings_for_agents([agent], blocklist)

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].finding_type.value == "MCP_BLOCKLIST"
    assert findings[0].evidence["match_type"] == "exact"
    assert server.security_blocked is True
    assert any("MCP_BLOCKLIST[critical/exact]" in warning for warning in server.security_warnings)


def test_pattern_blocklist_match_is_high_warning() -> None:
    blocklist = {
        "entries": [
            {
                "id": "suspicious-token-grabber",
                "title": "Suspicious token grabber name",
                "patterns": ["token[-_]?grabber"],
            }
        ]
    }
    server = MCPServer(name="workspace-token-grabber", command="uvx", args=["workspace-token-grabber"])

    matches = match_mcp_server(server, blocklist)

    assert len(matches) == 1
    assert matches[0].severity == "high"
    assert matches[0].match_type == "pattern"


def test_blocklist_checks_package_identity_values() -> None:
    blocklist = {
        "entries": [
            {
                "id": "bad-package",
                "title": "Blocked package-backed MCP server",
                "packages": ["@bad/mcp-server"],
            }
        ]
    }
    server = MCPServer(
        name="renamed-server",
        command="npx",
        args=["@bad/mcp-server"],
        packages=[Package(name="@bad/mcp-server", version="1.0.0", ecosystem="npm")],
    )

    matches = match_mcp_server(server, blocklist)

    assert len(matches) == 1
    assert matches[0].severity == "critical"
    assert matches[0].matched_value == "@bad/mcp-server"


def test_json_output_includes_mcp_blocklist_findings() -> None:
    blocklist = {
        "entries": [
            {
                "id": "confirmed-bad-server",
                "title": "Confirmed malicious MCP server",
                "names": ["evil-mcp"],
            }
        ]
    }
    server = MCPServer(name="evil-mcp", command="npx", args=["evil-mcp"])
    agent = _agent_with_server(server)
    findings = blocklist_findings_for_agents([agent], blocklist)

    payload = to_json(AIBOMReport(agents=[agent], findings=findings))

    assert payload["findings"][0]["finding_type"] == "MCP_BLOCKLIST"
    assert payload["findings"][0]["severity"] == "critical"
    assert payload["findings"][0]["evidence"]["entry_id"] == "confirmed-bad-server"
    assert payload["agents"][0]["mcp_servers"][0]["security_blocked"] is True
