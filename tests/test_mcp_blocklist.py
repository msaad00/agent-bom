import json
from pathlib import Path

from agent_bom.mcp_blocklist import (
    blocklist_findings_for_agents,
    flag_blocklisted_mcp_servers,
    load_mcp_blocklist,
    match_mcp_server,
    sanitize_security_intelligence_entry,
)
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
from agent_bom.output import to_json
from agent_bom.output.sarif import to_sarif


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
                "confidence": "confirmed_malicious",
                "default_recommendation": "block",
                "source_type": "security_advisory",
                "last_verified": "2026-04-28",
                "names": ["evil-mcp"],
                "references": ["https://example.com/advisory"],
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
    assert findings[0].evidence["confidence"] == "confirmed_malicious"
    assert findings[0].evidence["default_recommendation"] == "block"
    assert server.security_blocked is True
    assert any("MCP_BLOCKLIST[critical/exact]" in warning for warning in server.security_warnings)
    assert server.security_intelligence[0]["entry_id"] == "confirmed-bad-server"
    assert server.security_intelligence[0]["references"] == ["https://example.com/advisory"]


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
    assert payload["agents"][0]["mcp_servers"][0]["security_intelligence"][0]["entry_id"] == "confirmed-bad-server"


def test_match_values_are_redacted_before_output() -> None:
    raw_token = "ghp_" + "A" * 36
    server = MCPServer(
        name="runner",
        command="npx",
        args=[
            "credential-stealer",
            "--api-key",
            "sk-live-secret",
            raw_token,
            "session=" + raw_token,
            "url=https://user:pass@example.com/path?token=secret",
        ],
    )
    blocklist = {
        "entries": [
            {
                "id": "suspicious-name",
                "title": "Suspicious server",
                "description": "Suspicious command.",
                "patterns": ["credential-stealer"],
                "severity": "high",
                "confidence": "heuristic",
                "default_recommendation": "review",
                "source_type": "heuristic",
                "last_verified": "2026-04-28",
                "references": [],
            }
        ]
    }

    match = match_mcp_server(server, blocklist)[0]
    agent = _agent_with_server(server)
    findings = blocklist_findings_for_agents([agent], blocklist)
    json_payload = json.dumps(to_json(AIBOMReport(agents=[agent], findings=findings)))
    sarif_payload = json.dumps(to_sarif(AIBOMReport(agents=[agent], findings=findings)))

    assert "sk-live-secret" not in match.matched_value
    assert raw_token not in match.matched_value
    assert "user:pass" not in match.matched_value
    assert "token=secret" not in match.matched_value
    assert "--api-key <redacted>" in match.matched_value
    for payload in (json_payload, sarif_payload):
        assert "sk-live-secret" not in payload
        assert raw_token not in payload
        assert "user:pass" not in payload
        assert "token=secret" not in payload


def test_security_intelligence_sanitizer_drops_unknown_secret_fields() -> None:
    raw_token = "ghp_" + "B" * 36

    safe = sanitize_security_intelligence_entry(
        {
            "entry_id": "intel-a",
            "title": "Suspicious MCP",
            "matched_value": f"npx suspicious --token {raw_token}",
            "source": "community",
            "references": ["https://example.com/advisory#fragment", "javascript:alert(1)"],
            "remediation_actions": [f"remove token={raw_token}", "disable the server"],
            "debug_token": raw_token,
            "nested": {"authorization": raw_token},
        }
    )

    serialized = json.dumps(safe)
    assert "debug_token" not in safe
    assert "nested" not in safe
    assert raw_token not in serialized
    assert safe["matched_value"] == "npx suspicious --token <redacted>"
    assert safe["references"] == ["https://example.com/advisory"]
    assert safe["remediation_actions"][0] == "***REDACTED***"


def test_sarif_output_includes_mcp_blocklist_findings() -> None:
    server = MCPServer(name="evil-mcp", command="npx", args=["evil-mcp"], config_path="mcp.json")
    agent = _agent_with_server(server)
    findings = blocklist_findings_for_agents(
        [agent],
        {
            "entries": [
                {
                    "id": "confirmed-bad-server",
                    "title": "Confirmed malicious MCP server",
                    "description": "Confirmed malicious behavior.",
                    "names": ["evil-mcp"],
                    "severity": "critical",
                    "confidence": "confirmed_malicious",
                    "default_recommendation": "block",
                    "source_type": "security_advisory",
                    "last_verified": "2026-04-28",
                    "references": ["https://example.com/advisory"],
                }
            ]
        },
    )

    sarif = to_sarif(AIBOMReport(agents=[agent], findings=findings))

    assert sarif["runs"][0]["results"]
    assert sarif["runs"][0]["results"][0]["ruleId"] == "finding/MCP_BLOCKLIST"


def test_flag_blocklisted_servers_blocks_before_report_building() -> None:
    blocklist = {
        "entries": [
            {
                "id": "confirmed-bad-server",
                "title": "Confirmed malicious MCP server",
                "patterns": ["evil-mcp"],
                "severity": "critical",
            }
        ]
    }
    server = MCPServer(name="renamed", command="npx", args=["evil-mcp"])
    agent = _agent_with_server(server)

    assert flag_blocklisted_mcp_servers([agent], blocklist) == 1
    assert server.security_blocked is True
    assert any("confirmed-bad-server" in warning for warning in server.security_warnings)


def test_bundled_blocklist_matches_curated_malicious_mcp_packages() -> None:
    blocklist = load_mcp_blocklist()
    cases = [
        ("npx", ["-y", "postmark-mcp"], "malicious-npm-postmark-mcp"),
        ("npx", ["-y", "@lanyer640/mcp-runcommand-server"], "malicious-npm-lanyer640-mcp-runcommand-server"),
        ("uvx", ["mcp-server-todo"], "malicious-npm-mcp-server-todo"),
    ]

    for command, args, expected_entry_id in cases:
        matches = match_mcp_server(MCPServer(name="candidate", command=command, args=args), blocklist)
        match = next(match for match in matches if match.entry_id == expected_entry_id)

        assert match.severity == "critical"
        assert match.match_type == "pattern"


def test_bundled_blocklist_matches_suspicious_exfiltration_names() -> None:
    blocklist = load_mcp_blocklist()
    cases = ["credential-stealer", "secret-exfiltrator", "token-grabber"]

    for name in cases:
        matches = match_mcp_server(MCPServer(name=name, command="npx", args=["-y", name]), blocklist)
        match = next(match for match in matches if match.entry_id == "suspicious-credential-exfiltration-name")

        assert match.severity == "high"
        assert match.match_type == "pattern"


def test_bundled_blocklist_keeps_version_specific_mcp_package_pinned() -> None:
    blocklist = load_mcp_blocklist()

    vulnerable = MCPServer(name="ids", command="npx", args=["ids-enterprise-mcp-server@0.0.2"])
    unpinned = MCPServer(name="ids", command="npx", args=["ids-enterprise-mcp-server"])

    assert [
        match.entry_id
        for match in match_mcp_server(vulnerable, blocklist)
        if match.entry_id == "malicious-npm-ids-enterprise-mcp-server-0-0-2"
    ]
    assert not [
        match.entry_id
        for match in match_mcp_server(unpinned, blocklist)
        if match.entry_id == "malicious-npm-ids-enterprise-mcp-server-0-0-2"
    ]


def test_bundled_mcp_intelligence_entries_have_policy_contract() -> None:
    root = Path(__file__).resolve().parents[1]
    data = json.loads((root / "src/agent_bom/data/mcp-blocklist.json").read_text())

    assert data["schema_version"] == 2
    assert data["policy_contract"]["confidence_levels"] == ["confirmed_malicious", "suspicious", "heuristic"]

    required = {
        "id",
        "title",
        "description",
        "confidence",
        "default_recommendation",
        "source_type",
        "severity",
        "match_type",
        "last_verified",
        "references",
    }
    confirmed = [entry for entry in data["entries"] if entry["confidence"] == "confirmed_malicious"]
    assert confirmed
    for entry in data["entries"]:
        assert required <= set(entry)
        assert entry["default_recommendation"] in {"block", "warn", "review"}
        assert entry["confidence"] in data["policy_contract"]["confidence_levels"]
        if entry["default_recommendation"] == "block":
            assert entry["references"], entry["id"]
            assert entry.get("package"), entry["id"]
