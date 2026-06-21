"""Unit tests for the MCP server + agent→MCP auth posture evaluator."""

from __future__ import annotations

from agent_bom.finding import FindingType
from agent_bom.mcp_auth_posture import (
    annotate_graph_mcp_auth,
    annotate_graph_mcp_auth_from_report,
    evaluate_mcp_auth_posture,
    normalize_proxy_policy,
)
from agent_bom.models import Agent, AgentType, MCPServer, TransportType


def _agent(name: str, *, servers: list[MCPServer] | None = None) -> Agent:
    return Agent(
        name=name,
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path=f"/tmp/{name}.json",
        mcp_servers=servers or [],
    )


def _net_server(name: str, *, url: str = "https://mcp.example.com/sse", env: dict | None = None) -> MCPServer:
    transport = TransportType.SSE if "sse" in url.lower() else TransportType.STREAMABLE_HTTP
    return MCPServer(name=name, transport=transport, url=url, env=env or {})


def _weaknesses(findings: list) -> set[str]:
    return {f.evidence.get("mcp_auth_weakness") for f in findings}


# ── Weakness 1: unauthenticated network-reachable MCP server ─────────────────


def test_unauthenticated_network_server_flagged() -> None:
    server = _net_server("payments", url="https://mcp.example.com/sse")  # no auth env, no policy
    findings = evaluate_mcp_auth_posture([_agent("orchestrator", servers=[server])])
    unauth = [f for f in findings if f.evidence.get("mcp_auth_weakness") == "unauthenticated_server"]
    assert unauth, "expected an unauthenticated-server finding"
    f = unauth[0]
    assert f.finding_type == FindingType.PROMPT_SECURITY
    assert f.severity == "high"
    assert "MCP01" in f.owasp_mcp_tags
    assert f.asset.asset_type == "mcp_server"


def test_local_stdio_server_not_flagged_as_unauthenticated() -> None:
    server = MCPServer(name="fs", command="npx", transport=TransportType.STDIO)
    findings = evaluate_mcp_auth_posture([_agent("a", servers=[server])])
    assert "unauthenticated_server" not in _weaknesses(findings)


def test_authenticated_network_server_clean() -> None:
    # Network server presenting a bearer/oauth credential to the upstream and
    # served over TLS, fronted by a bound, identity-requiring proxy → no findings.
    server = _net_server("docs", url="https://mcp.example.com/sse", env={"MCP_OAUTH_ACCESS_TOKEN": "x"})
    policy = {"policy_id": "p-docs", "server": "docs", "bound_agents": ["agent-a"], "require_agent_identity": True}
    findings = evaluate_mcp_auth_posture([_agent("agent-a", servers=[server])], proxy_policies=[policy])
    assert findings == []


# ── Weakness 2: weak transport security ──────────────────────────────────────


def test_non_tls_remote_server_flagged() -> None:
    server = _net_server("plain", url="http://mcp.example.com/mcp", env={"MCP_BEARER_TOKEN": "x"})
    findings = evaluate_mcp_auth_posture([_agent("a", servers=[server])])
    weak = [f for f in findings if f.title == "Remote MCP server over non-TLS transport"]
    assert weak
    assert weak[0].severity == "high"
    assert weak[0].evidence["tls"] is False


def test_url_embedded_credentials_flagged() -> None:
    server = _net_server("embed", url="https://user:s3cret@mcp.example.com/sse", env={"MCP_TOKEN": "x"})
    findings = evaluate_mcp_auth_posture([_agent("a", servers=[server])])
    embed = [f for f in findings if "credentials embedded in connection URL" in f.title]
    assert embed
    # Reference-only: the secret value never appears in the serialized finding.
    assert "s3cret" not in str(embed[0].to_dict())


def test_query_string_at_sign_not_treated_as_embedded_credentials() -> None:
    server = _net_server("q", url="https://mcp.example.com/sse?cc=a@b.com", env={"MCP_TOKEN": "x"})
    findings = evaluate_mcp_auth_posture([_agent("a", servers=[server])])
    assert not [f for f in findings if "embedded in connection URL" in f.title]


# ── Weakness 3: over-broad / static MCP credentials ──────────────────────────


def test_static_api_key_on_network_server_flagged() -> None:
    server = _net_server("static", url="https://mcp.example.com/sse", env={"SERVICE_API_KEY": "x"})
    findings = evaluate_mcp_auth_posture([_agent("a", servers=[server])])
    static = [f for f in findings if f.evidence.get("mcp_auth_weakness") == "static_credentials"]
    assert static
    assert static[0].evidence["static_credential_refs"] == ["SERVICE_API_KEY"]
    # Secret value not leaked.
    assert '"x"' not in str(static[0].to_dict())


def test_oauth_only_credentials_not_flagged_as_static() -> None:
    server = _net_server("oauth", url="https://mcp.example.com/sse", env={"MCP_OAUTH_ACCESS_TOKEN": "x"})
    findings = evaluate_mcp_auth_posture([_agent("a", servers=[server])])
    assert "static_credentials" not in _weaknesses(findings)


def test_static_credential_allowlist_suppresses(monkeypatch) -> None:
    import agent_bom.mcp_auth_posture as mod

    monkeypatch.setattr(mod, "MCP_AUTH_STATIC_CRED_ALLOWLIST", ["service_api_key"])
    server = _net_server("static", url="https://mcp.example.com/sse", env={"SERVICE_API_KEY": "x"})
    findings = evaluate_mcp_auth_posture([_agent("a", servers=[server])])
    assert "static_credentials" not in _weaknesses(findings)


# ── Weakness 4: agent→MCP auth gap ───────────────────────────────────────────


def test_agent_mcp_gap_when_no_policy() -> None:
    server = _net_server("svc", url="https://mcp.example.com/sse", env={"MCP_BEARER_TOKEN": "x"})
    findings = evaluate_mcp_auth_posture([_agent("worker", servers=[server])])
    gap = [f for f in findings if f.evidence.get("mcp_auth_weakness") == "agent_mcp_auth_gap"]
    assert gap
    assert gap[0].evidence["agent"] == "worker"
    assert gap[0].severity == "high"


def test_agent_mcp_gap_closed_by_bound_identity_policy() -> None:
    server = _net_server("svc", url="https://mcp.example.com/sse", env={"MCP_BEARER_TOKEN": "x"})
    policy = {"policy_id": "p", "server": "svc", "bound_agents": ["worker"], "require_agent_identity": True}
    findings = evaluate_mcp_auth_posture([_agent("worker", servers=[server])], proxy_policies=[policy])
    assert "agent_mcp_auth_gap" not in _weaknesses(findings)


def test_wildcard_policy_does_not_close_gap() -> None:
    server = _net_server("svc", url="https://mcp.example.com/sse", env={"MCP_BEARER_TOKEN": "x"})
    policy = {"policy_id": "p", "server": "svc", "bound_agents": ["*"], "require_agent_identity": True}
    findings = evaluate_mcp_auth_posture([_agent("worker", servers=[server])], proxy_policies=[policy])
    assert "agent_mcp_auth_gap" in _weaknesses(findings)


# ── normalization + reference-only invariants ────────────────────────────────


def test_normalize_proxy_policy_reads_aliases() -> None:
    view = normalize_proxy_policy({"id": "x", "upstream": "svc", "bound_agents": "worker"})
    assert view.policy_id == "x"
    assert view.server == "svc"
    assert view.bound_agents == ["worker"]


def test_blocked_server_not_evaluated() -> None:
    server = _net_server("blk", url="https://mcp.example.com/sse")
    server.security_blocked = True
    findings = evaluate_mcp_auth_posture([_agent("a", servers=[server])])
    assert findings == []


def test_no_secret_values_in_any_finding() -> None:
    server = _net_server("svc", url="http://user:topsecret@mcp.example.com/sse", env={"SERVICE_API_KEY": "leakme"})
    findings = evaluate_mcp_auth_posture([_agent("a", servers=[server])])
    blob = str([f.to_dict() for f in findings])
    assert "topsecret" not in blob
    assert "leakme" not in blob


# ── graph annotation ─────────────────────────────────────────────────────────


def test_annotate_graph_flags_server_nodes() -> None:
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.types import EntityType

    graph = UnifiedGraph()
    node = UnifiedNode(id="n1", entity_type=EntityType.SERVER, label="payments")
    graph.add_node(node)

    server = _net_server("payments", url="https://mcp.example.com/sse")
    findings = evaluate_mcp_auth_posture([_agent("a", servers=[server])])
    result = annotate_graph_mcp_auth(graph, findings)
    assert result["nodes_flagged"] >= 1
    assert node.attributes.get("mcp_auth_weak") is True
    assert node.attributes.get("mcp_auth_unauthenticated") is True
    assert any(r.pattern.startswith("mcp_auth.") for r in graph.interaction_risks)


def test_annotate_graph_from_report_no_op_without_findings() -> None:
    from agent_bom.graph.container import UnifiedGraph

    graph = UnifiedGraph()
    result = annotate_graph_mcp_auth_from_report(graph, {"findings": []})
    assert result == {"nodes_flagged": 0, "interaction_risks": 0}
