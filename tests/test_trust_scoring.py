"""Tests for agent_bom.fleet.trust_scoring — trust score computation."""

from agent_bom.fleet.trust_scoring import compute_trust_score
from agent_bom.models import (
    Agent,
    AgentType,
    MCPServer,
    MCPTool,
    Package,
    PermissionProfile,
)


def _agent(servers=None, **kw) -> Agent:
    return Agent(
        name="test",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/config.json",
        mcp_servers=servers or [],
        **kw,
    )


def _server(
    name: str = "srv",
    verified: bool = False,
    env: dict | None = None,
    tools: list | None = None,
    priv: str | None = None,
) -> MCPServer:
    srv = MCPServer(
        name=name,
        command="npx",
        args=["-y", name],
        env=env or {},
        packages=[Package(name="pkg", version="1.0.0", ecosystem="npm")],
        tools=tools or [],
        registry_verified=verified,
    )
    if priv:
        if priv == "critical":
            srv.permission_profile = PermissionProfile(container_privileged=True)
        elif priv == "high":
            srv.permission_profile = PermissionProfile(runs_as_root=True)
        elif priv == "medium":
            srv.permission_profile = PermissionProfile(network_access=True, filesystem_write=True)
    return srv


def test_high_trust_all_verified():
    """All servers verified, no vulns, no creds → high score."""
    srv = _server(
        verified=True,
        tools=[MCPTool(name="t", description="d")],
    )
    agent = _agent(servers=[srv], version="1.0")
    score, factors = compute_trust_score(agent)
    assert score >= 80
    assert factors["registry_verification"] == 20.0
    assert factors["vulnerability_posture"] == 25.0
    assert factors["credential_hygiene"] == 15.0


def test_unverified_servers_lower_registry():
    """Unverified servers get 0 registry score."""
    agent = _agent(servers=[_server(verified=False)])
    score, factors = compute_trust_score(agent)
    assert factors["registry_verification"] == 0.0


def test_mixed_verification():
    """One verified, one not → 50% of 20 = 10."""
    agent = _agent(servers=[
        _server(name="a", verified=True),
        _server(name="b", verified=False),
    ])
    _, factors = compute_trust_score(agent)
    assert factors["registry_verification"] == 10.0


def test_vuln_penalty():
    """Critical vulns heavily penalize trust."""
    agent = _agent(servers=[_server()])
    score_clean, _ = compute_trust_score(agent, vuln_counts=None)
    score_vuln, factors = compute_trust_score(
        agent,
        vuln_counts={"critical": 3, "high": 2, "medium": 1, "low": 0},
    )
    assert score_vuln < score_clean
    # 3*10 + 2*5 + 1*2 = 42 → 25 - 42 = -17 → clamped to 0
    assert factors["vulnerability_posture"] == 0.0


def test_credential_penalty():
    """Agents with many credential-like env vars get lower hygiene score."""
    srv = _server(env={
        "API_KEY": "sk-abc",
        "AUTH_TOKEN": "tok",
        "SECRET": "s",
        "DATABASE_URL": "pg://...",
        "DEBUG": "1",
        "LOG_LEVEL": "info",
    })
    agent = _agent(servers=[srv])
    _, factors = compute_trust_score(agent)
    # 4 credential-like vars → cred_count=4 → score=5.0
    assert factors["credential_hygiene"] == 5.0


def test_permission_critical():
    """Critical privilege level → 0 permission score."""
    srv = _server(priv="critical")
    agent = _agent(servers=[srv])
    _, factors = compute_trust_score(agent)
    assert factors["permission_profile"] == 0.0


def test_permission_high():
    """High privilege level → 5 permission score."""
    srv = _server(priv="high")
    agent = _agent(servers=[srv])
    _, factors = compute_trust_score(agent)
    assert factors["permission_profile"] == 5.0


def test_no_servers():
    """Agent with no servers gets neutral scores."""
    agent = _agent(servers=[])
    score, factors = compute_trust_score(agent)
    assert factors["registry_verification"] == 10.0
    assert factors["credential_hygiene"] == 15.0
    assert score > 0


def test_score_capped_at_100():
    """Total never exceeds 100."""
    srv = _server(verified=True, tools=[MCPTool(name="t", description="d")])
    agent = _agent(servers=[srv], version="1.0")
    score, _ = compute_trust_score(agent)
    assert score <= 100.0


def test_config_quality_bonus():
    """Config path + version + servers + tools → max config quality."""
    srv = _server(
        verified=True,
        tools=[MCPTool(name="t", description="d")],
    )
    agent = _agent(servers=[srv], version="1.0")
    _, factors = compute_trust_score(agent)
    # config_path=3 + version=2 + servers=2 + tools=3 = 10
    assert factors["configuration_quality"] == 10.0
