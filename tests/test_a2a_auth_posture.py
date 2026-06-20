"""Unit tests for the A2A auth posture governance evaluator."""

from __future__ import annotations

from agent_bom.a2a_auth_posture import (
    annotate_graph_a2a_auth_from_report,
    evaluate_a2a_auth_posture,
    normalize_policy,
)
from agent_bom.finding import FindingType
from agent_bom.models import Agent, AgentType, MCPServer, TransportType


def _agent(name: str, *, metadata: dict | None = None, servers: list[MCPServer] | None = None, parent: str | None = None) -> Agent:
    return Agent(
        name=name,
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path=f"/tmp/{name}.json",
        mcp_servers=servers or [],
        metadata=metadata or {},
        parent_agent=parent,
    )


def _weaknesses(findings: list) -> set[str]:
    return {f.evidence.get("a2a_weakness") for f in findings}


# ── Weakness 1: shared / long-lived credentials ──────────────────────────────


def test_shared_static_token_across_agents_flagged() -> None:
    policy = {
        "policy_id": "p-shared",
        "agent_tokens": {"static-token-xyz": "agent-a", "another": "agent-b"},
        # One token mapped to two agents → shared credential.
    }
    policy["agent_tokens"] = {"static-token-xyz": "agent-a"}
    # Simulate the same token resolving to two agents via two policies.
    policy_b = {"policy_id": "p-shared-2", "agent_tokens": {"static-token-xyz": "agent-b"}}
    findings = evaluate_a2a_auth_posture([_agent("agent-a"), _agent("agent-b")], gateway_policies=[policy, policy_b])
    shared = [f for f in findings if f.evidence.get("a2a_weakness") == "shared_credentials"]
    assert shared, "expected a shared-credential finding"
    f = shared[0]
    assert f.finding_type == FindingType.PROMPT_SECURITY
    assert f.severity == "high"
    assert set(f.evidence["shared_agent_ids"]) == {"agent-a", "agent-b"}
    # Reference-only: the token value itself never appears in the finding.
    assert "static-token-xyz" not in str(f.to_dict())


def test_shared_credential_env_var_across_agents_flagged() -> None:
    server_a = MCPServer(name="db", env={"SHARED_API_TOKEN": "x"})
    server_b = MCPServer(name="db2", env={"SHARED_API_TOKEN": "y"})
    findings = evaluate_a2a_auth_posture(
        [_agent("a", servers=[server_a]), _agent("b", servers=[server_b])],
    )
    shared = [f for f in findings if f.evidence.get("credential_ref") == "SHARED_API_TOKEN"]
    assert shared
    assert set(shared[0].evidence["agents"]) == {"a", "b"}
    # Secret value must not leak.
    assert '"x"' not in str(shared[0].to_dict())


# ── Weakness 2: missing mutual auth ──────────────────────────────────────────


def test_missing_mutual_auth_when_no_identity_required() -> None:
    delegator = _agent("orchestrator", metadata={"delegation_chains": ["orchestrator→worker"]})
    findings = evaluate_a2a_auth_posture([delegator], gateway_policies=[{"policy_id": "p", "bound_agents": ["orchestrator"]}])
    missing = [f for f in findings if f.evidence.get("a2a_weakness") == "missing_mutual_auth"]
    assert missing
    assert missing[0].severity == "high"


def test_unbounded_wildcard_policy_flagged() -> None:
    findings = evaluate_a2a_auth_posture([], gateway_policies=[{"policy_id": "p-wild", "bound_agents": ["*"]}])
    unbounded = [f for f in findings if "Unbounded" in f.title]
    assert unbounded
    assert unbounded[0].evidence["policy_id"] == "p-wild"


# ── Weakness 3: over-broad delegation scope ──────────────────────────────────


def test_overbroad_bound_agents_flagged() -> None:
    policy = {"policy_id": "p-broad", "bound_agents": [f"agent-{i}" for i in range(20)]}
    findings = evaluate_a2a_auth_posture([], gateway_policies=[policy])
    broad = [f for f in findings if "Over-broad delegation scope" in f.title]
    assert broad
    assert broad[0].evidence["bound_agent_count"] == 20


def test_unbounded_delegation_depth_flagged() -> None:
    deep_chain = "a1→a2→a3→a4→a5→a6"  # depth 5 > default 4
    agent = _agent("a6", metadata={"delegation_chains": [deep_chain]})
    findings = evaluate_a2a_auth_posture([agent])
    deep = [f for f in findings if "Unbounded transitive delegation depth" in f.title]
    assert deep
    assert deep[0].evidence["delegation_depth"] == 5


# ── Weakness 4: unverified actor / on-behalf-of tokens ───────────────────────


def test_unverified_actor_token_across_boundary_flagged() -> None:
    agent = _agent(
        "cross-domain-worker",
        metadata={
            "delegation_chains": ["prod-orchestrator→staging-worker"],
            "delegation_environments": {"prod-orchestrator": "prod", "staging-worker": "staging"},
        },
    )
    findings = evaluate_a2a_auth_posture([agent])
    unverified = [f for f in findings if f.evidence.get("a2a_weakness") == "unverified_actor_token"]
    assert unverified
    assert unverified[0].severity == "high"


def test_verified_actor_token_not_flagged() -> None:
    agent = _agent(
        "cross-domain-worker",
        metadata={
            "delegation_chains": ["prod-orchestrator→staging-worker"],
            "delegation_environments": {"prod-orchestrator": "prod", "staging-worker": "staging"},
            "actor_token": {"verified": True, "type": "jwt"},
        },
    )
    findings = evaluate_a2a_auth_posture([agent])
    assert not [f for f in findings if f.evidence.get("a2a_weakness") == "unverified_actor_token"]


# ── Clean configuration produces no findings ─────────────────────────────────


def test_clean_a2a_config_produces_no_findings() -> None:
    # Per-agent identity, bounded policy that requires verified identity,
    # signed cross-boundary token, single-credential-per-agent, shallow chain.
    server = MCPServer(name="vault", url="https://vault.internal", transport=TransportType.STREAMABLE_HTTP, env={"AGENT_A_TOKEN": "x"})
    agent = _agent(
        "worker",
        servers=[server],
        metadata={
            "delegation_chains": ["orchestrator→worker"],
            "delegation_environments": {"orchestrator": "prod", "worker": "prod"},
            "actor_token": {"verified": True},
        },
    )
    policy = {
        "policy_id": "p-clean",
        "bound_agents": ["worker"],
        "require_agent_identity": True,
        "jwks_uri": "https://idp.internal/jwks",
    }
    findings = evaluate_a2a_auth_posture([agent], gateway_policies=[policy])
    assert findings == [], f"clean config should be silent, got {_weaknesses(findings)}"


def test_local_stdio_agent_with_no_delegation_is_silent() -> None:
    agent = _agent("solo", servers=[MCPServer(name="fs", command="npx")])
    assert evaluate_a2a_auth_posture([agent]) == []


# ── Policy normalization ─────────────────────────────────────────────────────


def test_normalize_policy_from_object() -> None:
    class _P:
        policy_id = "obj"
        bound_agents = ["a"]
        require_agent_identity = True
        jwks_uri = "https://j"
        oidc_issuer = ""
        agent_tokens = {"t": "a"}

    view = normalize_policy(_P())
    assert view.policy_id == "obj"
    assert view.require_agent_identity is True
    assert view.has_signature_verification is True
    assert not view.is_unbounded


def test_normalize_policy_unbounded_detection() -> None:
    assert normalize_policy({"policy_id": "x", "bound_agents": []}).is_unbounded
    assert normalize_policy({"policy_id": "x", "bound_agents": ["*"]}).is_unbounded
    assert not normalize_policy({"policy_id": "x", "bound_agents": ["a"]}).is_unbounded


# ── Graph annotation ─────────────────────────────────────────────────────────


def test_graph_annotation_flags_agent_nodes() -> None:
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.types import EntityType

    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(UnifiedNode(id="agent:orch", entity_type=EntityType.AGENT, label="orchestrator"))

    report_json = {
        "findings": [
            {
                "finding_type": FindingType.PROMPT_SECURITY.value,
                "title": "Missing mutual authentication on inter-agent edges",
                "risk_score": 7.0,
                "asset": {"name": "orchestrator"},
                "evidence": {"a2a_weakness": "missing_mutual_auth", "agent": "orchestrator"},
            }
        ]
    }
    result = annotate_graph_a2a_auth_from_report(graph, report_json)
    assert result["nodes_flagged"] == 1
    assert result["interaction_risks"] == 1
    node = graph.nodes["agent:orch"]
    assert node.attributes.get("a2a_missing_mutual_auth") is True
    assert node.attributes.get("a2a_auth_weak") is True
    assert any(r.pattern == "a2a_auth.missing_mutual_auth" for r in graph.interaction_risks)


def test_graph_annotation_noop_without_a2a_findings() -> None:
    from agent_bom.graph.container import UnifiedGraph

    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    result = annotate_graph_a2a_auth_from_report(graph, {"findings": [{"finding_type": "CVE"}]})
    assert result == {"nodes_flagged": 0, "interaction_risks": 0}
