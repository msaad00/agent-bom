"""Cross-environment correlation tests (#1892 Phase 1: AWS Bedrock).

Pinned contracts:
- Exact match when local model_refs substring matches the cloud Bedrock
  agent's foundationModel.
- Inferred match when the local agent uses Bedrock SDK signals but no
  model_id evidence.
- No match when local agent has no Bedrock SDK signals and no overlapping
  model_refs.
- The graph builder emits a `correlates_with` edge between the local
  framework agent node and the promoted cloud_resource lineage node.
- Cross-tenant safety: the correlator only operates within the data the
  graph builder hands it, so a similarly-named local/cloud pair from a
  different tenant cannot accidentally merge.
"""

from __future__ import annotations

from agent_bom.cross_env_correlation import (
    CorrelationSignal,
    CrossEnvironmentLink,
    _bedrock_model_tokens,
    correlate_bedrock,
)
from agent_bom.graph import EntityType, RelationshipType
from agent_bom.graph.builder import build_unified_graph_from_report


def _local_agent(stable_id: str, *, model_refs: list[str], framework: str = "langchain", credential_refs: list[str] | None = None) -> dict:
    return {
        "stable_id": stable_id,
        "name": stable_id,
        "framework": framework,
        "file_path": f"src/{stable_id}.py",
        "line_number": 10,
        "confidence": "high",
        "model_refs": model_refs,
        "credential_refs": credential_refs or [],
        "capabilities": [],
        "dynamic_edges": False,
    }


def _bedrock_cloud_agent(name: str, *, foundation_model: str, region: str = "us-east-1") -> dict:
    arn = f"arn:aws:bedrock:{region}:111122223333:agent/{name}"
    return {
        "name": f"bedrock:{name}",
        "type": "custom",
        "stable_id": f"agent:bedrock:{name}",
        "config_path": arn,
        "source": "aws-bedrock",
        "version": foundation_model,
        "mcp_servers": [],
        "metadata": {
            "cloud_origin": {
                "provider": "aws",
                "service": "bedrock",
                "resource_type": "agent",
                "resource_id": arn,
                "resource_name": name,
                "location": region,
            },
        },
    }


# ── Token extraction ────────────────────────────────────────────────────────


def test_bedrock_model_tokens_extracts_family_short_form() -> None:
    tokens = _bedrock_model_tokens("anthropic.claude-3-5-sonnet-20240620-v1:0")
    # The full id, the post-vendor-prefix slug, the short form (no version),
    # and the stripped form (no date) all need to be in the set so the
    # substring matcher in _correlate_bedrock_one can hit on a local
    # `model_refs` of "claude-3-5-sonnet".
    assert "anthropic.claude-3-5-sonnet-20240620-v1:0" in tokens
    assert "claude-3-5-sonnet-20240620-v1:0" in tokens
    assert "anthropic.claude-3-5-sonnet-20240620-v1" in tokens
    assert "anthropic.claude-3-5-sonnet" in tokens


def test_bedrock_model_tokens_handles_empty() -> None:
    assert _bedrock_model_tokens("") == set()


# ── Direct correlator ──────────────────────────────────────────────────────


def test_exact_match_via_model_id() -> None:
    local = _local_agent("agent:cli:support_bot", model_refs=["claude-3-5-sonnet"])
    cloud = _bedrock_cloud_agent("support-bot", foundation_model="anthropic.claude-3-5-sonnet-20240620-v1:0")
    links = correlate_bedrock([local], [cloud])
    assert len(links) == 1
    link = links[0]
    assert link.confidence == "exact"
    assert link.local_agent_id == "agent:cli:support_bot"
    assert link.cloud_resource_id.startswith("cloud_resource:aws:bedrock:agent:")
    assert any(s.kind == "model_id_match" for s in link.signals)


def test_inferred_match_via_bedrock_sdk_signal() -> None:
    local = _local_agent(
        "agent:cli:rag_bot",
        model_refs=["text-embedding-3-small"],  # OpenAI-style, no Bedrock token
        framework="langchain-bedrock-runtime",  # SDK hint
        credential_refs=["AWS_ACCESS_KEY_ID"],
    )
    cloud = _bedrock_cloud_agent("rag-bot", foundation_model="amazon.titan-embed-text-v1")
    links = correlate_bedrock([local], [cloud])
    assert len(links) == 1
    assert links[0].confidence == "inferred"
    kinds = {s.kind for s in links[0].signals}
    assert "local_uses_bedrock_sdk" in kinds


def test_no_match_when_neither_signal_present() -> None:
    local = _local_agent("agent:cli:openai_only", model_refs=["gpt-4o"], framework="openai-assistants")
    cloud = _bedrock_cloud_agent("support", foundation_model="anthropic.claude-3-5-sonnet-20240620-v1:0")
    assert correlate_bedrock([local], [cloud]) == []


def test_dedup_prevents_duplicate_edges_between_same_pair() -> None:
    # If a single local/cloud pair would match by both exact and inferred
    # rules, only the higher-confidence (first-found) link is emitted.
    local = _local_agent(
        "agent:cli:dual",
        model_refs=["claude-3-5-sonnet"],
        framework="langchain-bedrock-runtime",
    )
    cloud = _bedrock_cloud_agent("dual", foundation_model="anthropic.claude-3-5-sonnet-20240620-v1:0")
    links = correlate_bedrock([local, local], [cloud])
    assert len(links) == 1
    assert links[0].confidence == "exact"


def test_ignores_non_bedrock_cloud_agents() -> None:
    local = _local_agent("agent:cli:anything", model_refs=["claude-3-5-sonnet"])
    not_bedrock = {
        **_bedrock_cloud_agent("x", foundation_model="anthropic.claude-3-5-sonnet"),
        "metadata": {
            "cloud_origin": {
                "provider": "aws",
                "service": "lambda",  # not bedrock
                "resource_type": "function",
                "resource_id": "arn:aws:lambda:...:fn",
            }
        },
    }
    assert correlate_bedrock([local], [not_bedrock]) == []


def test_signal_serialises_for_edge_evidence() -> None:
    sig = CorrelationSignal(kind="model_id_match", value="x", weight=1.0)
    link = CrossEnvironmentLink("agent:cli:x", "cloud_resource:aws:bedrock:agent:y", "exact", (sig,))
    evidence = link.to_evidence()
    assert evidence["source"] == "cross_env_correlation"
    assert evidence["confidence"] == "exact"
    assert evidence["signals"] == [{"kind": "model_id_match", "value": "x", "weight": 1.0}]


# ── End-to-end through the graph builder ───────────────────────────────────


def _report_with(local_framework_agents: list[dict], cloud_agents: list[dict]) -> dict:
    return {
        "scan_id": "xenv-001",
        "agents": cloud_agents,
        "blast_radius": [],
        "ai_inventory": {"framework_agents": local_framework_agents},
    }


def _correlates_edges(graph) -> list:
    return [e for e in graph.edges if e.relationship == RelationshipType.CORRELATES_WITH]


def test_graph_builder_emits_correlates_with_edge() -> None:
    local = _local_agent("agent:cli:support_bot", model_refs=["claude-3-5-sonnet"])
    cloud = _bedrock_cloud_agent("support-bot", foundation_model="anthropic.claude-3-5-sonnet-20240620-v1:0")
    graph = build_unified_graph_from_report(_report_with([local], [cloud]), tenant_id="tenant-a")

    assert "agent:cli:support_bot" in graph.nodes
    cloud_resource_id = "cloud_resource:aws:bedrock:agent:arn:aws:bedrock:us-east-1:111122223333:agent/support-bot"
    assert cloud_resource_id in graph.nodes
    edges = _correlates_edges(graph)
    assert len(edges) == 1
    edge = edges[0]
    assert edge.source == "agent:cli:support_bot"
    assert edge.target == cloud_resource_id
    assert edge.evidence["source"] == "cross_env_correlation"
    assert edge.evidence["confidence"] == "exact"
    assert any(s["kind"] == "model_id_match" for s in edge.evidence["signals"])


def test_graph_builder_drops_correlation_when_endpoint_missing() -> None:
    local_without_id = _local_agent("", model_refs=["claude-3-5-sonnet"])
    local_without_id["stable_id"] = ""
    cloud = _bedrock_cloud_agent("support-bot", foundation_model="anthropic.claude-3-5-sonnet")
    graph = build_unified_graph_from_report(_report_with([local_without_id], [cloud]), tenant_id="tenant-a")
    assert _correlates_edges(graph) == []


def test_cross_tenant_pairs_do_not_merge_in_separate_scans() -> None:
    # Two scans, one per tenant, with the same local/cloud names. Each
    # scan builds its own graph; no edge crosses between them.
    local = _local_agent("agent:cli:support", model_refs=["claude-3-5-sonnet"])
    cloud = _bedrock_cloud_agent("support", foundation_model="anthropic.claude-3-5-sonnet")
    graph_a = build_unified_graph_from_report(_report_with([local], [cloud]), tenant_id="tenant-a")
    graph_b = build_unified_graph_from_report(_report_with([local], [cloud]), tenant_id="tenant-b")

    assert graph_a.tenant_id == "tenant-a"
    assert graph_b.tenant_id == "tenant-b"
    assert len(_correlates_edges(graph_a)) == 1
    assert len(_correlates_edges(graph_b)) == 1
    # Every edge endpoint in each graph is contained inside that graph's
    # own node set; the two scans cannot cross.
    for edge in graph_a.edges:
        assert edge.source in graph_a.nodes
        assert edge.target in graph_a.nodes


def test_cli_or_api_can_distinguish_confidence_levels() -> None:
    # Acceptance criterion: "CLI/API output distinguishes exact, inferred,
    # and unmatched cloud-runtime links." The confidence is exposed on
    # the edge evidence so any consumer can split by it without re-running
    # the matcher.
    exact_local = _local_agent("agent:exact", model_refs=["claude-3-5-sonnet"])
    inferred_local = _local_agent(
        "agent:inferred",
        model_refs=["unrelated"],
        framework="boto3-bedrock-runtime",
    )
    cloud = _bedrock_cloud_agent("svc", foundation_model="anthropic.claude-3-5-sonnet")
    graph = build_unified_graph_from_report(_report_with([exact_local, inferred_local], [cloud]), tenant_id="t")
    confidences = sorted(e.evidence["confidence"] for e in _correlates_edges(graph))
    assert confidences == ["exact", "inferred"]


def test_correlates_with_edge_targets_a_cloud_resource_node() -> None:
    local = _local_agent("agent:x", model_refs=["claude-3-5-sonnet"])
    cloud = _bedrock_cloud_agent("svc", foundation_model="anthropic.claude-3-5-sonnet")
    graph = build_unified_graph_from_report(_report_with([local], [cloud]), tenant_id="t")
    for edge in _correlates_edges(graph):
        node = graph.nodes[edge.target]
        assert node.entity_type == EntityType.CLOUD_RESOURCE
