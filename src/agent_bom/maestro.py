"""MAESTRO 7-layer framework — classify agent-bom findings by agentic AI layer.

MAESTRO (Mission, Assets, Evaluations, Security, Trustworthiness, Risk,
Outcomes) is a layered framework for agentic AI security that classifies system
components into knowledge component (KC) layers.

Each agent-bom finding is tagged with the MAESTRO layer it affects so that
outputs are interoperable with MAESTRO-based threat modelers and cross-reference
cleanly against MITRE ATT&CK (cloud/infra) and MITRE ATLAS (AI/agent).

Layer coverage:
- KC1 AI Models      — model provenance, serialization safety, supply chain
- KC2 Agent Arch     — blast radius, orchestration, multi-agent trust
- KC3 Agentic Patterns — tool drift, prompt injection, guardrail bypass
- KC4 Memory/Context — vector databases, memory stores, knowledge bases
- KC5 Tools/Capabilities — MCP servers, tool APIs, capability scope
- KC6 Infrastructure — cloud CIS findings, compute, networking, deployment

Reference: Vineeth Sai Narajala, Cisco Agentic Security Hub
"""

from __future__ import annotations

from enum import Enum

# ---------------------------------------------------------------------------
# Layer enum
# ---------------------------------------------------------------------------


class MaestroLayer(str, Enum):
    """MAESTRO knowledge component layers."""

    KC1_AI_MODELS = "KC1: AI Models"
    KC2_AGENT_ARCHITECTURE = "KC2: Agent Architecture"
    KC3_AGENTIC_PATTERNS = "KC3: Agentic Patterns"
    KC4_MEMORY_CONTEXT = "KC4: Memory & Context"
    KC5_TOOLS_CAPABILITIES = "KC5: Tools & Capabilities"
    KC6_INFRASTRUCTURE = "KC6: Infrastructure"


LAYER_DESCRIPTIONS: dict[MaestroLayer, str] = {
    MaestroLayer.KC1_AI_MODELS: "LLM, foundation models, embedding models",
    MaestroLayer.KC2_AGENT_ARCHITECTURE: "AI agents, orchestrators, multi-agent patterns",
    MaestroLayer.KC3_AGENTIC_PATTERNS: "RAG pipelines, CoT, prompt templates, guardrails",
    MaestroLayer.KC4_MEMORY_CONTEXT: "Vector databases, memory stores, knowledge bases",
    MaestroLayer.KC5_TOOLS_CAPABILITIES: "MCP servers, tool APIs, search capabilities",
    MaestroLayer.KC6_INFRASTRUCTURE: "Cloud infra, networking, compute, deployments",
}


# ---------------------------------------------------------------------------
# Source → layer mapping
# ---------------------------------------------------------------------------

_SOURCE_TO_LAYER: dict[str, MaestroLayer] = {
    # KC1: AI Models
    "huggingface": MaestroLayer.KC1_AI_MODELS,
    "ollama": MaestroLayer.KC1_AI_MODELS,
    "model_file": MaestroLayer.KC1_AI_MODELS,
    "model_provenance": MaestroLayer.KC1_AI_MODELS,
    # KC2: Agent Architecture
    "blast_radius": MaestroLayer.KC2_AGENT_ARCHITECTURE,
    "agent": MaestroLayer.KC2_AGENT_ARCHITECTURE,
    "orchestrator": MaestroLayer.KC2_AGENT_ARCHITECTURE,
    # KC3: Agentic Patterns
    "tool_drift": MaestroLayer.KC3_AGENTIC_PATTERNS,
    "prompt_injection": MaestroLayer.KC3_AGENTIC_PATTERNS,
    "rag": MaestroLayer.KC3_AGENTIC_PATTERNS,
    "guardrail": MaestroLayer.KC3_AGENTIC_PATTERNS,
    "argument_injection": MaestroLayer.KC3_AGENTIC_PATTERNS,
    "sequence_anomaly": MaestroLayer.KC3_AGENTIC_PATTERNS,
    # KC4: Memory & Context
    "vector_db": MaestroLayer.KC4_MEMORY_CONTEXT,
    "qdrant": MaestroLayer.KC4_MEMORY_CONTEXT,
    "weaviate": MaestroLayer.KC4_MEMORY_CONTEXT,
    "chroma": MaestroLayer.KC4_MEMORY_CONTEXT,
    "milvus": MaestroLayer.KC4_MEMORY_CONTEXT,
    "pinecone": MaestroLayer.KC4_MEMORY_CONTEXT,
    # KC5: Tools & Capabilities
    "mcp_server": MaestroLayer.KC5_TOOLS_CAPABILITIES,
    "mcp_tool": MaestroLayer.KC5_TOOLS_CAPABILITIES,
    "tool_call": MaestroLayer.KC5_TOOLS_CAPABILITIES,
    "credential_leak": MaestroLayer.KC5_TOOLS_CAPABILITIES,
    # KC6: Infrastructure
    "cis": MaestroLayer.KC6_INFRASTRUCTURE,
    "aws_cis": MaestroLayer.KC6_INFRASTRUCTURE,
    "azure_cis": MaestroLayer.KC6_INFRASTRUCTURE,
    "gcp_cis": MaestroLayer.KC6_INFRASTRUCTURE,
    "snowflake_cis": MaestroLayer.KC6_INFRASTRUCTURE,
    "container": MaestroLayer.KC6_INFRASTRUCTURE,
}

# AISVS check_id → layer  (checks span multiple layers)
_AISVS_TO_LAYER: dict[str, MaestroLayer] = {
    "AI-4.1": MaestroLayer.KC1_AI_MODELS,  # Model serialization safety
    "AI-4.2": MaestroLayer.KC1_AI_MODELS,  # Model integrity digest
    "AI-4.3": MaestroLayer.KC1_AI_MODELS,  # Model access gating
    "AI-5.1": MaestroLayer.KC6_INFRASTRUCTURE,  # Inference API not internet-exposed
    "AI-5.2": MaestroLayer.KC3_AGENTIC_PATTERNS,  # No exposed ML tooling without auth
    "AI-6.1": MaestroLayer.KC4_MEMORY_CONTEXT,  # Vector store auth
    "AI-6.2": MaestroLayer.KC4_MEMORY_CONTEXT,  # Vector store not internet-exposed
    "AI-7.1": MaestroLayer.KC1_AI_MODELS,  # No malicious ML packages
    "AI-7.2": MaestroLayer.KC1_AI_MODELS,  # Model provenance verifiable
    "AI-8.1": MaestroLayer.KC5_TOOLS_CAPABILITIES,  # MCP tool scope bounded
}


# ---------------------------------------------------------------------------
# Public tagging API
# ---------------------------------------------------------------------------


def tag_by_source(source: str) -> MaestroLayer:
    """Return the MAESTRO layer for a given source or finding type.

    Args:
        source: Identifier such as 'huggingface', 'mcp_server', 'vector_db',
                'blast_radius', or a CIS provider key.

    Returns:
        MaestroLayer. Defaults to KC6_INFRASTRUCTURE when source is unknown.
    """
    return _SOURCE_TO_LAYER.get(source.lower(), MaestroLayer.KC6_INFRASTRUCTURE)


def tag_provenance_result(result: object) -> MaestroLayer:
    """Return KC1: AI Models for any ProvenanceResult (HF or Ollama)."""
    source = getattr(result, "source", "").lower()
    return _SOURCE_TO_LAYER.get(source, MaestroLayer.KC1_AI_MODELS)


def tag_vector_db(db_type: str) -> MaestroLayer:
    """Return KC4: Memory & Context for any vector database finding."""
    return MaestroLayer.KC4_MEMORY_CONTEXT


def tag_cis_check(_check: object) -> MaestroLayer:
    """Return KC6: Infrastructure for any CIS benchmark check."""
    return MaestroLayer.KC6_INFRASTRUCTURE


def tag_aisvs_check(check_id: str) -> MaestroLayer:
    """Return the MAESTRO layer for an AISVS check ID."""
    return _AISVS_TO_LAYER.get(check_id, MaestroLayer.KC6_INFRASTRUCTURE)


def layer_label(layer: MaestroLayer) -> str:
    """Return a human-readable label: 'KC1: AI Models (LLM, foundation models, ...)'."""
    desc = LAYER_DESCRIPTIONS.get(layer, "")
    return f"{layer.value} ({desc})" if desc else layer.value


def layer_labels(layers: list[MaestroLayer]) -> list[str]:
    """Return human-readable labels for a list of MAESTRO layers."""
    return [layer_label(layer) for layer in layers]
