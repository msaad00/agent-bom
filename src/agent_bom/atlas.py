"""MITRE ATLAS — map blast radius findings to AI/ML adversarial techniques.

MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems)
catalogs adversary tactics, techniques, and procedures (TTPs) targeting AI/ML
systems. We map agent-bom findings to the most relevant ATLAS techniques so
security teams can prioritize remediation using a familiar framework.

Reference: https://atlas.mitre.org/
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.models import Severity
from agent_bom.risk_analyzer import ToolCapability, classify_tool

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius


# ─── Catalog ──────────────────────────────────────────────────────────────────

ATLAS_TECHNIQUES: dict[str, str] = {
    "AML.T0010": "ML Supply Chain Compromise",
    "AML.T0020": "Poison Training Data",
    "AML.T0024": "Exfiltration via ML Inference API",
    "AML.T0043": "Craft Adversarial Data",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0052": "Phishing via AI",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "LLM Meta Prompt Extraction",
    "AML.T0058": "AI Agent Context Poisoning",
    "AML.T0059": "Activation Triggers",
    "AML.T0060": "Data from AI Services",
    "AML.T0061": "AI Agent Tools",
    "AML.T0062": "Exfiltration via AI Agent Tool Invocation",
}

# AI/ML framework packages — CVEs here enable model-level attacks
_AI_PACKAGES: frozenset[str] = frozenset({
    "torch", "torchvision", "torchaudio",
    "transformers", "diffusers", "tokenizers",
    "langchain", "langchain-core", "langchain-community",
    "langchain-openai", "langchain-anthropic",
    "openai", "anthropic", "google-generativeai",
    "crewai", "autogen", "pyautogen",
    "haystack", "haystack-ai",
    "llama-index", "llama-cpp-python",
    "dspy-ai", "guidance",
    "semantic-kernel",
    "pydantic-ai",
    # Vector stores / RAG backends
    "chromadb", "pinecone-client", "weaviate-client", "qdrant-client",
    "faiss-cpu", "faiss-gpu", "pymilvus", "milvus",
    "pgvector", "lancedb",
    "sentence-transformers",
})

# Severity levels considered high-risk
_HIGH_RISK: frozenset[Severity] = frozenset({
    Severity.CRITICAL,
    Severity.HIGH,
})


# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted MITRE ATLAS technique IDs applicable to this blast radius.

    Rules:
    - AML.T0010: Always — any package CVE in an AI agent is supply chain compromise.
    - AML.T0062: Credential env vars exposed → exfiltration via agent tool invocation.
    - AML.T0061: >3 tools reachable through vulnerability → AI agent tools abuse.
    - AML.T0051: Reachable tools can read prompts/context → prompt injection surface.
    - AML.T0056: Reachable tools can read files/resources → meta prompt extraction.
    - AML.T0043: Reachable tools have exec/shell capability → craft adversarial data.
    - AML.T0020: AI/ML framework package with HIGH+ CVE → poison training data.
    - AML.T0058: AI/ML framework + credentials + HIGH+ → agent context poisoning.
    - AML.T0024: AI/ML framework + credentials → exfiltration via inference API.
    """
    tags: set[str] = {"AML.T0010"}  # always — supply chain compromise

    # AML.T0062 — exfiltration via AI agent tool invocation
    if br.exposed_credentials:
        tags.add("AML.T0062")

    has_exec = False
    has_read = False

    for tool in br.exposed_tools:
        caps = classify_tool(tool.name, tool.description)
        if ToolCapability.EXECUTE in caps:
            has_exec = True
        if ToolCapability.READ in caps:
            has_read = True

    # AML.T0061 — AI agent tools (broad tool surface)
    if len(br.exposed_tools) > 3:
        tags.add("AML.T0061")

    # AML.T0051 — LLM prompt injection (read tools reachable — can access context)
    if has_read:
        tags.add("AML.T0051")

    # AML.T0056 — meta prompt extraction (read tools)
    if has_read:
        tags.add("AML.T0056")

    # AML.T0043 — craft adversarial data (exec tools)
    if has_exec:
        tags.add("AML.T0043")

    is_ai_pkg = br.package.name.lower() in _AI_PACKAGES
    is_high = br.vulnerability.severity in _HIGH_RISK

    # AML.T0020 — poison training data (AI framework + HIGH+ CVE)
    if is_ai_pkg and is_high:
        tags.add("AML.T0020")

    # AML.T0058 — AI agent context poisoning (AI + creds + HIGH+)
    if is_ai_pkg and br.exposed_credentials and is_high:
        tags.add("AML.T0058")

    # AML.T0024 — exfiltration via ML inference API (AI + creds)
    if is_ai_pkg and br.exposed_credentials:
        tags.add("AML.T0024")

    return sorted(tags)


def atlas_label(technique_id: str) -> str:
    """Return human-readable label, e.g. 'AML.T0010 ML Supply Chain Compromise'."""
    name = ATLAS_TECHNIQUES.get(technique_id, "Unknown")
    return f"{technique_id} {name}"


def atlas_labels(technique_ids: list[str]) -> list[str]:
    """Return human-readable labels for a list of ATLAS technique IDs."""
    return [atlas_label(t) for t in technique_ids]
