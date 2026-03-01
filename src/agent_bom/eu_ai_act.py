"""EU AI Act risk classification — map findings to relevant articles.

Maps agent-bom blast radius findings to key articles of the EU Artificial
Intelligence Act (Regulation (EU) 2024/1689).  Every finding triggers at
minimum ART-9 (risk management) and ART-15 (cybersecurity), since any CVE
in an AI agent dependency tree requires both.

Reference: https://artificialintelligenceact.eu/
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.models import Severity
from agent_bom.risk_analyzer import ToolCapability, classify_tool

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius


# ─── Catalog ──────────────────────────────────────────────────────────────────

EU_AI_ACT: dict[str, str] = {
    "ART-5": "Prohibited AI Practices",
    "ART-6": "High-Risk AI System Classification",
    "ART-9": "Risk Management System",
    "ART-10": "Data & Data Governance",
    "ART-15": "Accuracy, Robustness & Cybersecurity",
    "ART-17": "Quality Management System",
}

# AI/ML framework packages
_AI_PACKAGES: frozenset[str] = frozenset(
    {
        "torch",
        "torchvision",
        "torchaudio",
        "transformers",
        "diffusers",
        "tokenizers",
        "langchain",
        "langchain-core",
        "langchain-community",
        "langchain-openai",
        "langchain-anthropic",
        "openai",
        "anthropic",
        "google-generativeai",
        "crewai",
        "autogen",
        "pyautogen",
        "haystack",
        "haystack-ai",
        "llama-index",
        "llama-cpp-python",
        "dspy-ai",
        "guidance",
        "semantic-kernel",
        "pydantic-ai",
        "chromadb",
        "pinecone-client",
        "weaviate-client",
        "qdrant-client",
        "faiss-cpu",
        "faiss-gpu",
        "pymilvus",
        "milvus",
        "pgvector",
        "lancedb",
        "sentence-transformers",
    }
)


# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted EU AI Act article codes applicable to this blast radius.

    Rules:
    - ART-5:  Credentials + EXECUTE + CRITICAL severity (autonomous harm potential).
    - ART-6:  AI framework package present (high-risk system classification).
    - ART-9:  Always — any CVE triggers risk management requirement.
    - ART-10: READ-capable tools + credentials (data governance concern).
    - ART-15: Always — any cybersecurity finding.
    - ART-17: Fixable vulnerability exists (quality management remediation needed).
    """
    tags: set[str] = {
        "ART-9",  # always — risk management
        "ART-15",  # always — cybersecurity
    }

    has_exec = False
    has_read = False
    for tool in br.exposed_tools:
        caps = classify_tool(tool.name, tool.description)
        if ToolCapability.EXECUTE in caps:
            has_exec = True
        if ToolCapability.READ in caps:
            has_read = True

    is_ai_pkg = br.package.name.lower() in _AI_PACKAGES

    # ART-5 — prohibited practices: credentials + exec + critical (autonomous harm)
    if br.exposed_credentials and has_exec and br.vulnerability.severity == Severity.CRITICAL:
        tags.add("ART-5")

    # ART-6 — high-risk classification: AI framework package
    if is_ai_pkg:
        tags.add("ART-6")

    # ART-10 — data governance: read tools + credentials
    if has_read and br.exposed_credentials:
        tags.add("ART-10")

    # ART-17 — quality management: fixable vulnerability
    if br.vulnerability.fixed_version:
        tags.add("ART-17")

    return sorted(tags)


def eu_ai_act_label(code: str) -> str:
    """Return human-readable label, e.g. 'ART-15 Accuracy, Robustness & Cybersecurity'."""
    name = EU_AI_ACT.get(code, "Unknown")
    return f"{code} {name}"


def eu_ai_act_labels(codes: list[str]) -> list[str]:
    """Return human-readable labels for a list of EU AI Act article codes."""
    return [eu_ai_act_label(c) for c in codes]
