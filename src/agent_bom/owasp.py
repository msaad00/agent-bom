"""OWASP Top 10 for LLM Applications — tag blast radius findings.

Maps agent-bom findings to the OWASP Top 10 for Large Language Model
Applications (2025 edition). LLM05 (Supply Chain Vulnerabilities) is
applied when the package is an AI/ML framework or shares an MCP server
with one — not unconditionally.

Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.models import Severity
from agent_bom.risk_analyzer import ToolCapability, classify_tool

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius


# ─── Catalog ──────────────────────────────────────────────────────────────────

OWASP_LLM_TOP10: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output Handling",
    "LLM03": "Training Data Poisoning",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Supply Chain Vulnerabilities",
    "LLM06": "Sensitive Information Disclosure",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Excessive Agency",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# Package names associated with AI/ML frameworks
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
        # Vector stores / RAG backends
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
        # Embedding models
        "sentence-transformers",
    }
)

# Packages directly involved in training data handling and fine-tuning.
# CVEs here risk training data poisoning (LLM03).
_TRAINING_DATA_PACKAGES: frozenset[str] = frozenset(
    {
        "datasets",
        "huggingface-hub",
        "tokenizers",
        "transformers",
        "diffusers",
        "accelerate",
        "trl",
        "sentence-transformers",
        "peft",
        "torch",
        "torchvision",
        "torchaudio",
        "tensorflow",
        "tensorflow-gpu",
        "safetensors",
        "optimum",
    }
)

# Severity levels considered high-risk for agency/AI-poisoning checks
_HIGH_RISK_SEVERITIES: frozenset[Severity] = frozenset(
    {
        Severity.CRITICAL,
        Severity.HIGH,
    }
)


# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted OWASP LLM Top 10 codes applicable to this blast radius.

    Rules applied:
    - LLM05: Package is an AI/ML framework or shares a server with one.
    - LLM06: Credential env vars are exposed alongside a vulnerable package.
    - LLM02: A reachable tool has EXECUTE capability (code injection risk).
    - LLM07: A reachable tool has READ capability (context leakage risk).
    - LLM08: Server has >5 tools AND severity is CRITICAL/HIGH (excessive agency).
    - LLM04: Vulnerable package is a core AI/ML framework AND severity is HIGH+.
    """
    tags: set[str] = set()

    # LLM05 — supply chain vulnerability: only when package is AI-related
    if br.package.name.lower() in _AI_PACKAGES or br.package.name.lower() in _TRAINING_DATA_PACKAGES:
        tags.add("LLM05")

    # LLM06 — sensitive information disclosure via credential exposure
    if br.exposed_credentials:
        tags.add("LLM06")

    # LLM02 / LLM07 — tool-level risks via semantic capability analysis
    for tool in br.exposed_tools:
        caps = classify_tool(tool.name, tool.description)
        if ToolCapability.EXECUTE in caps:
            tags.add("LLM02")
        if ToolCapability.READ in caps:
            tags.add("LLM07")

    # LLM08 — excessive agency: many tools + high-severity CVE
    if len(br.exposed_tools) > 5 and br.vulnerability.severity in _HIGH_RISK_SEVERITIES:
        tags.add("LLM08")

    # LLM03 — training data poisoning: training/dataset package with CVE
    if br.package.name.lower() in _TRAINING_DATA_PACKAGES:
        tags.add("LLM03")

    # LLM04 — data/model poisoning: AI framework package with high CVE
    if br.package.name.lower() in _AI_PACKAGES and br.vulnerability.severity in _HIGH_RISK_SEVERITIES:
        tags.add("LLM04")

    return sorted(tags)


def owasp_label(code: str) -> str:
    """Return human-readable label for an OWASP code, e.g. 'LLM05 Supply Chain'."""
    name = OWASP_LLM_TOP10.get(code, "Unknown")
    return f"{code} {name}"


def owasp_labels(codes: list[str]) -> list[str]:
    """Return human-readable labels for a list of OWASP codes."""
    return [owasp_label(c) for c in codes]
