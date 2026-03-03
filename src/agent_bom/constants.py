"""Shared constants — single source of truth for AI package catalogs,
severity classifications, and credential detection patterns.

All compliance modules and graph/model code import from here to avoid
drift between duplicated definitions.
"""

from __future__ import annotations

# ── AI/ML Framework Packages ────────────────────────────────────────────────
# Used by compliance taggers (owasp, atlas, nist_ai_rmf, eu_ai_act,
# owasp_agentic) to determine if a vulnerability affects an AI/ML component.

AI_PACKAGES: frozenset[str] = frozenset(
    {
        # LLM orchestration
        "langchain",
        "langchain-core",
        "langchain-community",
        "langchain-openai",
        "langchain-anthropic",
        "llama-index",
        "llama-cpp-python",
        "autogen",
        "pyautogen",
        "crewai",
        "haystack",
        "haystack-ai",
        "dspy-ai",
        "guidance",
        "semantic-kernel",
        "pydantic-ai",
        # LLM clients
        "openai",
        "anthropic",
        "google-generativeai",
        # Model inference
        "torch",
        "torchvision",
        "torchaudio",
        "transformers",
        "diffusers",
        "tokenizers",
        # Embedding models
        "sentence-transformers",
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
    }
)

# Packages directly involved in training data handling and fine-tuning.
# CVEs here risk training data poisoning (OWASP LLM03).
TRAINING_DATA_PACKAGES: frozenset[str] = frozenset(
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


def high_risk_severities() -> frozenset:
    """Return severity levels considered high-risk (CRITICAL + HIGH).

    Lazy import to avoid circular dependency with models.Severity.
    """
    from agent_bom.models import Severity

    return frozenset({Severity.CRITICAL, Severity.HIGH})


def critical_severities() -> frozenset:
    """Return CRITICAL-only severity set.

    Use for controls that should only trigger on the most severe findings
    (e.g., EU AI Act ART-5 Prohibited Practices).
    """
    from agent_bom.models import Severity

    return frozenset({Severity.CRITICAL})


# ── Credential Detection Patterns ───────────────────────────────────────────
# Used by models.MCPServer.has_credentials / credential_names and
# context_graph._is_credential_key.

SENSITIVE_PATTERNS: list[str] = [
    "key",
    "token",
    "secret",
    "password",
    "credential",
    "api_key",
    "apikey",
    "auth",
    "private",
    "connection",
    "conn_str",
    "database_url",
    "db_url",
    # SSH key management
    "ssh_key",
    "ssh_private",
    "id_rsa",
    "id_ed25519",
    # OAuth / OIDC
    "client_secret",
    "oauth",
    "refresh_token",
    "access_token",
    "bearer",
    # PKI / certificates
    "certificate",
    "tls_key",
    "ssl_key",
    "ca_cert",
    "client_cert",
    # SCIM / provisioning
    "scim_token",
    "provisioning_key",
]


def is_credential_key(name: str) -> bool:
    """Check if an environment variable name matches credential patterns."""
    low = name.lower()
    return any(pat in low for pat in SENSITIVE_PATTERNS)
