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
        "langgraph",
        "llama-index",
        "llama_index",
        "llama-hub",
        "llama-cpp-python",
        "autogen",
        "pyautogen",
        "crewai",
        "agency-swarm",
        "haystack",
        "haystack-ai",
        "dspy-ai",
        "guidance",
        "semantic-kernel",
        "pydantic-ai",
        # LLM clients
        "openai",
        "anthropic",
        "mistralai",
        "cohere",
        "together",
        "google-generativeai",
        "google-cloud-aiplatform",
        "boto3",
        "deepseek",
        "fireworks-ai",
        "ai21",
        "cerebras-cloud-sdk",
        # Model inference
        "transformers",
        "huggingface-hub",
        "diffusers",
        "accelerate",
        "sentence-transformers",
        "optimum",
        "tokenizers",
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
        # MCP and agent infrastructure
        "mcp",
        "fastmcp",
        "modelcontextprotocol",
        # GPU / AI infrastructure — NVIDIA
        "cuda-python",
        "cupy",
        "cupy-cuda11x",
        "cupy-cuda12x",
        "nvidia-cublas-cu11",
        "nvidia-cublas-cu12",
        "nvidia-cudnn-cu11",
        "nvidia-cudnn-cu12",
        "nvidia-cufft-cu11",
        "nvidia-cufft-cu12",
        "nvidia-cusolver-cu11",
        "nvidia-cusolver-cu12",
        "nvidia-cusparse-cu11",
        "nvidia-cusparse-cu12",
        "nvidia-nccl-cu11",
        "nvidia-nccl-cu12",
        "nvidia-cuda-runtime-cu11",
        "nvidia-cuda-runtime-cu12",
        "nvidia-cuda-nvrtc-cu11",
        "nvidia-cuda-nvrtc-cu12",
        "tensorrt",
        "nvidia-tensorrt",
        "triton",
        "tritonclient",
        # GPU / AI infrastructure — AMD ROCm
        "hip-python",
        "rocm-smi",
        # ML frameworks with GPU backends
        "torch",
        "torchvision",
        "torchaudio",
        "tensorflow",
        "tensorflow-gpu",
        "tf-nightly",
        "jax",
        "jaxlib",
        # Inference servers
        "vllm",
        "text-generation-inference",
        "ctransformers",
        # MLOps / experiment tracking
        "mlflow",
        "wandb",
        "neptune",
        "clearml",
        "ray",
        "ray[serve]",
        # Training data handling (also in TRAINING_DATA_PACKAGES)
        "datasets",
        "trl",
        "peft",
        "safetensors",
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


# ── CWE-to-Compliance Mapping ────────────────────────────────────────────────
# Maps CWE weakness IDs to applicable compliance framework tags.
# Used by compliance taggers for ALL vulnerabilities with CWE data (OSV, NVD, GHSA, SAST).

CWE_COMPLIANCE_MAP: dict[str, dict[str, list[str]]] = {
    "CWE-78": {  # OS Command Injection
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.1"],
    },
    "CWE-79": {  # Cross-Site Scripting (XSS)
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
    },
    "CWE-89": {  # SQL Injection
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.1"],
    },
    "CWE-22": {  # Path Traversal
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
    },
    "CWE-327": {  # Broken/Risky Crypto Algorithm
        "iso_27001": ["A.8.24"],
        "nist_csf": ["PR.DS-01", "PR.DS-02"],
        "soc2": ["CC6.1"],
    },
    "CWE-502": {  # Deserialization of Untrusted Data
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
    },
    "CWE-798": {  # Hardcoded Credentials
        "owasp_llm": ["LLM06"],
        "iso_27001": ["A.8.9", "A.8.24"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
        "cis": ["CIS-16.1"],
    },
    "CWE-918": {  # Server-Side Request Forgery (SSRF)
        "iso_27001": ["A.8.28"],
        "nist_csf": ["DE.CM-01"],
    },
    "CWE-611": {  # XXE (XML External Entity)
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
    },
    "CWE-94": {  # Code Injection
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.1"],
    },
    # ── Input validation & injection variants ────────────────────────────────
    "CWE-20": {  # Improper Input Validation
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.12"],
    },
    "CWE-77": {  # Command Injection (generic)
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.12"],
    },
    "CWE-80": {  # Script Injection (Basic XSS)
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
    },
    "CWE-90": {  # LDAP Injection
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.1"],
    },
    "CWE-91": {  # XML Injection (XPath)
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
    },
    "CWE-117": {  # Log Injection
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.1"],
    },
    "CWE-352": {  # Cross-Site Request Forgery (CSRF)
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "soc2": ["CC6.1"],
    },
    "CWE-434": {  # Unrestricted Upload of Dangerous File Type
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.1"],
    },
    "CWE-444": {  # HTTP Request Smuggling
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.12"],
    },
    "CWE-601": {  # Open Redirect
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.1"],
    },
    "CWE-643": {  # XPath Injection
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
    },
    # ── Authentication & authorization ───────────────────────────────────────
    "CWE-269": {  # Improper Privilege Management
        "owasp_llm": ["LLM08"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.AA-01", "PR.AA-03"],
        "soc2": ["CC6.1"],
        "cis": ["CIS-16.1"],
    },
    "CWE-276": {  # Incorrect Default Permissions
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
        "cis": ["CIS-16.1"],
    },
    "CWE-287": {  # Improper Authentication
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
        "cis": ["CIS-16.1"],
    },
    "CWE-306": {  # Missing Authentication for Critical Function
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
        "cis": ["CIS-16.1"],
    },
    "CWE-639": {  # Authorization Bypass via User-Controlled Key (IDOR)
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.AA-01"],
        "cis": ["CIS-16.1"],
    },
    "CWE-862": {  # Missing Authorization
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
    },
    "CWE-863": {  # Incorrect Authorization
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
    },
    # ── Sensitive data exposure ──────────────────────────────────────────────
    "CWE-200": {  # Exposure of Sensitive Information
        "owasp_llm": ["LLM06"],
        "iso_27001": ["A.8.9"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
    },
    "CWE-209": {  # Error Message Information Leak
        "owasp_llm": ["LLM06"],
        "iso_27001": ["A.8.9"],
        "nist_csf": ["PR.AA-01"],
    },
    "CWE-215": {  # Information Exposure Through Debug Information
        "owasp_llm": ["LLM06"],
        "iso_27001": ["A.8.9"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
    },
    "CWE-312": {  # Cleartext Storage of Sensitive Information
        "owasp_llm": ["LLM06"],
        "iso_27001": ["A.8.9", "A.8.24"],
        "nist_csf": ["PR.DS-01"],
        "soc2": ["CC6.1"],
        "cis": ["CIS-16.1"],
    },
    "CWE-319": {  # Cleartext Transmission of Sensitive Information
        "owasp_llm": ["LLM06"],
        "iso_27001": ["A.8.24"],
        "nist_csf": ["PR.DS-02"],
        "soc2": ["CC6.1"],
    },
    "CWE-497": {  # Exposure of Sensitive System Information
        "owasp_llm": ["LLM06"],
        "iso_27001": ["A.8.9"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
    },
    "CWE-538": {  # Sensitive Information in Log Files
        "owasp_llm": ["LLM06"],
        "iso_27001": ["A.8.9"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
    },
    # ── Cryptography ─────────────────────────────────────────────────────────
    "CWE-295": {  # Improper Certificate Validation
        "iso_27001": ["A.8.24"],
        "nist_csf": ["PR.DS-02"],
        "soc2": ["CC6.1"],
        "cis": ["CIS-16.1"],
    },
    "CWE-326": {  # Inadequate Encryption Strength
        "iso_27001": ["A.8.24"],
        "nist_csf": ["PR.DS-01", "PR.DS-02"],
        "soc2": ["CC6.1"],
    },
    "CWE-330": {  # Use of Insufficiently Random Values
        "iso_27001": ["A.8.24"],
        "nist_csf": ["PR.DS-02"],
        "soc2": ["CC6.1"],
    },
    "CWE-347": {  # Improper Verification of Cryptographic Signature
        "iso_27001": ["A.8.24"],
        "nist_csf": ["PR.DS-02"],
        "soc2": ["CC6.1"],
    },
    # ── Memory safety & resource management ──────────────────────────────────
    "CWE-119": {  # Buffer Overflow
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.12"],
    },
    "CWE-125": {  # Out-of-bounds Read
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
    },
    "CWE-190": {  # Integer Overflow
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.12"],
    },
    "CWE-362": {  # Race Condition
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
    },
    "CWE-400": {  # Uncontrolled Resource Consumption (DoS)
        "owasp_llm": ["LLM10"],
        "iso_27001": ["A.8.8"],
        "nist_csf": ["DE.CM-09"],
        "cis": ["CIS-07.5"],
    },
    "CWE-416": {  # Use After Free
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.12"],
    },
    "CWE-476": {  # NULL Pointer Dereference
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
    },
    "CWE-787": {  # Out-of-bounds Write
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.12"],
    },
    # ── Supply chain & trust boundaries ──────────────────────────────────────
    "CWE-426": {  # Untrusted Search Path
        "owasp_llm": ["LLM05"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.1"],
    },
    "CWE-427": {  # Uncontrolled Search Path Element
        "owasp_llm": ["LLM05"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.1"],
    },
    "CWE-501": {  # Trust Boundary Violation
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.11"],
    },
    "CWE-776": {  # XML Bomb (Billion Laughs)
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.12"],
    },
    "CWE-829": {  # Inclusion of Functionality from Untrusted Control Sphere
        "owasp_llm": ["LLM05"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-02.7"],
    },
    "CWE-942": {  # Permissive Cross-domain Policy
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
    },
}
