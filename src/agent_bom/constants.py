"""Shared constants — single source of truth for AI package catalogs,
severity classifications, and credential detection patterns.

All compliance modules and graph/model code import from here to avoid
drift between duplicated definitions.
"""

from __future__ import annotations

import re

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
        "gpt4all",
        "ollama",
        # Emerging agent frameworks
        "smolagents",
        "qwen-agent",
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
# Compatibility vocabulary for callers that display the broad families.  The
# product judgement itself lives in ``is_credential_key`` below; consumers
# must call it instead of repeating substring matching.

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


# These words make the variable a policy/lifecycle setting about a credential,
# not the credential (or a reference to it).  Examples from agent-bom's own
# supported configuration include ``API_KEY_DEFAULT_TTL_SECONDS`` and
# ``TOKEN_ROTATION_DAYS``.
_CONFIGURATION_WORDS = frozenset(
    {
        "age",
        "configured",
        "days",
        "disable",
        "disabled",
        "enable",
        "enabled",
        "expires",
        "expiry",
        "max",
        "method",
        "min",
        "mode",
        "policy",
        "records",
        "require",
        "required",
        "rotated",
        "rotation",
        "seconds",
        "status",
        "ttl",
        "type",
    }
)

# A name carrying one of these is authentication material, or a reference to
# some, wherever the word appears.  ``SNOWFLAKE_PRIVATE_KEY_PATH`` names the
# file holding a private key and is as much credential evidence as the key.
_CREDENTIAL_WORDS = frozenset(
    {
        "apikey",
        "authorization",
        "bearer",
        "credential",
        "key",
        "password",
        "passwd",
        "secret",
        "token",
    }
)

# Weaker evidence: on its own the word names credential material, but qualified
# by a locator it names a *file or endpoint* that is not itself secret.
# ``CERTIFICATE`` holds a PEM blob; ``CERTIFICATE_PATH`` holds ``/etc/ssl/…``
# and ``OAUTH_CLIENT_ID`` holds a public identifier.  Widening these two words
# without the locator guard is what previously turned ``CERTIFICATE_PATH`` into
# a credential node.
_CREDENTIAL_MATERIAL_WORDS = frozenset({"cert", "certificate", "oauth"})

_LOCATOR_WORDS = frozenset(
    {
        "arn",
        "dir",
        "directories",
        "directory",
        "endpoint",
        "file",
        "filename",
        "host",
        "hostname",
        "id",
        "location",
        "name",
        "path",
        "port",
        "ref",
        "url",
    }
)

# Only words this module already knows are folded to their singular, so an
# unrelated plural is left alone — ``DAYS`` must keep matching the
# configuration word ``days`` rather than becoming an unknown ``day``.
_SINGULARIZABLE_WORDS = _CREDENTIAL_WORDS | _CREDENTIAL_MATERIAL_WORDS | _LOCATOR_WORDS


def _singularize(token: str) -> str:
    if token.endswith("s") and token[:-1] in _SINGULARIZABLE_WORDS:
        return token[:-1]
    return token


_CREDENTIAL_WORD_PAIRS = frozenset(
    {
        ("ca", "cert"),
        ("client", "cert"),
        ("client", "certificate"),
        ("conn", "str"),
        ("connection", "string"),
        ("connection", "uri"),
        ("connection", "url"),
        ("database", "url"),
        ("db", "url"),
    }
)

# Established names for real credentials that contain no credential word at all,
# so no amount of vocabulary matching reaches them.  ``PGPASSWORD`` is libpq's;
# the ``ID_*`` family is what ``ssh-keygen`` writes.  Matched on the whole name
# so a qualified variant (``ID_RSA_PATH``) still goes through the normal rules.
_CREDENTIAL_COMPOUND_NAMES = frozenset(
    {
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "mysql_pwd",
        "pgpassword",
    }
)


def is_credential_key(name: str) -> bool:
    """Return whether an environment-variable name denotes a credential.

    Credential inventory feeds graph, posture, and blast-radius evidence, so
    substring matching is too imprecise: ``AUTH_MODE``, ``KEYBOARD_LAYOUT``,
    and ``DB_CONNECTION_POOL_SIZE`` are configuration rather than credentials.
    Split on identifier boundaries and match credential words or the few
    credential-shaped compound names that do not contain one.

    Plural forms count: a name is no less a credential for holding more than
    one, and ``API_KEYS``/``CREDENTIALS`` are common.

    This predicate intentionally answers a narrower question than payload
    sanitization.  Redaction may conservatively hide additional values; those
    values must not become credential nodes merely because their names contain
    an adjacent substring.
    """
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    tokens = tuple(_singularize(token) for token in re.findall(r"[a-z0-9]+", separated.casefold()))
    if not tokens:
        return False

    if any(token in _CONFIGURATION_WORDS for token in tokens):
        return False
    if "no" in tokens:
        return False

    if "_".join(tokens) in _CREDENTIAL_COMPOUND_NAMES:
        return True

    if any(token in _CREDENTIAL_WORDS for token in tokens):
        return True

    if set(zip(tokens, tokens[1:])) & _CREDENTIAL_WORD_PAIRS:
        return True

    if any(token in _CREDENTIAL_MATERIAL_WORDS for token in tokens) and not any(token in _LOCATOR_WORDS for token in tokens):
        return True

    # A terminal AUTH commonly holds an auth header/blob.  AUTH_MODE and
    # NO_AUTH are posture settings and must not become credential evidence.
    return tokens[-1] == "auth" and (len(tokens) == 1 or tokens[-2] != "no")


# ── CWE-to-Compliance Mapping ────────────────────────────────────────────────
# Maps CWE weakness IDs to applicable compliance framework tags.
# Used by compliance taggers for ALL vulnerabilities with CWE data (OSV, NVD, GHSA, SAST).

CWE_COMPLIANCE_MAP: dict[str, dict[str, list[str]]] = {
    "CWE-78": {  # OS Command Injection
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.1"],
        "nist_800_53": ["SI-10", "SI-3"],
    },
    "CWE-79": {  # Cross-Site Scripting (XSS)
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "nist_800_53": ["SI-10"],
    },
    "CWE-89": {  # SQL Injection
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.1"],
        "nist_800_53": ["SI-10", "SI-3"],
    },
    "CWE-22": {  # Path Traversal
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "nist_800_53": ["AC-3", "SI-10"],
    },
    "CWE-327": {  # Broken/Risky Crypto Algorithm
        "iso_27001": ["A.8.24"],
        "nist_csf": ["PR.DS-01", "PR.DS-02"],
        "soc2": ["CC6.1"],
        "nist_800_53": ["SC-12", "SC-13"],
    },
    "CWE-502": {  # Deserialization of Untrusted Data
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_800_53": ["SI-10", "SI-3"],
    },
    "CWE-798": {  # Hardcoded Credentials
        "owasp_llm": ["LLM06"],
        "iso_27001": ["A.8.9", "A.8.24"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
        "cis": ["CIS-16.1"],
        "nist_800_53": ["IA-5", "SC-28"],
    },
    "CWE-918": {  # Server-Side Request Forgery (SSRF)
        "iso_27001": ["A.8.28"],
        "nist_csf": ["DE.CM-01"],
        "nist_800_53": ["AC-3", "SI-10"],
    },
    "CWE-611": {  # XXE (XML External Entity)
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "nist_800_53": ["SI-10", "SI-3"],
    },
    "CWE-94": {  # Code Injection
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.1"],
        "nist_800_53": ["SI-10", "SI-3"],
    },
    # ── Input validation & injection variants ────────────────────────────────
    "CWE-20": {  # Improper Input Validation
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.12"],
        "nist_800_53": ["SI-10"],
    },
    "CWE-77": {  # Command Injection (generic)
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.12"],
        "nist_800_53": ["SI-10", "SI-3"],
    },
    "CWE-80": {  # Script Injection (Basic XSS)
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "nist_800_53": ["SI-10"],
    },
    "CWE-90": {  # LDAP Injection
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.1"],
        "nist_800_53": ["SI-10", "SI-3"],
    },
    "CWE-91": {  # XML Injection (XPath)
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "nist_800_53": ["SI-10"],
    },
    "CWE-117": {  # Log Injection
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.1"],
        "nist_800_53": ["SI-10", "AU-2"],
    },
    "CWE-352": {  # Cross-Site Request Forgery (CSRF)
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "soc2": ["CC6.1"],
        "nist_800_53": ["SI-10", "AC-3"],
    },
    "CWE-434": {  # Unrestricted Upload of Dangerous File Type
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.1"],
        "nist_800_53": ["SI-10", "SI-3"],
    },
    "CWE-444": {  # HTTP Request Smuggling
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.12"],
        "nist_800_53": ["SI-10", "SC-8"],
    },
    "CWE-601": {  # Open Redirect
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.1"],
        "nist_800_53": ["SI-10"],
    },
    "CWE-643": {  # XPath Injection
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "nist_800_53": ["SI-10"],
    },
    # ── Authentication & authorization ───────────────────────────────────────
    "CWE-269": {  # Improper Privilege Management
        "owasp_llm": ["LLM08"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.AA-01", "PR.AA-03"],
        "soc2": ["CC6.1"],
        "cis": ["CIS-16.1"],
        "nist_800_53": ["AC-3", "AC-6"],
    },
    "CWE-276": {  # Incorrect Default Permissions
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
        "cis": ["CIS-16.1"],
        "nist_800_53": ["AC-3", "AC-6"],
    },
    "CWE-287": {  # Improper Authentication
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
        "cis": ["CIS-16.1"],
        "nist_800_53": ["AC-3", "IA-5"],
    },
    "CWE-306": {  # Missing Authentication for Critical Function
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
        "cis": ["CIS-16.1"],
        "nist_800_53": ["AC-3", "IA-5"],
    },
    "CWE-639": {  # Authorization Bypass via User-Controlled Key (IDOR)
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.AA-01"],
        "cis": ["CIS-16.1"],
        "nist_800_53": ["AC-3"],
    },
    "CWE-862": {  # Missing Authorization
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
        "nist_800_53": ["AC-3", "AC-6"],
    },
    "CWE-863": {  # Incorrect Authorization
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
        "nist_800_53": ["AC-3", "AC-6"],
    },
    # ── Sensitive data exposure ──────────────────────────────────────────────
    "CWE-200": {  # Exposure of Sensitive Information
        "owasp_llm": ["LLM06"],
        "iso_27001": ["A.8.9"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
        "nist_800_53": ["AC-3", "SC-28"],
    },
    "CWE-209": {  # Error Message Information Leak
        "owasp_llm": ["LLM06"],
        "iso_27001": ["A.8.9"],
        "nist_csf": ["PR.AA-01"],
        "nist_800_53": ["SI-10"],
    },
    "CWE-215": {  # Information Exposure Through Debug Information
        "owasp_llm": ["LLM06"],
        "iso_27001": ["A.8.9"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
        "nist_800_53": ["CM-7"],
    },
    "CWE-312": {  # Cleartext Storage of Sensitive Information
        "owasp_llm": ["LLM06"],
        "iso_27001": ["A.8.9", "A.8.24"],
        "nist_csf": ["PR.DS-01"],
        "soc2": ["CC6.1"],
        "cis": ["CIS-16.1"],
        "nist_800_53": ["SC-28"],
    },
    "CWE-319": {  # Cleartext Transmission of Sensitive Information
        "owasp_llm": ["LLM06"],
        "iso_27001": ["A.8.24"],
        "nist_csf": ["PR.DS-02"],
        "soc2": ["CC6.1"],
        "nist_800_53": ["SC-8"],
    },
    "CWE-497": {  # Exposure of Sensitive System Information
        "owasp_llm": ["LLM06"],
        "iso_27001": ["A.8.9"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
        "nist_800_53": ["AC-3", "SC-28"],
    },
    "CWE-538": {  # Sensitive Information in Log Files
        "owasp_llm": ["LLM06"],
        "iso_27001": ["A.8.9"],
        "nist_csf": ["PR.AA-01"],
        "soc2": ["CC6.1"],
        "nist_800_53": ["AU-2", "SC-28"],
    },
    # ── Cryptography ─────────────────────────────────────────────────────────
    "CWE-295": {  # Improper Certificate Validation
        "iso_27001": ["A.8.24"],
        "nist_csf": ["PR.DS-02"],
        "soc2": ["CC6.1"],
        "cis": ["CIS-16.1"],
        "nist_800_53": ["SC-13", "SC-17"],
    },
    "CWE-326": {  # Inadequate Encryption Strength
        "iso_27001": ["A.8.24"],
        "nist_csf": ["PR.DS-01", "PR.DS-02"],
        "soc2": ["CC6.1"],
        "nist_800_53": ["SC-12", "SC-13"],
    },
    "CWE-330": {  # Use of Insufficiently Random Values
        "iso_27001": ["A.8.24"],
        "nist_csf": ["PR.DS-02"],
        "soc2": ["CC6.1"],
        "nist_800_53": ["SC-13"],
    },
    "CWE-347": {  # Improper Verification of Cryptographic Signature
        "iso_27001": ["A.8.24"],
        "nist_csf": ["PR.DS-02"],
        "soc2": ["CC6.1"],
        "nist_800_53": ["SC-13", "SI-7"],
    },
    # ── Memory safety & resource management ──────────────────────────────────
    "CWE-119": {  # Buffer Overflow
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.12"],
        "nist_800_53": ["SI-16"],
    },
    "CWE-125": {  # Out-of-bounds Read
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "nist_800_53": ["SI-16"],
    },
    "CWE-190": {  # Integer Overflow
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.12"],
        "nist_800_53": ["SI-16"],
    },
    "CWE-362": {  # Race Condition
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "nist_800_53": ["SI-4"],
    },
    "CWE-400": {  # Uncontrolled Resource Consumption (DoS)
        "owasp_llm": ["LLM10"],
        "iso_27001": ["A.8.8"],
        "nist_csf": ["DE.CM-09"],
        "cis": ["CIS-07.5"],
        "nist_800_53": ["SI-4", "CM-7"],
    },
    "CWE-416": {  # Use After Free
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.12"],
        "nist_800_53": ["SI-16"],
    },
    "CWE-476": {  # NULL Pointer Dereference
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "nist_800_53": ["SI-16"],
    },
    "CWE-787": {  # Out-of-bounds Write
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.12"],
        "nist_800_53": ["SI-16"],
    },
    # ── Supply chain & trust boundaries ──────────────────────────────────────
    "CWE-426": {  # Untrusted Search Path
        "owasp_llm": ["LLM05"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.1"],
        "nist_800_53": ["CM-7", "SI-7"],
    },
    "CWE-427": {  # Uncontrolled Search Path Element
        "owasp_llm": ["LLM05"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.1"],
        "nist_800_53": ["CM-7", "SI-7"],
    },
    "CWE-501": {  # Trust Boundary Violation
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.11"],
        "nist_800_53": ["AC-3", "SI-10"],
    },
    "CWE-776": {  # XML Bomb (Billion Laughs)
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-16.12"],
        "nist_800_53": ["SI-10", "SI-3"],
    },
    "CWE-829": {  # Inclusion of Functionality from Untrusted Control Sphere
        "owasp_llm": ["LLM05"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "cis": ["CIS-02.7"],
        "nist_800_53": ["CM-7", "SR-3", "SI-7"],
    },
    "CWE-942": {  # Permissive Cross-domain Policy
        "owasp_llm": ["LLM02"],
        "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.DS-01"],
        "nist_800_53": ["AC-3", "SC-8"],
    },
}


# ── Compliance Framework Registry ──────────────────────────────────────────
#
# Single source of truth for framework count.  Every tagger called in
# scanners/__init__.py must have an entry here.  Code that displays
# "N frameworks" should reference COMPLIANCE_FRAMEWORK_COUNT instead of
# hardcoding a number.

COMPLIANCE_FRAMEWORKS: tuple[tuple[str, str], ...] = (
    ("owasp_llm", "OWASP LLM Top 10"),
    ("atlas", "MITRE ATLAS"),
    ("attack", "MITRE ATT&CK Enterprise"),
    ("nist_ai_rmf", "NIST AI RMF 1.0"),
    ("owasp_mcp", "OWASP MCP Top 10"),
    ("owasp_agentic", "OWASP Agentic Top 10"),
    ("eu_ai_act", "EU AI Act"),
    ("nist_csf", "NIST CSF 2.0"),
    ("iso_27001", "ISO 27001:2022"),
    ("soc2", "SOC 2 TSC"),
    ("cis", "CIS Controls v8"),
    ("cmmc", "CMMC 2.0"),
    ("nist_800_53", "NIST 800-53 Rev 5"),
    ("fedramp", "FedRAMP Moderate"),
    ("pci_dss", "PCI DSS"),
)

COMPLIANCE_FRAMEWORK_COUNT: int = len(COMPLIANCE_FRAMEWORKS)
