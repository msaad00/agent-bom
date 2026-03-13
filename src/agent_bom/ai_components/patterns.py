"""AI SDK import patterns, model references, API key patterns, and deprecated models.

Patterns are organized by language and component type. Each pattern maps a regex
to metadata (package name, ecosystem, component type) for classification.

Zero external dependencies — stdlib ``re`` only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from agent_bom.ai_components.models import AIComponentSeverity, AIComponentType

# ── Pattern dataclass ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SDKPattern:
    """A single SDK import detection pattern."""

    regex: re.Pattern[str]
    name: str  # canonical SDK name
    component_type: AIComponentType
    package_name: str  # package manager name for CVE linking
    ecosystem: str  # pypi, npm, cargo, go, maven, nuget, rubygems
    language: str  # python, javascript, java, go, rust, ruby


@dataclass(frozen=True)
class ModelPattern:
    """A model string reference pattern."""

    regex: re.Pattern[str]
    provider: str  # openai, anthropic, google, meta, etc.
    deprecated: bool = False
    replacement: Optional[str] = None  # suggested replacement if deprecated
    severity: AIComponentSeverity = AIComponentSeverity.INFO


@dataclass(frozen=True)
class APIKeyPattern:
    """An API key pattern for detecting hardcoded credentials."""

    regex: re.Pattern[str]
    provider: str
    description: str
    severity: AIComponentSeverity = AIComponentSeverity.CRITICAL


# ── SDK import patterns by language ──────────────────────────────────────────

# Helpers to build word-boundary-safe import patterns
_WB = r"\b"


def _py_import(module: str) -> str:
    """Python import pattern: import X / from X import ..."""
    escaped = re.escape(module)
    return rf"(?:^|\n)\s*(?:import\s+{escaped}|from\s+{escaped}(?:\.\w+)*\s+import)"


def _js_import(module: str) -> str:
    """JS/TS import/require pattern."""
    escaped = re.escape(module)
    return rf"""(?:import\s+.*?from\s+['"](?:@[^/]+/)?{escaped}['"]|require\s*\(\s*['"](?:@[^/]+/)?{escaped}['"]\s*\))"""


def _java_import(package: str) -> str:
    """Java import pattern."""
    escaped = re.escape(package)
    return rf"import\s+{escaped}(?:\.\w+)*\s*;"


def _go_import(module: str) -> str:
    """Go import pattern."""
    escaped = re.escape(module)
    return rf'(?:import\s+.*?"{escaped}|"{escaped}[^"]*")'


def _rust_use(crate: str) -> str:
    """Rust use/extern crate pattern."""
    escaped = re.escape(crate)
    return rf"(?:use\s+{escaped}|extern\s+crate\s+{escaped})"


def _ruby_require(gem: str) -> str:
    """Ruby require pattern."""
    escaped = re.escape(gem)
    return rf"""require\s+['"]({escaped})['"]"""


# ── Python SDK patterns ──────────────────────────────────────────────────────

PYTHON_SDK_PATTERNS: list[SDKPattern] = [
    # LLM providers
    SDKPattern(re.compile(_py_import("openai")), "openai", AIComponentType.LLM_PROVIDER, "openai", "pypi", "python"),
    SDKPattern(re.compile(_py_import("anthropic")), "anthropic", AIComponentType.LLM_PROVIDER, "anthropic", "pypi", "python"),
    SDKPattern(
        re.compile(_py_import("google.generativeai")),
        "google-generativeai",
        AIComponentType.LLM_PROVIDER,
        "google-generativeai",
        "pypi",
        "python",
    ),
    SDKPattern(
        re.compile(_py_import("google.cloud.aiplatform")),
        "vertex-ai",
        AIComponentType.LLM_PROVIDER,
        "google-cloud-aiplatform",
        "pypi",
        "python",
    ),
    SDKPattern(re.compile(_py_import("mistralai")), "mistral", AIComponentType.LLM_PROVIDER, "mistralai", "pypi", "python"),
    SDKPattern(re.compile(_py_import("cohere")), "cohere", AIComponentType.LLM_PROVIDER, "cohere", "pypi", "python"),
    SDKPattern(re.compile(_py_import("together")), "together", AIComponentType.LLM_PROVIDER, "together", "pypi", "python"),
    SDKPattern(re.compile(_py_import("groq")), "groq", AIComponentType.LLM_PROVIDER, "groq", "pypi", "python"),
    SDKPattern(re.compile(_py_import("litellm")), "litellm", AIComponentType.LLM_PROVIDER, "litellm", "pypi", "python"),
    SDKPattern(re.compile(_py_import("ollama")), "ollama", AIComponentType.LLM_PROVIDER, "ollama", "pypi", "python"),
    SDKPattern(re.compile(_py_import("replicate")), "replicate", AIComponentType.LLM_PROVIDER, "replicate", "pypi", "python"),
    # Agent frameworks
    SDKPattern(
        re.compile(_py_import("langchain")),
        "langchain",
        AIComponentType.AGENT_FRAMEWORK,
        "langchain",
        "pypi",
        "python",
    ),
    SDKPattern(
        re.compile(_py_import("langgraph")),
        "langgraph",
        AIComponentType.AGENT_FRAMEWORK,
        "langgraph",
        "pypi",
        "python",
    ),
    SDKPattern(re.compile(_py_import("crewai")), "crewai", AIComponentType.AGENT_FRAMEWORK, "crewai", "pypi", "python"),
    SDKPattern(re.compile(_py_import("autogen")), "autogen", AIComponentType.AGENT_FRAMEWORK, "pyautogen", "pypi", "python"),
    SDKPattern(
        re.compile(_py_import("llama_index")),
        "llama-index",
        AIComponentType.AGENT_FRAMEWORK,
        "llama-index-core",
        "pypi",
        "python",
    ),
    SDKPattern(
        re.compile(_py_import("pydantic_ai")),
        "pydantic-ai",
        AIComponentType.AGENT_FRAMEWORK,
        "pydantic-ai",
        "pypi",
        "python",
    ),
    SDKPattern(
        re.compile(_py_import("smolagents")),
        "smolagents",
        AIComponentType.AGENT_FRAMEWORK,
        "smolagents",
        "pypi",
        "python",
    ),
    SDKPattern(
        re.compile(_py_import("semantic_kernel")),
        "semantic-kernel",
        AIComponentType.AGENT_FRAMEWORK,
        "semantic-kernel",
        "pypi",
        "python",
    ),
    SDKPattern(
        re.compile(_py_import("haystack")),
        "haystack",
        AIComponentType.AGENT_FRAMEWORK,
        "haystack-ai",
        "pypi",
        "python",
    ),
    SDKPattern(re.compile(_py_import("dspy")), "dspy", AIComponentType.AGENT_FRAMEWORK, "dspy-ai", "pypi", "python"),
    SDKPattern(re.compile(_py_import("guidance")), "guidance", AIComponentType.AGENT_FRAMEWORK, "guidance", "pypi", "python"),
    # ML frameworks
    SDKPattern(re.compile(_py_import("torch")), "pytorch", AIComponentType.ML_FRAMEWORK, "torch", "pypi", "python"),
    SDKPattern(
        re.compile(_py_import("tensorflow")),
        "tensorflow",
        AIComponentType.ML_FRAMEWORK,
        "tensorflow",
        "pypi",
        "python",
    ),
    SDKPattern(re.compile(_py_import("jax")), "jax", AIComponentType.ML_FRAMEWORK, "jax", "pypi", "python"),
    SDKPattern(
        re.compile(_py_import("transformers")),
        "transformers",
        AIComponentType.ML_FRAMEWORK,
        "transformers",
        "pypi",
        "python",
    ),
    SDKPattern(re.compile(_py_import("diffusers")), "diffusers", AIComponentType.ML_FRAMEWORK, "diffusers", "pypi", "python"),
    SDKPattern(
        re.compile(_py_import("sentence_transformers")),
        "sentence-transformers",
        AIComponentType.ML_FRAMEWORK,
        "sentence-transformers",
        "pypi",
        "python",
    ),
    SDKPattern(
        re.compile(_py_import("safetensors")),
        "safetensors",
        AIComponentType.ML_FRAMEWORK,
        "safetensors",
        "pypi",
        "python",
    ),
    # Vector stores
    SDKPattern(re.compile(_py_import("chromadb")), "chromadb", AIComponentType.VECTOR_STORE, "chromadb", "pypi", "python"),
    SDKPattern(re.compile(_py_import("pinecone")), "pinecone", AIComponentType.VECTOR_STORE, "pinecone-client", "pypi", "python"),
    SDKPattern(
        re.compile(_py_import("weaviate")),
        "weaviate",
        AIComponentType.VECTOR_STORE,
        "weaviate-client",
        "pypi",
        "python",
    ),
    SDKPattern(
        re.compile(_py_import("qdrant_client")),
        "qdrant",
        AIComponentType.VECTOR_STORE,
        "qdrant-client",
        "pypi",
        "python",
    ),
    SDKPattern(re.compile(_py_import("pymilvus")), "milvus", AIComponentType.VECTOR_STORE, "pymilvus", "pypi", "python"),
    SDKPattern(re.compile(_py_import("lancedb")), "lancedb", AIComponentType.VECTOR_STORE, "lancedb", "pypi", "python"),
    # MLOps
    SDKPattern(re.compile(_py_import("mlflow")), "mlflow", AIComponentType.MLOPS, "mlflow", "pypi", "python"),
    SDKPattern(re.compile(_py_import("wandb")), "wandb", AIComponentType.MLOPS, "wandb", "pypi", "python"),
    SDKPattern(re.compile(_py_import("neptune")), "neptune", AIComponentType.MLOPS, "neptune", "pypi", "python"),
    SDKPattern(re.compile(_py_import("clearml")), "clearml", AIComponentType.MLOPS, "clearml", "pypi", "python"),
    # Inference servers
    SDKPattern(re.compile(_py_import("vllm")), "vllm", AIComponentType.INFERENCE_SERVER, "vllm", "pypi", "python"),
]

# ── JavaScript/TypeScript SDK patterns ───────────────────────────────────────

JS_SDK_PATTERNS: list[SDKPattern] = [
    # LLM providers
    SDKPattern(re.compile(_js_import("openai")), "openai", AIComponentType.LLM_PROVIDER, "openai", "npm", "javascript"),
    SDKPattern(
        re.compile(_js_import("@anthropic-ai/sdk")),
        "anthropic",
        AIComponentType.LLM_PROVIDER,
        "@anthropic-ai/sdk",
        "npm",
        "javascript",
    ),
    SDKPattern(
        re.compile(_js_import("@google/generative-ai")),
        "google-generativeai",
        AIComponentType.LLM_PROVIDER,
        "@google/generative-ai",
        "npm",
        "javascript",
    ),
    SDKPattern(
        re.compile(_js_import("@mistralai/mistralai")),
        "mistral",
        AIComponentType.LLM_PROVIDER,
        "@mistralai/mistralai",
        "npm",
        "javascript",
    ),
    SDKPattern(re.compile(_js_import("cohere-ai")), "cohere", AIComponentType.LLM_PROVIDER, "cohere-ai", "npm", "javascript"),
    SDKPattern(re.compile(_js_import("groq-sdk")), "groq", AIComponentType.LLM_PROVIDER, "groq-sdk", "npm", "javascript"),
    SDKPattern(re.compile(_js_import("replicate")), "replicate", AIComponentType.LLM_PROVIDER, "replicate", "npm", "javascript"),
    SDKPattern(re.compile(_js_import("ollama")), "ollama", AIComponentType.LLM_PROVIDER, "ollama", "npm", "javascript"),
    # Agent frameworks
    SDKPattern(
        re.compile(_js_import("langchain")),
        "langchain",
        AIComponentType.AGENT_FRAMEWORK,
        "langchain",
        "npm",
        "javascript",
    ),
    SDKPattern(
        re.compile(_js_import("@langchain/core")),
        "langchain-core",
        AIComponentType.AGENT_FRAMEWORK,
        "@langchain/core",
        "npm",
        "javascript",
    ),
    SDKPattern(
        re.compile(_js_import("llamaindex")),
        "llama-index",
        AIComponentType.AGENT_FRAMEWORK,
        "llamaindex",
        "npm",
        "javascript",
    ),
    SDKPattern(
        re.compile(_js_import("@modelcontextprotocol/sdk")),
        "mcp-sdk",
        AIComponentType.AGENT_FRAMEWORK,
        "@modelcontextprotocol/sdk",
        "npm",
        "javascript",
    ),
    # ML frameworks
    SDKPattern(
        re.compile(_js_import("@tensorflow/tfjs")),
        "tensorflow-js",
        AIComponentType.ML_FRAMEWORK,
        "@tensorflow/tfjs",
        "npm",
        "javascript",
    ),
    SDKPattern(
        re.compile(_js_import("onnxruntime-node")),
        "onnxruntime",
        AIComponentType.ML_FRAMEWORK,
        "onnxruntime-node",
        "npm",
        "javascript",
    ),
    SDKPattern(
        re.compile(_js_import("@huggingface/inference")),
        "huggingface",
        AIComponentType.ML_FRAMEWORK,
        "@huggingface/inference",
        "npm",
        "javascript",
    ),
    # Vector stores
    SDKPattern(re.compile(_js_import("chromadb")), "chromadb", AIComponentType.VECTOR_STORE, "chromadb", "npm", "javascript"),
    SDKPattern(
        re.compile(_js_import("@pinecone-database/pinecone")),
        "pinecone",
        AIComponentType.VECTOR_STORE,
        "@pinecone-database/pinecone",
        "npm",
        "javascript",
    ),
    SDKPattern(
        re.compile(_js_import("weaviate-ts-client")),
        "weaviate",
        AIComponentType.VECTOR_STORE,
        "weaviate-ts-client",
        "npm",
        "javascript",
    ),
]

# ── Java SDK patterns ────────────────────────────────────────────────────────

JAVA_SDK_PATTERNS: list[SDKPattern] = [
    SDKPattern(
        re.compile(_java_import("com.theokanning.openai")),
        "openai-java",
        AIComponentType.LLM_PROVIDER,
        "com.theokanning.openai-gpt3-java:service",
        "maven",
        "java",
    ),
    SDKPattern(
        re.compile(_java_import("dev.langchain4j")),
        "langchain4j",
        AIComponentType.AGENT_FRAMEWORK,
        "dev.langchain4j:langchain4j",
        "maven",
        "java",
    ),
    SDKPattern(
        re.compile(_java_import("com.microsoft.semantickernel")),
        "semantic-kernel-java",
        AIComponentType.AGENT_FRAMEWORK,
        "com.microsoft.semantic-kernel:semantickernel-api",
        "maven",
        "java",
    ),
    SDKPattern(
        re.compile(_java_import("ai.djl")),
        "djl",
        AIComponentType.ML_FRAMEWORK,
        "ai.djl:api",
        "maven",
        "java",
    ),
    SDKPattern(
        re.compile(_java_import("org.tensorflow")),
        "tensorflow-java",
        AIComponentType.ML_FRAMEWORK,
        "org.tensorflow:tensorflow-core-api",
        "maven",
        "java",
    ),
    SDKPattern(
        re.compile(_java_import("ai.onnxruntime")),
        "onnxruntime-java",
        AIComponentType.ML_FRAMEWORK,
        "com.microsoft.onnxruntime:onnxruntime",
        "maven",
        "java",
    ),
]

# ── Go SDK patterns ──────────────────────────────────────────────────────────

GO_SDK_PATTERNS: list[SDKPattern] = [
    SDKPattern(
        re.compile(_go_import("github.com/sashabaranov/go-openai")),
        "go-openai",
        AIComponentType.LLM_PROVIDER,
        "github.com/sashabaranov/go-openai",
        "go",
        "go",
    ),
    SDKPattern(
        re.compile(_go_import("github.com/anthropics/anthropic-sdk-go")),
        "anthropic-go",
        AIComponentType.LLM_PROVIDER,
        "github.com/anthropics/anthropic-sdk-go",
        "go",
        "go",
    ),
    SDKPattern(
        re.compile(_go_import("github.com/google/generative-ai-go")),
        "google-genai-go",
        AIComponentType.LLM_PROVIDER,
        "github.com/google/generative-ai-go",
        "go",
        "go",
    ),
    SDKPattern(
        re.compile(_go_import("github.com/tmc/langchaingo")),
        "langchaingo",
        AIComponentType.AGENT_FRAMEWORK,
        "github.com/tmc/langchaingo",
        "go",
        "go",
    ),
    SDKPattern(
        re.compile(_go_import("github.com/ollama/ollama")),
        "ollama-go",
        AIComponentType.LLM_PROVIDER,
        "github.com/ollama/ollama",
        "go",
        "go",
    ),
]

# ── Rust SDK patterns ────────────────────────────────────────────────────────

RUST_SDK_PATTERNS: list[SDKPattern] = [
    SDKPattern(
        re.compile(_rust_use("async_openai")),
        "async-openai",
        AIComponentType.LLM_PROVIDER,
        "async-openai",
        "cargo",
        "rust",
    ),
    SDKPattern(
        re.compile(_rust_use("llm_chain")),
        "llm-chain",
        AIComponentType.AGENT_FRAMEWORK,
        "llm-chain",
        "cargo",
        "rust",
    ),
    SDKPattern(
        re.compile(_rust_use("candle_core")),
        "candle",
        AIComponentType.ML_FRAMEWORK,
        "candle-core",
        "cargo",
        "rust",
    ),
    SDKPattern(
        re.compile(_rust_use("ort")),
        "ort",
        AIComponentType.ML_FRAMEWORK,
        "ort",
        "cargo",
        "rust",
    ),
]

# ── Ruby SDK patterns ────────────────────────────────────────────────────────

RUBY_SDK_PATTERNS: list[SDKPattern] = [
    SDKPattern(
        re.compile(_ruby_require("ruby-openai")),
        "ruby-openai",
        AIComponentType.LLM_PROVIDER,
        "ruby-openai",
        "rubygems",
        "ruby",
    ),
    SDKPattern(
        re.compile(_ruby_require("anthropic")),
        "anthropic-ruby",
        AIComponentType.LLM_PROVIDER,
        "anthropic",
        "rubygems",
        "ruby",
    ),
    SDKPattern(
        re.compile(_ruby_require("langchainrb")),
        "langchainrb",
        AIComponentType.AGENT_FRAMEWORK,
        "langchainrb",
        "rubygems",
        "ruby",
    ),
]

# ── All SDK patterns combined ────────────────────────────────────────────────

ALL_SDK_PATTERNS: list[SDKPattern] = (
    PYTHON_SDK_PATTERNS + JS_SDK_PATTERNS + JAVA_SDK_PATTERNS + GO_SDK_PATTERNS + RUST_SDK_PATTERNS + RUBY_SDK_PATTERNS
)

# ── Language → file extensions ───────────────────────────────────────────────

LANGUAGE_EXTENSIONS: dict[str, list[str]] = {
    "python": [".py", ".pyx"],
    "javascript": [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts"],
    "java": [".java"],
    "go": [".go"],
    "rust": [".rs"],
    "ruby": [".rb"],
}

EXTENSION_TO_LANGUAGE: dict[str, str] = {ext: lang for lang, exts in LANGUAGE_EXTENSIONS.items() for ext in exts}

# ── Model string patterns ────────────────────────────────────────────────────
# Match model name strings in source code (string literals, config values)

MODEL_PATTERNS: list[ModelPattern] = [
    # OpenAI current models
    ModelPattern(re.compile(rf"{_WB}gpt-4o(?:-mini)?(?:-\d{{4}}-\d{{2}}-\d{{2}})?{_WB}"), "openai"),
    ModelPattern(re.compile(rf"{_WB}gpt-4-turbo(?:-preview)?(?:-\d{{4}}-\d{{2}}-\d{{2}})?{_WB}"), "openai"),
    ModelPattern(re.compile(rf"{_WB}gpt-4(?:-\d{{4}}-\d{{2}}-\d{{2}})?{_WB}"), "openai"),
    ModelPattern(re.compile(rf"{_WB}o[134]-(?:mini|preview)(?:-\d{{4}}-\d{{2}}-\d{{2}})?{_WB}"), "openai"),
    ModelPattern(re.compile(rf"{_WB}text-embedding-3-(?:small|large){_WB}"), "openai"),
    ModelPattern(re.compile(rf"{_WB}dall-e-[23]{_WB}"), "openai"),
    ModelPattern(re.compile(rf"{_WB}whisper-1{_WB}"), "openai"),
    ModelPattern(re.compile(rf"{_WB}tts-1(?:-hd)?{_WB}"), "openai"),
    # Anthropic models
    ModelPattern(re.compile(rf"{_WB}claude-(?:opus|sonnet|haiku)-4-\d+-\d+{_WB}"), "anthropic"),
    ModelPattern(re.compile(rf"{_WB}claude-3(?:\.5)?-(?:opus|sonnet|haiku)(?:-\d+)?{_WB}"), "anthropic"),
    ModelPattern(re.compile(rf"{_WB}claude-(?:opus|sonnet|haiku)-4(?:\.\d+)?{_WB}"), "anthropic"),
    # Google models
    ModelPattern(re.compile(rf"{_WB}gemini-(?:2\.5|2\.0|1\.5|1\.0)-(?:pro|flash|ultra)(?:-\d+)?{_WB}"), "google"),
    ModelPattern(re.compile(rf"{_WB}gemma-[23](?:-\d+b)?(?:-it)?{_WB}"), "google"),
    # Meta models
    ModelPattern(re.compile(rf"{_WB}llama-?[234](?:\.\d)?(?:-\d+b)?(?:-instruct|-chat)?{_WB}", re.I), "meta"),
    # Mistral models
    ModelPattern(re.compile(rf"{_WB}mistral-(?:large|medium|small|tiny)(?:-latest|-\d+)?{_WB}"), "mistral"),
    ModelPattern(re.compile(rf"{_WB}mixtral-\d+x\d+b(?:-instruct)?{_WB}", re.I), "mistral"),
    ModelPattern(re.compile(rf"{_WB}codestral(?:-latest|-\d+)?{_WB}"), "mistral"),
    # Cohere models
    ModelPattern(re.compile(rf"{_WB}command-r(?:-plus)?(?:-\d+)?{_WB}"), "cohere"),
    # Embedding models
    ModelPattern(re.compile(rf"{_WB}text-embedding-ada-002{_WB}"), "openai"),
]

# ── Deprecated model patterns ────────────────────────────────────────────────

DEPRECATED_MODEL_PATTERNS: list[ModelPattern] = [
    # OpenAI deprecated
    ModelPattern(
        re.compile(rf"{_WB}gpt-3\.5-turbo(?:-\d+)?{_WB}"),
        "openai",
        deprecated=True,
        replacement="gpt-4o-mini",
        severity=AIComponentSeverity.MEDIUM,
    ),
    ModelPattern(
        re.compile(rf"{_WB}text-davinci-00[1234]{_WB}"),
        "openai",
        deprecated=True,
        replacement="gpt-4o",
        severity=AIComponentSeverity.HIGH,
    ),
    ModelPattern(
        re.compile(rf"{_WB}code-davinci-002{_WB}"),
        "openai",
        deprecated=True,
        replacement="gpt-4o",
        severity=AIComponentSeverity.HIGH,
    ),
    ModelPattern(
        re.compile(rf"{_WB}text-embedding-ada-002{_WB}"),
        "openai",
        deprecated=True,
        replacement="text-embedding-3-small",
        severity=AIComponentSeverity.LOW,
    ),
    ModelPattern(
        re.compile(rf"{_WB}text-curie-001{_WB}"),
        "openai",
        deprecated=True,
        replacement="gpt-4o-mini",
        severity=AIComponentSeverity.HIGH,
    ),
    ModelPattern(
        re.compile(rf"{_WB}text-babbage-001{_WB}"),
        "openai",
        deprecated=True,
        replacement="gpt-4o-mini",
        severity=AIComponentSeverity.HIGH,
    ),
    # Anthropic deprecated
    ModelPattern(
        re.compile(rf"{_WB}claude-2(?:\.\d)?{_WB}"),
        "anthropic",
        deprecated=True,
        replacement="claude-sonnet-4-20250514",
        severity=AIComponentSeverity.MEDIUM,
    ),
    ModelPattern(
        re.compile(rf"{_WB}claude-instant-1(?:\.\d)?{_WB}"),
        "anthropic",
        deprecated=True,
        replacement="claude-haiku-4-5-20251001",
        severity=AIComponentSeverity.MEDIUM,
    ),
    # Google deprecated
    ModelPattern(
        re.compile(rf"{_WB}palm-2{_WB}", re.I),
        "google",
        deprecated=True,
        replacement="gemini-2.0-flash",
        severity=AIComponentSeverity.MEDIUM,
    ),
    ModelPattern(
        re.compile(rf"{_WB}bard{_WB}", re.I),
        "google",
        deprecated=True,
        replacement="gemini-2.0-flash",
        severity=AIComponentSeverity.MEDIUM,
    ),
]

# ── API key patterns ─────────────────────────────────────────────────────────
# Match hardcoded API keys/tokens in source code (not env var references)

API_KEY_PATTERNS: list[APIKeyPattern] = [
    APIKeyPattern(
        re.compile(r"""(?:['"])(sk-(?:proj-)?[A-Za-z0-9_-]{20,})(?:['"])"""),
        "openai",
        "OpenAI API key hardcoded in source",
    ),
    APIKeyPattern(
        re.compile(r"""(?:['"])(sk-ant-[A-Za-z0-9_-]{20,})(?:['"])"""),
        "anthropic",
        "Anthropic API key hardcoded in source",
    ),
    APIKeyPattern(
        re.compile(r"""(?:['"])(hf_[A-Za-z0-9]{20,})(?:['"])"""),
        "huggingface",
        "HuggingFace token hardcoded in source",
    ),
    APIKeyPattern(
        re.compile(r"""(?:['"])(AIza[A-Za-z0-9_-]{35})(?:['"])"""),
        "google",
        "Google AI API key hardcoded in source",
    ),
    APIKeyPattern(
        re.compile(r"""(?:['"])(gsk_[A-Za-z0-9]{20,})(?:['"])"""),
        "groq",
        "Groq API key hardcoded in source",
    ),
    APIKeyPattern(
        re.compile(r"""(?:['"])(r8_[A-Za-z0-9]{20,})(?:['"])"""),
        "replicate",
        "Replicate API token hardcoded in source",
    ),
    APIKeyPattern(
        re.compile(r"""(?:['"])(sess-[A-Za-z0-9]{20,})(?:['"])"""),
        "together",
        "Together AI session token hardcoded in source",
    ),
    APIKeyPattern(
        re.compile(r"""(?:['"])(xai-[A-Za-z0-9]{20,})(?:['"])"""),
        "xai",
        "xAI API key hardcoded in source",
    ),
]

# ── Language → pattern set mapping ───────────────────────────────────────────

SDK_PATTERNS_BY_LANGUAGE: dict[str, list[SDKPattern]] = {
    "python": PYTHON_SDK_PATTERNS,
    "javascript": JS_SDK_PATTERNS,
    "java": JAVA_SDK_PATTERNS,
    "go": GO_SDK_PATTERNS,
    "rust": RUST_SDK_PATTERNS,
    "ruby": RUBY_SDK_PATTERNS,
}
