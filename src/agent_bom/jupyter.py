"""Jupyter notebook scanner — detect AI library usage in .ipynb files.

Scans code cells for AI/ML library imports, pip install commands,
model loading patterns, and credential environment variables.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from agent_bom.models import Agent, AgentType, MCPServer, Package

logger = logging.getLogger(__name__)

# Map Python import names -> PyPI package names
_IMPORT_TO_PACKAGE: dict[str, str] = {
    "openai": "openai",
    "anthropic": "anthropic",
    "langchain": "langchain",
    "langchain_core": "langchain-core",
    "langchain_community": "langchain-community",
    "langgraph": "langgraph",
    "transformers": "transformers",
    "torch": "torch",
    "tensorflow": "tensorflow",
    "keras": "keras",
    "huggingface_hub": "huggingface-hub",
    "litellm": "litellm",
    "crewai": "crewai",
    "autogen": "autogen",
    "llama_index": "llama-index",
    "pydantic_ai": "pydantic-ai",
    "smolagents": "smolagents",
    "semantic_kernel": "semantic-kernel",
    "haystack": "haystack-ai",
    "cohere": "cohere",
    "mistralai": "mistralai",
    "google.generativeai": "google-generativeai",
    "vertexai": "google-cloud-aiplatform",
    "bedrock": "boto3",
    "sentence_transformers": "sentence-transformers",
    "chromadb": "chromadb",
    "pinecone": "pinecone-client",
    "weaviate": "weaviate-client",
    "qdrant_client": "qdrant-client",
}

# Regex: import statement for AI libraries
_AI_IMPORT_RE = re.compile(
    r"^(?:import|from)\s+("
    + "|".join(re.escape(k) for k in _IMPORT_TO_PACKAGE)
    + r")(?:\s|\.|$)",
    re.MULTILINE,
)

# Regex: pip install in notebook cells (! or % prefix)
_PIP_INSTALL_RE = re.compile(
    r"[!%]pip\s+install\s+([^\n]+)", re.MULTILINE
)

# Regex: credential env vars
_CRED_ENV_RE = re.compile(
    r'os\.environ\s*[\[\.]\s*["\']([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[A-Z0-9_]*)["\']',
)

# Regex: hardcoded API keys (warning)
_HARDCODED_KEY_RE = re.compile(
    r'(?:api_key|apikey|token|secret)\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
    re.IGNORECASE,
)

# Regex: pip package name + optional version
_PKG_SPEC_RE = re.compile(r"([a-zA-Z0-9_-]+(?:\[[a-zA-Z0-9_,-]+\])?)\s*(?:[=<>!~]+\s*([0-9][0-9a-zA-Z.*]*))?\s*")


def _extract_code_cells(notebook_path: Path) -> list[str]:
    """Extract source code from all code cells in a notebook."""
    try:
        data = json.loads(notebook_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        logger.warning("Failed to parse notebook %s: %s", notebook_path, exc)
        return []

    cells = data.get("cells", [])
    code_sources = []
    for cell in cells:
        if cell.get("cell_type") == "code":
            source = cell.get("source", [])
            if isinstance(source, list):
                code_sources.append("".join(source))
            elif isinstance(source, str):
                code_sources.append(source)
    return code_sources


def _parse_pip_packages(line: str) -> list[tuple[str, str]]:
    """Parse package names and versions from a pip install line."""
    results = []
    # Remove flags like -q, --quiet, -U, --upgrade, --no-cache-dir
    cleaned = re.sub(r"\s-[-\w]+(?:\s+\S+)?", " ", line)
    for match in _PKG_SPEC_RE.finditer(cleaned):
        name = match.group(1).strip()
        version = match.group(2) or ""
        # Skip if it looks like a flag or URL
        if name.startswith("-") or name.startswith("http") or name.startswith("git+"):
            continue
        if name:
            results.append((name, version))
    return results


def scan_jupyter_notebooks(
    directory: str | Path,
) -> tuple[list[Agent], list[str]]:
    """Scan Jupyter notebooks in a directory for AI library usage.

    Detects:
    - AI/ML library imports (openai, langchain, transformers, etc.)
    - pip install commands in code cells
    - Credential environment variable references
    - Hardcoded API keys (warning)

    Returns (agents, warnings) following the standard scanner interface.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return [], [f"Jupyter scan: {directory} is not a directory"]

    notebooks = sorted(directory.rglob("*.ipynb"))
    # Exclude checkpoint directories
    notebooks = [nb for nb in notebooks if ".ipynb_checkpoints" not in str(nb)]

    if not notebooks:
        return [], []

    agents: list[Agent] = []
    warnings: list[str] = []

    for nb_path in notebooks:
        code_cells = _extract_code_cells(nb_path)
        if not code_cells:
            continue

        full_source = "\n".join(code_cells)
        seen_packages: dict[str, str] = {}  # name -> version
        credential_env_vars: list[str] = []

        # 1. Detect AI library imports
        for match in _AI_IMPORT_RE.finditer(full_source):
            import_name = match.group(1)
            pkg_name = _IMPORT_TO_PACKAGE.get(import_name)
            if pkg_name and pkg_name not in seen_packages:
                seen_packages[pkg_name] = ""

        # 2. Detect pip install commands
        for match in _PIP_INSTALL_RE.finditer(full_source):
            install_line = match.group(1)
            for name, version in _parse_pip_packages(install_line):
                # Normalize: strip extras brackets for dedup key
                base_name = re.sub(r"\[.*\]", "", name)
                if base_name not in seen_packages:
                    seen_packages[base_name] = version

        # 3. Detect credential env vars
        for match in _CRED_ENV_RE.finditer(full_source):
            env_name = match.group(1)
            if env_name not in credential_env_vars:
                credential_env_vars.append(env_name)

        # 4. Detect hardcoded API keys (warning only)
        for match in _HARDCODED_KEY_RE.finditer(full_source):
            key_value = match.group(1)
            # Skip common false positives
            if key_value in ("your_api_key_here", "YOUR_API_KEY", "test", "example"):
                continue
            warnings.append(
                f"Jupyter: possible hardcoded API key in {nb_path.name} "
                f"(value starts with '{key_value[:8]}...')"
            )

        # Skip notebooks with no AI-related findings
        if not seen_packages and not credential_env_vars:
            continue

        # Build Package objects
        packages = [
            Package(
                name=name,
                version=version or "latest",
                ecosystem="pypi",
            )
            for name, version in seen_packages.items()
        ]

        # Build a synthetic MCPServer to hold the packages/creds
        env_dict = {k: "***REDACTED***" for k in credential_env_vars}
        server = MCPServer(
            name=f"notebook:{nb_path.stem}",
            command="jupyter",
            args=[str(nb_path.name)],
            env=env_dict,
            packages=packages,
        )

        # Build Agent
        agent = Agent(
            name=f"jupyter:{nb_path.stem}",
            agent_type=AgentType.CUSTOM,
            config_path=str(nb_path),
            mcp_servers=[server],
            source="jupyter",
        )
        agents.append(agent)

    return agents, warnings
